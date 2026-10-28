package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"maps"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"syscall"
	"testing"
	"time"
)

// The api's /connect/control carries one request per contract, so a busy
// provider sends far more of them than the lb's shared per-address limit
// (450/min, burst 150 in main) admits, and the lb refused most of its
// contract requests with 429 (support inbox 8093, 8077). services.yml now
// gives such a route a per-address zone of its own (route_rate_limits). The
// tests below put svc-b, an api-like service with cors origins, in the place
// of the api.

const routeRateLimitTestService = "        svc-b:\n"

// the test services with route_rate_limits on svc-b. extra is inserted
// before the services, e.g. hidden_prefixes.
func routeRateLimitServicesYaml(t *testing.T, routeRateLimits string, extra string) []byte {
	t.Helper()
	baseYaml, err := testServicesFS.ReadFile("testdata/services.yml")
	if err != nil {
		t.Fatal(err)
	}
	servicesYaml := string(baseYaml)
	// the first svc-b is the latest version's, which the lb is generated from
	if !strings.Contains(servicesYaml, routeRateLimitTestService) {
		t.Fatal("test services fixture lacks svc-b")
	}
	servicesYaml = strings.Replace(servicesYaml, routeRateLimitTestService, routeRateLimitTestService+routeRateLimits, 1)
	if extra != "" {
		domains := "domains:\n    example.com: route53\n"
		if !strings.Contains(servicesYaml, domains) {
			t.Fatal("test services fixture lacks the domains insertion boundary")
		}
		servicesYaml = strings.Replace(servicesYaml, domains, domains+extra, 1)
	}
	return []byte(servicesYaml)
}

const connectControlRouteRateLimits = "" +
	"            route_rate_limits:\n" +
	"                -   path: /connect/control\n" +
	"                    requests_per_minute: 12000\n" +
	"                    burst: 6000\n"

// The server blocks of a generated config, each from its `server {` line to
// its closing brace at the same indent.
func nginxServerBlocks(config string) []string {
	blocks := []string{}
	lines := strings.Split(config, "\n")
	for i := 0; i < len(lines); i += 1 {
		if strings.TrimSpace(lines[i]) != "server {" {
			continue
		}
		indent := lines[i][:len(lines[i])-len(strings.TrimLeft(lines[i], " "))]
		for j := i + 1; j < len(lines); j += 1 {
			if lines[j] == indent+"}" {
				blocks = append(blocks, strings.Join(lines[i:j+1], "\n"))
				i = j
				break
			}
		}
	}
	return blocks
}

// The body of every `<header> {` block in a generated config, from its open
// line to its closing brace at the same indent.
func nginxBlocks(config string, header string) []string {
	blocks := []string{}
	lines := strings.Split(config, "\n")
	for i := 0; i < len(lines); i += 1 {
		if strings.TrimSpace(lines[i]) != header+" {" {
			continue
		}
		indent := lines[i][:len(lines[i])-len(strings.TrimLeft(lines[i], " "))]
		for j := i + 1; j < len(lines); j += 1 {
			if lines[j] == indent+"}" {
				blocks = append(blocks, strings.Join(lines[i:j+1], "\n"))
				break
			}
		}
	}
	return blocks
}

// /connect/control gets an exact location in each of the service's https
// server blocks, which counts it in its own zone at its own rate and burst
// and proxies it as the service's prefix location does, while every other
// route of the lb stays in the shared standardlimit zone. Before
// route_rate_limits the key was ignored and /connect/control spent the
// shared per-address budget.
func TestNginxConfigLimitsARouteRateLimitInItsOwnZone(t *testing.T) {
	servicesYaml := routeRateLimitServicesYaml(t, connectControlRouteRateLimits, "")
	env, _ := setupTestVaultWithTLS(t, servicesYaml)
	nginxConfig, err := NewNginxConfig(env, nil)
	if err != nil {
		t.Fatal(err)
	}

	blockConfigs := nginxConfig.Generate()
	if len(blockConfigs) == 0 {
		t.Fatal("no lb block config generated")
	}
	for blockName, config := range blockConfigs {
		zone := "limit_req_zone $limit_key zone=route_svc-b_connect_control:64m rate=12000r/m;"
		if count := strings.Count(config, zone); count != 1 {
			t.Errorf("block %s defines the route zone %d times, want 1 %q", blockName, count, zone)
		}
		// the http block's shared limit is unchanged and applies to every
		// location that declares no limit of its own
		if count := strings.Count(config, "limit_req zone=standardlimit burst=150 nodelay;"); count != 1 {
			t.Errorf("block %s applies the shared limit %d times, want once at the http level", blockName, count)
		}
		if !strings.Contains(config, "limit_req_zone $limit_key zone=standardlimit:256m rate=450r/m;") {
			t.Errorf("block %s lost the shared zone", blockName)
		}

		routeLocationCount := 0
		svcBHttpsServerCount := 0
		for _, server := range nginxServerBlocks(config) {
			routeLocations := nginxBlocks(server, "location = /connect/control")
			svcBHttps := strings.Contains(server, "server_name test-svc-b.example.com;") &&
				strings.Contains(server, "listen 443 ssl;")
			if svcBHttps {
				svcBHttpsServerCount += 1
				if len(routeLocations) != 1 {
					t.Errorf("block %s svc-b https server has %d /connect/control locations, want 1", blockName, len(routeLocations))
				}
			} else if 0 < len(routeLocations) {
				t.Errorf("block %s has a /connect/control location outside svc-b's https server:\n%s", blockName, server)
			}
			routeLocationCount += len(routeLocations)

			for _, routeLocation := range routeLocations {
				for _, required := range []string{
					"limit_req zone=route_svc-b_connect_control burst=6000 nodelay;",
					// the exact location replaces the whole uri with the path
					"proxy_pass http://service-block-svc-b/connect/control;",
					// the lb-to-service contract headers of the prefix location
					"proxy_set_header X-UR-Forwarded-For $warp_client_addr:$remote_port;",
					`proxy_set_header X-Forwarded-For "";`,
					`proxy_set_header X-UR-Request-Buffering "";`,
					// the service's cors policy and security headers
					"set $cors_origin '';",
					"if ($http_origin = 'https://example.com') {",
					"if ($request_method = 'OPTIONS') {",
					"add_header 'Access-Control-Allow-Origin' $cors_origin always;",
					"add_header Strict-Transport-Security 'max-age=63072000; includeSubDomains; preload' always;",
				} {
					if !strings.Contains(routeLocation, required) {
						t.Errorf("block %s /connect/control location lacks %q:\n%s", blockName, required, routeLocation)
					}
				}
				if strings.Contains(routeLocation, "standardlimit") {
					t.Errorf("block %s /connect/control location still uses the shared zone:\n%s", blockName, routeLocation)
				}
			}

			// the service's prefix location keeps the shared limit, which it
			// inherits from the http block
			for _, prefixLocation := range nginxBlocks(server, "location /") {
				if strings.Contains(prefixLocation, "limit_req ") {
					t.Errorf("block %s prefix location declares a limit of its own:\n%s", blockName, prefixLocation)
				}
			}
		}
		if svcBHttpsServerCount == 0 {
			t.Errorf("block %s serves no svc-b https server", blockName)
		}
		if routeLocationCount != svcBHttpsServerCount {
			t.Errorf("block %s has %d /connect/control locations for %d svc-b https servers", blockName, routeLocationCount, svcBHttpsServerCount)
		}
	}
}

// Behind a hidden route prefix the exact location matches the prefixed uri
// and proxies the service-relative path, as the prefix location strips the
// prefix.
func TestNginxConfigRouteRateLimitBehindHiddenPrefixes(t *testing.T) {
	servicesYaml := routeRateLimitServicesYaml(t, connectControlRouteRateLimits, "hidden_prefixes:\n    - hidden-one\n    - hidden-two\n")
	env, _ := setupTestVaultWithTLS(t, servicesYaml)
	nginxConfig, err := NewNginxConfig(env, nil)
	if err != nil {
		t.Fatal(err)
	}

	for blockName, config := range nginxConfig.Generate() {
		for _, routePrefix := range []string{"/hidden-one", "/hidden-two"} {
			routeLocations := nginxBlocks(config, "location = "+routePrefix+"/connect/control")
			if len(routeLocations) == 0 {
				t.Errorf("block %s has no /connect/control location behind %s", blockName, routePrefix)
			}
			for _, routeLocation := range routeLocations {
				if !strings.Contains(routeLocation, "proxy_pass http://service-block-svc-b/connect/control;") {
					t.Errorf("block %s does not strip %s from the route:\n%s", blockName, routePrefix, routeLocation)
				}
				if !strings.Contains(routeLocation, "limit_req zone=route_svc-b_connect_control burst=6000 nodelay;") {
					t.Errorf("block %s route behind %s lacks its own limit:\n%s", blockName, routePrefix, routeLocation)
				}
			}
		}
		if 0 < len(nginxBlocks(config, "location = /connect/control")) {
			t.Errorf("block %s serves the route without its hidden prefix", blockName)
		}
	}
}

// A service with no route_rate_limits gets no route zone or exact location,
// so an lb generated from a services.yml without the key is unchanged.
func TestNginxConfigWithoutRouteRateLimitsHasNoRouteZone(t *testing.T) {
	servicesYaml, err := testServicesFS.ReadFile("testdata/services.yml")
	if err != nil {
		t.Fatal(err)
	}
	env, _ := setupTestVaultWithTLS(t, servicesYaml)
	nginxConfig, err := NewNginxConfig(env, nil)
	if err != nil {
		t.Fatal(err)
	}
	for blockName, config := range nginxConfig.Generate() {
		if strings.Contains(config, "zone=route_") || strings.Contains(config, "location = /") {
			t.Errorf("block %s has a route limit without route_rate_limits", blockName)
		}
	}
}

// nginx accepts the generated config with route limits: the zones, the exact
// locations behind every route prefix, and their cors and proxy directives.
func TestNginxConfigValidationWithRouteRateLimits(t *testing.T) {
	nginxBinary := nginxConfigValidationBinary(t)

	for _, extra := range []string{"", "hidden_prefixes:\n    - hidden-one\n    - hidden-two\n"} {
		servicesYaml := nginxServicesWithLongStatusMapKey(t, routeRateLimitServicesYaml(t, connectControlRouteRateLimits, extra))
		env, vaultDir := setupTestVaultWithTLS(t, servicesYaml)
		nginxConfig, err := NewNginxConfig(env, nil)
		if err != nil {
			t.Fatal(err)
		}
		blockConfigs := nginxConfig.Generate()
		if len(blockConfigs) == 0 {
			t.Fatal("no lb block config generated")
		}
		for block, config := range blockConfigs {
			if !strings.Contains(config, "zone=route_svc-b_connect_control") {
				t.Fatalf("block %s has no route zone to validate", block)
			}
			config = localNginxConfig(config, vaultDir)
			tmpDir := t.TempDir()
			confPath := filepath.Join(tmpDir, "nginx.conf")
			if err := os.WriteFile(confPath, []byte(config), 0644); err != nil {
				t.Fatal(err)
			}
			for _, dir := range []string{"logs", "run"} {
				os.MkdirAll(filepath.Join(tmpDir, dir), 0755)
			}
			cmd := exec.Command(nginxBinary, "-t", "-c", confPath, "-p", tmpDir, "-e", filepath.Join(tmpDir, "error.log"))
			if output, err := cmd.CombinedOutput(); err != nil {
				t.Errorf("nginx config validation failed for block %s (hidden prefixes %q):\n%s\n\nConfig written to: %s", block, extra, string(output), confPath)
			}
		}
	}
}

// Runs a generated lb config in nginx and spends one address's budgets: the
// route's own budget on /connect/control, and the shared budget on another
// route of the same service. Each route is refused once its own budget is
// spent and not before, so neither spends the other's. With /connect/control
// in the shared zone, as before route_rate_limits, its requests spent the
// shared budget: the other route was refused early and /connect/control
// late.
func TestNginxCountsARouteRateLimitApartFromTheSharedLimit(t *testing.T) {
	nginxBinary := nginxConfigValidationBinary(t)

	// one request a minute refills nothing while the test runs, so each
	// budget is exactly its burst plus one
	const sharedBurst = 30
	const routeBurst = 20
	servicesYaml := string(routeRateLimitServicesYaml(t, ""+
		"            route_rate_limits:\n"+
		"                -   path: /connect/control\n"+
		"                    requests_per_minute: 1\n"+
		fmt.Sprintf("                    burst: %d\n", routeBurst),
		"",
	))
	sharedLimit := "    requests_per_minute: 450\n    burst: 150\n"
	if !strings.Contains(servicesYaml, sharedLimit) {
		t.Fatal("test services fixture lacks the default rate limit")
	}
	servicesYaml = strings.Replace(servicesYaml, sharedLimit, fmt.Sprintf("    requests_per_minute: 1\n    burst: %d\n", sharedBurst), 1)
	// without capacity sizing nginx runs one worker, so one zone state
	servicesYaml = strings.ReplaceAll(servicesYaml, "                    concurrent_clients: 786432\n", "")
	servicesYaml = strings.ReplaceAll(servicesYaml, "                    cores: 24\n", "")

	env, vaultDir := setupTestVaultWithTLS(t, []byte(servicesYaml))
	nginxConfig, err := NewNginxConfig(env, nil)
	if err != nil {
		t.Fatal(err)
	}
	blockConfigs := nginxConfig.Generate()
	blocks := slices.Collect(maps.Keys(blockConfigs))
	if len(blocks) == 0 {
		t.Fatal("no lb block config generated")
	}
	sort.Strings(blocks)
	config := localNginxConfig(blockConfigs[blocks[0]], vaultDir)
	// the stream block, last in the config, proxies other ports and is not
	// under test
	if i := strings.Index(config, "\nstream {"); 0 <= i {
		config = config[:i+1]
	}

	service := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "ok")
	}))
	defer service.Close()
	servicePort := service.Listener.Addr().(*net.TCPAddr).Port
	config = regexp.MustCompile(`server 127\.0\.0\.1:\d+`).ReplaceAllString(
		config,
		fmt.Sprintf("server 127.0.0.1:%d", servicePort),
	)

	httpPort := freeLoopbackPort(t)
	httpsPort := freeLoopbackPort(t)
	config = loopbackNginxListens(t, config, map[int]int{80: httpPort, 443: httpsPort})

	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "logs"), 0755); err != nil {
		t.Fatal(err)
	}
	confPath := filepath.Join(dir, "nginx.conf")
	if err := os.WriteFile(confPath, []byte(config), 0644); err != nil {
		t.Fatal(err)
	}
	stderrPath := filepath.Join(dir, "stderr")
	stderr, err := os.Create(stderrPath)
	if err != nil {
		t.Fatal(err)
	}
	defer stderr.Close()
	nginxErrors := func() string {
		data, _ := os.ReadFile(stderrPath)
		errorLog, _ := os.ReadFile(filepath.Join(dir, "error.log"))
		return string(data) + string(errorLog)
	}

	cmd := exec.Command(nginxBinary, "-g", "daemon off;", "-c", confPath, "-p", dir, "-e", filepath.Join(dir, "error.log"))
	cmd.Stdout = stderr
	cmd.Stderr = stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		cmd.Process.Signal(syscall.SIGTERM)
		cmd.Wait()
	}()

	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network string, addr string) (net.Conn, error) {
				_, port, err := net.SplitHostPort(addr)
				if err != nil {
					return nil, err
				}
				localPort := httpPort
				if port == "443" {
					localPort = httpsPort
				}
				return (&net.Dialer{}).DialContext(ctx, network, fmt.Sprintf("127.0.0.1:%d", localPort))
			},
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
			DisableKeepAlives: true,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Timeout: 10 * time.Second,
	}

	// a connection shows nginx is up without a request, which would spend a
	// budget: limit_req runs before the access phase, even for a deny
	started := false
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); {
		if conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", httpsPort), time.Second); err == nil {
			conn.Close()
			started = true
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !started {
		t.Fatalf("nginx did not start:\n%s", nginxErrors())
	}

	send := func(method string, path string) int {
		t.Helper()
		request, err := http.NewRequest(method, "https://test-svc-b.example.com"+path, strings.NewReader("{}"))
		if err != nil {
			t.Fatal(err)
		}
		response, err := client.Do(request)
		if err != nil {
			t.Fatalf("%s %s: %s\n%s", method, path, err, nginxErrors())
		}
		response.Body.Close()
		return response.StatusCode
	}
	// sends n requests and returns how many were answered with each status
	sendAll := func(n int, method string, path string) map[int]int {
		t.Helper()
		statuses := map[int]int{}
		for range n {
			statuses[send(method, path)] += 1
		}
		return statuses
	}

	// the route's budget, all of it: none of the shared budget is spent
	if statuses := sendAll(routeBurst+1, "POST", "/connect/control"); statuses[http.StatusOK] != routeBurst+1 {
		t.Fatalf("/connect/control within its own budget: %v, want %d 200", statuses, routeBurst+1)
	}
	// the shared budget is still whole for the other route
	if statuses := sendAll(sharedBurst+1, "POST", "/other"); statuses[http.StatusOK] != sharedBurst+1 {
		t.Fatalf("another route after /connect/control spent its own budget: %v, want %d 200 (the route spent the shared budget)", statuses, sharedBurst+1)
	}
	// each budget is now spent, and each route is refused
	if status := send("POST", "/other"); status != http.StatusTooManyRequests {
		t.Fatalf("another route past the shared budget: %d, want 429", status)
	}
	if status := send("POST", "/connect/control"); status != http.StatusTooManyRequests {
		t.Fatalf("/connect/control past its own budget: %d, want 429 (the route is not limited by its own zone)", status)
	}
}
