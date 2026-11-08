package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"fmt"
	"io"
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
	"sync"
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

// The test services with text inserted at the top of a service in the latest
// version, which the lb is generated from.
func testServicesYamlWith(t *testing.T, baseYaml []byte, service string, text string) []byte {
	t.Helper()
	header := "        " + service + ":\n"
	if !strings.Contains(string(baseYaml), header) {
		t.Fatalf("test services fixture lacks %s", service)
	}
	return []byte(strings.Replace(string(baseYaml), header, header+text, 1))
}

func testServicesYaml(t *testing.T) []byte {
	t.Helper()
	baseYaml, err := testServicesFS.ReadFile("testdata/services.yml")
	if err != nil {
		t.Fatal(err)
	}
	return baseYaml
}

// W2's whole-service forms (DESIGN 19.5). svc-d, whose streamable_paths make it
// evs-like, stands in for evs, and svc-b for gkm, whose limit has no burst.
const evsServiceRateLimit = "" +
	"            service_rate_limit:\n" +
	"                requests_per_minute: 3000\n" +
	"                burst: 1000\n"

const gkmServiceRateLimit = "" +
	"            service_rate_limit:\n" +
	"                requests_per_minute: 1200\n"

// W2's exact routes need no new code, only their values: sockets' registration
// and Find ride route_rate_limits, here on svc-a.
const socketsRouteRateLimits = "" +
	"            route_rate_limits:\n" +
	"                -   path: /socket/registrations\n" +
	"                    requests_per_minute: 12000\n" +
	"                    burst: 3000\n" +
	"                -   path: /socket/find\n" +
	"                    requests_per_minute: 12000\n" +
	"                    burst: 3000\n"

// everything in a generated config before the stream block, whose upstreams
// come out in map order, so two renders of one document can be compared
func nginxHttpConfig(config string) string {
	if i := strings.Index(config, "\nstream {"); 0 <= i {
		return config[:i+1]
	}
	return config
}

// One zone per service, defined once whatever the number of the service's
// hosts and route prefixes, keyed like the shared zone. Each prefix location of
// the service's own hosts applies it, and the nested streamable location
// inherits it by declaring no limit of its own. No other service's location
// does.
func TestNginxConfigLimitsAWholeServiceInItsOwnZone(t *testing.T) {
	servicesYaml := testServicesYamlWith(t, testServicesYaml(t), "svc-d", evsServiceRateLimit)
	env, _ := setupTestVaultWithTLS(t, servicesYaml)
	nginxConfig, err := NewNginxConfig(env, []string{"alias-env"})
	if err != nil {
		t.Fatal(err)
	}

	blockConfigs := nginxConfig.Generate()
	if len(blockConfigs) == 0 {
		t.Fatal("no lb block config generated")
	}
	const limitReq = "limit_req zone=service_svc-d burst=1000 nodelay;"
	for blockName, config := range blockConfigs {
		zone := "limit_req_zone $limit_key zone=service_svc-d:64m rate=3000r/m;"
		if count := strings.Count(config, zone); count != 1 {
			t.Errorf("block %s defines the service zone %d times, want 1 %q", blockName, count, zone)
		}
		// the http block's shared limit stays, for every location with none
		if count := strings.Count(config, "limit_req zone=standardlimit burst=150 nodelay;"); count != 1 {
			t.Errorf("block %s applies the shared limit %d times, want once at the http level", blockName, count)
		}

		svcDServerCount := 0
		for _, server := range nginxServerBlocks(config) {
			svcD := strings.Contains(server, "listen 443 ssl;") &&
				(strings.Contains(server, "server_name test-svc-d.example.com;") ||
					strings.Contains(server, "server_name alias-env-svc-d.example.com;"))
			prefixLocations := nginxBlocks(server, "location /")
			if svcD {
				svcDServerCount += 1
				if len(prefixLocations) != 1 {
					t.Fatalf("block %s svc-d server has %d prefix locations, want 1", blockName, len(prefixLocations))
				}
				prefixLocation := prefixLocations[0]
				if count := strings.Count(prefixLocation, "limit_req "); count != 1 {
					t.Errorf("block %s svc-d prefix location limits %d times, want 1:\n%s", blockName, count, prefixLocation)
				}
				if !strings.Contains(prefixLocation, limitReq) {
					t.Errorf("block %s svc-d prefix location lacks %q:\n%s", blockName, limitReq, prefixLocation)
				}
				// the streamable location is nested in the limited one, and a
				// limit of its own there would replace what it inherits
				streamableLocations := nginxBlocks(prefixLocation, `location ~ "^`+streamedPathsRegexTail[:len(streamedPathsRegexTail)-2])
				if len(streamableLocations) != 1 {
					t.Fatalf("block %s svc-d prefix location nests %d streamable locations, want 1:\n%s", blockName, len(streamableLocations), prefixLocation)
				}
				if strings.Contains(streamableLocations[0], "limit_req") {
					t.Errorf("block %s streamable location limits itself:\n%s", blockName, streamableLocations[0])
				}
				continue
			}
			if strings.Contains(server, "zone=service_") {
				t.Errorf("block %s applies the service zone outside svc-d's server:\n%s", blockName, server)
			}
		}
		if svcDServerCount != 2 {
			t.Errorf("block %s serves svc-d on %d https servers, want 2", blockName, svcDServerCount)
		}
	}
}

// Behind hidden route prefixes each prefix location applies the one zone.
func TestNginxConfigServiceRateLimitBehindHiddenPrefixes(t *testing.T) {
	servicesYaml := []byte(strings.Replace(
		string(testServicesYamlWith(t, testServicesYaml(t), "svc-d", evsServiceRateLimit)),
		"domains:\n    example.com: route53\n",
		"domains:\n    example.com: route53\nhidden_prefixes:\n    - hidden-one\n    - hidden-two\n",
		1,
	))
	env, _ := setupTestVaultWithTLS(t, servicesYaml)
	nginxConfig, err := NewNginxConfig(env, nil)
	if err != nil {
		t.Fatal(err)
	}
	for blockName, config := range nginxConfig.Generate() {
		for _, server := range nginxServerBlocks(config) {
			if !strings.Contains(server, "server_name test-svc-d.example.com;") || !strings.Contains(server, "listen 443 ssl;") {
				continue
			}
			for _, routePrefix := range []string{"/hidden-one", "/hidden-two"} {
				locations := nginxBlocks(server, "location "+routePrefix+"/")
				if len(locations) != 1 || !strings.Contains(locations[0], "limit_req zone=service_svc-d burst=1000 nodelay;") {
					t.Errorf("block %s location behind %s is not limited:\n%v", blockName, routePrefix, locations)
				}
			}
		}
		if count := strings.Count(config, "zone=service_svc-d:64m"); count != 1 {
			t.Errorf("block %s defines the service zone %d times, want 1", blockName, count)
		}
	}
}

// An exact route of a limited service keeps its own zone: a location takes one
// limit_req set, so the route spends its zone and not the service's. Both zones
// exist under different names.
func TestNginxConfigExactRouteOfALimitedServiceCountsOnce(t *testing.T) {
	servicesYaml := testServicesYamlWith(t, testServicesYaml(t), "svc-b", gkmServiceRateLimit+connectControlRouteRateLimits)
	env, _ := setupTestVaultWithTLS(t, servicesYaml)
	nginxConfig, err := NewNginxConfig(env, nil)
	if err != nil {
		t.Fatal(err)
	}
	for blockName, config := range nginxConfig.Generate() {
		for _, zone := range []string{
			"limit_req_zone $limit_key zone=service_svc-b:64m rate=1200r/m;",
			"limit_req_zone $limit_key zone=route_svc-b_connect_control:64m rate=12000r/m;",
		} {
			if count := strings.Count(config, zone); count != 1 {
				t.Errorf("block %s defines %q %d times, want 1", blockName, zone, count)
			}
		}
		routeLocations := nginxBlocks(config, "location = /connect/control")
		if len(routeLocations) == 0 {
			t.Fatalf("block %s has no exact route", blockName)
		}
		for _, routeLocation := range routeLocations {
			if count := strings.Count(routeLocation, "limit_req "); count != 1 {
				t.Errorf("block %s route limits %d times, want 1:\n%s", blockName, count, routeLocation)
			}
			if !strings.Contains(routeLocation, "limit_req zone=route_svc-b_connect_control burst=6000 nodelay;") {
				t.Errorf("block %s route lost its own zone:\n%s", blockName, routeLocation)
			}
		}
	}
}

// With no rate on the interface the http block sets no limit_req_status, and
// nginx would answer a service zone's refusal 503. Like the route form, the
// service form sets it, once, whichever forms a config uses.
func TestNginxConfigServiceRateLimitAnswers429WithoutAnInterfaceRate(t *testing.T) {
	interfaceLimit := "    requests_per_minute: 450\n    burst: 150\n    net_connections: 50\n"
	for _, text := range []string{evsServiceRateLimit, evsServiceRateLimit + connectControlRouteRateLimits} {
		servicesYaml := string(testServicesYamlWith(t, testServicesYaml(t), "svc-d", text))
		if !strings.Contains(servicesYaml, interfaceLimit) {
			t.Fatal("test services fixture lacks the default rate limit")
		}
		servicesYaml = strings.Replace(servicesYaml, interfaceLimit, "    net_connections: 50\n", 1)
		env, _ := setupTestVaultWithTLS(t, []byte(servicesYaml))
		nginxConfig, err := NewNginxConfig(env, nil)
		if err != nil {
			t.Fatal(err)
		}
		for blockName, config := range nginxConfig.Generate() {
			if strings.Contains(config, "standardlimit") {
				t.Errorf("block %s has a shared zone with no interface rate", blockName)
			}
			for _, directive := range []string{"limit_req_status 429;", "limit_req_log_level info;"} {
				if count := strings.Count(config, directive); count != 1 {
					t.Errorf("block %s has %q %d times, want 1", blockName, directive, count)
				}
			}
		}
	}
}

// What the form adds is its zone and a limit in each of the service's prefix
// locations. Take those lines away and the render is byte for byte the one
// from a document without the key, so a service with no form is as it was.
func TestNginxConfigServiceRateLimitAddsOnlyItsOwnLines(t *testing.T) {
	renderHttp := func(servicesYaml []byte) map[string]string {
		env, _ := setupTestVaultWithTLS(t, servicesYaml)
		nginxConfig, err := NewNginxConfig(env, nil)
		if err != nil {
			t.Fatal(err)
		}
		httpConfigs := map[string]string{}
		for blockName, config := range nginxConfig.Generate() {
			httpConfigs[blockName] = nginxHttpConfig(config)
		}
		return httpConfigs
	}
	without := renderHttp(testServicesYaml(t))
	with := renderHttp(testServicesYamlWith(t, testServicesYaml(t), "svc-d", evsServiceRateLimit))
	if len(without) == 0 || len(with) != len(without) {
		t.Fatalf("rendered %d blocks with the form and %d without", len(with), len(without))
	}
	for blockName, config := range with {
		lines := []string{}
		removed := 0
		for _, line := range strings.Split(config, "\n") {
			if strings.Contains(line, "zone=service_svc-d") {
				removed += 1
				continue
			}
			lines = append(lines, line)
		}
		if removed < 2 {
			t.Errorf("block %s took away %d lines, want the zone and at least one location", blockName, removed)
		}
		if got := strings.Join(lines, "\n"); got != without[blockName] {
			t.Errorf("block %s changed beyond the form's own lines", blockName)
		}
		if strings.Contains(without[blockName], "zone=service_") {
			t.Errorf("block %s has a service zone without the form", blockName)
		}
	}
}

// nginx refuses `burst=0` outright, which fails the whole lb config, so a form
// with no burst leaves the parameter out. This holds for gkm's limit, for a
// route with no burst, and for an interface's own rate_limit.
func TestNginxConfigOmitsAZeroBurst(t *testing.T) {
	servicesYaml := string(testServicesYamlWith(t, testServicesYaml(t), "svc-b", gkmServiceRateLimit+
		"            route_rate_limits:\n"+
		"                -   path: /connect/control\n"+
		"                    requests_per_minute: 12000\n"))
	servicesYaml = strings.Replace(servicesYaml, "    requests_per_minute: 450\n    burst: 150\n", "    requests_per_minute: 450\n", 1)
	env, vaultDir := setupTestVaultWithTLS(t, []byte(servicesYaml))
	nginxConfig, err := NewNginxConfig(env, nil)
	if err != nil {
		t.Fatal(err)
	}
	blockConfigs := nginxConfig.Generate()
	if len(blockConfigs) == 0 {
		t.Fatal("no lb block config generated")
	}
	for blockName, config := range blockConfigs {
		if strings.Contains(config, "burst=0") {
			t.Errorf("block %s renders a burst nginx refuses", blockName)
		}
		for _, directive := range []string{
			"limit_req zone=standardlimit nodelay;",
			"limit_req zone=service_svc-b nodelay;",
			"limit_req zone=route_svc-b_connect_control nodelay;",
		} {
			if !strings.Contains(config, directive) {
				t.Errorf("block %s lacks %q", blockName, directive)
			}
		}
	}
	checkNginxAcceptsConfigs(t, blockConfigs, vaultDir)
}

// `nginx -t` on each generated config.
func checkNginxAcceptsConfigs(t *testing.T, blockConfigs map[string]string, vaultDir string) {
	t.Helper()
	nginxBinary := nginxConfigValidationBinary(t)
	for block, config := range blockConfigs {
		tmpDir := t.TempDir()
		confPath := filepath.Join(tmpDir, "nginx.conf")
		if err := os.WriteFile(confPath, []byte(localNginxConfig(config, vaultDir)), 0644); err != nil {
			t.Fatal(err)
		}
		for _, dir := range []string{"logs", "run"} {
			if err := os.MkdirAll(filepath.Join(tmpDir, dir), 0755); err != nil {
				t.Fatal(err)
			}
		}
		cmd := exec.Command(nginxBinary, "-t", "-c", confPath, "-p", tmpDir, "-e", filepath.Join(tmpDir, "error.log"))
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Errorf("nginx config validation failed for block %s:\n%s", block, string(output))
		}
	}
}

// nginx accepts W2's values together: evs's limit over streamable paths, gkm's
// with no burst, and sockets' two exact routes, with and without route
// prefixes.
func TestNginxConfigValidationWithW2Forms(t *testing.T) {
	for _, extra := range []string{"", "hidden_prefixes:\n    - hidden-one\n    - hidden-two\n"} {
		servicesYaml := testServicesYamlWith(t, testServicesYaml(t), "svc-d", evsServiceRateLimit)
		servicesYaml = testServicesYamlWith(t, servicesYaml, "svc-b", gkmServiceRateLimit)
		servicesYaml = testServicesYamlWith(t, servicesYaml, "svc-a", socketsRouteRateLimits)
		if extra != "" {
			servicesYaml = []byte(strings.Replace(string(servicesYaml), "domains:\n    example.com: route53\n", "domains:\n    example.com: route53\n"+extra, 1))
		}
		env, vaultDir := setupTestVaultWithTLS(t, nginxServicesWithLongStatusMapKey(t, servicesYaml))
		nginxConfig, err := NewNginxConfig(env, nil)
		if err != nil {
			t.Fatal(err)
		}
		blockConfigs := nginxConfig.Generate()
		if len(blockConfigs) == 0 {
			t.Fatal("no lb block config generated")
		}
		for blockName, config := range blockConfigs {
			for _, zone := range []string{
				"zone=service_svc-d:64m rate=3000r/m;",
				"zone=service_svc-b:64m rate=1200r/m;",
				"zone=route_svc-a_socket_registrations:64m rate=12000r/m;",
				"zone=route_svc-a_socket_find:64m rate=12000r/m;",
			} {
				if !strings.Contains(config, zone) {
					t.Errorf("block %s lacks %q", blockName, zone)
				}
			}
			if !strings.Contains(config, "limit_req zone=route_svc-a_socket_find burst=3000 nodelay;") {
				t.Errorf("block %s lacks the Find route's burst", blockName)
			}
		}
		checkNginxAcceptsConfigs(t, blockConfigs, vaultDir)
	}
}

// W3: a segment is at most 8 MiB, so no service needs a body limit of its own.
// One http-level limit stays, and no form adds another.
func TestNginxConfigKeepsOneBodyLimit(t *testing.T) {
	servicesYaml := testServicesYamlWith(t, testServicesYaml(t), "svc-d", evsServiceRateLimit)
	env, _ := setupTestVaultWithTLS(t, servicesYaml)
	nginxConfig, err := NewNginxConfig(env, nil)
	if err != nil {
		t.Fatal(err)
	}
	for blockName, config := range nginxConfig.Generate() {
		if bodyLimits := nginxDirectives(config, "client_max_body_size"); !slices.Equal(bodyLimits, []string{"client_max_body_size 16m;"}) {
			t.Errorf("block %s body limits = %q, want the one of 16m", blockName, bodyLimits)
		}
	}
}

// A generated lb config running in a real nginx on high loopback ports, with
// every upstream pointed at one test service, so a test can drive its limits
// and logs as a client does. A request goes to the lb by its url's host and
// scheme, whatever the name.
type nginxTestLb struct {
	t         *testing.T
	client    *http.Client
	dir       string
	httpPort  int
	httpsPort int
	// the access log, which the lb writes to its stdout
	stdout *nginxTestLbStdout
}

// What nginx writes to its stdout, kept whole, with a channel that closes at
// each write, so a test waits for a line as it arrives rather than polling.
// Safe for concurrent use.
type nginxTestLbStdout struct {
	stateLock sync.Mutex
	data      []byte
	update    chan struct{}
}

func newNginxTestLbStdout() *nginxTestLbStdout {
	return &nginxTestLbStdout{
		update: make(chan struct{}),
	}
}

func (self *nginxTestLbStdout) Write(b []byte) (int, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.data = append(self.data, b...)
	close(self.update)
	self.update = make(chan struct{})
	return len(b), nil
}

// Returns what has been written so far, and a channel that closes at the next
// write, read together so no write falls between them.
func (self *nginxTestLbStdout) get() (string, chan struct{}) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return string(self.data), self.update
}

// The nginx a test drives traffic through: NGINX_SPLIT_BINARY when it is set,
// which then must run, and otherwise the one the config tests pick, skipping
// where there is none.
func nginxTestLbBinary(t *testing.T) string {
	t.Helper()
	if configuredBinary := os.Getenv("NGINX_SPLIT_BINARY"); configuredBinary != "" {
		resolvedBinary, err := exec.LookPath(configuredBinary)
		if err != nil {
			t.Fatalf("NGINX_SPLIT_BINARY=%q is not executable: %v", configuredBinary, err)
		}
		return resolvedBinary
	}
	return nginxConfigValidationBinary(t)
}

type nginxTestLbSettings struct {
	servicesYaml []byte
	service      http.Handler
	// adds to the test vault before the lb config is generated, if set
	editVault func(vaultDir string)
	// adjusts the generated config before nginx loads it, if set
	editConfig func(config string) string
}

// Starts the first lb block of a services document. Capacity sizing comes off,
// so nginx runs one worker, which writes the log in request order.
func startNginxTestLb(t *testing.T, settings *nginxTestLbSettings) *nginxTestLb {
	t.Helper()
	nginxBinary := nginxTestLbBinary(t)

	servicesYaml := strings.ReplaceAll(string(settings.servicesYaml), "                    concurrent_clients: 786432\n", "")
	servicesYaml = strings.ReplaceAll(servicesYaml, "                    cores: 24\n", "")
	env, vaultDir := setupTestVaultWithTLS(t, []byte(servicesYaml))
	if settings.editVault != nil {
		settings.editVault(vaultDir)
	}
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
	// the stream block proxies other ports and is not under test
	config := nginxHttpConfig(localNginxConfig(blockConfigs[blocks[0]], vaultDir))

	// every upstream block is this one service
	testService := httptest.NewServer(settings.service)
	t.Cleanup(testService.Close)
	config = regexp.MustCompile(`server 127\.0\.0\.1:\d+`).ReplaceAllString(
		config,
		fmt.Sprintf("server 127.0.0.1:%d", testService.Listener.Addr().(*net.TCPAddr).Port),
	)

	httpPort := freeLoopbackPort(t)
	httpsPort := freeLoopbackPort(t)
	config = loopbackNginxListens(t, config, map[int]int{80: httpPort, 443: httpsPort})
	if settings.editConfig != nil {
		config = settings.editConfig(config)
	}

	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "logs"), 0755); err != nil {
		t.Fatal(err)
	}
	confPath := filepath.Join(dir, "nginx.conf")
	if err := os.WriteFile(confPath, []byte(config), 0644); err != nil {
		t.Fatal(err)
	}
	// a file rather than a pipe, so a test can read it while nginx runs
	stderr, err := os.Create(filepath.Join(dir, "stderr"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { stderr.Close() })
	stdout := newNginxTestLbStdout()

	cmd := exec.Command(nginxBinary, "-g", "daemon off;", "-c", confPath, "-p", dir, "-e", filepath.Join(dir, "error.log"))
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cmd.Process.Signal(syscall.SIGTERM)
		cmd.Wait()
	})

	lb := &nginxTestLb{
		t:         t,
		dir:       dir,
		httpPort:  httpPort,
		httpsPort: httpsPort,
		stdout:    stdout,
		client: &http.Client{
			Transport: &http.Transport{
				// every name is the local lb, on the port of the url's scheme
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
			// a redirect is an answer to check, not to follow
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
			Timeout: 30 * time.Second,
		},
	}

	// a connection shows nginx is up without a request, which would spend a
	// budget: limit_req runs before the access phase, even for a deny
	for deadline := time.Now().Add(10 * time.Second); ; {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", httpsPort), time.Second)
		if err == nil {
			conn.Close()
			return lb
		}
		if time.Now().After(deadline) {
			t.Fatalf("nginx did not start:\n%s", lb.errors())
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// what nginx has written to its error sinks
func (self *nginxTestLb) errors() string {
	stderr, _ := os.ReadFile(filepath.Join(self.dir, "stderr"))
	errorLog, _ := os.ReadFile(filepath.Join(self.dir, "error.log"))
	return string(stderr) + string(errorLog)
}

// the access log, which the lb writes to its stdout
func (self *nginxTestLb) accessLog() string {
	accessLog, _ := self.stdout.get()
	return accessLog
}

// Waits for a line holding text in the access log, which nginx writes after it
// answers, waking at each write. The bound only turns a missing line into a
// failure.
func (self *nginxTestLb) waitForAccessLogLine(text string) {
	self.t.Helper()
	timeout := time.After(10 * time.Second)
	for {
		accessLog, update := self.stdout.get()
		if strings.Contains(accessLog, text) {
			return
		}
		select {
		case <-update:
		case <-timeout:
			self.t.Fatalf("the access log has no line with %q:\n%s\n%s", text, accessLog, self.errors())
		}
	}
}

// Sends one request and returns its status. edit, if set, adjusts the request.
func (self *nginxTestLb) send(method string, url string, body []byte, edit func(*http.Request)) int {
	self.t.Helper()
	request, err := http.NewRequest(method, url, bytes.NewReader(body))
	if err != nil {
		self.t.Fatal(err)
	}
	if edit != nil {
		edit(request)
	}
	response, err := self.client.Do(request)
	if err != nil {
		self.t.Fatalf("%s %s: %s\n%s", method, url, err, self.errors())
	}
	defer response.Body.Close()
	if _, err := io.Copy(io.Discard, response.Body); err != nil {
		self.t.Fatalf("%s %s: read: %s", method, url, err)
	}
	return response.StatusCode
}

const nginxTestClientAddrHeader = "X-Test-Client-Addr"

// Lets a test name the client address of each request with a header, by
// realip, which the production lb gets from PROXY: $binary_remote_addr and the
// exclude geo read the address it sets. Loopback alone cannot give two
// addresses on every platform, and a test address can sit in an excluded
// subnet.
func nginxClientAddrFromHeader(config string) string {
	return strings.Replace(config, "http {\n", fmt.Sprintf(
		"http {\n    set_real_ip_from 127.0.0.1;\n    real_ip_header %s;\n",
		nginxTestClientAddrHeader,
	), 1)
}

// a request option that sends as the given client address
func asClientAddr(clientAddr string) func(*http.Request) {
	return func(request *http.Request) {
		request.Header.Set(nginxTestClientAddrHeader, clientAddr)
	}
}

// Runs a generated lb config in nginx and spends one address's whole-service
// budget across the service's prefix and streamable paths. Past it, both are
// refused 429 while the same address keeps its exact route's budget and the
// shared budget, another address keeps a whole budget, and an excluded address
// and the lb's status paths have no limit at all.
func TestNginxCountsAServiceRateLimitPerAddress(t *testing.T) {
	// one request a minute refills nothing while the test runs, so each
	// budget is exactly its burst plus one
	const sharedBurst = 7
	const serviceBurst = 12
	const routeBurst = 5
	servicesYaml := string(testServicesYamlWith(t, testServicesYaml(t), "svc-d", fmt.Sprintf(""+
		"            service_rate_limit:\n"+
		"                requests_per_minute: 1\n"+
		"                burst: %d\n"+
		"            route_rate_limits:\n"+
		"                -   path: /connect/control\n"+
		"                    requests_per_minute: 1\n"+
		"                    burst: %d\n",
		serviceBurst, routeBurst,
	)))
	sharedLimit := "    requests_per_minute: 450\n    burst: 150\n"
	if !strings.Contains(servicesYaml, sharedLimit) {
		t.Fatal("test services fixture lacks the default rate limit")
	}
	servicesYaml = strings.Replace(servicesYaml, sharedLimit, fmt.Sprintf("    requests_per_minute: 1\n    burst: %d\n", sharedBurst), 1)
	lb := startNginxTestLb(t, &nginxTestLbSettings{
		servicesYaml: []byte(servicesYaml),
		service: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintln(w, "ok")
		}),
		editConfig: nginxClientAddrFromHeader,
	})

	const addr = "203.0.113.9"
	const otherAddr = "203.0.113.10"
	// in the fixture's exclude_subnets
	const excludedAddr = "198.51.100.7"
	const serviceUrl = "https://test-svc-d.example.com"

	// a request of each kind spends the one budget: a buffered path and
	// streamable ones, in turn
	urls := []string{serviceUrl + "/plain", serviceUrl + "/upload/segment", serviceUrl + "/blob/one"}
	for i := range serviceBurst + 1 {
		if status := lb.send("POST", urls[i%len(urls)], []byte("{}"), asClientAddr(addr)); status != http.StatusOK {
			t.Fatalf("request %d within the service's budget: %d, want 200\n%s", i, status, lb.errors())
		}
	}
	for _, url := range urls {
		if status := lb.send("POST", url, []byte("{}"), asClientAddr(addr)); status != http.StatusTooManyRequests {
			t.Errorf("%s past the service's budget: %d, want 429", url, status)
		}
	}

	// the exact route counted nothing above, and spends only its own budget
	for i := range routeBurst + 1 {
		if status := lb.send("POST", serviceUrl+"/connect/control", []byte("{}"), asClientAddr(addr)); status != http.StatusOK {
			t.Fatalf("exact route request %d: %d, want 200 (it is in the service's zone)", i, status)
		}
	}
	if status := lb.send("POST", serviceUrl+"/connect/control", []byte("{}"), asClientAddr(addr)); status != http.StatusTooManyRequests {
		t.Errorf("exact route past its own budget: %d, want 429", status)
	}

	// the service spent none of the shared budget
	for i := range sharedBurst + 1 {
		if status := lb.send("POST", "https://test-svc-a.example.com/other", []byte("{}"), asClientAddr(addr)); status != http.StatusOK {
			t.Fatalf("shared request %d: %d, want 200 (the service spent the shared budget)", i, status)
		}
	}
	if status := lb.send("POST", "https://test-svc-a.example.com/other", []byte("{}"), asClientAddr(addr)); status != http.StatusTooManyRequests {
		t.Errorf("past the shared budget: %d, want 429", status)
	}

	// another address has a whole budget of its own
	for i := range serviceBurst + 1 {
		if status := lb.send("POST", serviceUrl+"/plain", []byte("{}"), asClientAddr(otherAddr)); status != http.StatusOK {
			t.Fatalf("other address request %d: %d, want 200", i, status)
		}
	}
	if status := lb.send("POST", serviceUrl+"/plain", []byte("{}"), asClientAddr(otherAddr)); status != http.StatusTooManyRequests {
		t.Errorf("other address past its budget: %d, want 429", status)
	}

	// an excluded address is never limited
	for i := range 3 * (serviceBurst + 1) {
		if status := lb.send("POST", urls[i%len(urls)], []byte("{}"), asClientAddr(excludedAddr)); status != http.StatusOK {
			t.Fatalf("excluded address request %d: %d, want 200", i, status)
		}
	}

	// the lb's status path of the service stays exempt for the spent address
	for i := range 3 * (sharedBurst + 1) {
		if status := lb.send("GET", "https://test-lb.example.com/by/service/svc-d/status", nil, asClientAddr(addr)); status != http.StatusOK {
			t.Fatalf("status request %d: %d, want 200", i, status)
		}
	}
}

// W3: an 8 MiB segment passes the lb on a streamable path and reaches the
// service whole, as the mark says, and so does the same body on a buffered
// path. Bodies stop at the one 16 MiB limit: the largest passes, and anything
// past it is refused at the lb.
func TestNginxPassesAnEightMibSegmentOnAStreamablePath(t *testing.T) {
	const maxBodySize = 16 * 1024 * 1024
	const segmentSize = 8 * 1024 * 1024

	type received struct {
		path     string
		sum      [sha256.Size]byte
		size     int
		buffered string
	}
	receivedRequests := make(chan received, 8)
	lb := startNginxTestLb(t, &nginxTestLbSettings{
		servicesYaml: testServicesYaml(t),
		service: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			receivedRequests <- received{
				path:     r.URL.Path,
				sum:      sha256.Sum256(body),
				size:     len(body),
				buffered: r.Header.Get("X-UR-Request-Buffering"),
			}
		}),
	})

	send := func(path string, body []byte) int {
		t.Helper()
		return lb.send("PUT", "https://test-svc-d.example.com"+path, body, nil)
	}
	body := make([]byte, maxBodySize+1)
	for i := range body {
		body[i] = byte(i % 251)
	}

	for _, test := range []struct {
		path     string
		size     int
		buffered string
	}{
		{"/upload/segment", segmentSize, "off"},
		{"/plain", segmentSize, ""},
		{"/upload/segment", maxBodySize, "off"},
	} {
		if status := send(test.path, body[:test.size]); status != http.StatusOK {
			t.Fatalf("%d bytes to %s: %d, want 200\n%s", test.size, test.path, status, lb.errors())
		}
		got := <-receivedRequests
		if got.path != test.path || got.size != test.size || got.sum != sha256.Sum256(body[:test.size]) {
			t.Errorf("%d bytes to %s arrived as %d bytes at %s", test.size, test.path, got.size, got.path)
		}
		if got.buffered != test.buffered {
			t.Errorf("%s: X-UR-Request-Buffering = %q, want %q", test.path, got.buffered, test.buffered)
		}
	}

	if status := send("/upload/segment", body); status != http.StatusRequestEntityTooLarge {
		t.Fatalf("a body past the limit: %d, want 413", status)
	}
	if len(receivedRequests) != 0 {
		t.Fatal("a body past the limit reached the service")
	}
}
