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
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// the api's two busiest routes, as services.yml lists them for svc-b
const noSuccessAccessLogTestPaths = "" +
	"            no_success_access_log:\n" +
	"                - /connect/control\n" +
	"                - /hello\n"

// servicesYaml with svc-b's no_success_access_log set to the two routes
func noSuccessAccessLogServicesYaml(t *testing.T, servicesYaml []byte) []byte {
	t.Helper()
	// the first svc-b is the latest version's, which the lb is generated from
	if !strings.Contains(string(servicesYaml), routeRateLimitTestService) {
		t.Fatal("test services fixture lacks svc-b")
	}
	return []byte(strings.Replace(string(servicesYaml), routeRateLimitTestService, routeRateLimitTestService+noSuccessAccessLogTestPaths, 1))
}

// the entries of the one `<header> {` block in a generated config, trimmed, in
// order
func nginxBlockLines(t *testing.T, config string, header string) []string {
	t.Helper()
	lines := strings.Split(config, "\n")
	start := -1
	for i, line := range lines {
		if strings.TrimSpace(line) == header+" {" {
			if 0 <= start {
				t.Fatalf("config has more than one %q", header)
			}
			start = i
		}
	}
	if start < 0 {
		t.Fatalf("config has no %q", header)
	}
	entries := []string{}
	for _, line := range lines[start+1:] {
		entry := strings.TrimSpace(line)
		if entry == "}" {
			return entries
		}
		entries = append(entries, entry)
	}
	t.Fatalf("%q is not closed", header)
	return nil
}

// With no_access_log and svc-b's no_success_access_log both set, the one
// access_log stays conditional on $warp_loggable, which now also leaves out a
// 2xx answer on the two routes of svc-b's hosts. The no_access_log hosts move
// to $warp_loggable_host, the default of the new map, so they stay unlogged
// whatever their status.
func TestNginxConfigLeavesNoSuccessAccessLogSuccessesOutOfTheAccessLog(t *testing.T) {
	servicesYaml := noSuccessAccessLogServicesYaml(t, lagDevServicesYaml(t, "lag.dev", "www.lag.dev"))
	env, _ := setupLagDevTestVault(t, servicesYaml)
	nginxConfig, err := NewNginxConfig(env, nil)
	if err != nil {
		t.Fatal(err)
	}

	blockConfigs := nginxConfig.Generate()
	if len(blockConfigs) == 0 {
		t.Fatal("no lb block config generated")
	}
	for block, config := range blockConfigs {
		accessLogs := nginxDirectives(config, "access_log")
		if len(accessLogs) == 0 {
			t.Errorf("block %s has no access_log", block)
		}
		for _, accessLog := range accessLogs {
			if accessLog != "access_log /dev/stdout noclientaddr if=$warp_loggable;" && accessLog != "access_log off;" {
				t.Errorf("block %s logs unconditionally: %q", block, accessLog)
			}
		}

		loggableHost := nginxMapEntries(t, config, "map $host $warp_loggable_host")
		wantLoggableHost := map[string]string{
			"default":     "1",
			"lag.dev":     "0",
			"www.lag.dev": "0",
		}
		if !maps.Equal(loggableHost, wantLoggableHost) {
			t.Errorf("block %s $warp_loggable_host = %v, want %v", block, loggableHost, wantLoggableHost)
		}
		if strings.Contains(config, "map $host $warp_loggable {") {
			t.Errorf("block %s still defines $warp_loggable from the host alone", block)
		}

		// svc-b's env host in both domains
		loggable := nginxBlockLines(t, config, `map "$status $host$uri" $warp_loggable`)
		wantLoggable := []string{
			"default $warp_loggable_host;",
			`"~^2[0-9][0-9] (?:test-svc-b\.example\.com|test-svc-b\.lag\.dev)(?:/connect/control|/hello)$" 0;`,
		}
		if !slices.Equal(loggable, wantLoggable) {
			t.Errorf("block %s $warp_loggable = %q, want %q", block, loggable, wantLoggable)
		}
	}
}

// Without no_access_log every host is loggable by default, and an env alias's
// host of the service is quieted like the env's own.
func TestNginxConfigNoSuccessAccessLogWithoutNoAccessLog(t *testing.T) {
	baseYaml, err := testServicesFS.ReadFile("testdata/services.yml")
	if err != nil {
		t.Fatal(err)
	}
	env, _ := setupTestVaultWithTLS(t, noSuccessAccessLogServicesYaml(t, baseYaml))
	nginxConfig, err := NewNginxConfig(env, []string{"alias"})
	if err != nil {
		t.Fatal(err)
	}

	blockConfigs := nginxConfig.Generate()
	if len(blockConfigs) == 0 {
		t.Fatal("no lb block config generated")
	}
	for block, config := range blockConfigs {
		accessLogs := nginxDirectives(config, "access_log")
		if !slices.Equal(accessLogs, []string{"access_log /dev/stdout noclientaddr if=$warp_loggable;"}) {
			t.Errorf("block %s access_log = %q, want the one conditional access_log", block, accessLogs)
		}
		if strings.Contains(config, "$warp_loggable_host") {
			t.Errorf("block %s defines $warp_loggable_host with no no_access_log host", block)
		}
		loggable := nginxBlockLines(t, config, `map "$status $host$uri" $warp_loggable`)
		wantLoggable := []string{
			"default 1;",
			`"~^2[0-9][0-9] (?:test-svc-b\.example\.com|alias-svc-b\.example\.com)(?:/connect/control|/hello)$" 0;`,
		}
		if !slices.Equal(loggable, wantLoggable) {
			t.Errorf("block %s $warp_loggable = %q, want %q", block, loggable, wantLoggable)
		}
	}
}

// Runs the generated lb config in nginx with svc-b's no_success_access_log and
// lag.dev's no_access_log, and sends it 2xx answers on svc-b's two routes,
// which get no line, and the requests that must keep theirs: an error and a
// refusal on the routes, near misses of the paths, another route, the paths on
// another service's host and the port 80 redirect. lag.dev stays unlogged.
// Before no_success_access_log, every svc-b line was written.
func TestNginxWritesNoAccessLogLineForSuccessesOnNoSuccessAccessLogPaths(t *testing.T) {
	nginxBinary := nginxConfigValidationBinary(t)

	// without capacity sizing nginx runs one worker, which writes the log in
	// the order the requests are sent
	servicesYaml := string(noSuccessAccessLogServicesYaml(t, lagDevServicesYaml(t, "lag.dev", "www.lag.dev")))
	servicesYaml = strings.ReplaceAll(servicesYaml, "                    concurrent_clients: 786432\n", "")
	servicesYaml = strings.ReplaceAll(servicesYaml, "                    cores: 24\n", "")
	env, vaultDir := setupLagDevTestVault(t, []byte(servicesYaml))
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

	// every upstream block is this one service, which answers the status the
	// request's `status` names, 200 by default. 503 is not used: the lb
	// retries it on a sibling.
	service := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		status := http.StatusOK
		if statusText := r.URL.Query().Get("status"); statusText != "" {
			parsedStatus, err := strconv.Atoi(statusText)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			status = parsedStatus
		}
		w.WriteHeader(status)
		if status != http.StatusNoContent {
			fmt.Fprintln(w, "ok")
		}
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

	// the lb's stdout carries the access log and its stderr the error log.
	// Files rather than pipes, so the test can read them while nginx runs.
	stdoutPath := filepath.Join(dir, "stdout")
	stdout, err := os.Create(stdoutPath)
	if err != nil {
		t.Fatal(err)
	}
	defer stdout.Close()
	stderrPath := filepath.Join(dir, "stderr")
	stderr, err := os.Create(stderrPath)
	if err != nil {
		t.Fatal(err)
	}
	defer stderr.Close()
	nginxErrors := func() string {
		data, _ := os.ReadFile(stderrPath)
		return string(data)
	}

	cmd := exec.Command(nginxBinary, "-g", "daemon off;", "-c", confPath, "-p", dir, "-e", filepath.Join(dir, "error.log"))
	cmd.Stdout = stdout
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
		Timeout: 10 * time.Second,
	}

	started := false
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); {
		if response, err := client.Get("http://startup.invalid/"); err == nil {
			response.Body.Close()
			started = true
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !started {
		t.Fatalf("nginx did not start:\n%s", nginxErrors())
	}

	type lbRequest struct {
		method string
		url    string
		status int
	}
	send := func(request lbRequest) {
		t.Helper()
		httpRequest, err := http.NewRequest(request.method, request.url, strings.NewReader("{}"))
		if err != nil {
			t.Fatal(err)
		}
		response, err := client.Do(httpRequest)
		if err != nil {
			t.Fatalf("%s %s: %s\n%s", request.method, request.url, err, nginxErrors())
		}
		response.Body.Close()
		if response.StatusCode != request.status {
			t.Fatalf("%s %s: status %d, want %d\n%s", request.method, request.url, response.StatusCode, request.status, nginxErrors())
		}
	}

	for _, request := range []lbRequest{
		{method: "POST", url: "https://test-svc-b.example.com/connect/control?m=unlogged-marker", status: http.StatusOK},
		{method: "GET", url: "https://test-svc-b.example.com/hello?m=unlogged-marker", status: http.StatusOK},
		{method: "GET", url: "https://test-svc-b.example.com/hello?status=204&m=unlogged-marker", status: http.StatusNoContent},
		{method: "GET", url: "https://test-svc-b.example.com/connect//control?m=unlogged-marker", status: http.StatusOK},
		{method: "GET", url: "https://lag.dev/hello?m=unlogged-marker", status: http.StatusOK},
		{method: "GET", url: "https://lag.dev/hello?status=500&m=unlogged-marker", status: http.StatusInternalServerError},
	} {
		send(request)
	}

	// sent last, so once their lines are written every earlier request's line
	// would have been too
	loggedRequests := []struct {
		request lbRequest
		line    string
	}{
		{
			request: lbRequest{method: "POST", url: "https://test-svc-b.example.com/connect/control?status=500&m=logged-marker-1", status: http.StatusInternalServerError},
			line:    `test-svc-b.example.com "POST /connect/control?status=500&m=logged-marker-1 HTTP/1.1" 500 `,
		},
		{
			request: lbRequest{method: "GET", url: "https://test-svc-b.example.com/hello?status=429&m=logged-marker-2", status: http.StatusTooManyRequests},
			line:    `test-svc-b.example.com "GET /hello?status=429&m=logged-marker-2 HTTP/1.1" 429 `,
		},
		{
			request: lbRequest{method: "GET", url: "https://test-svc-b.example.com/hello/?m=logged-marker-3", status: http.StatusOK},
			line:    `test-svc-b.example.com "GET /hello/?m=logged-marker-3 HTTP/1.1" 200 `,
		},
		{
			request: lbRequest{method: "GET", url: "https://test-svc-b.example.com/hellos?m=logged-marker-4", status: http.StatusOK},
			line:    `test-svc-b.example.com "GET /hellos?m=logged-marker-4 HTTP/1.1" 200 `,
		},
		{
			request: lbRequest{method: "POST", url: "https://test-svc-b.example.com/connect/control/x?m=logged-marker-5", status: http.StatusOK},
			line:    `test-svc-b.example.com "POST /connect/control/x?m=logged-marker-5 HTTP/1.1" 200 `,
		},
		{
			request: lbRequest{method: "GET", url: "https://test-svc-b.example.com/other?m=logged-marker-6", status: http.StatusOK},
			line:    `test-svc-b.example.com "GET /other?m=logged-marker-6 HTTP/1.1" 200 `,
		},
		{
			request: lbRequest{method: "GET", url: "https://test-svc-a.example.com/hello?m=logged-marker-7", status: http.StatusOK},
			line:    `test-svc-a.example.com "GET /hello?m=logged-marker-7 HTTP/1.1" 200 `,
		},
		{
			request: lbRequest{method: "GET", url: "http://test-svc-b.example.com/hello?m=logged-marker-8", status: http.StatusMovedPermanently},
			line:    `test-svc-b.example.com "GET /hello?m=logged-marker-8 HTTP/1.1" 301 `,
		},
	}
	for _, loggedRequest := range loggedRequests {
		send(loggedRequest.request)
	}

	accessLog := ""
	for deadline := time.Now().Add(10 * time.Second); ; {
		data, err := os.ReadFile(stdoutPath)
		if err != nil {
			t.Fatal(err)
		}
		accessLog = string(data)
		logged := true
		for _, loggedRequest := range loggedRequests {
			logged = logged && strings.Contains(accessLog, loggedRequest.line)
		}
		if logged {
			break
		}
		if time.Now().After(deadline) {
			for _, loggedRequest := range loggedRequests {
				if !strings.Contains(accessLog, loggedRequest.line) {
					t.Errorf("the access log has no line %q", loggedRequest.line)
				}
			}
			t.Fatalf("access log:\n%s\n%s", accessLog, nginxErrors())
		}
		time.Sleep(20 * time.Millisecond)
	}

	for _, line := range strings.Split(strings.TrimSpace(accessLog), "\n") {
		if strings.Contains(line, "unlogged-marker") {
			t.Errorf("the access log has a line for a quieted answer: %q", line)
		}
	}
}
