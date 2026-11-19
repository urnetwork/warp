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

// The vault edit that launches drift.example (mmm/drift.example/ops/launch-checklist.md
// §4) applied to the test services, with svc-a in the place of mmm: drift.example is
// a domain, drift.example and www.drift.example are svc-a aliases, and www redirects to the
// apex. noAccessLog is the services.yml no_access_log list.
func driftExampleServicesYaml(t *testing.T, noAccessLog ...string) []byte {
	t.Helper()
	baseYaml, err := testServicesFS.ReadFile("testdata/services.yml")
	if err != nil {
		t.Fatal(err)
	}
	servicesYaml := string(baseYaml)

	domains := "domains:\n    example.com: route53\n"
	driftExampleDomains := domains + "    drift.example: cloudflare\n"
	if 0 < len(noAccessLog) {
		driftExampleDomains += "no_access_log:\n"
		for _, host := range noAccessLog {
			driftExampleDomains += fmt.Sprintf("    - %s\n", host)
		}
	}
	if !strings.Contains(servicesYaml, domains) {
		t.Fatal("test services fixture lacks the domains insertion boundary")
	}
	servicesYaml = strings.Replace(servicesYaml, domains, driftExampleDomains, 1)

	// the first svc-a is the latest version's, which the lb is generated from
	svcA := "        svc-a:\n"
	if !strings.Contains(servicesYaml, svcA) {
		t.Fatal("test services fixture lacks svc-a")
	}
	servicesYaml = strings.Replace(servicesYaml, svcA, svcA+
		"            expose_aliases:\n"+
		"                - drift.example\n"+
		"                - www.drift.example\n"+
		"            redirect_aliases:\n"+
		"                www.drift.example: drift.example\n",
		1,
	)
	return []byte(servicesYaml)
}

// the test vault, with certificates for every example.com and drift.example host
func setupDriftExampleTestVault(t *testing.T, servicesYaml []byte) (env string, vaultDir string) {
	t.Helper()
	env, vaultDir = setupTestVaultWithTLS(t, servicesYaml)
	tlsDir := filepath.Join(vaultDir, "tls", "1.0.0")
	generateTestTLSFiles(t, tlsDir, "drift.example", true)
	generateTestTLSFiles(t, tlsDir, "drift.example", false)
	return env, vaultDir
}

// every one-line `<name> ...;` statement in a generated config, trimmed
func nginxDirectives(config string, name string) []string {
	directives := []string{}
	for _, line := range strings.Split(config, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, name+" ") {
			directives = append(directives, trimmed)
		}
	}
	return directives
}

// the entries of the one `<header> {` map block in a generated config
func nginxMapEntries(t *testing.T, config string, header string) map[string]string {
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
	entries := map[string]string{}
	for _, line := range lines[start+1:] {
		entry := strings.TrimSpace(line)
		if entry == "}" {
			return entries
		}
		fields := strings.Fields(strings.TrimSuffix(entry, ";"))
		if len(fields) != 2 || !strings.HasSuffix(entry, ";") {
			t.Fatalf("%q has an unexpected entry %q", header, entry)
		}
		entries[fields[0]] = fields[1]
	}
	t.Fatalf("%q is not closed", header)
	return nil
}

// drift.example keeps no request logs (mmm/drift.example/PLAN.md W1). With drift.example and
// www.drift.example in no_access_log, every access_log the lb has is conditional on
// $warp_loggable, which is 0 for those two hosts and 1 for every other, and
// both hosts are still served.
func TestNginxConfigLeavesNoAccessLogHostsOutOfTheAccessLog(t *testing.T) {
	env, _ := setupDriftExampleTestVault(t, driftExampleServicesYaml(t, "drift.example", "www.drift.example"))
	nginxConfig, err := NewNginxConfig(env, nil)
	if err != nil {
		t.Fatal(err)
	}

	blockConfigs := nginxConfig.Generate()
	if len(blockConfigs) == 0 {
		t.Fatal("no lb block config generated")
	}
	for block, config := range blockConfigs {
		// an access_log in a server or location replaces the http one for its
		// requests, condition and all
		accessLogs := nginxDirectives(config, "access_log")
		if len(accessLogs) == 0 {
			t.Errorf("block %s has no access_log", block)
		}
		for _, accessLog := range accessLogs {
			if accessLog != "access_log /dev/stdout noclientaddr if=$warp_loggable;" && accessLog != "access_log off;" {
				t.Errorf("block %s logs whatever the host: %q", block, accessLog)
			}
		}

		loggable := nginxMapEntries(t, config, "map $host $warp_loggable")
		want := map[string]string{
			"default":           "1",
			"drift.example":     "0",
			"www.drift.example": "0",
		}
		if !maps.Equal(loggable, want) {
			t.Errorf("block %s $warp_loggable = %v, want %v", block, loggable, want)
		}

		serverNames := nginxDirectives(config, "server_name")
		for _, serverName := range []string{"server_name drift.example;", "server_name www.drift.example;"} {
			if !slices.Contains(serverNames, serverName) {
				t.Errorf("block %s does not serve %q", block, serverName)
			}
		}
	}
}

// no_access_log is opt in: without it the access log is unconditional, as it
// was before, and drift.example is logged like any other host.
func TestNginxConfigWithoutNoAccessLogLogsEveryHost(t *testing.T) {
	env, _ := setupDriftExampleTestVault(t, driftExampleServicesYaml(t))
	nginxConfig, err := NewNginxConfig(env, nil)
	if err != nil {
		t.Fatal(err)
	}

	for block, config := range nginxConfig.Generate() {
		accessLogs := nginxDirectives(config, "access_log")
		if !slices.Equal(accessLogs, []string{"access_log /dev/stdout noclientaddr;"}) {
			t.Errorf("block %s access_log = %q, want the unconditional one", block, accessLogs)
		}
		if strings.Contains(config, "$warp_loggable") {
			t.Errorf("block %s defines $warp_loggable with no host listed", block)
		}
	}
}

// A misspelled no_access_log host would leave the host that was meant logged,
// so the lb config is not generated at all.
func TestNginxConfigRejectsNoAccessLogHostTheLbDoesNotServe(t *testing.T) {
	env, _ := setupDriftExampleTestVault(t, driftExampleServicesYaml(t, "drift.example", "ww.drift.example"))
	_, err := NewNginxConfig(env, nil)
	if err == nil || !strings.Contains(err.Error(), "ww.drift.example") {
		t.Fatalf("err = %v, want ww.drift.example rejected", err)
	}
}

func freeLoopbackPort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	return listener.Addr().(*net.TCPAddr).Port
}

// Moves every http listen of a generated config onto a loopback port, the
// local port for each public one in ports. One address family is enough to
// test, quic is not under test, and reuseport and backlog only tune.
func loopbackNginxListens(t *testing.T, config string, ports map[int]int) string {
	t.Helper()
	lines := []string{}
	for _, line := range strings.Split(config, "\n") {
		fields := strings.Fields(strings.TrimSuffix(strings.TrimSpace(line), ";"))
		if len(fields) < 2 || fields[0] != "listen" {
			lines = append(lines, line)
			continue
		}
		if strings.HasPrefix(fields[1], "[::]:") || slices.Contains(fields, "quic") {
			continue
		}
		port, err := strconv.Atoi(fields[1])
		if err != nil {
			t.Fatalf("unexpected listen %q", line)
		}
		localPort, ok := ports[port]
		if !ok {
			t.Fatalf("no local port for listen %q", line)
		}
		listen := []string{"listen", fmt.Sprintf("127.0.0.1:%d", localPort)}
		for _, option := range fields[2:] {
			if option == "reuseport" || strings.HasPrefix(option, "backlog=") {
				continue
			}
			listen = append(listen, option)
		}
		indent := line[:len(line)-len(strings.TrimLeft(line, " \t"))]
		lines = append(lines, indent+strings.Join(listen, " ")+";")
	}
	return strings.Join(lines, "\n")
}

// Runs the generated lb config in nginx and sends it drift.example requests: a share
// link's landing proxied to the service, the www redirect, the port 80
// redirects, and spellings nginx folds into $host. Then it sends the same
// kinds of request for another host of the same service. The access log, which
// the lb writes to its stdout, gets the other host's lines and none for
// drift.example.
func TestNginxWritesNoAccessLogLineForNoAccessLogHosts(t *testing.T) {
	nginxBinary := nginxConfigValidationBinary(t)

	// without capacity sizing nginx runs one worker, which writes the log in
	// the order the requests are sent
	servicesYaml := string(driftExampleServicesYaml(t, "drift.example", "www.drift.example"))
	servicesYaml = strings.ReplaceAll(servicesYaml, "                    concurrent_clients: 786432\n", "")
	servicesYaml = strings.ReplaceAll(servicesYaml, "                    cores: 24\n", "")
	env, vaultDir := setupDriftExampleTestVault(t, []byte(servicesYaml))
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

	// every upstream block is this one service
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
		url string
		// the Host header, when it is not the url's host
		host   string
		status int
	}
	send := func(request lbRequest) {
		t.Helper()
		httpRequest, err := http.NewRequest("GET", request.url, nil)
		if err != nil {
			t.Fatal(err)
		}
		if request.host != "" {
			httpRequest.Host = request.host
		}
		response, err := client.Do(httpRequest)
		if err != nil {
			t.Fatalf("%s (host %q): %s\n%s", request.url, request.host, err, nginxErrors())
		}
		response.Body.Close()
		if response.StatusCode != request.status {
			t.Fatalf("%s (host %q): status %d, want %d\n%s", request.url, request.host, response.StatusCode, request.status, nginxErrors())
		}
	}

	for _, request := range []lbRequest{
		{url: "https://drift.example/r/?utm_source=unlogged-marker", status: http.StatusOK},
		{url: "https://www.drift.example/r/?utm_source=unlogged-marker", status: http.StatusMovedPermanently},
		{url: "http://drift.example/r/?utm_source=unlogged-marker", status: http.StatusMovedPermanently},
		{url: "http://www.drift.example/r/?utm_source=unlogged-marker", status: http.StatusMovedPermanently},
		{url: "http://drift.example/r/?utm_source=unlogged-marker", host: "DRIFT.EXAMPLE", status: http.StatusMovedPermanently},
		{url: "http://drift.example/r/?utm_source=unlogged-marker", host: "drift.example.", status: http.StatusMovedPermanently},
		{url: "http://drift.example/r/?utm_source=unlogged-marker", host: "www.drift.example:80", status: http.StatusMovedPermanently},
	} {
		send(request)
	}

	// sent last, so once their lines are written every earlier request's line
	// would have been too
	loggedLines := []string{
		`test-svc-a.example.com "GET /r/?utm_source=logged-marker HTTP/1.1" 200 `,
		`test-svc-a.example.com "GET /r/?utm_source=logged-marker HTTP/1.1" 301 `,
	}
	send(lbRequest{url: "https://test-svc-a.example.com/r/?utm_source=logged-marker", status: http.StatusOK})
	send(lbRequest{url: "http://test-svc-a.example.com/r/?utm_source=logged-marker", status: http.StatusMovedPermanently})

	accessLog := ""
	for deadline := time.Now().Add(10 * time.Second); ; {
		data, err := os.ReadFile(stdoutPath)
		if err != nil {
			t.Fatal(err)
		}
		accessLog = string(data)
		logged := true
		for _, loggedLine := range loggedLines {
			logged = logged && strings.Contains(accessLog, loggedLine)
		}
		if logged {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the access log has no line for the other host:\n%s\n%s", accessLog, nginxErrors())
		}
		time.Sleep(20 * time.Millisecond)
	}

	for _, line := range strings.Split(strings.TrimSpace(accessLog), "\n") {
		if strings.Contains(strings.ToLower(line), "drift.example") || strings.Contains(line, "unlogged-marker") {
			t.Errorf("the access log has a line for drift.example: %q", line)
		}
	}
}
