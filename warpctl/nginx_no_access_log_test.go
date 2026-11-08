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

// The vault edit that launches lag.dev (mmm/lag.dev/ops/launch-checklist.md
// §4) applied to the test services, with svc-a in the place of mmm: lag.dev is
// a domain, lag.dev and www.lag.dev are svc-a aliases, and www redirects to the
// apex. noAccessLog is the services.yml no_access_log list.
func lagDevServicesYaml(t *testing.T, noAccessLog ...string) []byte {
	t.Helper()
	baseYaml, err := testServicesFS.ReadFile("testdata/services.yml")
	if err != nil {
		t.Fatal(err)
	}
	servicesYaml := string(baseYaml)

	domains := "domains:\n    example.com: route53\n"
	lagDevDomains := domains + "    lag.dev: cloudflare\n"
	if 0 < len(noAccessLog) {
		lagDevDomains += "no_access_log:\n"
		for _, host := range noAccessLog {
			lagDevDomains += fmt.Sprintf("    - %s\n", host)
		}
	}
	if !strings.Contains(servicesYaml, domains) {
		t.Fatal("test services fixture lacks the domains insertion boundary")
	}
	servicesYaml = strings.Replace(servicesYaml, domains, lagDevDomains, 1)

	// the first svc-a is the latest version's, which the lb is generated from
	svcA := "        svc-a:\n"
	if !strings.Contains(servicesYaml, svcA) {
		t.Fatal("test services fixture lacks svc-a")
	}
	servicesYaml = strings.Replace(servicesYaml, svcA, svcA+
		"            expose_aliases:\n"+
		"                - lag.dev\n"+
		"                - www.lag.dev\n"+
		"            redirect_aliases:\n"+
		"                www.lag.dev: lag.dev\n",
		1,
	)
	return []byte(servicesYaml)
}

// the test vault, with certificates for every example.com and lag.dev host
func setupLagDevTestVault(t *testing.T, servicesYaml []byte) (env string, vaultDir string) {
	t.Helper()
	env, vaultDir = setupTestVaultWithTLS(t, servicesYaml)
	tlsDir := filepath.Join(vaultDir, "tls", "1.0.0")
	generateTestTLSFiles(t, tlsDir, "lag.dev", true)
	generateTestTLSFiles(t, tlsDir, "lag.dev", false)
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

// lag.dev keeps no request logs (mmm/lag.dev/PLAN.md W1). With lag.dev and
// www.lag.dev in no_access_log, every access_log the lb has is conditional on
// $warp_loggable, which is 0 for those two hosts and 1 for every other, and
// both hosts are still served.
func TestNginxConfigLeavesNoAccessLogHostsOutOfTheAccessLog(t *testing.T) {
	env, _ := setupLagDevTestVault(t, lagDevServicesYaml(t, "lag.dev", "www.lag.dev"))
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
			"default":     "1",
			"lag.dev":     "0",
			"www.lag.dev": "0",
		}
		if !maps.Equal(loggable, want) {
			t.Errorf("block %s $warp_loggable = %v, want %v", block, loggable, want)
		}

		serverNames := nginxDirectives(config, "server_name")
		for _, serverName := range []string{"server_name lag.dev;", "server_name www.lag.dev;"} {
			if !slices.Contains(serverNames, serverName) {
				t.Errorf("block %s does not serve %q", block, serverName)
			}
		}
	}
}

// no_access_log is opt in: without it the access log is unconditional, as it
// was before, and lag.dev is logged like any other host.
func TestNginxConfigWithoutNoAccessLogLogsEveryHost(t *testing.T) {
	env, _ := setupLagDevTestVault(t, lagDevServicesYaml(t))
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
	env, _ := setupLagDevTestVault(t, lagDevServicesYaml(t, "lag.dev", "ww.lag.dev"))
	_, err := NewNginxConfig(env, nil)
	if err == nil || !strings.Contains(err.Error(), "ww.lag.dev") {
		t.Fatalf("err = %v, want ww.lag.dev rejected", err)
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

// Runs the generated lb config in nginx and sends it lag.dev requests: a share
// link's landing proxied to the service, the www redirect, the port 80
// redirects, and spellings nginx folds into $host. Then it sends the same
// kinds of request for another host of the same service. The access log, which
// the lb writes to its stdout, gets the other host's lines and none for
// lag.dev.
func TestNginxWritesNoAccessLogLineForNoAccessLogHosts(t *testing.T) {
	nginxBinary := nginxConfigValidationBinary(t)

	// without capacity sizing nginx runs one worker, which writes the log in
	// the order the requests are sent
	servicesYaml := string(lagDevServicesYaml(t, "lag.dev", "www.lag.dev"))
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
		{url: "https://lag.dev/r/?utm_source=unlogged-marker", status: http.StatusOK},
		{url: "https://www.lag.dev/r/?utm_source=unlogged-marker", status: http.StatusMovedPermanently},
		{url: "http://lag.dev/r/?utm_source=unlogged-marker", status: http.StatusMovedPermanently},
		{url: "http://www.lag.dev/r/?utm_source=unlogged-marker", status: http.StatusMovedPermanently},
		{url: "http://lag.dev/r/?utm_source=unlogged-marker", host: "LAG.DEV", status: http.StatusMovedPermanently},
		{url: "http://lag.dev/r/?utm_source=unlogged-marker", host: "lag.dev.", status: http.StatusMovedPermanently},
		{url: "http://lag.dev/r/?utm_source=unlogged-marker", host: "www.lag.dev:80", status: http.StatusMovedPermanently},
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
		if strings.Contains(strings.ToLower(line), "lag.dev") || strings.Contains(line, "unlogged-marker") {
			t.Errorf("the access log has a line for lag.dev: %q", line)
		}
	}
}

// W8 (DESIGN 19.5): svc-a as a sidecar service, on every kind of name a service
// has. The fixture's env is test.
const logUriServiceYaml = "" +
	"            log_uri: true\n" +
	"            expose_aliases:\n" +
	"                - alias-a.example.com\n" +
	"                - \"*.wild.example.com\"\n" +
	"            expose_domains:\n" +
	"                - domain-a.example.com\n"

// the vault holds the wildcard alias's certificate as well as example.com's
func addLogUriTestTls(t *testing.T, vaultDir string) {
	t.Helper()
	generateTestTLSFiles(t, filepath.Join(vaultDir, "tls", "1.0.0"), "wild.example.com", true)
}

func logUriNginxConfigs(t *testing.T, servicesYaml []byte, envAliases []string) map[string]string {
	t.Helper()
	env, vaultDir := setupTestVaultWithTLS(t, servicesYaml)
	addLogUriTestTls(t, vaultDir)
	nginxConfig, err := NewNginxConfig(env, envAliases)
	if err != nil {
		t.Fatal(err)
	}
	blockConfigs := nginxConfig.Generate()
	if len(blockConfigs) == 0 {
		t.Fatal("no lb block config generated")
	}
	return blockConfigs
}

// the hosts of the one $warp_log_request map in a generated config, each
// checked to give the path alone
func logUriMapHosts(t *testing.T, config string) []string {
	t.Helper()
	maps := nginxBlocks(config, "map $host $warp_log_request")
	if len(maps) != 1 {
		t.Fatalf("config has %d $warp_log_request maps, want 1", len(maps))
	}
	lines := strings.Split(maps[0], "\n")
	entries := []string{}
	for _, line := range lines[1 : len(lines)-1] {
		entries = append(entries, strings.TrimSpace(line))
	}
	if len(entries) < 3 || entries[0] != "hostnames;" || entries[1] != "default $request;" {
		t.Fatalf("$warp_log_request does not start with hostnames and a $request default:\n%s", maps[0])
	}
	hosts := []string{}
	for _, entry := range entries[2:] {
		host, value, ok := strings.Cut(entry, " ")
		if !ok || value != `"$request_method $uri $server_protocol";` {
			t.Fatalf("$warp_log_request has an unexpected entry %q", entry)
		}
		hosts = append(hosts, host)
	}
	return hosts
}

// A log_uri service's hosts are in the map on every name: env and alias names,
// its aliases and domains, and the lb hosts, whose /by/ routes proxy to it. The
// format reads the map, and another service's host is not in it.
func TestNginxConfigMapsEveryNameOfALogUriService(t *testing.T) {
	servicesYaml := testServicesYamlWith(t, testServicesYaml(t), "svc-a", logUriServiceYaml)
	for block, config := range logUriNginxConfigs(t, servicesYaml, []string{"alias-env"}) {
		want := []string{
			"*.wild.example.com",
			"alias-a.example.com",
			"alias-env-lb.example.com",
			"alias-env-svc-a.example.com",
			"domain-a.example.com",
			"test-lb.example.com",
			"test-svc-a.example.com",
		}
		hosts := logUriMapHosts(t, config)
		if !slices.Equal(hosts, want) {
			t.Errorf("block %s $warp_log_request hosts = %q, want %q", block, hosts, want)
		}
		if !strings.Contains(config, `'$host "$warp_log_request" $status $body_bytes_sent $request_time '`) {
			t.Errorf("block %s log format does not read $warp_log_request", block)
		}
		if strings.Contains(config, `"$request"`) {
			t.Errorf("block %s log format still reads $request", block)
		}

		// whatever names a future server takes, one that proxies to the service
		// or names one of its hosts must be in the map
		proxyingServers := 0
		for _, server := range nginxServerBlocks(config) {
			names := []string{}
			for _, directive := range nginxDirectives(server, "server_name") {
				names = append(names, strings.Fields(strings.TrimSuffix(directive, ";"))[1:]...)
			}
			proxying := strings.Contains(server, "proxy_pass http://service-block-svc-a")
			if proxying {
				proxyingServers += 1
			}
			for _, name := range names {
				if (proxying || strings.Contains(name, "-a.") || strings.Contains(name, "svc-a") || strings.Contains(name, "wild")) && !slices.Contains(hosts, name) {
					t.Errorf("block %s serves svc-a on %s, which is not in $warp_log_request", block, name)
				}
			}
		}
		if proxyingServers == 0 {
			t.Errorf("block %s has no server proxying to svc-a", block)
		}
	}
}

// The lb hosts are in the map only for a service they proxy to, and a service
// with no server blocks of its own adds only them.
func TestNginxConfigLogUriHostsFollowTheServiceExposure(t *testing.T) {
	notOnLb := testServicesYamlWith(t, testServicesYaml(t), "svc-a", "            log_uri: true\n            lb_exposed: false\n")
	for block, config := range logUriNginxConfigs(t, notOnLb, nil) {
		if hosts := logUriMapHosts(t, config); !slices.Equal(hosts, []string{"test-svc-a.example.com"}) {
			t.Errorf("block %s hosts of a service not on the lb hosts = %q", block, hosts)
		}
	}
	onlyOnLb := testServicesYamlWith(t, testServicesYaml(t), "svc-a", "            log_uri: true\n            exposed: false\n")
	for block, config := range logUriNginxConfigs(t, onlyOnLb, nil) {
		if hosts := logUriMapHosts(t, config); !slices.Equal(hosts, []string{"test-lb.example.com"}) {
			t.Errorf("block %s hosts of an unexposed service = %q", block, hosts)
		}
	}
	// nothing serves this one, so nothing logs differently
	neither := testServicesYamlWith(t, testServicesYaml(t), "svc-a", "            log_uri: true\n            exposed: false\n            lb_exposed: false\n")
	for block, config := range logUriNginxConfigs(t, neither, nil) {
		if strings.Contains(config, "$warp_log_request") {
			t.Errorf("block %s maps a service nothing serves", block)
		}
	}
}

// A name in two services is one map entry, since nginx refuses a repeated key,
// and so is a name in two cases, since a map matches a string ignoring case.
func TestNginxConfigLogUriHostsAreDistinct(t *testing.T) {
	servicesYaml := testServicesYamlWith(t, testServicesYaml(t), "svc-a", ""+
		"            log_uri: true\n"+
		"            expose_aliases:\n"+
		"                - Alias-A.example.com\n"+
		"                - alias-a.example.com\n")
	servicesYaml = testServicesYamlWith(t, servicesYaml, "svc-b", "            log_uri: true\n")
	for block, config := range logUriNginxConfigs(t, servicesYaml, nil) {
		want := []string{"alias-a.example.com", "test-lb.example.com", "test-svc-a.example.com", "test-svc-b.example.com"}
		if hosts := logUriMapHosts(t, config); !slices.Equal(hosts, want) {
			t.Errorf("block %s hosts = %q, want %q", block, hosts, want)
		}
	}
}

// log_uri is opt in: the map and its one format change are all it adds. Take
// them away and the render is byte for byte the one without the key, and
// without the key nothing refers to $warp_log_request.
func TestNginxConfigLogUriAddsOnlyItsOwnLines(t *testing.T) {
	without := logUriNginxConfigs(t, testServicesYaml(t), nil)
	with := logUriNginxConfigs(t, testServicesYamlWith(t, testServicesYaml(t), "svc-a", "            log_uri: true\n"), nil)
	if len(with) != len(without) {
		t.Fatalf("rendered %d blocks with the form and %d without", len(with), len(without))
	}
	for block, config := range with {
		httpConfig := nginxHttpConfig(config)
		logUriMap := nginxBlocks(httpConfig, "map $host $warp_log_request")
		if len(logUriMap) != 1 {
			t.Fatalf("block %s has %d maps", block, len(logUriMap))
		}
		comment := "    # services.yml log_uri: no query string in the access log for these hosts\n"
		httpConfig = strings.Replace(httpConfig, comment, "", 1)
		httpConfig = strings.Replace(httpConfig, logUriMap[0]+"\n", "", 1)
		httpConfig = strings.Replace(httpConfig, `"$warp_log_request"`, `"$request"`, 1)
		if httpConfig != nginxHttpConfig(without[block]) {
			t.Errorf("block %s changed beyond the form's own lines", block)
		}
		if strings.Contains(without[block], "warp_log_request") {
			t.Errorf("block %s refers to $warp_log_request with no service flagged", block)
		}
	}
}

// log_uri changes what a line says and no_access_log whether it is written, so
// a host may have both and the access_log keeps its condition.
func TestNginxConfigKeepsNoAccessLogBesideLogUri(t *testing.T) {
	servicesYaml := []byte(strings.Replace(
		string(testServicesYamlWith(t, testServicesYaml(t), "svc-a", logUriServiceYaml)),
		"domains:\n    example.com: route53\n",
		"domains:\n    example.com: route53\nno_access_log:\n    - alias-a.example.com\n",
		1,
	))
	for block, config := range logUriNginxConfigs(t, servicesYaml, nil) {
		if accessLogs := nginxDirectives(config, "access_log"); !slices.Equal(accessLogs, []string{"access_log /dev/stdout noclientaddr if=$warp_loggable;"}) {
			t.Errorf("block %s access_log = %q", block, accessLogs)
		}
		loggable := nginxMapEntries(t, config, "map $host $warp_loggable")
		if !maps.Equal(loggable, map[string]string{"default": "1", "alias-a.example.com": "0"}) {
			t.Errorf("block %s $warp_loggable = %v", block, loggable)
		}
		if !slices.Contains(logUriMapHosts(t, config), "alias-a.example.com") {
			t.Errorf("block %s lost the host from $warp_log_request", block)
		}
	}
}

// Runs the generated lb config in nginx and sends requests with a query string
// to a log_uri service on every kind of name it has, and to another service.
// The access log holds a line for each, with the path alone for the flagged
// service, in the fields a $request line has, and the whole request line for
// the other. A no_access_log host beside it still writes no line at all.
func TestNginxLogsNoQueryStringOnALogUriHost(t *testing.T) {
	servicesYaml := []byte(strings.Replace(
		string(testServicesYamlWith(t, testServicesYaml(t), "svc-a", logUriServiceYaml+
			"            redirect_aliases:\n"+
			"                domain-a.example.com: alias-a.example.com\n")),
		"domains:\n    example.com: route53\n",
		"domains:\n    example.com: route53\nno_access_log:\n    - quiet.example.com\n",
		1,
	))
	servicesYaml = testServicesYamlWith(t, servicesYaml, "svc-b", ""+
		"            expose_aliases:\n"+
		"                - quiet.example.com\n")
	lb := startNginxTestLb(t, &nginxTestLbSettings{
		servicesYaml: servicesYaml,
		service: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintln(w, "ok")
		}),
		editVault: func(vaultDir string) {
			addLogUriTestTls(t, vaultDir)
		},
	})

	const query = "?token=unlogged-marker&other=unlogged-marker"
	type lbRequest struct {
		url string
		// the Host header, when it is not the url's host
		host   string
		status int
		// what the line's host and request fields must hold
		line string
	}
	for _, request := range []lbRequest{
		{url: "https://test-svc-a.example.com/r/one" + query, status: http.StatusOK, line: `test-svc-a.example.com "GET /r/one HTTP/1.1" 200 `},
		{url: "https://alias-a.example.com/r/two" + query, status: http.StatusOK, line: `alias-a.example.com "GET /r/two HTTP/1.1" 200 `},
		{url: "https://any.wild.example.com/r/three" + query, status: http.StatusOK, line: `any.wild.example.com "GET /r/three HTTP/1.1" 200 `},
		// a redirect alias answers from the server block, with no location
		{url: "https://domain-a.example.com/r/four" + query, status: http.StatusMovedPermanently, line: `domain-a.example.com "GET /r/four HTTP/1.1" 301 `},
		// the port 80 redirect server, which shares one server for every host
		{url: "http://test-svc-a.example.com/r/five" + query, status: http.StatusMovedPermanently, line: `test-svc-a.example.com "GET /r/five HTTP/1.1" 301 `},
		// the lb hosts' routes to the service and to one of its blocks
		{url: "https://test-lb.example.com/by/service/svc-a/r/six" + query, status: http.StatusOK, line: `test-lb.example.com "GET /by/service/svc-a/r/six HTTP/1.1" 200 `},
		{url: "https://test-lb.example.com/by/b/svc-a/beta/r/seven" + query, status: http.StatusOK, line: `test-lb.example.com "GET /by/b/svc-a/beta/r/seven HTTP/1.1" 200 `},
		// spellings nginx folds into $host
		{url: "http://test-svc-a.example.com/r/eight" + query, host: "TEST-SVC-A.EXAMPLE.COM", status: http.StatusMovedPermanently, line: `test-svc-a.example.com "GET /r/eight HTTP/1.1" 301 `},
		{url: "http://test-svc-a.example.com/r/nine" + query, host: "test-svc-a.example.com.", status: http.StatusMovedPermanently, line: `test-svc-a.example.com "GET /r/nine HTTP/1.1" 301 `},
		{url: "http://test-svc-a.example.com/r/ten" + query, host: "test-svc-a.example.com:80", status: http.StatusMovedPermanently, line: `test-svc-a.example.com "GET /r/ten HTTP/1.1" 301 `},
		// $uri is decoded, and nginx's log escaping writes what that makes of a
		// line break and a quote, so a path cannot forge a line or a field
		{url: "https://test-svc-a.example.com/r/a%0Ab%22c" + query, status: http.StatusOK, line: `test-svc-a.example.com "GET /r/a\x0Ab\x22c HTTP/1.1" 200 `},
		// an unflagged service stays as it is, on either port
		{url: "https://test-svc-b.example.com/r/?token=logged-marker", status: http.StatusOK, line: `test-svc-b.example.com "GET /r/?token=logged-marker HTTP/1.1" 200 `},
		{url: "http://test-svc-b.example.com/r/?token=logged-marker", status: http.StatusMovedPermanently, line: `test-svc-b.example.com "GET /r/?token=logged-marker HTTP/1.1" 301 `},
	} {
		status := lb.send("GET", request.url, nil, func(httpRequest *http.Request) {
			if request.host != "" {
				httpRequest.Host = request.host
			}
		})
		if status != request.status {
			t.Fatalf("%s (host %q): status %d, want %d\n%s", request.url, request.host, status, request.status, lb.errors())
		}
		// each line is on its way before the next request, so a failure names it
		lb.waitForAccessLogLine(request.line)
	}
	if status := lb.send("GET", "https://quiet.example.com/r/?token=unlogged-marker", nil, nil); status != http.StatusOK {
		t.Fatalf("no_access_log host: status %d", status)
	}
	// sent last, so once its line is written the one before it would have been
	if status := lb.send("GET", "https://test-svc-b.example.com/r/last", nil, nil); status != http.StatusOK {
		t.Fatalf("last request: status %d", status)
	}
	lb.waitForAccessLogLine(`test-svc-b.example.com "GET /r/last HTTP/1.1" 200 `)

	accessLog := lb.accessLog()
	if strings.Contains(accessLog, "unlogged-marker") {
		t.Errorf("a query string of a log_uri host reached the access log:\n%s", accessLog)
	}
	if strings.Contains(accessLog, "quiet.example.com") {
		t.Errorf("the no_access_log host has a line:\n%s", accessLog)
	}
	// the decoded line break did not start a line: one line per request
	if lines := strings.Count(accessLog, "\n"); lines != 14 {
		t.Errorf("the access log has %d lines, want 14:\n%s", lines, accessLog)
	}
}
