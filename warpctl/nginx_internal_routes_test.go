package main

// services.yml's internal_routes (sidecar DESIGN §8.9, §19.5's W8; QD-027, QD-680): the path prefixes of a service
// the lb serves only to the sources it lists, api's /internal/gate/ and the dns API's /dns/internal/, refused with
// 403 from everywhere else on every name the lb serves the service by. svc-a stands in for api here, and the real
// api.yml and dns.yml fragments are held to the same locations. Addresses are documentation ranges.

import (
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/urnetwork/warp/services"
)

// svc-a's internal routes in these tests: the gate's prefix and a second one, let through from two blocks the
// fixture's rate_limit exclude_subnets also hold, as the site's ranges are.
const internalRoutesTestYaml = "" +
	"            internal_routes:\n" +
	"                prefixes:\n" +
	"                    - /internal/gate/\n" +
	"                    - /other/internal/\n" +
	"                allow_subnets:\n" +
	"                    - 198.51.100.0/24\n" +
	"                    - \"2001:db8:1234::/48\"\n"

// The test services with svc-a's internal routes, and with extra beside the domains, e.g. hidden_prefixes.
func internalRoutesServicesYaml(t *testing.T, extra string) []byte {
	t.Helper()
	servicesYaml := testServicesYamlWith(t, testServicesYaml(t), "svc-a", internalRoutesTestYaml)
	if extra != "" {
		domains := "domains:\n    example.com: route53\n"
		if !strings.Contains(string(servicesYaml), domains) {
			t.Fatal("test services fixture lacks the domains insertion boundary")
		}
		servicesYaml = []byte(strings.Replace(string(servicesYaml), domains, domains+extra, 1))
	}
	return servicesYaml
}

// Each internal route location of a generated config, by its location header.
func nginxInternalRouteLocations(config string, locationPrefix string) []string {
	locations := []string{}
	for _, prefix := range []string{"/internal/gate/", "/other/internal/"} {
		locations = append(locations, nginxBlocks(config, "location ^~ "+locationPrefix+prefix)...)
	}
	return locations
}

// What every internal route location of svc-a holds: the allowed sources first and every other refused, then the
// proxy to upstream at the prefix, so the path reaches the service unchanged, with the lb's contract headers.
func checkInternalRouteLocation(t *testing.T, where string, location string, upstream string) {
	t.Helper()
	lines := []string{}
	for _, line := range strings.Split(location, "\n") {
		lines = append(lines, strings.TrimSpace(line))
	}
	allowV4 := slices.Index(lines, "allow 198.51.100.0/24;")
	allowV6 := slices.Index(lines, "allow 2001:db8:1234::/48;")
	deny := slices.Index(lines, "deny all;")
	if allowV4 < 0 || allowV6 < 0 || deny < 0 || deny < allowV4 || deny < allowV6 {
		t.Errorf("%s does not let the two blocks through and refuse the rest, in that order:\n%s", where, location)
	}
	// the location's own prefix, which the proxy keeps
	wantProxy := ""
	for _, routePrefix := range []string{"/internal/gate/", "/other/internal/"} {
		if strings.HasSuffix(strings.TrimSuffix(lines[0], " {"), routePrefix) {
			wantProxy = "proxy_pass http://" + upstream + routePrefix + ";"
		}
	}
	for _, required := range []string{
		wantProxy,
		"proxy_set_header X-UR-Forwarded-For $warp_client_addr:$remote_port;",
		`proxy_set_header X-Forwarded-For "";`,
		"proxy_set_header Host $host;",
	} {
		if required == "" || !slices.Contains(lines, required) {
			t.Errorf("%s lacks %q:\n%s", where, required, location)
		}
	}
	// no browser calls an internal route, and an OPTIONS answered in the rewrite phase would pass before the access
	// phase refuses anything
	if strings.Contains(location, "$request_method") || strings.Contains(location, "Access-Control-") {
		t.Errorf("%s answers cors:\n%s", where, location)
	}
}

// svc-a's internal routes are refused to every source outside its list on every name the lb serves it by: behind
// each of its route prefixes on each of its own https hosts, and on the lb hosts' /by/service and /by/b routes behind
// each lb route prefix, each location proxying the path unchanged. No other service gets one, and nothing changes in
// a config without internal_routes.
func TestNginxConfigRefusesInternalRoutesOnEveryName(t *testing.T) {
	for _, extra := range []string{
		"",
		"hidden_prefixes:\n    - hidden-one\n    - hidden-two\nlb_hidden_prefixes:\n    - control-one\n",
	} {
		env, _ := setupTestVaultWithTLS(t, internalRoutesServicesYaml(t, extra))
		nginxConfig, err := NewNginxConfig(env, nil)
		if err != nil {
			t.Fatal(err)
		}
		routePrefixes := []string{""}
		lbRoutePrefixes := []string{""}
		if extra != "" {
			routePrefixes = []string{"/hidden-one", "/hidden-two"}
			lbRoutePrefixes = []string{"/control-one"}
		}
		blockConfigs := nginxConfig.Generate()
		if len(blockConfigs) == 0 {
			t.Fatal("no lb block config generated")
		}
		for block, config := range blockConfigs {
			svcAServers := 0
			for _, server := range nginxServerBlocks(config) {
				svcAHttps := strings.Contains(server, "server_name test-svc-a.example.com;") && strings.Contains(server, "ssl_certificate ")
				if svcAHttps {
					svcAServers += 1
					for _, routePrefix := range routePrefixes {
						locations := nginxInternalRouteLocations(server, routePrefix)
						if len(locations) != 2 {
							t.Errorf("block %s svc-a's server has %d internal route locations behind %q, want 2:\n%s", block, len(locations), routePrefix, server)
						}
						for _, location := range locations {
							checkInternalRouteLocation(t, "block "+block+" svc-a's server", location, "service-block-svc-a")
						}
					}
					continue
				}
				isLbServer := strings.Contains(server, "server_name test-lb.example.com;") && strings.Contains(server, "ssl_certificate ")
				if !isLbServer {
					if strings.Contains(server, "location ^~") {
						t.Errorf("block %s gives internal routes to a server not svc-a's:\n%s", block, server)
					}
					continue
				}
				for _, lbRoutePrefix := range lbRoutePrefixes {
					byService := nginxInternalRouteLocations(server, lbRoutePrefix+"/by/service/svc-a")
					if len(byService) != 2 {
						t.Errorf("block %s's lb server has %d internal route locations on /by/service/svc-a, want 2", block, len(byService))
					}
					for _, location := range byService {
						checkInternalRouteLocation(t, "block "+block+" lb /by/service", location, "service-block-svc-a")
					}
					for _, svcABlock := range []string{"beta", "g1"} {
						byBlock := nginxInternalRouteLocations(server, lbRoutePrefix+"/by/b/svc-a/"+svcABlock)
						if len(byBlock) != 2 {
							t.Errorf("block %s's lb server has %d internal route locations on /by/b/svc-a/%s, want 2", block, len(byBlock), svcABlock)
						}
						for _, location := range byBlock {
							checkInternalRouteLocation(t, "block "+block+" lb /by/b", location, "service-block-svc-a-"+svcABlock)
						}
					}
					for _, other := range []string{"svc-b", "svc-c", "svc-d"} {
						if 0 < len(nginxInternalRouteLocations(server, lbRoutePrefix+"/by/service/"+other)) {
							t.Errorf("block %s gives %s internal routes", block, other)
						}
					}
				}
			}
			if svcAServers == 0 {
				t.Errorf("block %s serves svc-a on no https server", block)
			}
		}
	}

	env, _ := setupTestVaultWithTLS(t, testServicesYaml(t))
	nginxConfig, err := NewNginxConfig(env, nil)
	if err != nil {
		t.Fatal(err)
	}
	for block, config := range nginxConfig.Generate() {
		if strings.Contains(config, "location ^~") || strings.Contains(config, "deny all;\n            proxy_pass") {
			t.Errorf("block %s has an internal route location without internal_routes", block)
		}
	}
}

// nginx accepts the generated config with internal routes, behind route prefixes and without.
func TestNginxConfigValidationWithInternalRoutes(t *testing.T) {
	nginxBinary := nginxConfigValidationBinary(t)
	for _, extra := range []string{"", "hidden_prefixes:\n    - hidden-one\n    - hidden-two\n"} {
		servicesYaml := nginxServicesWithLongStatusMapKey(t, internalRoutesServicesYaml(t, extra))
		env, vaultDir := setupTestVaultWithTLS(t, servicesYaml)
		nginxConfig, err := NewNginxConfig(env, nil)
		if err != nil {
			t.Fatal(err)
		}
		for block, config := range nginxConfig.Generate() {
			if !strings.Contains(config, "location ^~") {
				t.Fatalf("block %s has no internal route to validate", block)
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
				t.Errorf("nginx refused block %s's config (extra %q):\n%s", block, extra, string(output))
			}
		}
	}
}

// Through a running nginx: a request under svc-a's internal routes from a source outside its list is answered 403
// and never reaches the service, on its own host and on the lb host's /by/ routes, however the path is spelled
// that nginx and the service both read as under the prefix (a doubled slash, a percent-encoded letter, a dot
// segment). One from a listed source, in either family, reaches the service at the path as sent, and every other
// path of the service still answers every source.
func TestNginxRefusesInternalRoutesFromOutside(t *testing.T) {
	received := []string{}
	receivedLock := sync.Mutex{}
	lb := startNginxTestLb(t, &nginxTestLbSettings{
		servicesYaml: internalRoutesServicesYaml(t, ""),
		service: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			receivedLock.Lock()
			defer receivedLock.Unlock()
			received = append(received, r.URL.Path)
		}),
		editConfig: nginxClientAddrFromHeader,
	})
	takeReceived := func() []string {
		receivedLock.Lock()
		defer receivedLock.Unlock()
		taken := received
		received = []string{}
		return taken
	}

	const outside = "203.0.113.9"
	const insideV4 = "198.51.100.7"
	const insideV6 = "2001:db8:1234::7"
	const serviceUrl = "https://test-svc-a.example.com"
	const lbUrl = "https://test-lb.example.com"
	gatePaths := []string{
		"/internal/gate/projection/n1",
		"/other/internal/x",
	}
	spellings := []string{
		serviceUrl + "/internal/gate/projection/n1",
		serviceUrl + "/internal//gate/projection/n1",
		serviceUrl + "/internal/%67ate/projection/n1",
		serviceUrl + "/x/../internal/gate/projection/n1",
		serviceUrl + "/other/internal/x",
		lbUrl + "/by/service/svc-a/internal/gate/projection/n1",
		lbUrl + "/by/b/svc-a/beta/internal/gate/projection/n1",
		lbUrl + "/by/b/svc-a/g1/other/internal/x",
	}
	for _, url := range spellings {
		for _, method := range []string{"GET", "POST", "OPTIONS"} {
			if status := lb.send(method, url, nil, asClientAddr(outside)); status != http.StatusForbidden {
				t.Errorf("%s %s from outside: %d, want 403", method, url, status)
			}
		}
	}
	// and with no address of its own named, the lb's view is the loopback, which is no listed source
	if status := lb.send("GET", serviceUrl+"/internal/gate/projection/n1", nil, nil); status != http.StatusForbidden {
		t.Errorf("an unnamed source: %d, want 403", status)
	}
	if got := takeReceived(); len(got) != 0 {
		t.Fatalf("refused requests reached the service: %q", got)
	}

	for _, inside := range []string{insideV4, insideV6} {
		for _, url := range []string{
			serviceUrl + gatePaths[0],
			serviceUrl + gatePaths[1],
			lbUrl + "/by/service/svc-a" + gatePaths[0],
			lbUrl + "/by/b/svc-a/beta" + gatePaths[1],
		} {
			if status := lb.send("GET", url, nil, asClientAddr(inside)); status != http.StatusOK {
				t.Errorf("GET %s from %s: %d, want 200\n%s", url, inside, status, lb.errors())
			}
		}
		want := []string{gatePaths[0], gatePaths[1], gatePaths[0], gatePaths[1]}
		if got := takeReceived(); !slices.Equal(got, want) {
			t.Errorf("from %s the service received %q, want %q", inside, got, want)
		}
	}

	// the prefix without its slash is redirected to it, as nginx does for every prefix location that proxies, and
	// reaches nothing
	if status := lb.send("GET", serviceUrl+"/internal/gate", nil, asClientAddr(outside)); status != http.StatusMovedPermanently {
		t.Errorf("GET /internal/gate from outside: %d, want nginx's 301 to the prefix", status)
	}
	// the service's other paths answer every source, near misses of a prefix included
	others := []string{"/other", "/internal/gateway/x", "/x/internal/gate/y", "/internal/gatex/y"}
	for _, path := range others {
		if status := lb.send("GET", serviceUrl+path, nil, asClientAddr(outside)); status != http.StatusOK {
			t.Errorf("GET %s from outside: %d, want 200", path, status)
		}
	}
	if got := takeReceived(); !slices.Equal(got, others) {
		t.Errorf("the service received %q, want %q", got, others)
	}
}

// A fragment of services/sidecar-blocks as the owner applies it: each fill-in- placeholder these tests know filled
// in with a synthetic value, the internal routes' sources as documentation blocks holding the fixtures' addresses.
func sidecarBlockFragmentFilled(t *testing.T, name string) *services.ServicesFragment {
	t.Helper()
	path := filepath.Join("..", "services", "sidecar-blocks", name)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	filled := strings.NewReplacer(
		"fill-in-site-ipv4-range", "10.0.0.0/8",
		"fill-in-site-ipv6-range", `"fd00::/8"`,
		"fill-in-monitor-outside-address", "203.0.113.7/32",
	).Replace(string(data))
	if placeholder := regexp.MustCompile(regexp.QuoteMeta(services.ServicesFragmentPlaceholderPrefix) + `[a-z0-9][a-z0-9-]*`).FindString(filled); placeholder != "" {
		t.Fatalf("%s holds the placeholder %s, which these tests do not fill", name, placeholder)
	}
	fragment, err := services.ParseServicesFragment(path, []byte(filled))
	if err != nil {
		t.Fatal(err)
	}
	return fragment
}

// api.yml and dns.yml as the owner applies them, merged into synthetic blocks of api and dns: the lb refuses api's
// /internal/gate/ and the dns API's /dns/internal/ to every source outside the sources each fragment lists, on every
// name it serves each by, the dns API's own name from dns.yml included, and on its lb host routes, each proxying
// its prefix unchanged.
func TestNginxConfigKeepsTheSidecarInternalRoutesToTheSite(t *testing.T) {
	baseYaml := strings.Replace(sidecarServiceBlocksYaml,
		"    services:\n",
		"    services:\n        api:\n            ports:\n                - 80\n            blocks:\n                - beta: 1\n                - g1: 99\n", 1)
	if baseYaml == sidecarServiceBlocksYaml {
		t.Fatal("the fixture's services moved")
	}
	// dns.yml adds the dns API's block whole, so the fixture's synthetic one makes way
	dnsBlock := "        dns:\n            mount: *sidecar_mount\n            user: \"65532\"\n            ports:\n                - 80\n            blocks: *sidecar_blocks\n"
	if !strings.Contains(baseYaml, dnsBlock) {
		t.Fatal("the fixture's dns block moved")
	}
	baseYaml = strings.Replace(baseYaml, dnsBlock, "", 1)
	result, err := services.ApplyServicesFragments([]byte(baseYaml), "services.yml", sidecarBlockFragmentFilled(t, "api.yml"), sidecarBlockFragmentFilled(t, "dns.yml"))
	if err != nil {
		t.Fatal(err)
	}
	merged, err := services.ParseServicesConfig(result.Text, "services.yml")
	if err != nil {
		t.Fatal(err)
	}
	env, vaultDir := setupTestVaultWithTLS(t, result.Text)
	// a certificate for the domain of each name dns.yml gives the dns API, which the lb serves under it
	dnsHosts := []string{"test-dns.example.com"}
	for _, alias := range merged.Versions[0].Services["dns"].ExposeAliases {
		dnsHosts = append(dnsHosts, alias)
		_, aliasDomain, _ := strings.Cut(alias, ".")
		generateTestTLSFiles(t, filepath.Join(vaultDir, "tls", "1.0.0"), aliasDomain, true)
		generateTestTLSFiles(t, filepath.Join(vaultDir, "tls", "1.0.0"), aliasDomain, false)
	}
	nginxConfig, err := NewNginxConfig(env, nil)
	if err != nil {
		t.Fatal(err)
	}
	type wantRoutes struct {
		service string
		hosts   []string
		prefix  string
		sources []string
	}
	for _, want := range []wantRoutes{
		{service: "api", hosts: []string{"test-api.example.com"}, prefix: "/internal/gate/", sources: []string{"10.0.0.0/8", "fd00::/8"}},
		{service: "dns", hosts: dnsHosts, prefix: "/dns/internal/", sources: []string{"10.0.0.0/8", "fd00::/8", "203.0.113.7/32"}},
	} {
		for block, config := range nginxConfig.Generate() {
			// the fixture's transparent interface on ns1 fronts only the dns edge
			if !strings.HasPrefix(block, "edge-0.example.com-") {
				continue
			}
			servedHosts := []string{}
			lbRoutes := 0
			for _, server := range nginxServerBlocks(config) {
				if !strings.Contains(server, "ssl_certificate ") {
					continue
				}
				locationPrefixes := []string{}
				for _, host := range want.hosts {
					if strings.Contains(server, "server_name "+host+";") {
						servedHosts = append(servedHosts, host)
						locationPrefixes = append(locationPrefixes, "")
					}
				}
				if strings.Contains(server, "server_name test-lb.example.com;") {
					lbRoutes += 1
					locationPrefixes = append(locationPrefixes, "/by/service/"+want.service, "/by/b/"+want.service+"/beta", "/by/b/"+want.service+"/g1")
				}
				for _, locationPrefix := range locationPrefixes {
					locations := nginxBlocks(server, "location ^~ "+locationPrefix+want.prefix)
					if len(locations) != 1 {
						t.Errorf("block %s has %d locations for %s%s, want 1", block, len(locations), locationPrefix, want.prefix)
						continue
					}
					lines := []string{}
					for _, line := range strings.Split(locations[0], "\n") {
						lines = append(lines, strings.TrimSpace(line))
					}
					wantAccess := []string{}
					for _, source := range want.sources {
						wantAccess = append(wantAccess, "allow "+source+";")
					}
					wantAccess = append(wantAccess, "deny all;")
					access := slices.DeleteFunc(slices.Clone(lines), func(line string) bool {
						return !strings.HasPrefix(line, "allow ") && !strings.HasPrefix(line, "deny ")
					})
					if !slices.Equal(access, wantAccess) {
						t.Errorf("block %s's %s%s lets through %q, want %q", block, locationPrefix, want.prefix, access, wantAccess)
					}
					upstream := "service-block-" + want.service
					if strings.HasPrefix(locationPrefix, "/by/b/") {
						upstream += "-" + locationPrefix[strings.LastIndex(locationPrefix, "/")+1:]
					}
					if !slices.Contains(lines, "proxy_pass http://"+upstream+want.prefix+";") {
						t.Errorf("block %s's %s%s does not proxy %s at the prefix:\n%s", block, locationPrefix, want.prefix, upstream, locations[0])
					}
				}
			}
			slices.Sort(servedHosts)
			wantHosts := slices.Sorted(slices.Values(want.hosts))
			if !slices.Equal(servedHosts, wantHosts) || lbRoutes != 1 {
				t.Errorf("block %s refuses %s on the names %q and %d lb hosts, want %q and 1", block, want.prefix, servedHosts, lbRoutes, wantHosts)
			}
		}
	}
}
