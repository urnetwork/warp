package main

// Tests of the lb_alt route renderer and route file (lbalt_route.go). The
// renderer runs on testdata/lbalt_route_services.yml, a synthetic services.yml
// whose render for edge-a.example is the shared example,
// testdata/lbalt_route_v1_example.json, and on variants of it, each a few
// exact replacements.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"github.com/urnetwork/warp/services"
)

// The host and generation the shared example is rendered for.
const (
	lbAltRouteExampleHost       = "edge-a.example"
	lbAltRouteExampleGeneration = "test-connect-g1-0123456789abcdef"
)

// The synthetic services fixture, with each old string replaced by the new one
// after it. Each old string must occur exactly once, so a fixture edit that
// strands a test's replacement fails here rather than testing nothing.
func lbAltRouteServicesYaml(t *testing.T, replacements ...string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "lbalt_route_services.yml"))
	if err != nil {
		t.Fatal(err)
	}
	if len(replacements)%2 != 0 {
		t.Fatal("replacements come in old, new pairs")
	}
	servicesYaml := string(data)
	for i := 0; i < len(replacements); i += 2 {
		if count := strings.Count(servicesYaml, replacements[i]); count != 1 {
			t.Fatalf("the fixture holds %q %d times, want once", replacements[i], count)
		}
		servicesYaml = strings.Replace(servicesYaml, replacements[i], replacements[i+1], 1)
	}
	return []byte(servicesYaml)
}

// The inputs of the shared example's generation, connect's block g1 on
// edge-a.example, with the services config the test vault holds for env. The
// interfaces come out of order and an address is written non-canonically,
// since the table depends on neither.
func lbAltRouteExampleInputs(env string) *lbAltRouteInputs {
	return &lbAltRouteInputs{
		servicesConfig: getServicesConfig(env),
		env:            env,
		host:           lbAltRouteExampleHost,
		generation:     lbAltRouteExampleGeneration,
		interfaces: []lbAltRouteInterfaceInput{
			{name: "eth2", lbAlt: false, ipv4: "198.51.100.2", ipv6: ""},
			{name: "eth1", lbAlt: true, ipv4: "198.51.100.1", ipv6: "2001:0db8:0001::0001"},
		},
		servicePorts: map[int]int{80: 7080, 443: 7443, 4053: 7453},
		upstreamIpv4: "192.0.2.1",
		whodisTlds:   []string{"whodis.example."},
	}
}

// Renders the example generation's table from servicesYaml in a fresh test
// vault, once mutate, when given, has changed the inputs. It returns the env
// too, for a test that reads the vault again. Every table rendered must
// encode, so no list of it is nil.
func renderLbAltRouteFixture(t *testing.T, servicesYaml []byte, mutate func(inputs *lbAltRouteInputs)) (*LbAltRouteTable, string, error) {
	t.Helper()
	env := setupTestVault(t, servicesYaml)
	inputs := lbAltRouteExampleInputs(env)
	if mutate != nil {
		mutate(inputs)
	}
	table, err := renderLbAltRouteTable(inputs)
	if err == nil {
		if _, err := encodeLbAltRouteTable(table); err != nil {
			t.Fatalf("a rendered table does not encode: %v", err)
		}
	}
	return table, env, err
}

// The table's service named name.
func lbAltRouteTableService(t *testing.T, table *LbAltRouteTable, name string) LbAltRouteService {
	t.Helper()
	for _, service := range table.Services {
		if service.Name == name {
			return service
		}
	}
	t.Fatalf("the table has no service %q", name)
	return LbAltRouteService{}
}

// The table's interface named name.
func lbAltRouteTableInterface(t *testing.T, table *LbAltRouteTable, name string) LbAltRouteInterface {
	t.Helper()
	for _, routeInterface := range table.Interfaces {
		if routeInterface.Name == name {
			return routeInterface
		}
	}
	t.Fatalf("the table has no interface %q", name)
	return LbAltRouteInterface{}
}

// Fails at the first line where got differs from want.
func requireLbAltRouteBytes(t *testing.T, got []byte, want []byte) {
	t.Helper()
	if bytes.Equal(got, want) {
		return
	}
	gotLines := strings.Split(string(got), "\n")
	wantLines := strings.Split(string(want), "\n")
	for i := range max(len(gotLines), len(wantLines)) {
		gotLine := ""
		if i < len(gotLines) {
			gotLine = gotLines[i]
		}
		wantLine := ""
		if i < len(wantLines) {
			wantLine = wantLines[i]
		}
		if gotLine != wantLine {
			t.Fatalf("line %d is %q, the example's is %q", i+1, gotLine, wantLine)
		}
	}
	t.Fatal("the bytes differ from the example")
}

// warpctl renders the shared example byte for byte from the synthetic
// services.yml. connect's parser is tested against the same file, so the two
// repos agree on the encoding, the ordering of every list and each resolved
// value: the redirect alias out of the api's names, the anchor's subnets
// sorted, the request body's buffer and the keepalives defaulted, and the
// block ports from the port allocation.
func TestLbAltRouteRendersTheSharedExample(t *testing.T) {
	table, _, err := renderLbAltRouteFixture(t, lbAltRouteServicesYaml(t), nil)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := encodeLbAltRouteTable(table)
	if err != nil {
		t.Fatal(err)
	}
	requireLbAltRouteBytes(t, encoded, readLbAltRouteExample(t))
}

// The table serves only what the host's lb serves: the lb names and the names
// of the services fronted on the host. The bare domains and web's names, which
// only edge-b.example fronts, are hostnames with certificates, but no server of
// edge-a.example's lb answers them. Every served name is a hostname, so the
// vault has a certificate for it.
func TestLbAltRouteServesOnlyTheHostsOwnNames(t *testing.T) {
	env := setupTestVault(t, lbAltRouteServicesYaml(t))
	inputs := lbAltRouteExampleInputs(env)
	table, err := renderLbAltRouteTable(inputs)
	if err != nil {
		t.Fatal(err)
	}
	servedNames := map[string]bool{}
	for _, name := range table.Lb.Names {
		servedNames[name] = true
	}
	for _, service := range table.Services {
		for _, name := range service.Names {
			servedNames[name] = true
		}
		for _, redirectAlias := range service.RedirectAliases {
			servedNames[redirectAlias.Name] = true
		}
	}

	hostnames := inputs.servicesConfig.Hostnames(env, nil)
	unservedNames := []string{
		"service.example",
		"other.example",
		"test-web.service.example",
		"test-web.other.example",
		"quiet.service.example",
	}
	for _, name := range unservedNames {
		if !slices.Contains(hostnames, name) {
			t.Fatalf("the fixture no longer makes %s a hostname", name)
		}
		if servedNames[name] {
			t.Errorf("edge-a.example serves %s, which its lb does not", name)
		}
	}
	for name := range servedNames {
		if !slices.Contains(hostnames, name) {
			t.Errorf("edge-a.example serves %s, which is not a hostname with a certificate", name)
		}
	}
	if gotServices := len(table.Services); gotServices != 3 {
		t.Errorf("the table fronts %d services, want edge-a.example's 3", gotServices)
	}
}

// The interfaces are the worker's: whether lb_alt is in effect on each and its
// bridge addresses come from the inputs, in canonical form, under the
// interface's lb block, so a flip of one interface's override reaches the
// file as the worker saw it.
func TestLbAltRouteTakesTheInterfacesFromTheInputs(t *testing.T) {
	table, _, err := renderLbAltRouteFixture(t, lbAltRouteServicesYaml(t), func(inputs *lbAltRouteInputs) {
		inputs.interfaces[0] = lbAltRouteInterfaceInput{
			name:  "eth2",
			lbAlt: true,
			ipv4:  "198.51.100.20",
			ipv6:  "2001:db8:2:0:0:0:0:20",
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	gotInterface := lbAltRouteTableInterface(t, table, "eth2")
	if gotInterface.Block != "edge-a.example-eth2" || !gotInterface.LbAlt || gotInterface.Ipv4 != "198.51.100.20" || gotInterface.Ipv6 != "2001:db8:2::20" {
		t.Errorf("eth2 = %+v, want block edge-a.example-eth2, lb_alt true, ipv4 198.51.100.20 and ipv6 2001:db8:2::20", gotInterface)
	}
}

// nginx matches server names in lowercase, and connect's parser takes names
// only in lowercase, so names, redirect targets and domains written in any
// case are served in lowercase. A redirect alias is matched to its name as
// written, as the nginx generator matches it. The domains after the primary
// are sorted once lowercase, as the contract orders them, while the lb names
// keep DomainNames order, nginx's server order.
func TestLbAltRouteLowercasesNames(t *testing.T) {
	servicesYaml := lbAltRouteServicesYaml(
		t,
		"                - old-api.service.example\n",
		"                - OLD-API.service.example\n",
		"                old-api.service.example: api.service.example\n",
		"                OLD-API.service.example: API.Service.Example\n",
		"                - connect.service.example\n",
		"                - connect.service.example\n                - Edge-Connect.Service.Example\n",
		// DomainNames sorts Other.example before another.example
		"    other.example: route53\n",
		"    Other.example: route53\n    another.example: route53\n",
	)
	table, _, err := renderLbAltRouteFixture(t, servicesYaml, nil)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"service.example", "another.example", "other.example"}; !slices.Equal(table.Domains, want) {
		t.Errorf("domains = %v, want the primary, then the rest sorted, %v", table.Domains, want)
	}
	wantLbNames := []string{"test-lb.service.example", "test-lb.other.example", "test-lb.another.example"}
	if !slices.Equal(table.Lb.Names, wantLbNames) {
		t.Errorf("lb names = %v, want DomainNames order %v", table.Lb.Names, wantLbNames)
	}
	wantRedirectAliases := []LbAltRouteRedirectAlias{
		{Name: "old-api.service.example", Target: "api.service.example"},
	}
	if got := lbAltRouteTableService(t, table, "api").RedirectAliases; !slices.Equal(got, wantRedirectAliases) {
		t.Errorf("api redirect aliases = %+v, want %+v", got, wantRedirectAliases)
	}
	if got := lbAltRouteTableService(t, table, "connect").Names; !slices.Contains(got, "edge-connect.service.example") {
		t.Errorf("connect names = %v, want edge-connect.service.example among them", got)
	}
}

// The table serves a service's names only where nginx does: for a service the
// lb proxies over http, exposed with service port 80, when the lb has port 80
// or 443. An unexposed service fronted on the host keeps its blocks, which the
// lb's per-block routes reach, but no names, and with them none of the route
// limits or quiet paths nginx applies on names. An lb without an http port
// serves no name and has no upstream.
func TestLbAltRouteServesNoNamesTheLbDoesNot(t *testing.T) {
	servicesYaml := lbAltRouteServicesYaml(
		t,
		"            - mcp\n            - connect\n            - api\n",
		"            - mcp\n            - connect\n            - api\n            - worker\n",
		"        web:\n            expose_aliases:\n",
		""+
			"        worker:\n"+
			"            exposed: false\n"+
			"            expose_aliases:\n"+
			"                - worker.service.example\n"+
			"            route_rate_limits:\n"+
			"                -   path: /busy\n"+
			"                    requests_per_minute: 60\n"+
			"                    burst: 10\n"+
			"            no_success_access_log:\n"+
			"                - /ping\n"+
			"            ports:\n"+
			"                - 80\n"+
			"            blocks:\n"+
			"                - g1: 1\n"+
			"        web:\n            expose_aliases:\n",
	)
	table, _, err := renderLbAltRouteFixture(t, servicesYaml, nil)
	if err != nil {
		t.Fatal(err)
	}
	worker := lbAltRouteTableService(t, table, "worker")
	if worker.Exposed || 0 < len(worker.Names) || 0 < len(worker.RedirectAliases) {
		t.Errorf("the unexposed worker is exposed %v with names %v and redirect aliases %+v, want none", worker.Exposed, worker.Names, worker.RedirectAliases)
	}
	if 0 < len(worker.RouteRateLimits) || 0 < len(worker.NoSuccessAccessLog) {
		t.Errorf("the unexposed worker has route limits %+v and quiet paths %v, which nginx applies to none of its requests", worker.RouteRateLimits, worker.NoSuccessAccessLog)
	}
	if len(worker.Blocks) != 1 || worker.Blocks[0].Name != "g1" || worker.Blocks[0].Port == 0 {
		t.Errorf("worker blocks = %+v, want g1 and its port", worker.Blocks)
	}

	// an lb with no http port has no http server and no upstream at all
	servicesYaml = lbAltRouteServicesYaml(
		t,
		"        ports:\n            - 80\n            - 443\n        udp_stream_port_services:\n",
		"        udp_stream_port_services:\n",
	)
	table, _, err = renderLbAltRouteFixture(t, servicesYaml, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, service := range table.Services {
		if 0 < len(service.Names) || 0 < len(service.RedirectAliases) || 0 < len(service.Blocks) {
			t.Errorf("%s has names %v, redirect aliases %+v and blocks %+v on an lb with no http port", service.Name, service.Names, service.RedirectAliases, service.Blocks)
		}
	}
}

// Checks the table against the lb config nginx runs on each of the host's
// interfaces, which the nginx generator writes from the test vault of env,
// the services.yml the table was rendered from, with a generated certificate
// for every name it looks up. Every interface that is not lb_alt has one; an
// lb_alt interface is checked while the generator still writes its config,
// the one a rollback would run. For each config:
//   - every name an https server of the lb answers routes to the same service,
//     or redirects to the same target, and the table serves no other name;
//   - each service's https servers have a prefix location for each of its
//     route prefixes and for no other, and in each a nested location for its
//     streamable paths when it has some and does not stream every path;
//   - the lb names are the lb's https servers, in order, the default first;
//   - the lb's https servers have a hidden by/service route for each lb route
//     prefix and lb_exposed service, and no other;
//   - each interface's shared limits are its lb's standardlimit and
//     standardconnlimit zones and excluded subnets;
//   - each route limit is its own zone's rate and burst, and nginx has no
//     other route zone;
//   - each service's blocks, balancing and keepalive are its upstream's.
func checkLbAltRouteNginxParity(t *testing.T, table *LbAltRouteTable, env string) {
	t.Helper()
	tlsDir := filepath.Join(os.Getenv("WARP_HOME"), "vault", env, "tls", "1.0.0")
	for _, domain := range []string{"service.example", "other.example"} {
		generateTestTLSFiles(t, tlsDir, domain, false)
		generateTestTLSFiles(t, tlsDir, domain, true)
	}
	// for *.connect.service.example
	generateTestTLSFiles(t, tlsDir, "connect.service.example", true)
	nginxConfig, err := NewNginxConfig(env, nil)
	if err != nil {
		t.Fatal(err)
	}
	blockConfigs := nginxConfig.Generate()

	serverNameRegex := regexp.MustCompile(`(?m)^\s*server_name ([^;]+);`)
	redirectRegex := regexp.MustCompile(`return 301 \$scheme://([^$;]+)\$request_uri;`)
	proxyRegex := regexp.MustCompile(`proxy_pass http://service-block-([A-Za-z0-9._-]+)/;`)
	// a prefix location, `location <route prefix>/ {`; an exact or regex
	// location has a space after its modifier, so it never matches
	routePrefixLocationRegex := regexp.MustCompile(`(?m)^\s*location (\S*)/ \{$`)
	streamableLocationRegex := regexp.MustCompile(`(?m)^\s*location ~ "(.*)" \{$`)
	lbServiceLocationRegex := regexp.MustCompile(`(?m)^\s*location (\S*)/by/service/([A-Za-z0-9._-]+)/ \{$`)
	netConnectionsRegex := regexp.MustCompile(`limit_conn standardconnlimit (\d+);`)
	excludeRegex := regexp.MustCompile(`(?s)geo \$limit_key_exclude \{(.*?)default 0;`)
	excludeSubnetRegex := regexp.MustCompile(`(?m)^\s*(\S+) 1;`)
	routeZoneRegex := regexp.MustCompile(`limit_req_zone \$limit_key zone=(route_[A-Za-z0-9_]+):`)
	keepaliveRegex := regexp.MustCompile(`(?m)^\s*keepalive (\d+);`)
	keepaliveRequestsRegex := regexp.MustCompile(`keepalive_requests (\d+);`)
	keepaliveTimeRegex := regexp.MustCompile(`keepalive_time ([^;]+);`)
	keepaliveTimeoutRegex := regexp.MustCompile(`keepalive_timeout ([^;]+);`)
	// a zone's rate as requests per minute, 0 when nginx declares no zone
	zoneRequestsPerMinute := func(config string, zone string) float64 {
		match := regexp.MustCompile(`limit_req_zone \$limit_key zone=` + regexp.QuoteMeta(zone) + `:\d+m rate=(\d+)r/(m|s);`).FindStringSubmatch(config)
		if match == nil {
			return 0
		}
		rate, err := strconv.Atoi(match[1])
		if err != nil {
			t.Fatal(err)
		}
		if match[2] == "s" {
			return float64(rate) * 60
		}
		return float64(rate)
	}
	// a zone's burst where it applies, 0 when nginx sets none
	zoneBurst := func(config string, zone string) int {
		match := regexp.MustCompile(`limit_req zone=` + regexp.QuoteMeta(zone) + `(?: burst=(\d+))? nodelay;`).FindStringSubmatch(config)
		if match == nil || match[1] == "" {
			return 0
		}
		burst, err := strconv.Atoi(match[1])
		if err != nil {
			t.Fatal(err)
		}
		return burst
	}
	atoi := func(value string) int {
		number, err := strconv.Atoi(value)
		if err != nil {
			t.Fatal(err)
		}
		return number
	}
	// the escaped location prefix and the streamable paths of a nested
	// streamable location's quoted regex (streamablePathsRegex), the paths
	// sorted and without repeats as the table holds them. The alternatives
	// are split on their separator, which no fixture's path holds.
	streamableRegexPaths := func(quotedRegex string) (string, []string) {
		regex := strings.NewReplacer(`\\`, `\`, `\"`, `"`).Replace(quotedRegex)
		quotedPrefix, alternatives, ok := strings.Cut(strings.TrimPrefix(regex, "^"), "(?:(?:")
		if !ok || !strings.HasSuffix(alternatives, "))$") {
			t.Fatalf("%q is not a streamable paths regex", regex)
		}
		return quotedPrefix, lbAltSortedUnique(strings.Split(strings.TrimSuffix(alternatives, "))$"), ")|(?:"))
	}

	routeServices := map[string]LbAltRouteService{}
	routeNameTargets := map[string]string{}
	for _, service := range table.Services {
		routeServices[service.Name] = service
		for _, name := range service.Names {
			routeNameTargets[name] = "service " + service.Name
		}
		for _, redirectAlias := range service.RedirectAliases {
			routeNameTargets[redirectAlias.Name] = "redirect to " + redirectAlias.Target
		}
	}
	routeLbServiceRoutes := []string{}
	for _, routePrefix := range table.Lb.RoutePrefixes {
		for _, service := range table.Services {
			if service.LbExposed {
				routeLbServiceRoutes = append(routeLbServiceRoutes, routePrefix+"/by/service/"+service.Name)
			}
		}
	}
	slices.Sort(routeLbServiceRoutes)

	checkedInterfaceCount := 0
	for _, routeInterface := range table.Interfaces {
		block := routeInterface.Block
		config, ok := blockConfigs[block]
		if !ok {
			// nginx runs on every interface that is not lb_alt; an lb_alt one's
			// config is checked when the generator still writes it
			if !routeInterface.LbAlt {
				t.Errorf("nginx has no config for the lb block %s", block)
			}
			continue
		}
		checkedInterfaceCount += 1

		nginxNameTargets := map[string]string{}
		nginxLbNames := []string{}
		for _, server := range nginxServerBlocks(config) {
			if !strings.Contains(server, "listen 443 ssl") {
				continue
			}
			serverNameMatch := serverNameRegex.FindStringSubmatch(server)
			if serverNameMatch == nil {
				t.Errorf("%s: an https server has no server_name", block)
				continue
			}
			serverNames := strings.Fields(serverNameMatch[1])
			if strings.Contains(server, "alias /srv/warp/status/status.json") {
				nginxLbNames = append(nginxLbNames, serverNames...)
				nginxLbServiceRoutes := []string{}
				for _, match := range lbServiceLocationRegex.FindAllStringSubmatch(server, -1) {
					nginxLbServiceRoutes = append(nginxLbServiceRoutes, match[1]+"/by/service/"+match[2])
				}
				slices.Sort(nginxLbServiceRoutes)
				if !slices.Equal(nginxLbServiceRoutes, routeLbServiceRoutes) {
					t.Errorf("%s: nginx's lb server %v has the hidden routes %v, the table %v", block, serverNames, nginxLbServiceRoutes, routeLbServiceRoutes)
				}
				continue
			}
			redirectMatch := redirectRegex.FindStringSubmatch(server)
			proxyMatch := proxyRegex.FindStringSubmatch(server)
			for _, serverName := range serverNames {
				if redirectMatch != nil {
					nginxNameTargets[serverName] = "redirect to " + redirectMatch[1]
				} else if proxyMatch != nil {
					nginxNameTargets[serverName] = "service " + proxyMatch[1]
				} else {
					t.Errorf("%s: the https server of %s neither proxies nor redirects", block, serverName)
				}
			}
			if redirectMatch != nil || proxyMatch == nil {
				continue
			}

			service, ok := routeServices[proxyMatch[1]]
			if !ok {
				// the name comparison below reports it
				continue
			}
			nginxRoutePrefixes := []string{}
			for _, match := range routePrefixLocationRegex.FindAllStringSubmatch(server, -1) {
				nginxRoutePrefixes = append(nginxRoutePrefixes, match[1])
			}
			if got := lbAltSortedUnique(nginxRoutePrefixes); !slices.Equal(got, service.RoutePrefixes) {
				t.Errorf("%s: nginx's server of %v proxies %s behind the prefixes %v, the table %v", block, serverNames, service.Name, got, service.RoutePrefixes)
			}
			streamableMatches := streamableLocationRegex.FindAllStringSubmatch(server, -1)
			if len(service.StreamablePaths) == 0 || service.Streamable {
				if len(streamableMatches) != 0 {
					t.Errorf("%s: nginx's server of %v streams some paths of %s, whose table streamable paths are %v and streamable %v", block, serverNames, service.Name, service.StreamablePaths, service.Streamable)
				}
				continue
			}
			if len(streamableMatches) != len(nginxRoutePrefixes) {
				t.Errorf("%s: nginx's server of %v has %d streamable locations for %d prefixes", block, serverNames, len(streamableMatches), len(nginxRoutePrefixes))
			}
			for _, match := range streamableMatches {
				quotedPrefix, streamablePaths := streamableRegexPaths(match[1])
				hasPrefix := slices.ContainsFunc(service.RoutePrefixes, func(routePrefix string) bool {
					return regexp.QuoteMeta(routePrefix) == quotedPrefix
				})
				if !hasPrefix || !slices.Equal(streamablePaths, service.StreamablePaths) {
					t.Errorf("%s: nginx's server of %v streams %v behind %q, the table %v behind %v", block, serverNames, streamablePaths, quotedPrefix, service.StreamablePaths, service.RoutePrefixes)
				}
			}
		}
		if !slices.Equal(nginxLbNames, table.Lb.Names) {
			t.Errorf("%s: nginx's lb servers are %v, the table's lb names %v", block, nginxLbNames, table.Lb.Names)
		}
		if !maps.Equal(nginxNameTargets, routeNameTargets) {
			t.Errorf("%s: nginx routes the names\n%v\nthe table\n%v", block, nginxNameTargets, routeNameTargets)
		}

		rateLimit := routeInterface.RateLimit
		if got := zoneRequestsPerMinute(config, "standardlimit"); got != rateLimit.RequestsPerMinute {
			t.Errorf("%s: nginx's shared rate is %v/min, the table's %v", block, got, rateLimit.RequestsPerMinute)
		}
		if got := zoneBurst(config, "standardlimit"); got != rateLimit.Burst {
			t.Errorf("%s: nginx's shared burst is %d, the table's %d", block, got, rateLimit.Burst)
		}
		nginxNetConnections := 0
		if match := netConnectionsRegex.FindStringSubmatch(config); match != nil {
			nginxNetConnections = atoi(match[1])
		}
		if nginxNetConnections != rateLimit.NetConnections {
			t.Errorf("%s: nginx's connection cap is %d, the table's %d", block, nginxNetConnections, rateLimit.NetConnections)
		}
		excludeMatch := excludeRegex.FindStringSubmatch(config)
		if excludeMatch == nil {
			t.Errorf("%s: nginx has no excluded subnets map", block)
		} else {
			nginxExcludeSubnets := []string{}
			for _, match := range excludeSubnetRegex.FindAllStringSubmatch(excludeMatch[1], -1) {
				nginxExcludeSubnets = append(nginxExcludeSubnets, match[1])
			}
			slices.Sort(nginxExcludeSubnets)
			if !slices.Equal(nginxExcludeSubnets, rateLimit.ExcludeSubnets) {
				t.Errorf("%s: nginx excludes %v, the table %v", block, nginxExcludeSubnets, rateLimit.ExcludeSubnets)
			}
		}

		nginxRouteZones := map[string]bool{}
		for _, match := range routeZoneRegex.FindAllStringSubmatch(config, -1) {
			nginxRouteZones[match[1]] = true
		}
		routeZones := map[string]bool{}
		for _, service := range table.Services {
			for _, routeRateLimit := range service.RouteRateLimits {
				zone := services.RouteRateLimitZoneName(service.Name, routeRateLimit.Path)
				routeZones[zone] = true
				if got := zoneRequestsPerMinute(config, zone); got != routeRateLimit.RequestsPerMinute {
					t.Errorf("%s: nginx's %s rate is %v/min, the table's %v", block, zone, got, routeRateLimit.RequestsPerMinute)
				}
				if got := zoneBurst(config, zone); got != routeRateLimit.Burst {
					t.Errorf("%s: nginx's %s burst is %d, the table's %d", block, zone, got, routeRateLimit.Burst)
				}
			}
		}
		if !maps.Equal(nginxRouteZones, routeZones) {
			t.Errorf("%s: nginx's route zones are %v, the table's %v", block, nginxRouteZones, routeZones)
		}

		upstreamServerRegex := regexp.MustCompile(`server ` + regexp.QuoteMeta(table.Upstream.Host) + `:(\d+) weight=(\d+) max_fails=0 max_conns=32768;`)
		for _, service := range table.Services {
			upstreams := nginxBlocks(config, "upstream service-block-"+service.Name)
			if len(service.Blocks) == 0 {
				if len(upstreams) != 0 {
					t.Errorf("%s: nginx has an upstream for %s, which the table gives no blocks", block, service.Name)
				}
				continue
			}
			if len(upstreams) != 1 {
				t.Errorf("%s: nginx has %d upstreams for %s, want 1", block, len(upstreams), service.Name)
				continue
			}
			upstream := upstreams[0]
			nginxServers := []string{}
			for _, match := range upstreamServerRegex.FindAllStringSubmatch(upstream, -1) {
				nginxServers = append(nginxServers, fmt.Sprintf("port %s weight %s", match[1], match[2]))
			}
			routeServers := []string{}
			for _, routeBlock := range service.Blocks {
				routeServers = append(routeServers, fmt.Sprintf("port %d weight %d", routeBlock.Port, routeBlock.Weight))
			}
			slices.Sort(nginxServers)
			slices.Sort(routeServers)
			if !slices.Equal(nginxServers, routeServers) {
				t.Errorf("%s: nginx's %s servers are %v, the table's %v", block, service.Name, nginxServers, routeServers)
			}
			if nginxStateful := strings.Contains(upstream, "hash $remote_addr consistent;"); nginxStateful != service.Stateful {
				t.Errorf("%s: nginx hashes %s %v, the table says stateful %v", block, service.Name, nginxStateful, service.Stateful)
			}

			nginxKeepalive := LbAltRouteKeepalive{
				Connections:    0,
				Requests:       0,
				TimeSeconds:    0,
				TimeoutSeconds: 0,
			}
			if match := keepaliveRegex.FindStringSubmatch(upstream); match != nil {
				nginxKeepalive.Connections = atoi(match[1])
				nginxKeepalive.Requests = atoi(keepaliveRequestsRegex.FindStringSubmatch(upstream)[1])
				timeSeconds, err := parseNginxTimeSeconds(keepaliveTimeRegex.FindStringSubmatch(upstream)[1])
				if err != nil {
					t.Fatal(err)
				}
				nginxKeepalive.TimeSeconds = timeSeconds
				timeoutSeconds, err := parseNginxTimeSeconds(keepaliveTimeoutRegex.FindStringSubmatch(upstream)[1])
				if err != nil {
					t.Fatal(err)
				}
				nginxKeepalive.TimeoutSeconds = timeoutSeconds
			}
			if nginxKeepalive != service.Keepalive {
				t.Errorf("%s: nginx's %s keepalive is %+v, the table's %+v", block, service.Name, nginxKeepalive, service.Keepalive)
			}
		}
	}
	if checkedInterfaceCount == 0 {
		t.Error("nginx has a config for none of the table's interfaces")
	}
}

// The route file and the lb config of each interface come from the same
// inputs and functions, so they agree: on the shared example, and on a
// variant whose rates are per second, whose second interface has a limit of
// its own, and whose keepalives come from the interfaces, a service and the
// zero that means none.
func TestLbAltRouteMatchesTheNginxConfig(t *testing.T) {
	cases := []struct {
		name         string
		servicesYaml []byte
	}{
		{
			name:         "the shared example",
			servicesYaml: lbAltRouteServicesYaml(t),
		},
		{
			name: "per-second rates and resolved keepalives",
			servicesYaml: lbAltRouteServicesYaml(
				t,
				"                eth2:\n                    docker_network: warpeth2\n                    rate_limit: *default_rate_limit\n",
				"                eth2:\n                    docker_network: warpeth2\n                    rate_limit:\n                        requests_per_second: 8\n                        burst: 4\n                    keepalive:\n                        keepalive: 64\n                        keepalive_requests: 512\n                        keepalive_time: 2m\n                        keepalive_timeout: 30s\n",
				"                    lb_alt: true\n",
				"                    lb_alt: true\n                    keepalive:\n                        keepalive: 64\n                        keepalive_requests: 512\n                        keepalive_time: 2m\n                        keepalive_timeout: 30s\n",
				"                    requests_per_minute: 12000\n",
				"                    requests_per_second: 250\n",
				"            stateful: true\n",
				"            stateful: true\n            keepalive:\n                keepalive: 16\n                keepalive_requests: 100\n                keepalive_time: 1h30m\n                keepalive_timeout: 75s\n",
				"            websocket: true\n",
				"            websocket: true\n            keepalive:\n                keepalive: 0\n",
			),
		},
	}
	for _, c := range cases {
		table, env, err := renderLbAltRouteFixture(t, c.servicesYaml, nil)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		checkLbAltRouteNginxParity(t, table, env)
	}
}

// A service's routing settings reach the table as nginx applies them, here
// in a variant with top-level hidden_prefixes and the api's own, the api's
// streamable_paths, mcp's lb_exposed: false, an api expose alias that
// repeats an env-derived name, and the api's redirect alias listed twice:
//   - a service's route prefixes are the top-level hidden prefixes and its
//     own, each behind "/", sorted, while the lb's stay lb_hidden_prefixes';
//   - its streamable paths are its own, sorted and without repeats;
//   - lb_exposed: false is kept, so the front opens no hidden by/service or
//     by/b route to the service;
//   - a name or redirect alias listed twice is served once.
func TestLbAltRouteRendersServiceRouteSettings(t *testing.T) {
	servicesYaml := lbAltRouteServicesYaml(
		t,
		"lb_hidden_prefixes:\n    - hidden-example\n",
		"lb_hidden_prefixes:\n    - hidden-example\n\nhidden_prefixes:\n    - top-b\n    - top-a\n",
		"            cors_origins:\n                - https://app.service.example\n",
		""+
			"            hidden_prefixes:\n"+
			"                - svc-x\n"+
			"            streamable_paths:\n"+
			"                - /upload/stream/[0-9]+\n"+
			"                - /upload/bulk\n"+
			"                - /upload/bulk\n"+
			"            cors_origins:\n"+
			"                - https://app.service.example\n",
		"                - api.service.example\n                - old-api.service.example\n",
		""+
			"                - api.service.example\n"+
			"                - old-api.service.example\n"+
			"                - test-api.service.example\n"+
			"                - old-api.service.example\n",
		"            cors_origins_from: api\n",
		"            cors_origins_from: api\n            lb_exposed: false\n",
	)
	table, env, err := renderLbAltRouteFixture(t, servicesYaml, nil)
	if err != nil {
		t.Fatal(err)
	}

	serviceRoutePrefixes := map[string][]string{
		"api":     {"/svc-x", "/top-a", "/top-b"},
		"connect": {"/top-a", "/top-b"},
		"mcp":     {"/top-a", "/top-b"},
	}
	for name, wantRoutePrefixes := range serviceRoutePrefixes {
		if got := lbAltRouteTableService(t, table, name).RoutePrefixes; !slices.Equal(got, wantRoutePrefixes) {
			t.Errorf("%s route prefixes = %v, want %v", name, got, wantRoutePrefixes)
		}
	}
	if got, want := table.Lb.RoutePrefixes, []string{"/hidden-example"}; !slices.Equal(got, want) {
		t.Errorf("lb route prefixes = %v, want lb_hidden_prefixes' %v", got, want)
	}

	api := lbAltRouteTableService(t, table, "api")
	if want := []string{"/upload/bulk", "/upload/stream/[0-9]+"}; !slices.Equal(api.StreamablePaths, want) {
		t.Errorf("api streamable paths = %v, want %v", api.StreamablePaths, want)
	}
	if mcp := lbAltRouteTableService(t, table, "mcp"); mcp.LbExposed || !api.LbExposed {
		t.Errorf("lb exposed: mcp %v and api %v, want false and true", mcp.LbExposed, api.LbExposed)
	}
	wantNames := []string{"api.service.example", "test-api.other.example", "test-api.service.example"}
	if !slices.Equal(api.Names, wantNames) {
		t.Errorf("api names = %v, want %v", api.Names, wantNames)
	}
	wantRedirectAliases := []LbAltRouteRedirectAlias{
		{Name: "old-api.service.example", Target: "api.service.example"},
	}
	if !slices.Equal(api.RedirectAliases, wantRedirectAliases) {
		t.Errorf("api redirect aliases = %+v, want %+v", api.RedirectAliases, wantRedirectAliases)
	}

	checkLbAltRouteNginxParity(t, table, env)
}

// nginx writes no upstream for a fronted service without service port 80,
// such as a port-less sidecar shaped like the injected config-updater, and
// so no keepalive. The table gives it no blocks and the zero keepalive, so
// the render does not refuse it when the host's interfaces resolve different
// keepalives, as they may for a service nginx gives none.
func TestLbAltRouteGivesAServiceWithoutAnUpstreamNoKeepalive(t *testing.T) {
	serviceKeepalive := "" +
		"            keepalive:\n" +
		"                keepalive: 16\n" +
		"                keepalive_requests: 100\n" +
		"                keepalive_time: 1h30m\n" +
		"                keepalive_timeout: 75s\n"
	servicesYaml := lbAltRouteServicesYaml(
		t,
		// only eth1 sets a keepalive, so eth2's lb resolves DefaultKeepalive
		"                    lb_alt: true\n",
		""+
			"                    lb_alt: true\n"+
			"                    keepalive:\n"+
			"                        keepalive: 64\n"+
			"                        keepalive_requests: 512\n"+
			"                        keepalive_time: 2m\n"+
			"                        keepalive_timeout: 30s\n",
		"            - mcp\n            - connect\n            - api\n",
		"            - mcp\n            - connect\n            - api\n            - sidecar\n",
		"        web:\n            expose_aliases:\n",
		""+
			"        sidecar:\n"+
			"            exposed: false\n"+
			"            lb_exposed: false\n"+
			"            blocks:\n"+
			"                - main: 1\n"+
			"        web:\n            expose_aliases:\n",
		// the services with an upstream set their own
		"            route_request_bodies:\n",
		serviceKeepalive+"            route_request_bodies:\n",
		"            stateful: true\n",
		"            stateful: true\n"+serviceKeepalive,
		"            websocket: true\n",
		"            websocket: true\n"+serviceKeepalive,
	)
	table, env, err := renderLbAltRouteFixture(t, servicesYaml, nil)
	if err != nil {
		t.Fatal(err)
	}
	sidecar := lbAltRouteTableService(t, table, "sidecar")
	wantKeepalive := LbAltRouteKeepalive{
		Connections:    0,
		Requests:       0,
		TimeSeconds:    0,
		TimeoutSeconds: 0,
	}
	if len(sidecar.Blocks) != 0 || sidecar.Keepalive != wantKeepalive {
		t.Errorf("sidecar blocks %+v and keepalive %+v, want none and the zero keepalive", sidecar.Blocks, sidecar.Keepalive)
	}
	for _, name := range []string{"api", "connect", "mcp"} {
		if got := lbAltRouteTableService(t, table, name).Keepalive.Connections; got != 16 {
			t.Errorf("%s keepalive connections = %d, want its own 16", name, got)
		}
	}

	checkLbAltRouteNginxParity(t, table, env)
}

// nginx sets no burst for a burst that is not positive, and no connection
// cap for a cap that is not positive (addRateLimits), so an interface whose
// rate_limit sets either below 1 renders it as 0, none, rather than failing
// the render on a config nginx runs: here eth1 with a per-second rate and
// eth2 with a per-minute one. Excluded subnets are written as nginx's geo
// writes them, in canonical form, sorted.
func TestLbAltRouteTakesANonPositiveBurstOrConnectionCapAsNone(t *testing.T) {
	servicesYaml := lbAltRouteServicesYaml(
		t,
		"                    lb_alt: true\n                    rate_limit: *default_rate_limit\n",
		""+
			"                    lb_alt: true\n"+
			"                    rate_limit:\n"+
			"                        requests_per_second: 5\n"+
			"                        burst: -1\n",
		"                eth2:\n                    docker_network: warpeth2\n                    rate_limit: *default_rate_limit\n",
		""+
			"                eth2:\n"+
			"                    docker_network: warpeth2\n"+
			"                    rate_limit:\n"+
			"                        requests_per_minute: 300\n"+
			"                        burst: -1\n"+
			"                        net_connections: -1\n"+
			"                        exclude_subnets:\n"+
			"                            - \"2001:DB8:0::/48\"\n"+
			"                            - \"198.51.100.0/24\"\n",
	)
	table, env, err := renderLbAltRouteFixture(t, servicesYaml, nil)
	if err != nil {
		t.Fatal(err)
	}
	interfaceNameRateLimits := map[string]LbAltRouteRateLimit{
		"eth1": {
			RequestsPerMinute: 300,
			Burst:             0,
			NetConnections:    0,
			ExcludeSubnets:    []string{},
		},
		"eth2": {
			RequestsPerMinute: 300,
			Burst:             0,
			NetConnections:    0,
			ExcludeSubnets:    []string{"198.51.100.0/24", "2001:db8::/48"},
		},
	}
	for interfaceName, wantRateLimit := range interfaceNameRateLimits {
		gotRateLimit := lbAltRouteTableInterface(t, table, interfaceName).RateLimit
		if gotRateLimit.RequestsPerMinute != wantRateLimit.RequestsPerMinute || gotRateLimit.Burst != wantRateLimit.Burst || gotRateLimit.NetConnections != wantRateLimit.NetConnections || !slices.Equal(gotRateLimit.ExcludeSubnets, wantRateLimit.ExcludeSubnets) {
			t.Errorf("%s rate limit = %+v, want %+v", interfaceName, gotRateLimit, wantRateLimit)
		}
	}

	checkLbAltRouteNginxParity(t, table, env)
}

// A render reads only its inputs: the block ports come from the services
// config it is given, with no second read of the vault, which may change
// under a running worker, and no log line, since every connect generation
// start renders.
func TestLbAltRouteReadsNoVaultAndLogsNothing(t *testing.T) {
	env := setupTestVault(t, lbAltRouteServicesYaml(t))
	inputs := lbAltRouteExampleInputs(env)
	errOutput := captureErrOutput(t)
	table, err := renderLbAltRouteTable(inputs)
	if err != nil {
		t.Fatal(err)
	}
	if errOutput.Len() != 0 {
		t.Fatalf("a render logged:\n%s", errOutput.String())
	}

	if err := os.Remove(filepath.Join(os.Getenv("WARP_HOME"), "vault", env, "services.yml")); err != nil {
		t.Fatal(err)
	}
	vaultlessTable, err := renderLbAltRouteTable(inputs)
	if err != nil {
		t.Fatalf("a render with no vault: %v", err)
	}
	if !reflect.DeepEqual(vaultlessTable, table) {
		t.Fatalf("a render with no vault differs:\n%+v\nwant\n%+v", vaultlessTable, table)
	}
}

// A render leaves its inputs as they were, so a worker may share its
// services config with another goroutine while it renders. The fixture's
// host_services list for the host is out of order, which the nginx
// generator's services list would sort in place, and its lb's udp stream port
// services are the lb's alone, which the port allocation would merge into
// each interface's.
func TestLbAltRouteLeavesItsInputsUnchanged(t *testing.T) {
	env := setupTestVault(t, lbAltRouteServicesYaml(t))
	inputs := lbAltRouteExampleInputs(env)
	if hostServices := inputs.servicesConfig.Versions[0].HostServices[lbAltRouteExampleHost]; slices.IsSorted(hostServices) {
		t.Fatalf("the fixture's host_services %v are sorted, which would hide a sort in place", hostServices)
	}
	if _, err := renderLbAltRouteTable(inputs); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(inputs, lbAltRouteExampleInputs(env)) {
		t.Errorf("the render changed its inputs; the host's host_services are now %v", inputs.servicesConfig.Versions[0].HostServices[lbAltRouteExampleHost])
	}
}

// A requests_per_second rate is the same limit per minute, 60 times the
// number, for an interface's shared zone and for a route's own zone, and a
// requests_per_minute rate set beside it wins, as it does in nginx's zone.
func TestLbAltRouteConvertsRequestsPerSecond(t *testing.T) {
	servicesYaml := lbAltRouteServicesYaml(
		t,
		"    requests_per_minute: 450\n",
		"    requests_per_minute: 450\n    requests_per_second: 99\n",
		"                eth2:\n                    docker_network: warpeth2\n                    rate_limit: *default_rate_limit\n",
		"                eth2:\n                    docker_network: warpeth2\n                    rate_limit:\n                        requests_per_second: 8\n                        burst: 4\n",
		"                    requests_per_minute: 12000\n                    burst: 6000\n",
		"                    requests_per_second: 250\n                    burst: 100\n",
	)
	table, _, err := renderLbAltRouteFixture(t, servicesYaml, nil)
	if err != nil {
		t.Fatal(err)
	}

	eth1RateLimit := lbAltRouteTableInterface(t, table, "eth1").RateLimit
	if eth1RateLimit.RequestsPerMinute != 450 || eth1RateLimit.Burst != 150 {
		t.Errorf("eth1 rate = %v/min burst %d, want requests_per_minute's 450/min burst 150", eth1RateLimit.RequestsPerMinute, eth1RateLimit.Burst)
	}
	eth2RateLimit := lbAltRouteTableInterface(t, table, "eth2").RateLimit
	if eth2RateLimit.RequestsPerMinute != 480 || eth2RateLimit.Burst != 4 {
		t.Errorf("eth2 rate = %v/min burst %d, want 8/s as 480/min burst 4", eth2RateLimit.RequestsPerMinute, eth2RateLimit.Burst)
	}
	routeRateLimits := lbAltRouteTableService(t, table, "api").RouteRateLimits
	if len(routeRateLimits) != 1 {
		t.Fatalf("api route rate limits = %+v, want one", routeRateLimits)
	}
	if routeRateLimits[0].RequestsPerMinute != 15000 || routeRateLimits[0].Burst != 100 {
		t.Errorf("/connect/control rate = %v/min burst %d, want 250/s as 15000/min burst 100", routeRateLimits[0].RequestsPerMinute, routeRateLimits[0].Burst)
	}
}

// Every value the route file carries is resolved, so connect applies no
// services.yml default: an interface without a rate_limit gets
// DefaultRateLimit, a route body value left unset gets the server-wide one, a
// service without a keepalive (nor its interfaces) gets DefaultKeepalive, an
// unset status is "standard", and a set one is written raw.
func TestLbAltRouteResolvesDefaults(t *testing.T) {
	servicesYaml := lbAltRouteServicesYaml(
		t,
		"                eth2:\n                    docker_network: warpeth2\n                    rate_limit: *default_rate_limit\n",
		"                eth2:\n                    docker_network: warpeth2\n",
		"                -   path: /upload/artifact\n                    client_body_timeout: 60s\n",
		"                -   path: /upload/artifact\n                    client_body_timeout: 60s\n                -   path: /upload/big\n                    client_body_buffer_size: 128kib\n",
		"            stateful: true\n",
		"            stateful: true\n            status: no\n",
	)
	table, _, err := renderLbAltRouteFixture(t, servicesYaml, nil)
	if err != nil {
		t.Fatal(err)
	}

	defaultRateLimit := services.DefaultRateLimit()
	wantRateLimit := LbAltRouteRateLimit{
		RequestsPerMinute: float64(defaultRateLimit.RequestsPerMinute),
		Burst:             defaultRateLimit.Burst,
		NetConnections:    defaultRateLimit.NetConnections,
		ExcludeSubnets:    []string{},
	}
	if wantRateLimit.RequestsPerMinute <= 0 || wantRateLimit.Burst <= 0 {
		t.Fatalf("DefaultRateLimit %+v has no rate to resolve", defaultRateLimit)
	}
	gotRateLimit := lbAltRouteTableInterface(t, table, "eth2").RateLimit
	if gotRateLimit.RequestsPerMinute != wantRateLimit.RequestsPerMinute || gotRateLimit.Burst != wantRateLimit.Burst || gotRateLimit.NetConnections != wantRateLimit.NetConnections || !slices.Equal(gotRateLimit.ExcludeSubnets, wantRateLimit.ExcludeSubnets) {
		t.Errorf("eth2 rate limit = %+v, want DefaultRateLimit's %+v", gotRateLimit, wantRateLimit)
	}

	requestBodySettings := services.DefaultRequestBodySettings()
	wantRouteRequestBodies := []LbAltRoutePathRequestBody{
		{
			Path:                     "/upload/artifact",
			ClientBodyBufferSize:     requestBodySettings.ClientBodyBufferSize,
			ClientBodyTimeoutSeconds: 60,
		},
		{
			Path:                     "/upload/big",
			ClientBodyBufferSize:     128 * 1024,
			ClientBodyTimeoutSeconds: int(requestBodySettings.ClientBodyTimeout.Seconds()),
		},
	}
	if gotRouteRequestBodies := lbAltRouteTableService(t, table, "api").RouteRequestBodies; !slices.Equal(gotRouteRequestBodies, wantRouteRequestBodies) {
		t.Errorf("api route request bodies = %+v, want %+v", gotRouteRequestBodies, wantRouteRequestBodies)
	}

	defaultKeepalive := services.DefaultKeepalive()
	defaultTimeSeconds, err := parseNginxTimeSeconds(defaultKeepalive.KeepaliveTime)
	if err != nil {
		t.Fatal(err)
	}
	defaultTimeoutSeconds, err := parseNginxTimeSeconds(defaultKeepalive.KeepaliveTimeout)
	if err != nil {
		t.Fatal(err)
	}
	wantKeepalive := LbAltRouteKeepalive{
		Connections:    defaultKeepalive.Keepalive,
		Requests:       defaultKeepalive.KeepaliveRequests,
		TimeSeconds:    defaultTimeSeconds,
		TimeoutSeconds: defaultTimeoutSeconds,
	}
	for _, service := range table.Services {
		if service.Keepalive != wantKeepalive {
			t.Errorf("%s keepalive = %+v, want DefaultKeepalive's %+v", service.Name, service.Keepalive, wantKeepalive)
		}
	}

	if got := lbAltRouteTableService(t, table, "api").Status; got != "standard" {
		t.Errorf("api status = %q, want the default, standard", got)
	}
	if got := lbAltRouteTableService(t, table, "mcp").Status; got != "no" {
		t.Errorf("mcp status = %q, want its own, no", got)
	}
}

// nginx resolves an upstream's keepalive per interface: the service's own,
// else the interface's, else DefaultKeepalive, with connections 0 for none.
// The table holds one per service, so a service that leaves it to interfaces
// that disagree is refused rather than given one of theirs.
func TestLbAltRouteResolvesKeepalive(t *testing.T) {
	interfaceKeepalive := "" +
		"                    keepalive:\n" +
		"                        keepalive: 64\n" +
		"                        keepalive_requests: 512\n" +
		"                        keepalive_time: 2m\n" +
		"                        keepalive_timeout: 30s\n"
	serviceKeepalives := []string{
		"            stateful: true\n",
		"            stateful: true\n            keepalive:\n                keepalive: 16\n                keepalive_requests: 100\n                keepalive_time: 1h30m\n                keepalive_timeout: 75s\n",
		"            websocket: true\n",
		"            websocket: true\n            keepalive:\n                keepalive: 0\n",
	}
	servicesYaml := lbAltRouteServicesYaml(t, append([]string{
		"                    lb_alt: true\n",
		"                    lb_alt: true\n" + interfaceKeepalive,
		"                    docker_network: warpeth2\n",
		"                    docker_network: warpeth2\n" + interfaceKeepalive,
	}, serviceKeepalives...)...)
	table, _, err := renderLbAltRouteFixture(t, servicesYaml, nil)
	if err != nil {
		t.Fatal(err)
	}
	wantKeepalives := map[string]LbAltRouteKeepalive{
		"api":     {Connections: 64, Requests: 512, TimeSeconds: 120, TimeoutSeconds: 30},
		"connect": {Connections: 0, Requests: 0, TimeSeconds: 0, TimeoutSeconds: 0},
		"mcp":     {Connections: 16, Requests: 100, TimeSeconds: 5400, TimeoutSeconds: 75},
	}
	for name, wantKeepalive := range wantKeepalives {
		if got := lbAltRouteTableService(t, table, name).Keepalive; got != wantKeepalive {
			t.Errorf("%s keepalive = %+v, want %+v", name, got, wantKeepalive)
		}
	}

	// only eth1 sets one, so eth2's lb gives the api DefaultKeepalive: load
	// refuses the config, and the render refuses one that reached it some
	// other way
	eth1OnlyYaml := lbAltRouteServicesYaml(t, append([]string{
		"                    lb_alt: true\n",
		"                    lb_alt: true\n" + interfaceKeepalive,
	}, serviceKeepalives...)...)
	env := setupTestVault(t, eth1OnlyYaml)
	_, err = services.LoadServicesConfigFrom(filepath.Join(os.Getenv("WARP_HOME"), "vault"), env)
	if err == nil || !strings.Contains(err.Error(), `edge-a.example: lb_alt is enabled on edge-a.example, and its lb interfaces eth1 and eth2 give service "api", which sets no keepalive of its own, different keepalives`) {
		t.Errorf("load err = %v, want the api's interfaces' keepalives refused", err)
	}
	_, _, err = renderLbAltRouteFixture(t, servicesYaml, func(inputs *lbAltRouteInputs) {
		inputs.servicesConfig.Latest().Lb.Interfaces[lbAltRouteExampleHost]["eth2"].Keepalive = nil
	})
	if err == nil || !strings.Contains(err.Error(), `service "api" has no keepalive of its own, and lb interfaces eth1 and eth2 of edge-a.example give it different ones`) {
		t.Errorf("err = %v, want the api's interfaces' keepalives refused", err)
	}
}

// A generation without one of its listen ports, its services bridge, or a
// bridge address for every lb interface of the host can't serve, so the
// render fails, and the generation never starts.
func TestLbAltRouteRefusesAMissingPortOrBridge(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(inputs *lbAltRouteInputs)
		want   string
	}{
		{
			name:   "no service port 80",
			mutate: func(inputs *lbAltRouteInputs) { delete(inputs.servicePorts, 80) },
			want:   "WARP_PORTS has no internal port for service port 80",
		},
		{
			name:   "no service port 443",
			mutate: func(inputs *lbAltRouteInputs) { delete(inputs.servicePorts, 443) },
			want:   "WARP_PORTS has no internal port for service port 443",
		},
		{
			name:   "no service port 4053",
			mutate: func(inputs *lbAltRouteInputs) { delete(inputs.servicePorts, 4053) },
			want:   "WARP_PORTS has no internal port for service port 4053",
		},
		{
			name: "an lb interface left out",
			mutate: func(inputs *lbAltRouteInputs) {
				inputs.interfaces = inputs.interfaces[1:]
			},
			want: "the inputs leave out lb interface eth2 of edge-a.example and its bridge",
		},
		{
			name: "an lb interface without an address",
			mutate: func(inputs *lbAltRouteInputs) {
				inputs.interfaces[0].ipv4 = ""
			},
			want: "lb interface eth2 of edge-a.example has no bridge address",
		},
		{
			name: "an interface the host does not have",
			mutate: func(inputs *lbAltRouteInputs) {
				inputs.interfaces = append(inputs.interfaces, lbAltRouteInterfaceInput{name: "eth9", lbAlt: false, ipv4: "198.51.100.9", ipv6: ""})
			},
			want: `"eth9" is not a non-transparent lb interface of edge-a.example`,
		},
		{
			name: "an interface given twice",
			mutate: func(inputs *lbAltRouteInputs) {
				inputs.interfaces = append(inputs.interfaces, inputs.interfaces[0])
			},
			want: `interface "eth2" is given twice`,
		},
		{
			name: "a bridge address of the other family",
			mutate: func(inputs *lbAltRouteInputs) {
				inputs.interfaces[0].ipv4 = "2001:db8:2::1"
			},
			want: `eth2 bridge "2001:db8:2::1" is not an ipv4 address`,
		},
		{
			name: "a bridge address that is the services bridge",
			mutate: func(inputs *lbAltRouteInputs) {
				inputs.interfaces[0].ipv4 = inputs.upstreamIpv4
			},
			want: "interfaces[1].ipv4: must not be the services bridge address",
		},
		{
			name:   "no services bridge",
			mutate: func(inputs *lbAltRouteInputs) { inputs.upstreamIpv4 = "" },
			want:   "the services bridge has no ipv4 address",
		},
		{
			name:   "a services bridge of the other family",
			mutate: func(inputs *lbAltRouteInputs) { inputs.upstreamIpv4 = "2001:db8::1" },
			want:   `the services bridge "2001:db8::1" is not an ipv4 address`,
		},
		{
			name:   "no generation",
			mutate: func(inputs *lbAltRouteInputs) { inputs.generation = "" },
			want:   "generation: must not be empty",
		},
		{
			name:   "no env",
			mutate: func(inputs *lbAltRouteInputs) { inputs.env = "" },
			want:   "lbalt route: no env",
		},
		{
			name: "no lb_alt service",
			mutate: func(inputs *lbAltRouteInputs) {
				inputs.servicesConfig.Versions[0].Services["connect"].LbAlt = nil
			},
			want: "no single service declares lb_alt",
		},
		{
			name:   "no services config",
			mutate: func(inputs *lbAltRouteInputs) { inputs.servicesConfig = nil },
			want:   "no services config",
		},
	}
	servicesYaml := lbAltRouteServicesYaml(t)
	for _, c := range cases {
		table, _, err := renderLbAltRouteFixture(t, servicesYaml, c.mutate)
		if err == nil {
			t.Errorf("%s: rendered %+v", c.name, table)
			continue
		}
		if !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err = %v, want %q", c.name, err, c.want)
		}
	}
}

// A services.yml whose table connect's parser would refuse, or whose lb
// config the nginx generator refuses, fails the render instead of the
// connect start: a name two services serve, a server_name form the route
// file can't hold, an api not fronted on the host, a no_access_log host the
// lb does not serve, and a fronted service the config does not define.
func TestLbAltRouteRefusesWhatNginxOrConnectWouldRefuse(t *testing.T) {
	cases := []struct {
		name         string
		servicesYaml []byte
		want         string
	}{
		{
			name: "a no_access_log host the lb does not serve",
			servicesYaml: lbAltRouteServicesYaml(
				t,
				"no_access_log:\n    - quiet.service.example\n",
				"no_access_log:\n    - quiet.service.example\n    - unserved.service.example\n",
			),
			want: "no_access_log names unserved.service.example, which the lb does not serve",
		},
		{
			name: "a fronted service the config does not define",
			servicesYaml: lbAltRouteServicesYaml(
				t,
				"            - mcp\n            - connect\n            - api\n",
				"            - mcp\n            - connect\n            - api\n            - ghost\n",
			),
			want: `edge-a.example fronts service "ghost", which the services config does not define`,
		},
		{
			name: "a name two services serve",
			servicesYaml: lbAltRouteServicesYaml(
				t,
				"                - mcp.service.example\n",
				"                - mcp.service.example\n                - api.service.example\n",
			),
			want: "services[2].names[0]: duplicates services[0].names[0]",
		},
		{
			name: "a trailing wildcard",
			servicesYaml: lbAltRouteServicesYaml(
				t,
				"                - connect.service.example\n",
				"                - connect.service.example\n                - \"connect.*\"\n",
			),
			want: `must be dot-separated labels of lowercase letters, digits, '-' and '_' (got "connect.*")`,
		},
		{
			name: "no api on the host",
			servicesYaml: lbAltRouteServicesYaml(
				t,
				"            - mcp\n            - connect\n            - api\n",
				"            - mcp\n            - connect\n",
			),
			want: `front.api_service: must name a service in services (got "api")`,
		},
	}
	for _, c := range cases {
		table, _, err := renderLbAltRouteFixture(t, c.servicesYaml, nil)
		if err == nil {
			t.Errorf("%s: rendered %+v", c.name, table)
			continue
		}
		if !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err = %v, want %q", c.name, err, c.want)
		}
	}
}

// The checks mirror connect's parser (LBALT-IMPL.md §5): the shared example
// passes, and each change to it that connect refuses is refused, naming the
// field.
func TestValidateLbAltRouteTableRefusesWhatConnectRefuses(t *testing.T) {
	if err := validateLbAltRouteTable(decodeLbAltRouteTable(t, readLbAltRouteExample(t))); err != nil {
		t.Fatalf("the shared example is refused: %v", err)
	}
	cases := []struct {
		name   string
		mutate func(table *LbAltRouteTable)
		want   string
	}{
		{
			name:   "a non-canonical address",
			mutate: func(table *LbAltRouteTable) { table.Interfaces[0].Ipv6 = "2001:db8:1:0::1" },
			want:   "interfaces[0].ipv6: must be written 2001:db8:1::1",
		},
		{
			name:   "two interfaces on one bridge",
			mutate: func(table *LbAltRouteTable) { table.Interfaces[1].Ipv4 = table.Interfaces[0].Ipv4 },
			want:   "interfaces[1].ipv4: duplicates interfaces[0].ipv4",
		},
		{
			name:   "a name in uppercase",
			mutate: func(table *LbAltRouteTable) { table.Services[0].Names[0] = "API.service.example" },
			want:   "services[0].names[0]: must be dot-separated labels",
		},
		{
			name:   "a wildcard lb name",
			mutate: func(table *LbAltRouteTable) { table.Lb.Names[1] = "*.other.example" },
			want:   "lb.names[1]: must be an exact name, not a wildcard",
		},
		{
			name:   "a redirect alias that is also a name",
			mutate: func(table *LbAltRouteTable) { table.Services[0].RedirectAliases[0].Name = "api.service.example" },
			want:   "services[0].redirect_aliases[0].name: duplicates services[0].names[0]",
		},
		{
			name:   "two blocks on one port",
			mutate: func(table *LbAltRouteTable) { table.Services[2].Blocks[0].Port = table.Services[0].Blocks[1].Port },
			want:   "services[2].blocks[0].port: duplicates services[0].blocks[1].port",
		},
		{
			name:   "a route zone without a rate",
			mutate: func(table *LbAltRouteTable) { table.Services[0].RouteRateLimits[0].RequestsPerMinute = 0 },
			want:   "services[0].route_rate_limits[0].requests_per_minute: must be positive",
		},
		{
			name:   "a route body without a timeout",
			mutate: func(table *LbAltRouteTable) { table.Services[0].RouteRequestBodies[0].ClientBodyTimeoutSeconds = 0 },
			want:   "services[0].route_request_bodies[0].client_body_timeout_seconds: must be positive",
		},
		{
			name:   "a negative keepalive",
			mutate: func(table *LbAltRouteTable) { table.Services[1].Keepalive.Requests = -1 },
			want:   "services[1].keepalive.requests: must not be negative",
		},
		{
			name:   "a streamable path that does not compile",
			mutate: func(table *LbAltRouteTable) { table.Services[2].StreamablePaths = []string{"/upload/("} },
			want:   "services[2].streamable_paths[0]: must compile as an anchored regular expression",
		},
		{
			name:   "no route prefix",
			mutate: func(table *LbAltRouteTable) { table.Lb.RoutePrefixes = []string{} },
			want:   "lb.route_prefixes: must list at least one prefix",
		},
		{
			name:   "one tcp port for http and https",
			mutate: func(table *LbAltRouteTable) { table.Listen.HttpsPort = table.Listen.HttpPort },
			want:   "listen.https_port: must differ from listen.http_port",
		},
		{
			name:   "one udp port for quic and whodis",
			mutate: func(table *LbAltRouteTable) { table.Listen.WhodisPort = table.Listen.QuicPort },
			want:   "listen.whodis_port: must differ from listen.quic_port",
		},
		{
			name:   "the api as the connect service",
			mutate: func(table *LbAltRouteTable) { table.Front.ConnectService = table.Front.ApiService },
			want:   "front.api_service: must differ from front.connect_service",
		},
		{
			name:   "a whodis tld without its dot",
			mutate: func(table *LbAltRouteTable) { table.Front.WhodisTlds[0] = "whodis.example" },
			want:   `front.whodis_tlds[0]: must end with . (got "whodis.example")`,
		},
		{
			name:   "an identity with a slash",
			mutate: func(table *LbAltRouteTable) { table.Generation = "test/connect" },
			want:   "generation: may hold only letters, digits",
		},
		{
			name:   "a negative rate",
			mutate: func(table *LbAltRouteTable) { table.Interfaces[1].RateLimit.RequestsPerMinute = -1 },
			want:   "interfaces[1].rate_limit.requests_per_minute: must not be negative",
		},
	}
	for _, c := range cases {
		table := decodeLbAltRouteTable(t, readLbAltRouteExample(t))
		c.mutate(table)
		err := validateLbAltRouteTable(table)
		if err == nil {
			t.Errorf("%s: the table passed", c.name)
			continue
		}
		if !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err = %v, want %q", c.name, err, c.want)
		}
	}
}

// The tlds whodis decodes come from the inputs, sorted and without repeats,
// and a generation whose inputs name none gets the one connect's trusted
// listener decodes today.
func TestLbAltRouteWhodisTlds(t *testing.T) {
	cases := []struct {
		name       string
		whodisTlds []string
		want       []string
	}{
		{
			name:       "none named",
			whodisTlds: nil,
			want:       []string{lbAltDefaultWhodisTld},
		},
		{
			name:       "named out of order and twice",
			whodisTlds: []string{"whodis.example.", "alt-whodis.example.", "whodis.example."},
			want:       []string{"alt-whodis.example.", "whodis.example."},
		},
	}
	servicesYaml := lbAltRouteServicesYaml(t)
	for _, c := range cases {
		table, _, err := renderLbAltRouteFixture(t, servicesYaml, func(inputs *lbAltRouteInputs) {
			inputs.whodisTlds = c.whodisTlds
		})
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if !slices.Equal(table.Front.WhodisTlds, c.want) {
			t.Errorf("%s: whodis tlds = %v, want %v", c.name, table.Front.WhodisTlds, c.want)
		}
	}
}

// The route file's keepalive times are nginx's time syntax for keepalive_time
// and keepalive_timeout, read as whole seconds.
func TestLbAltRouteReadsNginxTimesAsSeconds(t *testing.T) {
	cases := []struct {
		value   string
		seconds int
		ok      bool
	}{
		{value: "15m", seconds: 900, ok: true},
		{value: "1m", seconds: 60, ok: true},
		{value: "60", seconds: 60, ok: true},
		{value: "75s", seconds: 75, ok: true},
		{value: "1h30m", seconds: 5400, ok: true},
		{value: "1h 30m", seconds: 5400, ok: true},
		{value: "1d", seconds: 86400, ok: true},
		{value: "1w", seconds: 604800, ok: true},
		{value: "1m30", seconds: 90, ok: true},
		{value: "2000ms", seconds: 2, ok: true},
		{value: "1s500ms", seconds: 0, ok: false},
		{value: "0", seconds: 0, ok: true},
		{value: "", seconds: 0, ok: false},
		{value: "m", seconds: 0, ok: false},
		{value: "1M", seconds: 0, ok: false},
		{value: "1y", seconds: 0, ok: false},
		{value: "1m1h", seconds: 0, ok: false},
		{value: "1m1m", seconds: 0, ok: false},
		{value: "1 m", seconds: 0, ok: false},
		{value: "-1m", seconds: 0, ok: false},
		{value: "1.5m", seconds: 0, ok: false},
		{value: "99999999999999999999", seconds: 0, ok: false},
	}
	for _, c := range cases {
		seconds, err := parseNginxTimeSeconds(c.value)
		if c.ok != (err == nil) || seconds != c.seconds {
			t.Errorf("parseNginxTimeSeconds(%q) = %d, %v; want %d, ok %v", c.value, seconds, err, c.seconds, c.ok)
		}
	}
}

// The route file is the example's exact bytes, at
// <warp home>/lbalt/<container name>/route.json, and the revision is the
// sha256 of those bytes. It is written once: a second write, or a table of
// another generation, is refused and leaves the file as it was. A
// generation's directory that is already there, whatever its mode, is
// refused and left as it was, so the file only lands in a directory the
// write made, with its mode.
func TestLbAltRouteFileIsWrittenOnceWithItsRevision(t *testing.T) {
	warpHome := t.TempDir()
	table := decodeLbAltRouteTable(t, readLbAltRouteExample(t))
	example := readLbAltRouteExample(t)

	hostPath, revision, err := writeLbAltRouteFile(warpHome, lbAltRouteExampleGeneration, table)
	if err != nil {
		t.Fatal(err)
	}
	wantPath := filepath.Join(warpHome, "lbalt", lbAltRouteExampleGeneration, "route.json")
	if hostPath != wantPath {
		t.Errorf("host path = %s, want %s", hostPath, wantPath)
	}
	written, err := os.ReadFile(hostPath)
	if err != nil {
		t.Fatal(err)
	}
	requireLbAltRouteBytes(t, written, example)
	exampleDigest := sha256.Sum256(example)
	if wantRevision := hex.EncodeToString(exampleDigest[:]); revision != wantRevision {
		t.Errorf("revision = %s, want the sha256 of the bytes, %s", revision, wantRevision)
	}

	rewritten := decodeLbAltRouteTable(t, readLbAltRouteExample(t))
	rewritten.Listen.HttpPort = 7081
	if _, _, err := writeLbAltRouteFile(warpHome, lbAltRouteExampleGeneration, rewritten); !errors.Is(err, os.ErrExist) {
		t.Errorf("a second write: err = %v, want the file refused as existing", err)
	}
	otherGeneration := "test-connect-g1-fedcba9876543210"
	if _, _, err := writeLbAltRouteFile(warpHome, otherGeneration, table); err == nil || !strings.Contains(err.Error(), "not of the container") {
		t.Errorf("a table of another generation: err = %v, want a refusal", err)
	}
	if _, err := os.Stat(filepath.Join(warpHome, "lbalt", otherGeneration)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the refused generation's directory exists: %v", err)
	}
	written, err = os.ReadFile(hostPath)
	if err != nil {
		t.Fatal(err)
	}
	requireLbAltRouteBytes(t, written, example)

	existingGeneration := "test-connect-g1-0000000000000000"
	existingDirPath := filepath.Join(warpHome, "lbalt", existingGeneration)
	if err := os.Mkdir(existingDirPath, 0755); err != nil {
		t.Fatal(err)
	}
	existingTable := decodeLbAltRouteTable(t, readLbAltRouteExample(t))
	existingTable.Generation = existingGeneration
	if _, _, err := writeLbAltRouteFile(warpHome, existingGeneration, existingTable); !errors.Is(err, os.ErrExist) {
		t.Errorf("a write into a directory already there: err = %v, want it refused as existing", err)
	}
	if entries, err := os.ReadDir(existingDirPath); err != nil || len(entries) != 0 {
		t.Errorf("the directory already there holds %v (%v), want it as it was", entries, err)
	}
}

// Whatever the umask, the route file is mode 0444, so the container's user
// can read it at the mount, and <warp home>/lbalt and the generation's
// directory are 0700, so no other user of the host reaches the hidden lb
// prefix the file holds. A restrictive umask shows the file's explicit mode,
// and an open one the mode each directory is created with.
func TestLbAltRouteFileModesHoldWhateverTheUmask(t *testing.T) {
	table := decodeLbAltRouteTable(t, readLbAltRouteExample(t))
	for _, umask := range []int{0077, 0} {
		warpHome := t.TempDir()
		previousUmask := syscall.Umask(umask)
		hostPath, _, err := writeLbAltRouteFile(warpHome, lbAltRouteExampleGeneration, table)
		syscall.Umask(previousUmask)
		if err != nil {
			t.Fatalf("umask %#o: %v", umask, err)
		}
		pathModes := map[string]os.FileMode{
			hostPath:                         0444,
			filepath.Dir(hostPath):           0700,
			filepath.Join(warpHome, "lbalt"): 0700,
		}
		for path, wantMode := range pathModes {
			info, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			if mode := info.Mode().Perm(); mode != wantMode {
				t.Errorf("umask %#o: %s mode = %v, want %v", umask, path, mode, wantMode)
			}
		}
	}
}

// A write that fails part way leaves nothing behind: not the partial file,
// which a container would start from, and not the generation's directory,
// which no container removal would take, since the generation never starts.
// The failure reaches the caller, and the generation can then be written
// whole.
func TestLbAltRouteFileWriteFailureLeavesNothing(t *testing.T) {
	warpHome := t.TempDir()
	table := decodeLbAltRouteTable(t, readLbAltRouteExample(t))
	writeFailure := errors.New("test write failure")
	partialWritten := false
	_, _, err := writeLbAltRouteFileWith(warpHome, lbAltRouteExampleGeneration, table, func(routeFile *os.File, data []byte) error {
		partialData := data[:len(data)/2]
		if _, err := routeFile.Write(partialData); err != nil {
			return err
		}
		// the partial file is in place when the write fails
		info, err := os.Stat(routeFile.Name())
		if err != nil {
			return err
		}
		partialWritten = info.Size() == int64(len(partialData))
		return writeFailure
	})
	if !errors.Is(err, writeFailure) {
		t.Fatalf("err = %v, want the write's failure", err)
	}
	if !partialWritten {
		t.Fatal("the failed write left no partial file to remove")
	}
	routeDirPath := filepath.Join(warpHome, "lbalt", lbAltRouteExampleGeneration)
	if _, err := os.Lstat(routeDirPath); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the failed generation's directory is still there: %v", err)
	}

	hostPath, _, err := writeLbAltRouteFile(warpHome, lbAltRouteExampleGeneration, table)
	if err != nil {
		t.Fatal(err)
	}
	written, err := os.ReadFile(hostPath)
	if err != nil {
		t.Fatal(err)
	}
	requireLbAltRouteBytes(t, written, readLbAltRouteExample(t))
}

// A container name is one path element, so a write or removal can't reach
// outside its generation's directory. Removal takes only the named
// generation's directory, and a directory already gone is removed.
func TestLbAltRouteFileRemovalStaysInItsGeneration(t *testing.T) {
	warpHome := t.TempDir()
	table := decodeLbAltRouteTable(t, readLbAltRouteExample(t))
	if _, _, err := writeLbAltRouteFile(warpHome, lbAltRouteExampleGeneration, table); err != nil {
		t.Fatal(err)
	}
	otherGeneration := "test-connect-g2-fedcba9876543210"
	otherTable := decodeLbAltRouteTable(t, readLbAltRouteExample(t))
	otherTable.Generation = otherGeneration
	otherPath, _, err := writeLbAltRouteFile(warpHome, otherGeneration, otherTable)
	if err != nil {
		t.Fatal(err)
	}
	outsidePath := filepath.Join(warpHome, "keep")
	if err := os.WriteFile(outsidePath, []byte("keep\n"), 0644); err != nil {
		t.Fatal(err)
	}

	for _, containerName := range []string{"", ".", "..", "../keep", "a/b", "test connect"} {
		if err := removeLbAltRouteFile(warpHome, containerName); err == nil {
			t.Errorf("removing %q: no refusal", containerName)
		}
		if _, _, err := writeLbAltRouteFile(warpHome, containerName, table); err == nil {
			t.Errorf("writing %q: no refusal", containerName)
		}
	}
	if err := removeLbAltRouteFile("", lbAltRouteExampleGeneration); err == nil {
		t.Error("removing with no warp home: no refusal")
	}

	if err := removeLbAltRouteFile(warpHome, lbAltRouteExampleGeneration); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(warpHome, "lbalt", lbAltRouteExampleGeneration)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the generation's directory is still there: %v", err)
	}
	if err := removeLbAltRouteFile(warpHome, lbAltRouteExampleGeneration); err != nil {
		t.Errorf("removing a directory already gone: %v", err)
	}
	for _, keptPath := range []string{otherPath, outsidePath} {
		if _, err := os.Stat(keptPath); err != nil {
			t.Errorf("%s went with another generation: %v", keptPath, err)
		}
	}
}
