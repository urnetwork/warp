package services

// The sidecar's service blocks in sidecar-blocks/ (DESIGN §19.4; OPS-M2-03, OPS-M5-03, OPS-M7-01, OPS-M9-01), each loaded
// through warp's own loader on the synthetic base fragment_test.go keeps, since nobody here reads the vault's
// file. Every fragment in the directory is applied, so one added later is held to the same rules. A registrar
// or a fill-in- placeholder the owner fills in is filled in first, with a synthetic choice, as the owner would
// before applying.

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"sort"
	"strings"
	"testing"
)

// The names W10 and QD-012 give mmm: recurd.dev's two, which forward to ur.io/recurd, and the page
// Worker's key origin.
var sidecarBlockMmmAliases = []string{"recurd.dev", "www.recurd.dev", "sidecar.ur.io"}

// The origin the page Worker's requests carry (sidecar DESIGN §18.8).
const sidecarBlockKeyOrigin = "https://sidecar.ur.io"

// The registrar these tests fill each placeholder with, for the owner, who gives the real one.
const sidecarBlockFilledRegistrar = "route53"

// The vault file of the push sender's APNs and FCM keys, which taskworker's fragment mounts.
const sidecarBlockWakeVendorsFile = "wake-vendors.yml"

// The synthetic values these tests fill each fill-in- placeholder with, for the owner, who gives the
// production ones: the dns edges as two transparent interfaces on hosts of their own, with documentation
// addresses (RFC 5737, RFC 3849) and no router, so no router config is checked here (OPS-M5-01's fixtures pin
// the router rules), and rpt.bringyour.com's two interfaces, and the two sending hosts, as the base's two lb
// hosts.
var sidecarBlockFilledPlaceholders = map[string]string{
	"fill-in-ns1-host":             "ns1.example.com",
	"fill-in-ns1-interface":        "eth1",
	"fill-in-ns1-router":           `""`,
	"fill-in-ns1-router-port":      `""`,
	"fill-in-ns1-docker-network":   "warpeth1",
	"fill-in-ns1-ipv4":             "192.0.2.53",
	"fill-in-ns1-ipv6":             `"2001:db8::53"`,
	"fill-in-ns2-host":             "ns2.example.com",
	"fill-in-ns2-interface":        "eth1",
	"fill-in-ns2-router":           `""`,
	"fill-in-ns2-router-port":      `""`,
	"fill-in-ns2-docker-network":   "warpeth1",
	"fill-in-ns2-ipv4":             "198.51.100.53",
	"fill-in-ns2-ipv6":             `"2001:db8:1::53"`,
	"fill-in-rpt-host-1":           "edge-0.example.com",
	"fill-in-rpt-host-1-interface": "eth0",
	"fill-in-rpt-host-2":           "edge-1.example.com",
	"fill-in-rpt-host-2-interface": "eth0",
	"fill-in-smtp-host-1":          "edge-0.example.com",
	"fill-in-smtp-host-2":          "edge-1.example.com",
}

// The dns edges' and the report host's synthetic names, as the placeholders fill in.
const (
	sidecarBlockNs1Host  = "ns1.example.com"
	sidecarBlockNs2Host  = "ns2.example.com"
	sidecarBlockRptHost1 = "edge-0.example.com"
	sidecarBlockRptHost2 = "edge-1.example.com"
	// the two sending hosts
	sidecarBlockSmtpHost1 = "edge-0.example.com"
	sidecarBlockSmtpHost2 = "edge-1.example.com"
)

// A placeholder as fragments write one.
var sidecarBlockPlaceholderRegex = regexp.MustCompile(regexp.QuoteMeta(ServicesFragmentPlaceholderPrefix) + `[a-z0-9-]+`)

// mmm.yml's registrar placeholder, outside the versions, which applySidecarBlockFragments fills as the
// registrar check reads it.
const sidecarBlockRegistrarPlaceholder = "fill-in-route53-or-cloudflare"

// Each placeholder in text filled in with its synthetic value. A placeholder these tests do not know fails,
// so a fragment cannot carry one nobody fills.
func fillSidecarBlockPlaceholders(t *testing.T, name string, text []byte) []byte {
	t.Helper()
	return sidecarBlockPlaceholderRegex.ReplaceAllFunc(text, func(placeholder []byte) []byte {
		if string(placeholder) == sidecarBlockRegistrarPlaceholder {
			return placeholder
		}
		value, ok := sidecarBlockFilledPlaceholders[string(placeholder)]
		if !ok {
			t.Fatalf("%s holds the placeholder %s, which these tests do not fill", name, placeholder)
		}
		return []byte(value)
	})
}

// The fragments in sidecar-blocks/, by file name, each placeholder filled in.
func sidecarBlockFragments(t *testing.T) map[string]*ServicesFragment {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join("sidecar-blocks", "*.yml"))
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) == 0 {
		t.Fatal("sidecar-blocks/ holds no fragment")
	}
	sort.Strings(paths)
	fragments := map[string]*ServicesFragment{}
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		fragment, err := ParseServicesFragment(path, fillSidecarBlockPlaceholders(t, path, data))
		if err != nil {
			t.Fatal(err)
		}
		fragments[filepath.Base(path)] = fragment
	}
	return fragments
}

// The base with every fragment applied, each placeholder registrar filled in, as the loader reads it, and
// which services the fragments added.
func applySidecarBlockFragments(t *testing.T) (*ServicesConfig, []string) {
	t.Helper()
	fragments := sidecarBlockFragments(t)
	names := []string{}
	for name := range fragments {
		names = append(names, name)
	}
	sort.Strings(names)
	ordered := []*ServicesFragment{}
	for _, name := range names {
		for index, domain := range fragments[name].domains {
			if !slices.Contains(servicesFragmentRegistrars, domain.registrar) {
				fragments[name].domains[index].registrar = sidecarBlockFilledRegistrar
			}
		}
		ordered = append(ordered, fragments[name])
	}
	result, err := ApplyServicesFragments([]byte(fragmentBaseYaml), "services.yml", ordered...)
	if err != nil {
		t.Fatal(err)
	}
	servicesConfig, err := ParseServicesConfig(result.Text, "services.yml")
	if err != nil {
		t.Fatal(err)
	}
	base, err := ParseServicesConfig([]byte(fragmentBaseYaml), "services.yml")
	if err != nil {
		t.Fatal(err)
	}
	added := []string{}
	for service := range servicesConfig.Versions[0].Services {
		if _, ok := base.Versions[0].Services[service]; !ok {
			added = append(added, service)
		}
	}
	sort.Strings(added)
	return servicesConfig, added
}

// Vault files no block but the issuer may mount: the oauth issuer's signing keys, the session jwt keys,
// grafana.yml, whose push-only replacement every new block mounts (QD-249), and anything named a key.
var sidecarBlockForbiddenSecretRegex = regexp.MustCompile(`^(auth\.yml|jwt\.yml|grafana\.yml)$|signing|private|\.key$|\.pem$`)

// The two private keys a block may mount, each by exactly the services named: the dns edges' current ZSK
// (§12.6), and the platform listener's platform-mail certificate and key (§19.4, mx-4).
var sidecarBlockPrivateKeyServices = map[string][]string{
	"dns-zsk.private":   {"dnsedge-1", "dnsedge-2"},
	"platform-mail.key": {"mxedge-platform"},
	"platform-mail.pem": {"mxedge-platform"},
}

// The services the fragments add (§19.4's rows by milestone): evs and gkm at M2, sockets, dns, the two dns edges,
// tlsedge and mxedge's platform listener at M5, mxedge's router at M7, and smtpedge at M9.
var sidecarBlockAddedServices = []string{"dns", "dnsedge-1", "dnsedge-2", "evs", "gkm", "mxedge", "mxedge-platform", "smtpedge", "sockets", "tlsedge"}

// The outbound mail edge, which runs with no lb front on its two sending hosts.
const sidecarBlockSmtpEdge = SmtpEdgeService

// The host-pinned dns edges, which run with no lb front.
var sidecarBlockDnsEdges = []string{"dnsedge-1", "dnsedge-2"}

// The services §19.4 names on the platform's own domain, each served on <service>.bringyour.com.
var sidecarBlockNamedServices = []string{"dns", "evs", "gkm", "sockets"}

// Each block §19.4 adds: only config mounted, user 65532, the scoped vault home, sorted secrets with its own
// metrics push credential; an lb service with beta 1 and g1 99, GET /status on port 80 and path-only logs, named
// on bringyour.com where §19.4 names it; a dns edge pinned to its one host, unexposed, with one block and warp's
// persistent data volume for its snapshots; smtpedge pinned to its two sending hosts, unexposed, with one g1
// block, and alone given cap_net_admin.
func TestSidecarBlocksFollowTheNewBlockRules(t *testing.T) {
	servicesConfig, added := applySidecarBlockFragments(t)
	if !slices.Equal(added, sidecarBlockAddedServices) {
		t.Errorf("the fragments add %q, want %q", added, sidecarBlockAddedServices)
	}
	for _, service := range added {
		serviceConfig := servicesConfig.Versions[0].Services[service]
		dnsEdge := slices.Contains(sidecarBlockDnsEdges, service)
		wantMount := map[string]string{"vault": "no", "config": "yes", "site": "no"}
		if dnsEdge {
			wantMount["data"] = "yes"
		}
		if !mapsEqualStrings(serviceConfig.Mount, wantMount) {
			t.Errorf("%s mounts %v, want %v", service, serviceConfig.Mount, wantMount)
		}
		if serviceConfig.User != "65532:65532" {
			t.Errorf("%s runs as %q", service, serviceConfig.User)
		}
		if serviceConfig.EnvVars["WARP_VAULT_HOME"] != "/srv/warp/secrets" || len(serviceConfig.EnvVars) != 1 {
			t.Errorf("%s's env_vars are %v", service, serviceConfig.EnvVars)
		}
		if !slices.IsSorted(serviceConfig.SecretFiles) || len(serviceConfig.SecretFiles) == 0 {
			t.Errorf("%s's secret_files are %q", service, serviceConfig.SecretFiles)
		}
		if !slices.Contains(serviceConfig.SecretFiles, "grafana-push-"+service+".yml") {
			t.Errorf("%s does not mount its own metrics push credential", service)
		}
		if serviceConfig.CapNetAdmin != (service == sidecarBlockSmtpEdge) {
			t.Errorf("%s's cap_net_admin is %v: smtpedge alone holds it (plan-OPS-small-readings #14)", service, serviceConfig.CapNetAdmin)
		}
		if service == sidecarBlockSmtpEdge {
			if serviceConfig.IsExposed() || len(serviceConfig.Blocks) != 1 || len(serviceConfig.Blocks[0]) != 1 || serviceConfig.Blocks[0]["g1"] != 1 {
				t.Errorf("smtpedge is not one unexposed g1 block: %+v", serviceConfig)
			}
			if want := []string{sidecarBlockSmtpHost1, sidecarBlockSmtpHost2}; !slices.Equal(serviceConfig.Hosts, want) || !slices.Equal(HostsForService(servicesConfig.Versions[0], service), want) {
				t.Errorf("smtpedge runs on %q, placed on %q, want the two sending hosts %q", serviceConfig.Hosts, HostsForService(servicesConfig.Versions[0], service), want)
			}
			// no lb route, no inbound port: only its status port
			if !slices.Equal(serviceConfig.HttpTcpPorts(), []int{80}) || 0 < len(serviceConfig.StreamTcpPorts()) || 0 < len(serviceConfig.StreamUdpPorts()) || 0 < len(serviceConfig.ExposeAliases) {
				t.Errorf("smtpedge takes ports or names beyond its status port: %+v", serviceConfig)
			}
			for portType, ports := range serviceConfig.AllExternalPorts() {
				if 0 < len(ports) {
					t.Errorf("smtpedge owns public %s ports %v", portType, ports)
				}
			}
			continue
		}
		if dnsEdge {
			if serviceConfig.IsExposed() || len(serviceConfig.Hosts) != 1 || len(serviceConfig.Blocks) != 1 || serviceConfig.Blocks[0]["g1"] != 1 {
				t.Errorf("%s is not one unexposed block on one host: %+v", service, serviceConfig)
			}
			continue
		}
		if !serviceConfig.LogUri {
			t.Errorf("%s logs query strings (W8)", service)
		}
		if len(serviceConfig.Blocks) != 2 || serviceConfig.Blocks[0]["beta"] != 1 || serviceConfig.Blocks[1]["g1"] != 99 {
			t.Errorf("%s's blocks are %v", service, serviceConfig.Blocks)
		}
		if !serviceConfig.IsExposed() || !serviceConfig.IsLbExposed() || !serviceConfig.IsStandardStatus() || !slices.Equal(serviceConfig.HttpTcpPorts(), []int{80}) {
			t.Errorf("%s is not an lb service with GET /status on port 80", service)
		}
		var wantAliases []string
		if slices.Contains(sidecarBlockNamedServices, service) {
			wantAliases = []string{service + ".bringyour.com"}
		}
		if !slices.Equal(serviceConfig.ExposeAliases, wantAliases) {
			t.Errorf("%s is named %q, want %q (§19.4)", service, serviceConfig.ExposeAliases, wantAliases)
		}
		// only the platform listener is pinned, to the report host's two hosts (W4)
		if service == "mxedge-platform" {
			if want := []string{sidecarBlockRptHost1, sidecarBlockRptHost2}; !slices.Equal(serviceConfig.Hosts, want) {
				t.Errorf("mxedge-platform runs on %q, want %q", serviceConfig.Hosts, want)
			}
		} else if len(serviceConfig.Hosts) != 0 {
			t.Errorf("%s pins hosts %q", service, serviceConfig.Hosts)
		}
	}
	// evs and gkm read the file clusters with their own users, and their callers' service tokens
	for _, service := range []string{"evs", "gkm"} {
		for _, required := range []string{"oauth-jwks-svc.json", "redis.yml", "file-clusters-" + service + ".yml"} {
			if !slices.Contains(servicesConfig.Versions[0].Services[service].SecretFiles, required) {
				t.Errorf("%s does not mount %s", service, required)
			}
		}
	}
}

// No fragment mounts a signing key or grafana.yml on any block (D-OPS-1), new or extended.
func TestNoSidecarBlockFragmentNamesASigningKey(t *testing.T) {
	for name, fragment := range sidecarBlockFragments(t) {
		text, err := encodeServicesFragmentNode(fragment.version)
		if err != nil {
			t.Fatal(err)
		}
		var version ServicesConfigVersion
		if err := fragment.version.Decode(&version); err != nil {
			t.Fatal(err)
		}
		for service, serviceConfig := range version.Services {
			for _, secretFile := range serviceConfig.SecretFiles {
				if slices.Contains(sidecarBlockPrivateKeyServices[secretFile], service) {
					continue
				}
				if sidecarBlockForbiddenSecretRegex.MatchString(secretFile) {
					t.Errorf("%s gives %s the secret %s", name, service, secretFile)
				}
			}
		}
		if strings.Contains(string(text), "vault: yes") {
			t.Errorf("%s mounts a whole vault", name)
		}
	}
}

// The ZSK reaches the dns edges alone (§12.6) and the platform-mail key the platform listener alone (§19.4,
// mx-4): no other block in the merged file mounts either, the router included.
func TestOnlyTheirOwnBlocksMountTheZskAndThePlatformMailKey(t *testing.T) {
	servicesConfig, _ := applySidecarBlockFragments(t)
	for secretFile, owners := range sidecarBlockPrivateKeyServices {
		mounting := []string{}
		for service, serviceConfig := range servicesConfig.Versions[0].Services {
			if slices.Contains(serviceConfig.SecretFiles, secretFile) {
				mounting = append(mounting, service)
			}
		}
		sort.Strings(mounting)
		if !slices.Equal(mounting, owners) {
			t.Errorf("%s is mounted by %q, want %q alone", secretFile, mounting, owners)
		}
	}
}

// A block mounts a Postgres role only where it reads or writes rows, and at most one: dns and the platform
// listener the platform's pg.yml (§19.7; plan-SMTP-report-intake-home); tlsedge and mxedge's router a restricted
// role in a vault file of their own, pg-<service>.yml, which server's pool reads first (QD-029, QD-992), and so
// smtpedge for smtp_* (§19.4's own credentials); evs, gkm, sockets and the dns edges none (owner decision 2, §9.8,
// I-12).
func TestSidecarBlocksMountPostgresOnlyWhereTheyHoldIt(t *testing.T) {
	servicesConfig, added := applySidecarBlockFragments(t)
	want := map[string]string{
		"dns":             "pg.yml",
		"mxedge-platform": "pg.yml",
		"tlsedge":         "pg-tlsedge.yml",
		"mxedge":          "pg-mxedge.yml",
		"smtpedge":        "pg-smtpedge.yml",
	}
	postgresFile := regexp.MustCompile(`^pg(_maintenance)?(-[a-z0-9-]+)?\.yml$`)
	for _, service := range added {
		held := []string{}
		for _, secretFile := range servicesConfig.Versions[0].Services[service].SecretFiles {
			if postgresFile.MatchString(secretFile) {
				held = append(held, secretFile)
			}
		}
		wantHeld := []string{}
		if file, ok := want[service]; ok {
			wantHeld = append(wantHeld, file)
		}
		if !slices.Equal(held, wantHeld) {
			t.Errorf("%s mounts the Postgres roles %q, want %q", service, held, wantHeld)
		}
	}
}

// sockets' rows (§19.4, W2): its registration and Find each count in a per-address zone of their own, 12,000 a
// minute with a burst of 3,000, and nothing else of the service does; it verifies service tokens of audience sockets
// against its audience's public JWKS, reads rev/ through its own MinIO user, its ticket keys and gate bearer, and
// never auth.yml (QD-1029).
func TestSocketsBlockCarriesItsRows(t *testing.T) {
	servicesConfig, _ := applySidecarBlockFragments(t)
	sockets := servicesConfig.Versions[0].Services["sockets"]
	got := map[string]RouteRateLimit{}
	for _, routeRateLimit := range sockets.RouteRateLimits {
		got[routeRateLimit.Path] = *routeRateLimit
	}
	want := map[string]RouteRateLimit{
		"/socket/registrations": {Path: "/socket/registrations", RequestsPerMinute: 12000, Burst: 3000},
		"/socket/find":          {Path: "/socket/find", RequestsPerMinute: 12000, Burst: 3000},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("sockets' route_rate_limits are %v, want %v", got, want)
	}
	if sockets.ServiceRateLimit != nil {
		t.Errorf("sockets limits the whole service: %+v", sockets.ServiceRateLimit)
	}
	if want := []string{"file-clusters-sockets.yml", "grafana-push-sockets.yml", "internal-gate-sockets.yml", "oauth-jwks-svc.json", "redis.yml", "socket-ticket-keys.yml"}; !slices.Equal(sockets.SecretFiles, want) {
		t.Errorf("sockets mounts %q, want %q", sockets.SecretFiles, want)
	}
}

// tlsedge takes 443 through W1's split, which the fragment leaves to TLS-M5-01's lb.tls_split, and 8443, 8883 and
// 5671 unsplit on every lb interface (W7): the four are its stream ports, the lb gives it the three, and no entry
// claims 443. It holds no TLS key (D-TLS-1).
func TestTlsEdgeBlockTakesItsFourPorts(t *testing.T) {
	servicesConfig, _ := applySidecarBlockFragments(t)
	version := servicesConfig.Versions[0]
	tlsedge := version.Services["tlsedge"]
	if got := tlsedge.StreamTcpPorts(); !slices.Equal(got, TlsEdgePorts) {
		t.Errorf("tlsedge's tcp stream ports are %v, want %v", got, TlsEdgePorts)
	}
	for _, port := range []int{5671, 8443, 8883} {
		if service := version.Lb.TcpStreamPortServices[port]; service != TlsEdgeService {
			t.Errorf("the lb gives tcp %d to %q", port, service)
		}
	}
	if service, ok := version.Lb.TcpStreamPortServices[443]; ok {
		t.Errorf("the lb gives tcp 443 to %q, which the split owns", service)
	}
	if 0 < len(tlsedge.StreamUdpPorts()) {
		t.Errorf("tlsedge takes udp %v", tlsedge.StreamUdpPorts())
	}
	for _, secretFile := range tlsedge.SecretFiles {
		if strings.HasPrefix(secretFile, "tls") || strings.Contains(secretFile, "key") {
			t.Errorf("tlsedge mounts %s", secretFile)
		}
	}
}

// The dns edges (§19.5, D-OPS-15, W9): dnsedge-1 alone on ns1 and dnsedge-2 alone on ns2, each a transparent
// interface where no lb runs, each owning UDP and TCP 53, and no other service placed on either host.
func TestDnsEdgeBlocksRunOneToEachNs(t *testing.T) {
	servicesConfig, added := applySidecarBlockFragments(t)
	version := servicesConfig.Versions[0]
	for service, host := range map[string]string{"dnsedge-1": sidecarBlockNs1Host, "dnsedge-2": sidecarBlockNs2Host} {
		serviceConfig := version.Services[service]
		if !slices.Equal(serviceConfig.Hosts, []string{host}) || !slices.Equal(HostsForService(version, service), []string{host}) {
			t.Errorf("%s runs on %q, placed on %q, want %s alone", service, serviceConfig.Hosts, HostsForService(version, service), host)
		}
		allExternalPorts := serviceConfig.AllExternalPorts()
		if !slices.Equal(allExternalPorts["udp"], []int{53}) || !slices.Equal(allExternalPorts["tcp"], []int{53}) {
			t.Errorf("%s owns %v, want udp and tcp 53", service, allExternalPorts)
		}
		// warp's config-updater brings the edge its dns.yml and sidecar.yml
		if !slices.Equal(version.HostServices[host], []string{"config-updater", service}) {
			t.Errorf("%s runs %q", host, version.HostServices[host])
		}
		lbBlocks := version.Lb.Interfaces[host]
		if len(lbBlocks) != 1 {
			t.Fatalf("%s has interfaces %v", host, lbBlocks)
		}
		for interfaceName, lbBlock := range lbBlocks {
			if !lbBlock.Transparent {
				t.Errorf("%s %s is not transparent, so an lb would front it", host, interfaceName)
			}
			for _, address := range []string{lbBlock.Ipv4, lbBlock.Ipv6} {
				if parsed, err := netip.ParseAddr(address); err != nil || !parsed.IsValid() {
					t.Errorf("%s %s's address %q", host, interfaceName, address)
				}
			}
		}
		if !slices.Contains(serviceConfig.SecretFiles, "internal-"+service+".yml") {
			t.Errorf("%s does not mount its own bearer", service)
		}
		if slices.Contains(serviceConfig.SecretFiles, "redis.yml") {
			t.Errorf("%s mounts redis.yml, and an edge holds no Redis handle (I-12)", service)
		}
	}
	for _, service := range append(slices.Clone(added), "api", "mmm", "taskworker", "web", "app", "mcp") {
		if slices.Contains(sidecarBlockDnsEdges, service) {
			continue
		}
		for _, host := range HostsForService(version, service) {
			if host == sidecarBlockNs1Host || host == sidecarBlockNs2Host {
				t.Errorf("%s is placed on the dns edge %s", service, host)
			}
		}
	}
}

// W4: TCP 25 on the report host's two interfaces reaches the platform listener, which runs only there, and on
// every other lb interface the router (from M7), whose block mounts the platform and edge credentials and never
// the platform-mail key.
func TestMxEdgeRouterAndPlatformListenerSplitTcp25(t *testing.T) {
	servicesConfig, _ := applySidecarBlockFragments(t)
	version := servicesConfig.Versions[0]
	if service := version.Lb.TcpStreamPortServices[25]; service != "mxedge" {
		t.Errorf("the lb gives tcp 25 to %q, want mxedge's router", service)
	}
	rptHosts := []string{sidecarBlockRptHost1, sidecarBlockRptHost2}
	for host, lbBlocks := range version.Lb.Interfaces {
		for interfaceName, lbBlock := range lbBlocks {
			service, overridden := lbBlock.TcpStreamPortServices[25]
			if slices.Contains(rptHosts, host) != (overridden && service == "mxedge-platform") {
				t.Errorf("%s %s gives tcp 25 to %q", host, interfaceName, service)
			}
		}
	}
	if got := HostsForService(version, "mxedge-platform"); !slices.Equal(got, rptHosts) {
		t.Errorf("mxedge-platform is placed on %q, want %q", got, rptHosts)
	}
	for _, service := range []string{"mxedge", "mxedge-platform"} {
		if got := version.Services[service].StreamTcpPorts(); !slices.Equal(got, []int{25}) {
			t.Errorf("%s's tcp stream ports are %v", service, got)
		}
	}
	router := version.Services["mxedge"]
	for _, required := range []string{"internal-gate-edge.yml", "internal-gate-mxedge.yml", "redis.yml"} {
		if !slices.Contains(router.SecretFiles, required) {
			t.Errorf("mxedge's router does not mount %s", required)
		}
	}
}

// smtpedge's row (§19.4, §14.9): the edge bearer its platform client is minted on, its own gate bearer for the
// quota surface, the X-UR-Ref keys, Redis and a Postgres role of its own; no JWKS, since it verifies no token
// itself, no key of any other block, and no TLS key, since TLS runs end to end through it (X7). Nothing in the lb
// names it: no stream port goes to it, and the fragment changes nothing of the lb.
func TestSmtpEdgeBlockCarriesItsRow(t *testing.T) {
	servicesConfig, _ := applySidecarBlockFragments(t)
	version := servicesConfig.Versions[0]
	smtpEdge := version.Services[sidecarBlockSmtpEdge]
	if smtpEdge == nil {
		t.Fatal("no smtpedge block")
	}
	if want := []string{"grafana-push-smtpedge.yml", "internal-gate-edge.yml", "internal-gate-smtpedge.yml", "pg-smtpedge.yml", "redis.yml", "smtpedge-x-ur-ref.yml"}; !slices.Equal(smtpEdge.SecretFiles, want) {
		t.Errorf("smtpedge mounts %q, want %q", smtpEdge.SecretFiles, want)
	}
	for port, service := range version.Lb.TcpStreamPortServices {
		if service == sidecarBlockSmtpEdge {
			t.Errorf("the lb gives tcp %d to smtpedge", port)
		}
	}
	for host, lbBlocks := range version.Lb.Interfaces {
		for interfaceName, lbBlock := range lbBlocks {
			for port, service := range lbBlock.TcpStreamPortServices {
				if service == sidecarBlockSmtpEdge {
					t.Errorf("%s %s gives tcp %d to smtpedge", host, interfaceName, port)
				}
			}
		}
	}
	// the fragment adds the service and nothing else
	fragment := sidecarBlockFragments(t)["smtpedge.yml"]
	if fragment == nil {
		t.Fatal("no smtpedge.yml")
	}
	var fragmentVersion ServicesConfigVersion
	if err := fragment.version.Decode(&fragmentVersion); err != nil {
		t.Fatal(err)
	}
	if fragmentVersion.Lb != nil || len(fragmentVersion.HostServices) != 0 || len(fragmentVersion.Services) != 1 || 0 < len(fragment.domains) || 0 < len(fragment.noFrameOptions) {
		t.Errorf("smtpedge.yml adds more than its service: %+v", fragmentVersion)
	}
	// the capability reaches no other service of the merged file
	for service, serviceConfig := range version.Services {
		if serviceConfig.CapNetAdmin && service != sidecarBlockSmtpEdge {
			t.Errorf("%s holds cap_net_admin in the merged file", service)
		}
	}
}

// A fragment holding a fill-in- placeholder parses, so it is checked here filled in, and applied unfilled it is
// refused with the placeholder's line named, before anything is merged: dnsedge.yml's production hosts and
// addresses, mxedge-platform.yml's report host interfaces and smtpedge.yml's two sending hosts wait for the owner,
// and no other fragment holds one.
func TestFragmentsWithPlaceholdersAreRefusedUnfilled(t *testing.T) {
	paths, err := filepath.Glob(filepath.Join("sidecar-blocks", "*.yml"))
	if err != nil {
		t.Fatal(err)
	}
	holding := []string{}
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		fragment, err := ParseServicesFragment(path, data)
		if err != nil {
			t.Fatalf("%s does not parse unfilled: %v", path, err)
		}
		placeholder := findServicesFragmentPlaceholder(fragment.version)
		if placeholder == nil {
			continue
		}
		holding = append(holding, filepath.Base(path))
		result, err := ApplyServicesFragments([]byte(fragmentBaseYaml), "services.yml", fragment)
		wantMessage := fmt.Sprintf("line %d holds the placeholder %s", placeholder.Line, placeholder.Value)
		if err == nil || result != nil || !strings.Contains(err.Error(), wantMessage) {
			t.Errorf("%s applied unfilled: %v, want %q", path, err, wantMessage)
		}
	}
	sort.Strings(holding)
	if want := []string{"dnsedge.yml", "mxedge-platform.yml", "smtpedge.yml"}; !slices.Equal(holding, want) {
		t.Errorf("the fragments holding placeholders are %q, want %q", holding, want)
	}
}

// evs's rows: its segment PUT streams through the lb and nothing else does (§11.6), and the whole service
// shares W2's per-address limit; gkm's limit names no burst.
func TestEvsAndGkmBlocksCarryTheirRows(t *testing.T) {
	servicesConfig, _ := applySidecarBlockFragments(t)
	evs := servicesConfig.Versions[0].Services["evs"]
	if len(evs.StreamablePaths) != 1 {
		t.Fatalf("evs's streamable_paths are %q", evs.StreamablePaths)
	}
	streamable := regexp.MustCompile("^(?:" + evs.StreamablePaths[0] + ")$")
	for path, want := range map[string]bool{
		"/evs/v1/repos/r1/segments/s1":    true,
		"/evs/v1/repos/r1/segments/s1/x":  false,
		"/evs/v1/repos/r1":                false,
		"/evs/v1/repos/r1/push":           false,
		"/evs/v1/repos/r1/segments/":      false,
		"/x/evs/v1/repos/r1/segments/s1":  false,
		"/evs/v1/repos/r1/r2/segments/s1": false,
	} {
		if streamable.MatchString(path) != want {
			t.Errorf("evs streams %s: %v, want %v", path, !want, want)
		}
	}
	if limit := evs.ServiceRateLimit; limit == nil || limit.RequestsPerMinute != 3000 || limit.Burst != 1000 {
		t.Errorf("evs's service_rate_limit is %+v", limit)
	}
	if !slices.Contains(evs.SecretFiles, "evs-receipt-keys.json") {
		t.Errorf("evs does not mount its receipt keys")
	}
	gkm := servicesConfig.Versions[0].Services["gkm"]
	if limit := gkm.ServiceRateLimit; limit == nil || limit.RequestsPerMinute != 1200 || limit.Burst != 0 {
		t.Errorf("gkm's service_rate_limit is %+v", limit)
	}
	if 0 < len(gkm.StreamablePaths) || gkm.IsStreamable() {
		t.Errorf("gkm streams a request body")
	}
}

// api and taskworker keep what they had and add their file clusters, and taskworker the push sender's vendor keys;
// api's log keeps paths only (W8).
func TestApiAndTaskworkerBlocksAddTheirClusters(t *testing.T) {
	servicesConfig, _ := applySidecarBlockFragments(t)
	base, err := ParseServicesConfig([]byte(fragmentBaseYaml), "services.yml")
	if err != nil {
		t.Fatal(err)
	}
	api := servicesConfig.Versions[0].Services["api"]
	if !slices.Equal(api.SecretFiles, []string{"api-extra.yml", "file-clusters-api.yml"}) || !api.LogUri {
		t.Errorf("api = %+v", api)
	}
	taskworker := servicesConfig.Versions[0].Services["taskworker"]
	if !slices.Equal(taskworker.SecretFiles, []string{"file-clusters-taskworker.yml", sidecarBlockWakeVendorsFile}) || taskworker.LogUri {
		t.Errorf("taskworker = %+v", taskworker)
	}
	for _, service := range []string{"api", "taskworker"} {
		before := base.Versions[0].Services[service]
		after := servicesConfig.Versions[0].Services[service]
		if !mapsEqualStrings(before.Mount, after.Mount) || before.User != after.User || !slices.Equal(before.PortSpecs, after.PortSpecs) {
			t.Errorf("%s's mounts, user or ports changed", service)
		}
	}
}

// The push sender's APNs and FCM keys reach taskworker as the one vault file its sender reads (§19.4's push sender;
// OPS-M8-01, SDK-M8-10), and only taskworker mounts them (D-OPS-1). The name is checked against server's taskworker
// where server sits beside this checkout, so the fragment and the reader cannot drift apart.
func TestTaskworkerBlockMountsThePushSendersKeys(t *testing.T) {
	servicesConfig, _ := applySidecarBlockFragments(t)
	for service, serviceConfig := range servicesConfig.Versions[0].Services {
		if mounted := slices.Contains(serviceConfig.SecretFiles, sidecarBlockWakeVendorsFile); mounted != (service == "taskworker") {
			t.Errorf("%s mounts %s: %v", service, sidecarBlockWakeVendorsFile, mounted)
		}
	}
	sender, err := os.ReadFile(filepath.Join("..", "..", "server", "taskworker", "wake_sender.go"))
	if err != nil {
		t.Skipf("server is not beside this checkout: %v", err)
	}
	name := regexp.MustCompile(`(?m)^const wakeVendorsResourceName = "([^"]+)"$`).FindSubmatch(sender)
	if name == nil {
		t.Fatal("server/taskworker/wake_sender.go names no wakeVendorsResourceName")
	}
	if string(name[1]) != sidecarBlockWakeVendorsFile {
		t.Errorf("taskworker's sender reads %s, the fragment mounts %s", name[1], sidecarBlockWakeVendorsFile)
	}
}

// Every secret file a new block mounts is one xops makes readable to uid 65532, or the block cannot
// read it (plan-OPS-small-readings #4): playbook-edges.yml's edges play lists exactly the lb blocks' files,
// and the dns edges' own list, in group_vars/dns_edges.yml, gives each dns edge exactly its block's files, so
// the ZSK reaches the dns edges and no lb host (§12.6; OPS-M5-04).
func TestEdgesPlaybookRestrictsEveryNewBlockSecret(t *testing.T) {
	ansibleRoot := filepath.Join("..", "..", "xops", "main", "ansible")
	playbook, err := os.ReadFile(filepath.Join(ansibleRoot, "playbook-edges.yml"))
	if err != nil {
		t.Skipf("xops is not beside this checkout: %v", err)
	}
	servicesConfig, added := applySidecarBlockFragments(t)
	want := []string{}
	for _, service := range added {
		if slices.Contains(sidecarBlockDnsEdges, service) {
			continue
		}
		for _, secretFile := range servicesConfig.Versions[0].Services[service].SecretFiles {
			if !slices.Contains(want, secretFile) {
				want = append(want, secretFile)
			}
		}
	}
	sort.Strings(want)
	listed := func(text []byte, pattern string) []string {
		t.Helper()
		list := regexp.MustCompile(pattern).FindSubmatch(text)
		if list == nil {
			t.Fatalf("no list matches %s", pattern)
		}
		items := []string{}
		for _, line := range strings.Split(strings.TrimSpace(string(list[1])), "\n") {
			items = append(items, strings.Trim(strings.TrimPrefix(strings.TrimSpace(line), "- "), `"`))
		}
		return items
	}
	if got := listed(playbook, `(?s)- name: Find the sidecar blocks' scoped secrets\n.*?loop:\n((?:\s+- [^\n]+\n)+)`); !slices.Equal(got, want) {
		t.Errorf("playbook-edges.yml restricts %q, the lb blocks mount %q", got, want)
	}
	groupVars, err := os.ReadFile(filepath.Join(ansibleRoot, "group_vars", "dns_edges.yml"))
	if err != nil {
		t.Fatalf("xops has no dns edges' group vars: %v", err)
	}
	dnsEdgeSecrets := listed(groupVars, `(?s)\ndns_edge_scoped_secrets:\n((?:\s+- [^\n]+\n)+)`)
	for _, service := range sidecarBlockDnsEdges {
		got := []string{}
		for _, secretFile := range dnsEdgeSecrets {
			got = append(got, strings.ReplaceAll(secretFile, "{{ dns_edge_service }}", service))
		}
		if blockSecrets := servicesConfig.Versions[0].Services[service].SecretFiles; !slices.Equal(got, blockSecrets) {
			t.Errorf("%s's host is given %q, its block mounts %q", service, got, blockSecrets)
		}
	}
}

// mmm.yml (W10, QD-012): mmm gains recurd.dev's two names and the key origin and nothing else changes in
// its block; recurd.dev joins domains under the registrar the owner gives, ur.io stays cloudflare's, and
// the key origin alone is listed unproxied. Each name is under a registrar domain, so warpctl certs issue
// covers it and warpctl dns can publish it.
func TestMmmBlockServesRecurdDevAndTheKeyOrigin(t *testing.T) {
	servicesConfig, _ := applySidecarBlockFragments(t)
	base := mustParseServicesConfig(t, fragmentBaseYaml)
	before := base.Versions[0].Services["mmm"]
	mmm := servicesConfig.Versions[0].Services["mmm"]
	if want := append(slices.Clone(before.ExposeAliases), sidecarBlockMmmAliases...); !slices.Equal(mmm.ExposeAliases, want) {
		t.Errorf("mmm is named %q, want %q", mmm.ExposeAliases, want)
	}
	unchanged := *mmm
	unchanged.ExposeAliases = before.ExposeAliases
	if !reflect.DeepEqual(unchanged, *before) {
		t.Errorf("mmm's block changed beyond its names: %+v, was %+v", unchanged, *before)
	}
	if want := map[string]string{"example.com": "route53", "recurd.dev": sidecarBlockFilledRegistrar, "ur.io": "cloudflare"}; !reflect.DeepEqual(servicesConfig.DomainRegistrars(), want) {
		t.Errorf("domains = %v, want %v", servicesConfig.DomainRegistrars(), want)
	}
	if got := servicesConfig.DnsUnproxiedHosts(); !slices.Equal(got, []string{"sidecar.ur.io"}) {
		t.Errorf("unproxied = %q", got)
	}
	for _, alias := range sidecarBlockMmmAliases {
		covered := slices.ContainsFunc(servicesConfig.DomainNames(), func(domain string) bool {
			return alias == domain || strings.HasSuffix(alias, "."+domain)
		})
		if !covered {
			t.Errorf("%s is under no registrar domain", alias)
		}
	}
}

// mmm.yml (QD-678): the lb sends the key origin alone no X-Frame-Options, since its CSP frame-ancestors
// lets ur.io frame it, and the key origin is a host the merged file serves, which warpctl lb
// create-config checks again of the vault's file. No other fragment lists a host.
func TestMmmFragmentLeavesFrameOptionsOffTheKeyOriginAlone(t *testing.T) {
	servicesConfig, _ := applySidecarBlockFragments(t)
	keyOriginHost := strings.TrimPrefix(sidecarBlockKeyOrigin, "https://")
	if got := servicesConfig.NoFrameOptionsHosts(); !slices.Equal(got, []string{keyOriginHost}) {
		t.Errorf("no_frame_options = %q, want the key origin %s alone", got, keyOriginHost)
	}
	if !slices.Contains(servicesConfig.Hostnames("test", nil), keyOriginHost) {
		t.Errorf("the lb does not serve the key origin %s", keyOriginHost)
	}
	if got := mustParseServicesConfig(t, fragmentBaseYaml).NoFrameOptionsHosts(); len(got) != 0 {
		t.Fatalf("the base lists %q in no_frame_options", got)
	}
	for name, fragment := range sidecarBlockFragments(t) {
		if name != "mmm.yml" && 0 < len(fragment.noFrameOptions) {
			t.Errorf("%s lists %q in no_frame_options", name, fragment.noFrameOptions)
		}
	}
}

// mmm.yml leaves recurd.dev's registrar for the owner, and applied without it, the merge is refused and
// names the domain to fill in.
func TestMmmFragmentWaitsForItsRegistrar(t *testing.T) {
	fragment, err := LoadServicesFragment(filepath.Join("sidecar-blocks", "mmm.yml"))
	if err != nil {
		t.Fatal(err)
	}
	placeholders := []string{}
	for _, domain := range fragment.domains {
		if !slices.Contains(servicesFragmentRegistrars, domain.registrar) {
			placeholders = append(placeholders, domain.name)
		}
	}
	if !slices.Equal(placeholders, []string{"recurd.dev"}) {
		t.Errorf("mmm.yml leaves %q for the owner, want recurd.dev alone", placeholders)
	}
	result, err := ApplyServicesFragments([]byte(fragmentBaseYaml), "services.yml", fragment)
	if err == nil || !strings.Contains(err.Error(), "domains.recurd.dev's registrar") || result != nil {
		t.Errorf("an unfilled registrar: %v", err)
	}
}

// The page Worker calls api, whose names include auth's token exchange, evs and gkm across origins (§18.8,
// §18.9), so each allows the key origin beside what it allowed; no fragment allows any other origin; and
// the key origin is a name mmm serves and the dns block keeps unproxied.
func TestKeyOriginIsAllowedByWhatThePageWorkerCalls(t *testing.T) {
	servicesConfig, _ := applySidecarBlockFragments(t)
	base := mustParseServicesConfig(t, fragmentBaseYaml)
	for _, service := range []string{"api", "evs", "gkm"} {
		origins, err := servicesConfig.Versions[0].ResolveCorsOrigins(service)
		if err != nil {
			t.Fatal(err)
		}
		before := []string{}
		if _, ok := base.Versions[0].Services[service]; ok {
			if before, err = base.Versions[0].ResolveCorsOrigins(service); err != nil {
				t.Fatal(err)
			}
		}
		if want := append(before, sidecarBlockKeyOrigin); !slices.Equal(origins, want) {
			t.Errorf("%s allows %q, want %q", service, origins, want)
		}
	}
	for name, fragment := range sidecarBlockFragments(t) {
		var version ServicesConfigVersion
		if err := fragment.version.Decode(&version); err != nil {
			t.Fatal(err)
		}
		for service, serviceConfig := range version.Services {
			for _, origin := range serviceConfig.CorsOrigins {
				if origin != sidecarBlockKeyOrigin {
					t.Errorf("%s gives %s the origin %s", name, service, origin)
				}
			}
			if serviceConfig.CorsOriginsFrom != "" {
				t.Errorf("%s has %s take another service's origins", name, service)
			}
		}
	}
	keyOriginHost := strings.TrimPrefix(sidecarBlockKeyOrigin, "https://")
	if !slices.Contains(servicesConfig.Versions[0].Services["mmm"].ExposeAliases, keyOriginHost) || !slices.Contains(servicesConfig.DnsUnproxiedHosts(), keyOriginHost) {
		t.Errorf("the key origin %s is not an unproxied name of mmm", keyOriginHost)
	}
}

// Each name mmm.yml gives mmm is a server_name of mmm's own nginx, so the lb never sends mmm a name it
// would answer only with its default server.
func TestMmmNginxServesEveryNameTheFragmentAdds(t *testing.T) {
	nginxConf, err := os.ReadFile(filepath.Join("..", "..", "mmm", "mmm", "nginx", "nginx.conf.j2"))
	if err != nil {
		t.Skipf("mmm is not beside this checkout: %v", err)
	}
	serverNames := []string{}
	for _, match := range regexp.MustCompile(`(?m)^\s*server_name\s+([^;]+);`).FindAllStringSubmatch(string(nginxConf), -1) {
		serverNames = append(serverNames, strings.Fields(match[1])...)
	}
	for _, alias := range sidecarBlockMmmAliases {
		if !slices.Contains(serverNames, alias) {
			t.Errorf("mmm's nginx serves no %s", alias)
		}
	}
}

// Whether two string maps hold the same entries; nil and empty are equal.
func mapsEqualStrings(a map[string]string, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for key, value := range a {
		if other, ok := b[key]; !ok || other != value {
			return false
		}
	}
	return true
}
