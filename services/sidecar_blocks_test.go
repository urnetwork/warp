package services

// The sidecar's service blocks in sidecar-blocks/ (DESIGN §19.4; OPS-M2-03, OPS-M5-03, OPS-M7-01, OPS-M9-01), each loaded
// through warp's own loader on the synthetic base fragment_test.go keeps, since nobody here reads the vault's
// file. Every fragment in the directory is applied, so one added later is held to the same rules. A registrar
// or a fill-in- placeholder the owner fills in is filled in first, with a synthetic choice, as the owner would
// before applying.

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"maps"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"sort"
	"strconv"
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

// The monitor's own vault file, whose pager webhook api and taskworker read at start to page §21.8's notices
// (QD-1070, owner decision 612), and the server file whose constant names what they read.
const (
	sidecarBlockNoticePagerFile         = "monitor.yml"
	sidecarBlockNoticePagerServerSource = "controller/abuse_notice_controller.go"
	sidecarBlockNoticePagerServerConst  = "AbuseNoticePagerFileName"
)

// The mail breakers' credentials for their outside measures, which taskworker's fragment mounts (QD-1069, owner
// decision 611), each with the server file whose constant names what taskworker reads.
var sidecarBlockMailBreakerCredentialFiles = []struct {
	name         string
	serverSource string
	serverConst  string
}{
	{name: "abuse-postmaster-tools.yml", serverSource: "mail_measures_postmaster.go", serverConst: "PostmasterToolsCredentialFileName"},
	{name: "abuse-snds.yml", serverSource: "mail_measures_snds.go", serverConst: "SndsCredentialFileName"},
}

// The synthetic values these tests fill each fill-in- placeholder with, for the owner, who gives the
// production ones: the dns edges as two transparent interfaces on hosts of their own, with documentation
// addresses (RFC 5737, RFC 3849) and no router, so no router config is checked here (OPS-M5-01's fixtures pin
// the router rules), and rpt.bringyour.com's two interfaces, and the two sending hosts, as the base's two lb
// hosts; and the sources api's and the dns API's internal routes let through (W8; QD-027): the site's ranges,
// documentation blocks that hold the base's lb addresses, and the off-site monitor's address.
var sidecarBlockFilledPlaceholders = map[string]string{
	"fill-in-ns1-host":                "ns1.example.com",
	"fill-in-ns1-interface":           "eth1",
	"fill-in-ns1-router":              `""`,
	"fill-in-ns1-router-port":         `""`,
	"fill-in-ns1-docker-network":      "warpeth1",
	"fill-in-ns1-ipv4":                "192.0.2.53",
	"fill-in-ns1-ipv6":                `"2001:db8::53"`,
	"fill-in-ns2-host":                "ns2.example.com",
	"fill-in-ns2-interface":           "eth1",
	"fill-in-ns2-router":              `""`,
	"fill-in-ns2-router-port":         `""`,
	"fill-in-ns2-docker-network":      "warpeth1",
	"fill-in-ns2-ipv4":                "198.51.100.53",
	"fill-in-ns2-ipv6":                `"2001:db8:1::53"`,
	"fill-in-rpt-host-1":              "edge-0.example.com",
	"fill-in-rpt-host-1-interface":    "eth0",
	"fill-in-rpt-host-2":              "edge-1.example.com",
	"fill-in-rpt-host-2-interface":    "eth0",
	"fill-in-smtp-host-1":             "edge-0.example.com",
	"fill-in-smtp-host-2":             "edge-1.example.com",
	"fill-in-site-ipv4-range":         "192.0.2.0/24",
	"fill-in-site-ipv6-range":         `"2001:db8::/32"`,
	"fill-in-monitor-outside-address": "203.0.113.7/32",
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
// tlsedge and mxedge's platform listener at M5, mxedge's router at M7, smtpedge at M9, and compute at M12
// (DESIGN-COMPUTE §14.2).
var sidecarBlockAddedServices = []string{"compute", "dns", "dnsedge-1", "dnsedge-2", "evs", "gkm", "mxedge", "mxedge-platform", "smtpedge", "sockets", "tlsedge"}

// The outbound mail edge, which runs with no lb front on its two sending hosts.
const sidecarBlockSmtpEdge = SmtpEdgeService

// The host-pinned dns edges, which run with no lb front.
var sidecarBlockDnsEdges = []string{"dnsedge-1", "dnsedge-2"}

// The variables a block's binary reads its service urls from, each its flag's default (server's
// sidecarhost.ServiceUrlFlag): api's base url, or a dns edge's dns API block's, and the sockets service's; and gkm's,
// which api's route installs read from the environment themselves, taking no flag for it (sidecarhost.GkmUrlEnvName).
const (
	sidecarBlockApiUrlEnvName     = "UR_API_URL"
	sidecarBlockSocketsUrlEnvName = "UR_SOCKETS_URL"
	sidecarBlockGkmUrlEnvName     = "UR_GKM_URL"
)

// gkm's url as api.yml and alt.yml give it: gkm's own name on the deployment's domain.
const sidecarBlockGkmUrl = "https://gkm.${WARP_DOMAIN}"

// The blocks that run api's route set through server's controller.InstallApiRoutes, by their binary in server/cli:
// api's, and alt's, which serves the set over HTTP/3 on the proxy hosts (connect/EXTENDER.md L1). Its projection
// reads gkm's url for §14.8's report key source, so api.yml and alt.yml give each the url.
var sidecarBlockApiRouteBinaryServices = map[string]string{"alt": "alt", "api": "api"}

// Each sidecar block's binary in server/cli and the services it runs as.
var sidecarBlockBinaryServices = map[string][]string{
	"dns":      {"dns", "dnsedge-1", "dnsedge-2"},
	"evs":      {"evs"},
	"gkm":      {"gkm"},
	"mxedge":   {"mxedge", "mxedge-platform"},
	"smtpedge": {"smtpedge"},
	"sockets":  {"sockets"},
	"tlsedge":  {"tlsedge"},
}

// The service each url flag of a binary names: api's internal gate for -api_url, but for the dns edges the dns API
// block's internal feed, the sockets service for -sockets_url, and gkm for a -gkm_url.
func sidecarBlockUrlTarget(service string, flagName string) string {
	switch {
	case flagName == "sockets_url":
		return "sockets"
	case flagName == "gkm_url":
		return "gkm"
	case slices.Contains(sidecarBlockDnsEdges, service):
		return "dns"
	}
	return "api"
}

// The service urls each block's environment gives it, as its fragment's env_vars write them: the service's own name
// on the deployment's domain, which warpctl writes out when it renders the unit.
var sidecarBlockServiceUrlEnvVars = map[string]map[string]string{
	"dns":             {sidecarBlockApiUrlEnvName: "https://api.${WARP_DOMAIN}"},
	"dnsedge-1":       {sidecarBlockApiUrlEnvName: "https://dns.${WARP_DOMAIN}"},
	"dnsedge-2":       {sidecarBlockApiUrlEnvName: "https://dns.${WARP_DOMAIN}"},
	"evs":             {sidecarBlockApiUrlEnvName: "https://api.${WARP_DOMAIN}"},
	"gkm":             {sidecarBlockApiUrlEnvName: "https://api.${WARP_DOMAIN}"},
	"mxedge":          {sidecarBlockApiUrlEnvName: "https://api.${WARP_DOMAIN}", sidecarBlockSocketsUrlEnvName: "https://sockets.${WARP_DOMAIN}"},
	"mxedge-platform": {sidecarBlockApiUrlEnvName: "https://api.${WARP_DOMAIN}"},
	"smtpedge":        {sidecarBlockApiUrlEnvName: "https://api.${WARP_DOMAIN}", sidecarBlockSocketsUrlEnvName: "https://sockets.${WARP_DOMAIN}"},
	"sockets":         {sidecarBlockApiUrlEnvName: "https://api.${WARP_DOMAIN}"},
	"tlsedge":         {sidecarBlockApiUrlEnvName: "https://api.${WARP_DOMAIN}", sidecarBlockSocketsUrlEnvName: "https://sockets.${WARP_DOMAIN}"},
}

// The services §19.4 names on the platform's own domain, each served on <service>.bringyour.com.
var sidecarBlockNamedServices = []string{"compute", "dns", "evs", "gkm", "sockets"}

// Each block §19.4 adds: only config mounted, user 65532, the scoped vault home and the service urls its binary
// reads, sorted secrets with its own metrics push credential; an lb service with beta 1 and g1 99, GET /status on port 80 and path-only logs, named
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
		wantEnvVars := map[string]string{"WARP_VAULT_HOME": "/srv/warp/secrets"}
		for name, value := range sidecarBlockServiceUrlEnvVars[service] {
			wantEnvVars[name] = value
		}
		if !mapsEqualStrings(serviceConfig.EnvVars, wantEnvVars) {
			t.Errorf("%s's env_vars are %v, want %v", service, serviceConfig.EnvVars, wantEnvVars)
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

// A block mounts a Postgres role only where it reads or writes rows, and at most one: dns, the platform
// listener and compute the platform's pg.yml (§19.7; plan-SMTP-report-intake-home; DESIGN-COMPUTE §14.4); tlsedge and mxedge's router a restricted
// role in a vault file of their own, pg-<service>.yml, which server's pool reads first (QD-029, QD-992), and so
// smtpedge for smtp_* (§19.4's own credentials); evs, gkm, sockets and the dns edges none (owner decision 2, §9.8,
// I-12).
func TestSidecarBlocksMountPostgresOnlyWhereTheyHoldIt(t *testing.T) {
	servicesConfig, added := applySidecarBlockFragments(t)
	want := map[string]string{
		"compute":         "pg.yml",
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

// compute's row (DESIGN-COMPUTE §14.2, CSRV-M12-03): compute.bringyour.com, a websocket service for the tunnel and so
// no streamable path, one per-address limit over the whole service, and its secrets: the callers' JWKS, Redis and the
// {cmpa} instance, Postgres, its read-only first cluster, the areas' own files and its metrics credential, never an
// internal gate bearer, since it reads api for nothing.
func TestSidecarBlocksAddCompute(t *testing.T) {
	servicesConfig, _ := applySidecarBlockFragments(t)
	compute := servicesConfig.Versions[0].Services["compute"]
	if compute == nil {
		t.Fatal("no compute service")
	}
	if !compute.IsWebsocket() || 0 < len(compute.StreamablePaths) || compute.IsStreamable() {
		t.Errorf("compute is websocket %t with streamable paths %q", compute.IsWebsocket(), compute.StreamablePaths)
	}
	if compute.ServiceRateLimit == nil || compute.ServiceRateLimit.RequestsPerMinute <= 0 || 0 < len(compute.RouteRateLimits) {
		t.Errorf("compute's limits are %+v and %+v", compute.ServiceRateLimit, compute.RouteRateLimits)
	}
	want := []string{
		"compute-gamma-signer.yml", "compute-providers.yml", "compute-searchsigner-client.yml", "file-clusters-compute.yml",
		"grafana-push-compute.yml", "oauth-jwks-svc.json", "pg.yml", "redis-compute-admissions.yml", "redis.yml",
	}
	if !slices.Equal(compute.SecretFiles, want) {
		t.Errorf("compute mounts %q, want %q", compute.SecretFiles, want)
	}
	if !slices.Equal(compute.ExposeAliases, []string{"compute.bringyour.com"}) {
		t.Errorf("compute is named %q", compute.ExposeAliases)
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
// refused with the placeholder's line named, before anything is merged: api.yml's and dns.yml's internal route
// sources, the site's ranges and the off-site monitor's address, dnsedge.yml's production hosts and addresses,
// mxedge-platform.yml's report host interfaces and smtpedge.yml's two sending hosts wait for the owner, and no
// other fragment holds one.
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
	if want := []string{"api.yml", "dns.yml", "dnsedge.yml", "mxedge-platform.yml", "smtpedge.yml"}; !slices.Equal(holding, want) {
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

// api and taskworker keep what they had and add their file clusters and the monitor's pager file, and taskworker the
// push sender's vendor keys, the mail breakers' credentials and the compute provider adapters' credentials for compute's
// jobs (DESIGN-COMPUTE §14.5; CSRV-M12-05); api's log keeps paths only (W8).
func TestApiAndTaskworkerBlocksAddTheirClusters(t *testing.T) {
	servicesConfig, _ := applySidecarBlockFragments(t)
	base, err := ParseServicesConfig([]byte(fragmentBaseYaml), "services.yml")
	if err != nil {
		t.Fatal(err)
	}
	api := servicesConfig.Versions[0].Services["api"]
	if !slices.Equal(api.SecretFiles, []string{"api-extra.yml", "file-clusters-api.yml", sidecarBlockNoticePagerFile}) || !api.LogUri {
		t.Errorf("api = %+v", api)
	}
	taskworker := servicesConfig.Versions[0].Services["taskworker"]
	wantTaskworkerSecretFiles := []string{"compute-providers.yml", "file-clusters-taskworker.yml", sidecarBlockNoticePagerFile, sidecarBlockWakeVendorsFile}
	for _, credentialFile := range sidecarBlockMailBreakerCredentialFiles {
		wantTaskworkerSecretFiles = append(wantTaskworkerSecretFiles, credentialFile.name)
	}
	sort.Strings(wantTaskworkerSecretFiles)
	if !slices.Equal(taskworker.SecretFiles, wantTaskworkerSecretFiles) || taskworker.LogUri {
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

// The mail breakers' Postmaster Tools and SNDS credentials reach taskworker, which builds the breakers' outside
// measures from them at start (§21.5, §21.16; QD-1069, owner decision 611), and no other block mounts either. The
// names are checked against the constants server reads them by, where server sits beside this checkout, so the
// fragment and the reader cannot drift apart.
func TestTaskworkerBlockMountsTheMailBreakersCredentials(t *testing.T) {
	servicesConfig, _ := applySidecarBlockFragments(t)
	for _, credentialFile := range sidecarBlockMailBreakerCredentialFiles {
		for service, serviceConfig := range servicesConfig.Versions[0].Services {
			if mounted := slices.Contains(serviceConfig.SecretFiles, credentialFile.name); mounted != (service == "taskworker") {
				t.Errorf("%s mounts %s: %v", service, credentialFile.name, mounted)
			}
		}
	}
	for _, credentialFile := range sidecarBlockMailBreakerCredentialFiles {
		source, err := os.ReadFile(filepath.Join("..", "..", "server", credentialFile.serverSource))
		if err != nil {
			t.Skipf("server is not beside this checkout: %v", err)
		}
		name := regexp.MustCompile(`(?m)^const ` + credentialFile.serverConst + ` = "([^"]+)"$`).FindSubmatch(source)
		if name == nil {
			t.Fatalf("server/%s names no %s", credentialFile.serverSource, credentialFile.serverConst)
		}
		if string(name[1]) != credentialFile.name {
			t.Errorf("taskworker reads %s, the fragment mounts %s", name[1], credentialFile.name)
		}
	}
}

// The notice pager's webhook reaches api and taskworker as the monitor's own vault file, which each reads at start to
// page §21.8's notices from the process that committed the case and from the clock pass (QD-1070, owner decision
// 612), and no block the fragments add mounts it, so the pager's credential has these two readers beside the
// monitor. The name is checked against the constant server reads it by, where server sits beside this checkout, so
// the fragments and the reader cannot drift apart.
func TestApiAndTaskworkerBlocksMountTheNoticePagersFile(t *testing.T) {
	servicesConfig, added := applySidecarBlockFragments(t)
	for _, service := range []string{"api", "taskworker"} {
		if !slices.Contains(servicesConfig.Versions[0].Services[service].SecretFiles, sidecarBlockNoticePagerFile) {
			t.Errorf("%s does not mount %s", service, sidecarBlockNoticePagerFile)
		}
	}
	for _, service := range added {
		if slices.Contains(servicesConfig.Versions[0].Services[service].SecretFiles, sidecarBlockNoticePagerFile) {
			t.Errorf("%s, a block the fragments add, mounts %s", service, sidecarBlockNoticePagerFile)
		}
	}
	source, err := os.ReadFile(filepath.Join("..", "..", "server", sidecarBlockNoticePagerServerSource))
	if err != nil {
		t.Skipf("server is not beside this checkout: %v", err)
	}
	name := regexp.MustCompile(`(?m)^const ` + sidecarBlockNoticePagerServerConst + ` = "([^"]+)"$`).FindSubmatch(source)
	if name == nil {
		t.Fatalf("server/%s names no %s", sidecarBlockNoticePagerServerSource, sidecarBlockNoticePagerServerConst)
	}
	if string(name[1]) != sidecarBlockNoticePagerFile {
		t.Errorf("api and taskworker read %s, the fragments mount %s", name[1], sidecarBlockNoticePagerFile)
	}
}

// The platform listener's own internal gate bearer, on which its role-mail intake files each role mail's notice at
// api (QD-1070, owner decision 612; QD-1121) and its report intake reads each network's seal key there
// (plan-SMTP-report-seal-key), reaches mxedge-platform alone: no edge block, the router included, mounts it, and the
// platform listener mounts no edge bearer, so the edge class's holders cannot page the rota or read a report key, and
// warp's deploy slot keeps it out of the edge services. The name is checked against the file server's internal gate
// names the class's credential by, where server sits beside this checkout.
func TestPlatformListenerAloneMountsItsNoticeBearer(t *testing.T) {
	const bearerFile = "internal-gate-mxedge-platform.yml"
	servicesConfig, _ := applySidecarBlockFragments(t)
	for service, serviceConfig := range servicesConfig.Versions[0].Services {
		if mounted := slices.Contains(serviceConfig.SecretFiles, bearerFile); mounted != (service == "mxedge-platform") {
			t.Errorf("%s mounts %s: %v", service, bearerFile, mounted)
		}
	}
	if slices.Contains(servicesConfig.Versions[0].Services["mxedge-platform"].SecretFiles, "internal-gate-edge.yml") {
		t.Error("the platform listener mounts the edge class's bearer")
	}
	source, err := os.ReadFile(filepath.Join("..", "..", "server", "internal_gate.go"))
	if err != nil {
		t.Skipf("server is not beside this checkout: %v", err)
	}
	class := regexp.MustCompile(`(?m)^\s*InternalGateCallerMxedgePlatform InternalGateCaller = "([^"]+)"$`).FindSubmatch(source)
	if class == nil {
		t.Fatal("server/internal_gate.go names no InternalGateCallerMxedgePlatform")
	}
	if want := "internal-gate-" + string(class[1]) + ".yml"; want != bearerFile {
		t.Errorf("server reads the platform listener's bearer from %s, the fragment mounts %s", want, bearerFile)
	}
}

// Every internal gate bearer a block's binary reads is mounted by a block that runs the binary, and no block mounts
// one its binary does not read (§19.4's gate paragraph; QD-055, QD-1142). A class's bearer is its vault file,
// internal-gate-<class>.yml (server's InternalGateCredentialFileName), which the binary reads once at start through
// quotahost.NewBlockQuota or server.LoadInternalGateCredential, and a block that cannot read it serves without it:
// evs stays not ready, and gkm weighs every network's writes as Community's. evs and gkm each mount their own class's
// bearer, which no other block mounts. Where server sits beside this checkout, its classes are read from
// internal_gate.go and each binary's reads from its own package's sources, so a binary that comes to read a class
// fails here until a block that runs it mounts that class's file.
func TestEveryBlockMountsTheGateBearersItsBinaryReads(t *testing.T) {
	servicesConfig, _ := applySidecarBlockFragments(t)
	version := servicesConfig.Versions[0]
	// These blocks each hold a bearer scoped to their own service.
	for _, class := range []string{"dns", "evs", "gkm"} {
		bearerFile := "internal-gate-" + class + ".yml"
		for service, serviceConfig := range version.Services {
			if mounted := slices.Contains(serviceConfig.SecretFiles, bearerFile); mounted != (service == class) {
				t.Errorf("%s mounts %s: %v", service, bearerFile, mounted)
			}
		}
	}

	serverRoot := filepath.Join("..", "..", "server")
	gateSource, err := os.ReadFile(filepath.Join(serverRoot, "internal_gate.go"))
	if err != nil {
		t.Skipf("server is not beside this checkout: %v", err)
	}
	fileNameParts := regexp.MustCompile(`(?m)^func InternalGateCredentialFileName\(caller InternalGateCaller\) string \{\n\s*return "([^"]*)" \+ string\(caller\) \+ "([^"]*)"\n\}$`).FindSubmatch(gateSource)
	if fileNameParts == nil {
		t.Fatal("server/internal_gate.go names no class's credential file as InternalGateCredentialFileName did")
	}
	credentialFileName := func(class string) string {
		return string(fileNameParts[1]) + class + string(fileNameParts[2])
	}
	// each class by the name of its constant in server, and each class's credential file
	constNameClasses := map[string]string{}
	credentialFileClasses := map[string]string{}
	for _, match := range regexp.MustCompile(`(?m)^\s*(InternalGateCaller\w+)\s+InternalGateCaller = "([^"]+)"$`).FindAllSubmatch(gateSource, -1) {
		constNameClasses[string(match[1])] = string(match[2])
		credentialFileClasses[credentialFileName(string(match[2]))] = string(match[2])
	}
	if constNameClasses["InternalGateCallerEvs"] != "evs" || constNameClasses["InternalGateCallerGkm"] != "gkm" {
		t.Fatalf("server/internal_gate.go names the classes %v, without evs's and gkm's", constNameClasses)
	}
	// the classes each binary reads a bearer of, from the sources of its package in server/cli
	readPattern := regexp.MustCompile(`(?:NewBlockQuota|LoadInternalGateCredential)\([^)]*\bserver\.(InternalGateCaller\w+)\b`)
	mainPaths, err := filepath.Glob(filepath.Join(serverRoot, "cli", "*", "main.go"))
	if err != nil {
		t.Fatal(err)
	}
	binaryClasses := map[string][]string{}
	for _, mainPath := range mainPaths {
		binary := filepath.Base(filepath.Dir(mainPath))
		sourcePaths, err := filepath.Glob(filepath.Join(filepath.Dir(mainPath), "*.go"))
		if err != nil {
			t.Fatal(err)
		}
		for _, sourcePath := range sourcePaths {
			if strings.HasSuffix(sourcePath, "_test.go") {
				continue
			}
			source, err := os.ReadFile(sourcePath)
			if err != nil {
				t.Fatal(err)
			}
			for _, match := range readPattern.FindAllSubmatch(source, -1) {
				class, ok := constNameClasses[string(match[1])]
				if !ok {
					t.Fatalf("%s reads server.%s, which server/internal_gate.go does not name", sourcePath, match[1])
				}
				if !slices.Contains(binaryClasses[binary], class) {
					binaryClasses[binary] = append(binaryClasses[binary], class)
				}
			}
		}
	}
	if !slices.Equal(binaryClasses["evs"], []string{"evs"}) || !slices.Equal(binaryClasses["gkm"], []string{"gkm"}) {
		t.Fatalf("server/cli/evs reads the bearers of %q and server/cli/gkm of %q, want each its own class's alone", binaryClasses["evs"], binaryClasses["gkm"])
	}
	// some block that runs each binary mounts the bearer of every class it reads
	serviceClasses := map[string][]string{}
	for binary, classes := range binaryClasses {
		services, ok := sidecarBlockBinaryServices[binary]
		if !ok {
			t.Errorf("server/cli/%s reads the bearers of %q, and no block here runs it", binary, classes)
			continue
		}
		for _, class := range classes {
			mounted := slices.ContainsFunc(services, func(service string) bool {
				return slices.Contains(version.Services[service].SecretFiles, credentialFileName(class))
			})
			if !mounted {
				t.Errorf("no block that runs server/cli/%s mounts %s, the bearer of class %s it reads", binary, credentialFileName(class), class)
			}
		}
		for _, service := range services {
			serviceClasses[service] = append(serviceClasses[service], classes...)
		}
	}
	// The shared DNS binary's host package loads the projection credential
	// on its API role. Its authoritative edges use their own feed credentials.
	if class := constNameClasses["InternalGateCallerDns"]; class != "" {
		serviceClasses["dns"] = append(serviceClasses["dns"], class)
	}
	// and no block mounts the bearer of a class its binary does not read
	for service, serviceConfig := range version.Services {
		for _, secretFile := range serviceConfig.SecretFiles {
			if class, ok := credentialFileClasses[secretFile]; ok && !slices.Contains(serviceClasses[service], class) {
				t.Errorf("%s mounts %s, the bearer of class %s, which its binary does not read", service, secretFile, class)
			}
		}
	}
}

// smtpedge's X-UR-Ref keys reach the two blocks that read them and no other (§14.6, §14.8; SMTP-M9-15, SMTP-M9-16):
// smtpedge, which issues references under them, and the platform listener, whose report intake's attribution
// verifies the reference each report carries, from mxedge-platform-x-ur-ref.yml, which extends the listener's block
// with that one file and changes nothing else, so mxedge-platform.yml, applied at M5, does not mount them and the
// listener holds them only from M9. The name is checked against the file server's model reads them from, where
// server sits beside this checkout.
func TestXUrRefKeysReachTheEdgeAndThePlatformListenerAlone(t *testing.T) {
	const keyFile = "smtpedge-x-ur-ref.yml"
	servicesConfig, _ := applySidecarBlockFragments(t)
	for service, serviceConfig := range servicesConfig.Versions[0].Services {
		if mounted := slices.Contains(serviceConfig.SecretFiles, keyFile); mounted != (service == sidecarBlockSmtpEdge || service == "mxedge-platform") {
			t.Errorf("%s mounts %s: %v", service, keyFile, mounted)
		}
	}
	fragments := sidecarBlockFragments(t)
	extension := fragments["mxedge-platform-x-ur-ref.yml"]
	if extension == nil {
		t.Fatal("no mxedge-platform-x-ur-ref.yml")
	}
	var extensionVersion ServicesConfigVersion
	if err := extension.version.Decode(&extensionVersion); err != nil {
		t.Fatal(err)
	}
	platform := extensionVersion.Services["mxedge-platform"]
	unchanged := ServiceConfig{SecretFiles: []string{keyFile}}
	if extensionVersion.Lb != nil || len(extensionVersion.HostServices) != 0 || len(extensionVersion.Services) != 1 || platform == nil || !reflect.DeepEqual(*platform, unchanged) ||
		0 < len(extension.domains) || 0 < len(extension.dnsUnproxied) || 0 < len(extension.noFrameOptions) {
		t.Errorf("mxedge-platform-x-ur-ref.yml adds more than the key file to the platform listener: %+v", extensionVersion)
	}
	var platformVersion ServicesConfigVersion
	if err := fragments["mxedge-platform.yml"].version.Decode(&platformVersion); err != nil {
		t.Fatal(err)
	}
	if slices.Contains(platformVersion.Services["mxedge-platform"].SecretFiles, keyFile) {
		t.Errorf("mxedge-platform.yml, applied at M5, mounts %s", keyFile)
	}
	source, err := os.ReadFile(filepath.Join("..", "..", "server", "model", "smtp_x_ur_ref_key_file.go"))
	if err != nil {
		t.Skipf("server is not beside this checkout: %v", err)
	}
	name := regexp.MustCompile(`(?m)^const SmtpXUrRefKeyFileName = "([^"]+)"$`).FindSubmatch(source)
	if name == nil || string(name[1]) != keyFile {
		t.Errorf("server reads the X-UR-Ref keys from %q, the fragments mount %s", name, keyFile)
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

// Every block whose binary takes a service url is given each one it uses in its environment, from its fragment's
// env_vars, which its flag reads as its default (server's sidecarhost.ServiceUrlFlag): api's base url to every block
// that reads api's internal gate, the platform listener's role-mail notices included, the dns API block's to each
// dns edge, and the sockets service's to the edges that find or register there. Each is the service's own name on
// the deployment's domain, https://<service>.${WARP_DOMAIN}, which warpctl writes out when it renders the unit, so no
// fragment holds a production name. Without it a deployed block would start not ready or without Quota. Where server
// sits beside this checkout, the variables and every binary's url flags are read from it, so a binary that gains a
// url flag fails here until the fragment of a block that runs it gives the url, and a fragment cannot give a url its
// binary does not read.
func TestEveryBlockIsGivenTheServiceUrlsItsBinaryReads(t *testing.T) {
	servicesConfig, added := applySidecarBlockFragments(t)
	version := servicesConfig.Versions[0]
	isUrlEnvName := func(name string) bool {
		return name == sidecarBlockApiUrlEnvName || name == sidecarBlockSocketsUrlEnvName || name == sidecarBlockGkmUrlEnvName
	}
	for _, service := range added {
		got := map[string]string{}
		for name, value := range version.Services[service].EnvVars {
			if isUrlEnvName(name) {
				got[name] = value
			}
		}
		if want := sidecarBlockServiceUrlEnvVars[service]; !mapsEqualStrings(got, want) {
			t.Errorf("%s is given the urls %v, want %v", service, got, want)
		}
	}
	for service, envVars := range sidecarBlockServiceUrlEnvVars {
		if !slices.Contains(added, service) {
			t.Errorf("%s, given urls here, is no block the fragments add", service)
		}
		for name, value := range envVars {
			// each url names a service of the merged file, on the deployment's own domain
			target, ok := strings.CutSuffix(strings.TrimPrefix(value, "https://"), ".${WARP_DOMAIN}")
			if !ok || !strings.HasPrefix(value, "https://") || version.Services[target] == nil {
				t.Errorf("%s's %s is %q, which names no service on the deployment's domain", service, name, value)
			}
		}
	}
	// the names the dns API's and the sockets service's fragments give them are the ones the urls write
	for _, target := range []string{"dns", "sockets"} {
		if !slices.ContainsFunc(version.Services[target].ExposeAliases, func(alias string) bool { return strings.HasPrefix(alias, target+".") }) {
			t.Errorf("%s is named %q, and the blocks call it at %s.<domain>", target, version.Services[target].ExposeAliases, target)
		}
	}

	serverRoot := filepath.Join("..", "..", "server")
	urlSource, err := os.ReadFile(filepath.Join(serverRoot, "sidecarhost", "service_url.go"))
	if err != nil {
		t.Skipf("server is not beside this checkout: %v", err)
	}
	envNames := map[string]string{}
	for _, match := range regexp.MustCompile(`(?m)^\s*(\w+EnvName) = "([^"]+)"$`).FindAllSubmatch(urlSource, -1) {
		envNames[string(match[1])] = string(match[2])
	}
	if envNames["ApiUrlEnvName"] != sidecarBlockApiUrlEnvName || envNames["SocketsUrlEnvName"] != sidecarBlockSocketsUrlEnvName || envNames["GkmUrlEnvName"] != sidecarBlockGkmUrlEnvName {
		t.Fatalf("server's blocks read their urls from %v, the fragments give %s, %s and %s", envNames, sidecarBlockApiUrlEnvName, sidecarBlockSocketsUrlEnvName, sidecarBlockGkmUrlEnvName)
	}
	mainPaths, err := filepath.Glob(filepath.Join(serverRoot, "cli", "*", "main.go"))
	if err != nil {
		t.Fatal(err)
	}
	flagPattern := regexp.MustCompile(`NewServiceUrlFlag\(flag\.CommandLine, "(\w+)", sidecarhost\.(\w+),`)
	readingBinaries := []string{}
	for _, mainPath := range mainPaths {
		binary := filepath.Base(filepath.Dir(mainPath))
		mainSource, err := os.ReadFile(mainPath)
		if err != nil {
			t.Fatal(err)
		}
		flags := flagPattern.FindAllSubmatch(mainSource, -1)
		if len(flags) == 0 {
			continue
		}
		readingBinaries = append(readingBinaries, binary)
		services, ok := sidecarBlockBinaryServices[binary]
		if !ok {
			t.Errorf("server/cli/%s reads service urls, and no block here runs it", binary)
			continue
		}
		readEnvNames := map[string]string{}
		for _, match := range flags {
			flagName := string(match[1])
			envName := envNames[string(match[2])]
			readEnvNames[envName] = flagName
			// some block that runs the binary is given the url, at the service it names
			given := false
			for _, service := range services {
				if value, ok := version.Services[service].EnvVars[envName]; ok {
					given = true
					want := "https://" + sidecarBlockUrlTarget(service, flagName) + ".${WARP_DOMAIN}"
					if value != want {
						t.Errorf("%s runs server/cli/%s, whose -%s reads $%s, and is given %q, want %q", service, binary, flagName, envName, value, want)
					}
				}
			}
			if !given {
				t.Errorf("no block that runs server/cli/%s is given $%s, which its -%s reads", binary, envName, flagName)
			}
		}
		// and no block is given a url its binary does not read
		for _, service := range services {
			for name := range version.Services[service].EnvVars {
				if _, ok := readEnvNames[name]; isUrlEnvName(name) && !ok {
					t.Errorf("%s is given $%s, which server/cli/%s does not read", service, name, binary)
				}
			}
		}
	}
	sort.Strings(readingBinaries)
	wantBinaries := slices.Sorted(maps.Keys(sidecarBlockBinaryServices))
	if !slices.Equal(readingBinaries, wantBinaries) {
		t.Errorf("the binaries reading service urls are %q, want %q", readingBinaries, wantBinaries)
	}
}

// The lb keeps api's internal gate and the dns API's internal feed to the site's own sources (§8.9, §19.4, W8;
// QD-027, QD-680): api.yml gives api internal_routes for /internal/gate/ and dns.yml gives dns one for
// /dns/internal/, each letting through only the sources the owner fills in, the site's ranges and for dns the
// off-site monitor's address, and no other block has internal routes. On every name the lb serves either by, its
// lb hosts' /by/ routes included, a request under the prefix from any other source is answered 403 and never reaches
// the service (warpctl's addInternalRouteLocations, which warpctl's tests run in nginx). The prefixes are checked
// against those server's internal gate and sidecar's dns API serve, where they sit beside this checkout.
func TestInternalRoutesKeepTheGateAndTheDnsFeedToTheSite(t *testing.T) {
	servicesConfig, _ := applySidecarBlockFragments(t)
	site := []string{"192.0.2.0/24", "2001:db8::/32"}
	want := map[string]*InternalRoutes{
		"api": {Prefixes: []string{"/internal/gate/"}, AllowSubnets: site},
		"dns": {Prefixes: []string{"/dns/internal/"}, AllowSubnets: append(slices.Clone(site), "203.0.113.7/32")},
	}
	for service, serviceConfig := range servicesConfig.Versions[0].Services {
		if !reflect.DeepEqual(serviceConfig.InternalRoutes, want[service]) {
			t.Errorf("%s's internal_routes are %+v, want %+v", service, serviceConfig.InternalRoutes, want[service])
		}
	}
	// the base's lb hosts, which the blocks reach api from, are on the site's ranges
	for host, lbBlocks := range servicesConfig.Versions[0].Lb.Interfaces {
		if host == sidecarBlockNs1Host || host == sidecarBlockNs2Host {
			continue
		}
		for interfaceName, lbBlock := range lbBlocks {
			for _, address := range []string{lbBlock.Ipv4, lbBlock.Ipv6} {
				inside := slices.ContainsFunc(servicesConfig.Versions[0].Services["api"].GetInternalRouteAllowSubnets(), func(prefix netip.Prefix) bool {
					return prefix.Contains(netip.MustParseAddr(address))
				})
				if !inside {
					t.Errorf("%s %s's %s is outside api's internal route sources", host, interfaceName, address)
				}
			}
		}
	}
	for _, c := range []struct {
		source  []string
		pattern string
		prefix  string
	}{
		{source: []string{"..", "..", "server", "internal_gate.go"}, pattern: `(?m)^const InternalGatePathPrefix = "([^"]+)"$`, prefix: "/internal/gate/"},
		{source: []string{"..", "..", "sidecar", "dnsservice", "api.go"}, pattern: `(?m)^\s*DnsInternalPathPrefix\s*= "([^"]+)"$`, prefix: "/dns/internal/"},
	} {
		source, err := os.ReadFile(filepath.Join(c.source...))
		if err != nil {
			t.Skipf("%s is not beside this checkout: %v", c.source[2], err)
		}
		served := regexp.MustCompile(c.pattern).FindSubmatch(source)
		if served == nil || string(served[1]) != c.prefix {
			t.Errorf("%s serves its internal routes under %q, the fragment keeps %s to the site", filepath.Join(c.source[2:]...), served, c.prefix)
		}
	}
}

// api's report key source reads each network's seal key from gkm's drop-key route (§14.8, §19.4's api row;
// plan-SMTP-report-seal-key), at the url api's projection install reads from the environment itself, taking no flag
// for it (server's sidecarhost.GkmUrlEnvName). Both blocks that run api's route set through
// controller.InstallApiRoutes are given it, api by api.yml and alt by alt.yml, as gkm's own name on the deployment's
// domain, which warpctl writes out when it renders the unit, and no other block is. Where server sits beside this
// checkout, the variable, its read and the binaries that reach the read are found in server's sources, so a binary
// that comes to read the variable, or a read that leaves the shared install, fails here until the fragment of each
// block that runs it gives the url.
func TestApiRouteBlocksAreGivenGkmsUrl(t *testing.T) {
	servicesConfig, _ := applySidecarBlockFragments(t)
	version := servicesConfig.Versions[0]
	runsApiRoutes := slices.Sorted(maps.Values(sidecarBlockApiRouteBinaryServices))
	for service, serviceConfig := range version.Services {
		value, given := serviceConfig.EnvVars[sidecarBlockGkmUrlEnvName]
		if want := slices.Contains(runsApiRoutes, service); given != want || (given && value != sidecarBlockGkmUrl) {
			t.Errorf("%s is given $%s %q: %v, want %v", service, sidecarBlockGkmUrlEnvName, value, given, want)
		}
	}
	for _, service := range runsApiRoutes {
		if version.Services[service] == nil {
			t.Errorf("the merged file has no %s, which runs api's route set", service)
		}
	}
	// the url names gkm by the name gkm.yml gives it
	target, ok := strings.CutSuffix(strings.TrimPrefix(sidecarBlockGkmUrl, "https://"), ".${WARP_DOMAIN}")
	if gkm := version.Services[target]; !ok || target != "gkm" || gkm == nil || !slices.ContainsFunc(gkm.ExposeAliases, func(alias string) bool { return strings.HasPrefix(alias, target+".") }) {
		t.Errorf("%s names no gkm that the lb serves by gkm.<domain>", sidecarBlockGkmUrl)
	}

	serverRoot := filepath.Join("..", "..", "server")
	urlSource, err := os.ReadFile(filepath.Join(serverRoot, "sidecarhost", "service_url.go"))
	if err != nil {
		t.Skipf("server is not beside this checkout: %v", err)
	}
	envName := regexp.MustCompile(`(?m)^\s*GkmUrlEnvName = "([^"]+)"$`).FindSubmatch(urlSource)
	if envName == nil || string(envName[1]) != sidecarBlockGkmUrlEnvName {
		t.Fatalf("server's sidecarhost names gkm's url variable %q, the fragments give %s", envName, sidecarBlockGkmUrlEnvName)
	}
	references := serverSourceReferences(t, serverRoot, map[string]string{
		"GkmUrlEnvName":           sidecarBlockGkmUrlEnvName,
		"installApiProjection":    "",
		"installApiAuthorization": "",
		"InstallApiRoutes":        "",
	})
	// the variable's one read is the projection's, which the authorization install alone runs, which
	// InstallApiRoutes alone runs
	for name, want := range map[string][]string{
		"GkmUrlEnvName":           {"controller/config_log_install.go:installApiProjection"},
		"installApiProjection":    {"controller/config_log_install.go:installApiAuthorization"},
		"installApiAuthorization": {"controller/api_routes_install.go:InstallApiRoutes"},
	} {
		if !slices.Equal(references[name], want) {
			t.Errorf("server refers to %s in %q, want %q: a binary that reaches the read another way needs the url as well", name, references[name], want)
		}
	}
	// and the binaries whose mains run InstallApiRoutes are those of the blocks given the url
	wantMains := []string{}
	for _, binary := range slices.Sorted(maps.Keys(sidecarBlockApiRouteBinaryServices)) {
		wantMains = append(wantMains, "cli/"+binary+"/main.go:main")
	}
	if !slices.Equal(references["InstallApiRoutes"], wantMains) {
		t.Errorf("server runs InstallApiRoutes in %q, want %q, whose blocks api.yml and alt.yml give the url", references["InstallApiRoutes"], wantMains)
	}
}

// alt.yml extends alt's block with gkm's url alone: it names alt and nothing else, with alt's exposed: false, which
// alt's block already says, and the one variable. Applied over a file that runs alt, its one change is alt's
// env_vars, the variable joining any alt already sets, and the rest of alt's block is as it was. Applied over one
// that runs no alt, its one change reads services.alt, which is how the owner tells that output apart and leaves it
// out (README.md), and the alt it adds is no block the lb serves by any name or warp gives a port.
func TestAltFragmentAddsGkmsUrlAlone(t *testing.T) {
	fragment := sidecarBlockFragments(t)["alt.yml"]
	if fragment == nil {
		t.Fatal("no alt.yml")
	}
	var fragmentVersion ServicesConfigVersion
	if err := fragment.version.Decode(&fragmentVersion); err != nil {
		t.Fatal(err)
	}
	exposed := false
	want := ServiceConfig{Exposed: &exposed, EnvVars: map[string]string{sidecarBlockGkmUrlEnvName: sidecarBlockGkmUrl}}
	if alt := fragmentVersion.Services["alt"]; fragmentVersion.Lb != nil || len(fragmentVersion.HostServices) != 0 || len(fragmentVersion.Services) != 1 || alt == nil || !reflect.DeepEqual(*alt, want) ||
		0 < len(fragment.domains) || 0 < len(fragment.dnsUnproxied) || 0 < len(fragment.noFrameOptions) {
		t.Errorf("alt.yml adds more than gkm's url to alt: %+v", fragmentVersion)
	}

	// over a file that runs alt, with no variable of its own and with one
	altEntry := "        alt: &alt\n            exposed: false\n"
	withVariable := strings.Replace(fragmentBaseYaml, altEntry, altEntry+"            env_vars:\n                ALT_TEST_VARIABLE: kept\n", 1)
	if withVariable == fragmentBaseYaml {
		t.Fatal("the base's alt moved")
	}
	for _, c := range []struct {
		base        string
		wantChanges []string
	}{
		{base: fragmentBaseYaml, wantChanges: []string{"services.alt.env_vars"}},
		{base: withVariable, wantChanges: []string{"services.alt.env_vars." + sidecarBlockGkmUrlEnvName}},
	} {
		result, err := ApplyServicesFragments([]byte(c.base), "services.yml", fragment)
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(result.Changes, c.wantChanges) {
			t.Errorf("alt.yml's changes are %q, want %q", result.Changes, c.wantChanges)
		}
		before := mustParseServicesConfig(t, c.base).Versions[0].Services["alt"]
		after := mustParseServicesConfig(t, string(result.Text)).Versions[0].Services["alt"]
		wantEnvVars := map[string]string{sidecarBlockGkmUrlEnvName: sidecarBlockGkmUrl}
		maps.Copy(wantEnvVars, before.EnvVars)
		if !mapsEqualStrings(after.EnvVars, wantEnvVars) {
			t.Errorf("alt's env_vars are %v, want %v", after.EnvVars, wantEnvVars)
		}
		unchanged := *after
		unchanged.EnvVars = before.EnvVars
		if !reflect.DeepEqual(unchanged, *before) {
			t.Errorf("alt's block changed beyond its env_vars: %+v, was %+v", unchanged, *before)
		}
	}

	// over a file that runs no alt
	noAlt := fragmentBaseYaml
	for _, entry := range []string{
		altEntry + "            hosts:\n                - edge-1.example.com\n            ports:\n                - 80\n            external_udp_ports:\n                - 53\n            blocks:\n                - g1: 1\n",
		"        alt: *alt\n",
	} {
		if !strings.Contains(noAlt, entry) {
			t.Fatalf("the base's alt moved: it holds no %q", entry)
		}
		noAlt = strings.Replace(noAlt, entry, "", 1)
	}
	for _, version := range mustParseServicesConfig(t, noAlt).Versions {
		if _, ok := version.Services["alt"]; ok {
			t.Fatal("the base without alt still runs alt")
		}
	}
	result, err := ApplyServicesFragments([]byte(noAlt), "services.yml", fragment)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(result.Changes, []string{"services.alt"}) {
		t.Errorf("over a file with no alt, alt.yml's changes are %q, want services.alt alone", result.Changes)
	}
	merged := mustParseServicesConfig(t, string(result.Text))
	if stray := merged.Versions[0].Services["alt"]; stray == nil || stray.IsExposed() || 0 < len(stray.Blocks) || 0 < len(stray.Hosts) || 0 < len(stray.PortSpecs) {
		t.Errorf("over a file with no alt, alt.yml adds %+v", stray)
	}
	for _, hostname := range merged.Hostnames("test", nil) {
		if strings.Contains(hostname, "-alt.") {
			t.Errorf("the lb serves the alt alt.yml adds as %s", hostname)
		}
	}
	for host, servicePortBlocks := range fragmentPortBlocks(t, result.Text) {
		if 0 < len(servicePortBlocks["alt"]) {
			t.Errorf("warp gives the alt alt.yml adds ports on %q: %v", host, servicePortBlocks["alt"])
		}
	}
}

// Where server's non-test Go sources refer in code to each name, as "<path under server>:<function>", a method as
// <type>.<name> and a package-level declaration as "<path>:", sorted: the identifier, alone or as a qualified
// selector, or a string literal holding the name's literal where one is given. A declaration of the name is no
// reference, nor is a comment. third_party, testdata and dot directories are not read.
func serverSourceReferences(t *testing.T, serverRoot string, literals map[string]string) map[string][]string {
	t.Helper()
	root, err := filepath.EvalSymlinks(serverRoot)
	if err != nil {
		t.Fatal(err)
	}
	references := map[string][]string{}
	walkErr := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			if path != root && (strings.HasPrefix(entry.Name(), ".") || entry.Name() == "third_party" || entry.Name() == "testdata" || entry.Name() == "node_modules") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		source, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		mentioned := false
		for name, literal := range literals {
			if bytes.Contains(source, []byte(name)) || (literal != "" && bytes.Contains(source, []byte(literal))) {
				mentioned = true
			}
		}
		if !mentioned {
			return nil
		}
		file, err := parser.ParseFile(token.NewFileSet(), path, source, parser.SkipObjectResolution)
		if err != nil {
			return err
		}
		relativePath, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		for _, decl := range file.Decls {
			where := ""
			var node ast.Node = decl
			if funcDecl, ok := decl.(*ast.FuncDecl); ok {
				where = funcDecl.Name.Name
				if receiver := serverSourceReceiverName(funcDecl); receiver != "" {
					where = receiver + "." + where
				}
				if funcDecl.Body == nil {
					continue
				}
				// the body alone, so the function's own name is no reference
				node = funcDecl.Body
			}
			for name, literal := range literals {
				if serverSourceRefersTo(node, name, literal) {
					references[name] = append(references[name], filepath.ToSlash(relativePath)+":"+where)
				}
			}
		}
		return nil
	})
	if walkErr != nil {
		t.Fatal(walkErr)
	}
	for name := range references {
		sort.Strings(references[name])
		references[name] = slices.Compact(references[name])
	}
	return references
}

// Whether node refers in code to name, or holds literal as a string literal where literal is not empty. A
// declaration of name is passed over.
func serverSourceRefersTo(node ast.Node, name string, literal string) bool {
	refers := false
	ast.Inspect(node, func(node ast.Node) bool {
		switch node := node.(type) {
		case *ast.ValueSpec:
			if slices.ContainsFunc(node.Names, func(ident *ast.Ident) bool { return ident.Name == name }) {
				return false
			}
		case *ast.TypeSpec:
			if node.Name.Name == name {
				return false
			}
		case *ast.Ident:
			if node.Name == name {
				refers = true
			}
		case *ast.BasicLit:
			if value, err := strconv.Unquote(node.Value); literal != "" && node.Kind == token.STRING && err == nil && value == literal {
				refers = true
			}
		}
		return !refers
	})
	return refers
}

// The type name of funcDecl's receiver, or "" for a function.
func serverSourceReceiverName(funcDecl *ast.FuncDecl) string {
	if funcDecl.Recv == nil || len(funcDecl.Recv.List) == 0 {
		return ""
	}
	receiverType := funcDecl.Recv.List[0].Type
	for {
		switch typed := receiverType.(type) {
		case *ast.StarExpr:
			receiverType = typed.X
		case *ast.IndexExpr:
			receiverType = typed.X
		case *ast.IndexListExpr:
			receiverType = typed.X
		case *ast.Ident:
			return typed.Name
		default:
			return ""
		}
	}
}

// serverSourceReferences over a synthetic tree finds each use in code, in a function, a method or a package-level
// declaration, by the identifier, a qualified selector or the literal, and nothing else: not a comment, not the
// name's own declaration or a function's own name, not a test file, and nothing under third_party, testdata or a dot
// directory.
func TestServerSourceReferencesFindsCodeAlone(t *testing.T) {
	root := t.TempDir()
	for path, source := range map[string]string{
		// the declaration, a comment and a function named for it are no references
		"names/names.go": "package names\n\n// Target is read in code by Target's readers.\nconst Target = \"TARGET_VALUE\"\n\nfunc Other() string { return \"other\" }\n",
		// a read through the qualified name inside a closure, attributed to its function
		"reader/reader.go": "package reader\n\nimport (\n\t\"os\"\n\n\t\"example.com/names\"\n)\n\nfunc Read() func() string {\n\treturn func() string { return os.Getenv(names.Target) }\n}\n",
		// the literal in a method of a generic type, and the bare name at package level
		"reader/method.go": "package reader\n\ntype holder[T any] struct{ value T }\n\nfunc (self *holder[T]) Read() string { return \"TARGET_VALUE\" }\n\nvar shared = Target\n",
		// a mention in a comment alone, and a function whose name is the target's
		"quiet/quiet.go": "package quiet\n\n// Target, \"TARGET_VALUE\"\nfunc Target() {}\n",
		// never read: tests, vendored code, fixtures and dot directories
		"reader/reader_test.go":      "package reader\n\nvar _ = Target\n",
		"third_party/x/x.go":         "package x\n\nvar _ = Target\n",
		"reader/testdata/fixture.go": "package fixture\n\nvar _ = Target\n",
		".cache/y/y.go":              "package y\n\nvar _ = Target\n",
	} {
		full := filepath.Join(root, filepath.FromSlash(path))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(source), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	references := serverSourceReferences(t, root, map[string]string{"Target": "TARGET_VALUE", "Other": ""})
	want := map[string][]string{
		"Target": {"reader/method.go:", "reader/method.go:holder.Read", "reader/reader.go:Read"},
	}
	if !reflect.DeepEqual(references, want) {
		t.Errorf("references are %q, want %q", references, want)
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
