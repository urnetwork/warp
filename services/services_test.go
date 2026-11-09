package services

import (
	"bytes"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// newVault writes testdata/services.yml into a temp vault dir at the given
// relative subdir ("test" = local dev layout, "." = container layout where the
// env-specific vault is mounted at the root) and returns the vault dir.
func newVault(t *testing.T, relDir string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "services.yml"))
	if err != nil {
		t.Fatal(err)
	}
	vaultDir := t.TempDir()
	dir := filepath.Join(vaultDir, relDir)
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "services.yml"), data, 0644); err != nil {
		t.Fatal(err)
	}
	return vaultDir
}

func mustLoad(t *testing.T) *ServicesConfig {
	t.Helper()
	servicesConfig, err := LoadServicesConfigFrom(newVault(t, "test"), "test")
	if err != nil {
		t.Fatal(err)
	}
	return servicesConfig
}

// loadInlineServices writes a focused services document and returns its parse
// error so rejection tests exercise the production loader.
func loadInlineServicesConfig(t *testing.T, servicesYaml string) (*ServicesConfig, error) {
	t.Helper()
	vaultDir := t.TempDir()
	envDir := filepath.Join(vaultDir, "test")
	if err := os.MkdirAll(envDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(envDir, "services.yml"), []byte(servicesYaml), 0600); err != nil {
		t.Fatal(err)
	}
	return LoadServicesConfigFrom(vaultDir, "test")
}

func loadInlineServices(t *testing.T, servicesYaml string) error {
	t.Helper()
	_, err := loadInlineServicesConfig(t, servicesYaml)
	return err
}

// CAP_NET_ADMIN is an explicit, reviewed exception for proxy only.
func TestLoadServicesConfigRejectsCapabilityOnNonProxy(t *testing.T) {
	err := loadInlineServices(t, `
versions:
  - services:
      api:
        cap_net_admin: true
`)
	if err == nil {
		t.Fatal("expected CAP_NET_ADMIN on api to fail")
	}
}

// Proxy retains the capability required by SO_MARK on Ubuntu 22.04.
func TestLoadServicesConfigAllowsCapabilityOnProxy(t *testing.T) {
	err := loadInlineServices(t, `
versions:
  - services:
      proxy:
        cap_net_admin: true
`)
	if err != nil {
		t.Fatal(err)
	}
}

// No service may reintroduce raw Docker API access through configuration.
func TestLoadServicesConfigRejectsDockerSocketMount(t *testing.T) {
	err := loadInlineServices(t, `
versions:
  - services:
      grafana:
        mount:
          docker: yes
`)
	if err == nil {
		t.Fatal("expected a Docker API mount to fail")
	}
}

// Scoped secret mounts accept basenames only, preventing traversal into vault.
func TestLoadServicesConfigRejectsSecretTraversal(t *testing.T) {
	err := loadInlineServices(t, `
versions:
  - services:
      grafana:
        secret_files:
          - ../jwt.yml
`)
	if err == nil {
		t.Fatal("expected a traversing secret file to fail")
	}
}

func TestLoadServicesConfigAcceptsValidatedForwardPort(t *testing.T) {
	servicesConfig, err := loadInlineServicesConfig(t, `
versions:
  - lb:
      udp_stream_port_services:
        8053: connect
      udp_forward_ports:
        53: 8053
      interfaces:
        edge.example.com:
          eth0: {}
    services:
      connect:
        udp_stream_ports: [8053]
`)
	if err != nil {
		t.Fatal(err)
	}
	if got := servicesConfig.Latest().Lb.UdpForwardPorts[53]; got != 8053 {
		t.Fatalf("UDP forward target=%d want=8053", got)
	}
}

func TestLoadServicesConfigRejectsUnsafeForwardPorts(t *testing.T) {
	tests := []struct {
		name               string
		forwardPorts       string
		servicePorts       string
		interfaceOverrides string
		versionOverrides   string
	}{
		{name: "port-zero", forwardPorts: "0: 8053", servicePorts: "- 8053"},
		{name: "identity", forwardPorts: "8053: 8053", servicePorts: "- 8053"},
		{name: "chained", forwardPorts: "53: 8053\n        8053: 9000", servicePorts: "- 8053\n          - 9000"},
		{name: "missing-lb-target", forwardPorts: "53: 8054", servicePorts: "- 8053"},
		{name: "service-missing-target", forwardPorts: "53: 8053", servicePorts: "- 443"},
		{name: "direct-source-conflict", forwardPorts: "8053: 9000", servicePorts: "- 8053\n          - 9000"},
		{name: "external-pool-conflict", forwardPorts: "53: 8053", servicePorts: "- 8053", versionOverrides: "    external_ports: 1-100\n"},
		{
			name:               "interface-source-conflict",
			forwardPorts:       "53: 8053",
			servicePorts:       "- 8053",
			interfaceOverrides: "            udp_stream_port_services:\n              53: connect",
		},
		{
			name:               "interface-target-override",
			forwardPorts:       "53: 8053",
			servicePorts:       "- 8053",
			interfaceOverrides: "            udp_stream_port_services:\n              8053: other",
		},
		{
			name:               "interface-forced-external-conflict",
			forwardPorts:       "53: 8053",
			servicePorts:       "- 8053",
			interfaceOverrides: "            external_ports:\n              53: 443",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			interfaceBlock := "          eth0: {}"
			if test.interfaceOverrides != "" {
				interfaceBlock = "          eth0:\n" + test.interfaceOverrides
			}
			servicesYaml := `
versions:
  -
` + test.versionOverrides + `    lb:
      udp_stream_port_services:
        8053: connect
        9000: connect
      udp_forward_ports:
        ` + test.forwardPorts + `
      interfaces:
        edge.example.com:
` + interfaceBlock + `
    services:
      connect:
        udp_stream_ports:
          ` + test.servicePorts + `
`
			if err := loadInlineServices(t, servicesYaml); err == nil {
				t.Fatal("unsafe forward configuration was accepted")
			}
		})
	}
}

func TestLoadServicesConfigFromEnvDir(t *testing.T) {
	// local dev layout: <vaultDir>/<env>/services.yml
	servicesConfig, err := LoadServicesConfigFrom(newVault(t, "test"), "test")
	if err != nil {
		t.Fatal(err)
	}
	if servicesConfig.Domain != "example.com" {
		t.Errorf("domain = %q, want example.com", servicesConfig.Domain)
	}
	if len(servicesConfig.Versions) != 1 {
		t.Fatalf("versions = %d, want 1", len(servicesConfig.Versions))
	}
	if got := servicesConfig.Latest().ParallelBlockCount; got != 4 {
		t.Errorf("parallel_block_count = %d, want 4", got)
	}
}

func TestLoadServicesConfigFromVaultRoot(t *testing.T) {
	// container layout: the env-specific vault is mounted directly at the root,
	// so <vaultDir>/<env>/services.yml does not exist and we fall back
	servicesConfig, err := LoadServicesConfigFrom(newVault(t, "."), "test")
	if err != nil {
		t.Fatal(err)
	}
	if servicesConfig.Domain != "example.com" {
		t.Errorf("domain = %q, want example.com", servicesConfig.Domain)
	}
}

func TestLoadServicesConfigFromMissingReturnsError(t *testing.T) {
	// must return an error rather than panic
	if _, err := LoadServicesConfigFrom(t.TempDir(), "test"); err == nil {
		t.Error("expected an error for a missing services.yml")
	}
}

func TestLoadServicesConfigFromInjectsConfigUpdater(t *testing.T) {
	servicesConfig := mustLoad(t)
	configUpdater, ok := servicesConfig.Latest().Services["config-updater"]
	if !ok {
		t.Fatal("expected a default config-updater service to be injected")
	}
	if configUpdater.IsExposed() {
		t.Error("config-updater should not be exposed")
	}
	if configUpdater.IsLbExposed() {
		t.Error("config-updater should not be lb exposed")
	}
	if len(configUpdater.Blocks) != 1 || configUpdater.Blocks[0]["main"] != 1 {
		t.Errorf("config-updater blocks = %v, want [main:1]", configUpdater.Blocks)
	}
}

// Query authorization comes from config while the matching password comes
// from the scoped vault document.
func TestLoadGrafanaConfigFromSeparatesRolesAndPasswords(t *testing.T) {
	configDir := t.TempDir()
	vaultDir := t.TempDir()
	for _, rootDir := range []string{configDir, vaultDir} {
		if err := os.Mkdir(filepath.Join(rootDir, "main"), 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(configDir, "main", "grafana.yml"), []byte(`
users:
  - name: warpctl
    roles: [query]
`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(vaultDir, "main", "grafana.yml"), []byte(`
users:
  - name: warpctl
    password: secret
`), 0600); err != nil {
		t.Fatal(err)
	}
	grafanaConfig, err := LoadGrafanaConfigFrom(configDir, vaultDir, "main")
	if err != nil {
		t.Fatal(err)
	}
	queryUser, err := grafanaConfig.QueryUser()
	if err != nil {
		t.Fatal(err)
	}
	if queryUser.Name != "warpctl" || queryUser.Password != "secret" || !slices.Equal(queryUser.Roles, []string{"query"}) {
		t.Fatalf("query user = %+v", queryUser)
	}
}

// A vault document cannot grant itself a query role.
func TestLoadGrafanaConfigFromRejectsSecretRoles(t *testing.T) {
	configDir := t.TempDir()
	vaultDir := t.TempDir()
	for _, rootDir := range []string{configDir, vaultDir} {
		if err := os.Mkdir(filepath.Join(rootDir, "main"), 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(configDir, "main", "grafana.yml"), []byte("users: [{name: warpctl, roles: [query]}]\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(vaultDir, "main", "grafana.yml"), []byte("users: [{name: warpctl, password: secret, roles: [query]}]\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadGrafanaConfigFrom(configDir, vaultDir, "main"); err == nil {
		t.Fatal("expected vault-owned roles to fail")
	}
}

// Host-side consumers pick semantic version order rather than lexical order.
func TestResolveConfigPathUsesLatestSemanticVersion(t *testing.T) {
	configDir := t.TempDir()
	for _, version := range []string{"1.9.0", "1.10.0"} {
		versionDir := filepath.Join(configDir, version)
		if err := os.Mkdir(versionDir, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(versionDir, "grafana.yml"), []byte(version), 0600); err != nil {
			t.Fatal(err)
		}
	}
	configPath, err := resolveConfigPath(configDir, "main", "grafana.yml")
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(filepath.Dir(configPath)) != "1.10.0" {
		t.Fatalf("config path = %s", configPath)
	}
}

func TestLatest(t *testing.T) {
	servicesConfig := mustLoad(t)
	if servicesConfig.Latest() != servicesConfig.Versions[0] {
		t.Error("Latest() should be Versions[0]")
	}
}

func TestResolveCorsOriginsInheritsWithoutDrift(t *testing.T) {
	version := &ServicesConfigVersion{Services: map[string]*ServiceConfig{
		"api": {
			CorsOrigins: []string{"https://app.bringyour.com", "https://app.ur.network"},
		},
		"mcp": {
			CorsOriginsFrom: "api",
		},
	}}

	origins, err := version.ResolveCorsOrigins("mcp")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"https://app.bringyour.com", "https://app.ur.network"}
	if !slices.Equal(origins, want) {
		t.Fatalf("mcp origins = %v, want %v", origins, want)
	}

	// The caller receives a copy; rendering one service cannot mutate the
	// source service's policy.
	origins[0] = "https://changed.invalid"
	if version.Services["api"].CorsOrigins[0] != want[0] {
		t.Fatal("resolved CORS origins alias the source service slice")
	}
}

func TestResolveCorsOriginsRejectsInvalidReferences(t *testing.T) {
	tests := []struct {
		service string
		version *ServicesConfigVersion
	}{
		{
			service: "mcp",
			version: &ServicesConfigVersion{Services: map[string]*ServiceConfig{
				"mcp": {CorsOriginsFrom: "missing"},
			}},
		},
		{
			service: "mcp",
			version: &ServicesConfigVersion{Services: map[string]*ServiceConfig{
				"api": {CorsOriginsFrom: "mcp"},
				"mcp": {CorsOriginsFrom: "api"},
			}},
		},
		{
			service: "api",
			version: &ServicesConfigVersion{Services: map[string]*ServiceConfig{
				"api": {
					CorsOrigins:     []string{"https://app.bringyour.com"},
					CorsOriginsFrom: "web",
				},
				"web": {},
			}},
		},
	}
	for _, test := range tests {
		if _, err := test.version.ResolveCorsOrigins(test.service); err == nil {
			t.Fatal("expected invalid CORS inheritance to fail")
		}
	}
}

func TestHostsForService(t *testing.T) {
	version := mustLoad(t).Latest()

	tests := []struct {
		service string
		want    []string
		why     string
	}{
		{
			"api",
			[]string{"edge-a.example.com", "edge-b.example.com", "edge-c.example.com"},
			"every lb host: edge-b's host_services includes api, the others are unlisted",
		},
		{
			"web",
			[]string{"edge-a.example.com", "edge-c.example.com"},
			"edge-b is dropped because its host_services list does not include web",
		},
		{
			"edge",
			[]string{"edge-a.example.com"},
			"edge-b dropped by host_services, edge-c dropped by the service hosts list",
		},
	}
	for _, test := range tests {
		got := HostsForService(version, test.service)
		if !slices.Equal(got, test.want) {
			t.Errorf("HostsForService(%q) = %v, want %v (%s)", test.service, got, test.want, test.why)
		}
	}
}

func TestPortConfigPorts(t *testing.T) {
	api := mustLoad(t).Latest().Services["api"]

	// "8080+2" expands to 3 consecutive ports, "9000-9002" is an inclusive range
	wantHttp := []int{8000, 8080, 8081, 8082, 9000, 9001, 9002}
	if got := api.HttpTcpPorts(); !slices.Equal(got, wantHttp) {
		t.Errorf("HttpTcpPorts() = %v, want %v", got, wantHttp)
	}
	if got := api.StreamTcpPorts(); !slices.Equal(got, []int{5000}) {
		t.Errorf("StreamTcpPorts() = %v, want [5000]", got)
	}
	if got := api.StreamUdpPorts(); !slices.Equal(got, []int{5353}) {
		t.Errorf("StreamUdpPorts() = %v, want [5353]", got)
	}
	// TcpPorts is http + stream tcp; UdpPorts is stream udp
	if got := api.TcpPorts(); !slices.Equal(got, append(slices.Clone(wantHttp), 5000)) {
		t.Errorf("TcpPorts() = %v", got)
	}
	if got := api.UdpPorts(); !slices.Equal(got, []int{5353}) {
		t.Errorf("UdpPorts() = %v, want [5353]", got)
	}
}

func TestServiceConfigMethods(t *testing.T) {
	version := mustLoad(t).Latest()
	api := version.Services["api"]
	web := version.Services["web"]
	edge := version.Services["edge"]

	// exposure defaults to true when unset, and is honored when set
	if !api.IsExposed() || !api.IsLbExposed() {
		t.Error("api should default to exposed and lb exposed")
	}
	if web.IsExposed() || web.IsLbExposed() {
		t.Error("web is explicitly not exposed")
	}

	// status mode
	if !api.IsStandardStatus() || api.GetStatusMode() != "standard" {
		t.Errorf("api status = %q, want standard", api.GetStatusMode())
	}
	if web.IsStandardStatus() || web.GetStatusMode() != "none" {
		t.Errorf("web status = %q, want none", web.GetStatusMode())
	}

	// bool flags default false
	if !web.IsWebsocket() || api.IsWebsocket() {
		t.Error("only web is a websocket service")
	}
	if api.IsStreamable() || api.IsStateful() {
		t.Error("streamable/stateful default to false")
	}

	// an empty hosts list includes every host
	if !api.IncludesHost("edge-b.example.com") {
		t.Error("api has no hosts restriction so it includes every host")
	}
	if !edge.IncludesHost("edge-a.example.com") || edge.IncludesHost("edge-c.example.com") {
		t.Error("edge is restricted to edge-a")
	}

	if got := api.MemoryLimitBytes(); got != 512*1024*1024 {
		t.Errorf("MemoryLimitBytes() = %d, want %d", got, 512*1024*1024)
	}
	if got := web.MemoryLimitBytes(); got != 0 {
		t.Errorf("MemoryLimitBytes() with no limit = %d, want 0", got)
	}
}

func TestServicesConfigLookups(t *testing.T) {
	servicesConfig := mustLoad(t)

	if got := servicesConfig.GetDomain(); got != "example.com" {
		t.Errorf("GetDomain() = %q, want example.com", got)
	}
	if got := servicesConfig.DomainNames(); !slices.Equal(got, []string{"example.com"}) {
		t.Errorf("DomainNames() = %v, want [example.com]", got)
	}
	if got := servicesConfig.GetHiddenPrefix(); got != "h1dden" {
		t.Errorf("GetHiddenPrefix() = %q, want h1dden", got)
	}
	if got := servicesConfig.GetLbHiddenPrefix(); got != "lbh1dden" {
		t.Errorf("GetLbHiddenPrefix() = %q, want lbh1dden", got)
	}

	// lb is always exposed and never lb exposed; unknown services are neither
	if !servicesConfig.IsExposed("lb") || servicesConfig.IsLbExposed("lb") {
		t.Error("lb should be exposed but not lb exposed")
	}
	if !servicesConfig.IsStandardStatus("lb") {
		t.Error("lb should be standard status")
	}
	if servicesConfig.IsExposed("web") {
		t.Error("web is not exposed")
	}
	if servicesConfig.IsExposed("nope") || servicesConfig.IsLbExposed("nope") || servicesConfig.IsStandardStatus("nope") {
		t.Error("an unknown service should not be exposed or standard status")
	}
}

// log_uri is opt in per service.
func TestLoadServicesConfigParsesLogUri(t *testing.T) {
	servicesConfig, err := loadInlineServicesConfig(t, `
versions:
  - services:
      evs:
        log_uri: true
      web: {}
`)
	if err != nil {
		t.Fatal(err)
	}
	services := servicesConfig.Latest().Services
	if !services["evs"].LogUri {
		t.Fatal("evs log_uri was not parsed")
	}
	if services["web"].LogUri {
		t.Fatal("log_uri is on for a service that does not set it")
	}
}

// A public port a service publishes itself is only meaningful where the service
// is pinned: warp must know which host installs the dnat.
func TestLoadServicesConfigRejectsExternalPortsWithoutHosts(t *testing.T) {
	err := loadInlineServices(t, `
versions:
  - lb:
      interfaces:
        edge.example.com:
          eth0: {}
    services:
      alt:
        external_udp_ports: [443, 4053]
`)
	if err == nil {
		t.Fatal("expected external_udp_ports without hosts to fail")
	}
}

func TestLoadServicesConfigAcceptsHostPinnedExternalPorts(t *testing.T) {
	servicesConfig, err := loadInlineServicesConfig(t, `
versions:
  - lb:
      interfaces:
        edge.example.com:
          eth0: {}
    services:
      alt:
        hosts:
          - edge.example.com
        ports: [80]
        external_udp_ports: [443, 4053]
`)
	if err != nil {
		t.Fatal(err)
	}
	altConfig := servicesConfig.Latest().Services["alt"]
	if got := altConfig.ExternalUdpPorts; !slices.Equal(got, []int{443, 4053}) {
		t.Fatalf("external udp ports=%v want=[443 4053]", got)
	}
	if got := altConfig.AllExternalPorts()["udp"]; !slices.Equal(got, []int{443, 4053}) {
		t.Fatalf("all external udp ports=%v want=[443 4053]", got)
	}
	if got := altConfig.AllExternalPorts()["tcp"]; len(got) != 0 {
		t.Fatalf("all external tcp ports=%v want empty", got)
	}
	// the claim must stay out of the lb-fronted port sets
	if got := altConfig.AllStreamPorts()["udp"]; len(got) != 0 {
		t.Fatalf("stream udp ports=%v want empty", got)
	}
	if got := altConfig.AllHttpPorts()["tcp"]; !slices.Equal(got, []int{80}) {
		t.Fatalf("http tcp ports=%v want=[80]", got)
	}
}

// One port key carries one lb type, so a port cannot be fronted by the lb and
// published by the service at the same time.
func TestLoadServicesConfigRejectsExternalPortThatIsAlsoAnLbPort(t *testing.T) {
	err := loadInlineServices(t, `
versions:
  - lb:
      interfaces:
        edge.example.com:
          eth0: {}
    services:
      alt:
        hosts:
          - edge.example.com
        udp_stream_ports: [4053]
        external_udp_ports: [4053]
`)
	if err == nil {
		t.Fatal("expected a port declared as both a stream and an external port to fail")
	}
}

// Exactly one block may dnat a public port on a host interface.
func TestLoadServicesConfigRejectsExternalPortClaimedTwiceOnAHost(t *testing.T) {
	err := loadInlineServices(t, `
versions:
  - lb:
      interfaces:
        edge.example.com:
          eth0: {}
    services:
      alt:
        hosts:
          - edge.example.com
        external_udp_ports: [4053]
      alt2:
        hosts:
          - edge.example.com
        external_udp_ports: [4053]
`)
	if err == nil {
		t.Fatal("expected two services claiming one public port on a host to fail")
	}
}

// The same public port on disjoint hosts has a single owner per host.
func TestLoadServicesConfigAcceptsExternalPortOnDisjointHosts(t *testing.T) {
	err := loadInlineServices(t, `
versions:
  - lb:
      interfaces:
        edge-0.example.com:
          eth0: {}
        edge-1.example.com:
          eth0: {}
    services:
      alt:
        hosts:
          - edge-0.example.com
        external_udp_ports: [4053]
      alt2:
        hosts:
          - edge-1.example.com
        external_udp_ports: [4053]
`)
	if err != nil {
		t.Fatal(err)
	}
}

func TestLoadServicesConfigRejectsExternalPortOutOfRange(t *testing.T) {
	err := loadInlineServices(t, `
versions:
  - lb:
      interfaces:
        edge.example.com:
          eth0: {}
    services:
      alt:
        hosts:
          - edge.example.com
        external_udp_ports: [70000]
`)
	if err == nil {
		t.Fatal("expected an out of range external udp port to fail")
	}
}

// W9 (DESIGN 19.5): a dns edge owns 53 on both protocols, as one service port
// whose tcp and udp claims are separate.
const externalTcpPortsDnsEdgeYaml = `
versions:
  - lb:
      interfaces:
        edge.example.com:
          eth0: {}
        ns-a.example.com:
          eth1:
            transparent: true
    services:
      dnsedge:
        exposed: false
        hosts:
          - ns-a.example.com
        ports: [80]
        external_udp_ports: [53]
        external_tcp_ports: [53]
`

func TestLoadServicesConfigAcceptsHostPinnedExternalTcpPorts(t *testing.T) {
	servicesConfig, err := loadInlineServicesConfig(t, externalTcpPortsDnsEdgeYaml)
	if err != nil {
		t.Fatal(err)
	}
	dnsedgeConfig := servicesConfig.Latest().Services["dnsedge"]
	if got := dnsedgeConfig.ExternalTcpPorts; !slices.Equal(got, []int{53}) {
		t.Fatalf("external tcp ports=%v want=[53]", got)
	}
	allExternalPorts := dnsedgeConfig.AllExternalPorts()
	if !slices.Equal(allExternalPorts["tcp"], []int{53}) || !slices.Equal(allExternalPorts["udp"], []int{53}) {
		t.Fatalf("all external ports=%v want tcp and udp [53]", allExternalPorts)
	}
	// the copy is the caller's to sort
	allExternalPorts["tcp"][0] = 54
	if dnsedgeConfig.ExternalTcpPorts[0] != 53 {
		t.Fatal("all external ports shares its slice with the config")
	}
	// the claim stays out of the lb-fronted port sets, and tcp has no aliases
	if got := dnsedgeConfig.AllStreamPorts()["tcp"]; len(got) != 0 {
		t.Fatalf("stream tcp ports=%v want empty", got)
	}
	if got := dnsedgeConfig.AllHttpPorts()["tcp"]; !slices.Equal(got, []int{80}) {
		t.Fatalf("http tcp ports=%v want=[80]", got)
	}
	if got := dnsedgeConfig.AllExternalForwardPorts(); len(got) != 0 {
		t.Fatalf("external forward ports=%v want none", got)
	}
}

// The tcp claim takes the udp claim's refusals: an lb service, which runs on
// every lb host behind the lb, has no host to install the dnat on; a port the
// lb fronts for the service; a port out of range or repeated; and a port
// another service claims on the same host.
func TestLoadServicesConfigRejectsInvalidExternalTcpPorts(t *testing.T) {
	cases := []struct {
		name    string
		replace string
		with    string
		want    string
	}{
		{
			name:    "an lb service",
			replace: "        hosts:\n          - ns-a.example.com\n",
			with:    "",
			want:    "declares external ports without a hosts list",
		},
		{
			name:    "a tcp stream port of the service",
			replace: "        external_tcp_ports: [53]\n",
			with:    "        tcp_stream_ports: [53]\n        external_tcp_ports: [53]\n",
			want:    "declares tcp port 53 as both an lb port and an external port",
		},
		{
			name:    "an http port of the service",
			replace: "        external_tcp_ports: [53]\n",
			with:    "        external_tcp_ports: [53, 80]\n",
			want:    "declares tcp port 80 as both an lb port and an external port",
		},
		{
			name:    "out of range",
			replace: "        external_tcp_ports: [53]\n",
			with:    "        external_tcp_ports: [70000]\n",
			want:    "external tcp port 70000 is outside 1..65535",
		},
		{
			name:    "repeated",
			replace: "        external_tcp_ports: [53]\n",
			with:    "        external_tcp_ports: [53, 53]\n",
			want:    "repeats external tcp port 53",
		},
		{
			name:    "claimed twice on a host",
			replace: "        external_tcp_ports: [53]\n",
			with:    "        external_tcp_ports: [53]\n      dnsedge-b:\n        exposed: false\n        hosts:\n          - ns-a.example.com\n        external_tcp_ports: [53]\n",
			want:    `services "dnsedge" and "dnsedge-b" both claim external tcp port 53 on ns-a.example.com`,
		},
	}
	for _, c := range cases {
		servicesYaml := strings.Replace(externalTcpPortsDnsEdgeYaml, c.replace, c.with, 1)
		if servicesYaml == externalTcpPortsDnsEdgeYaml {
			t.Fatalf("%s: the fixture has no %q", c.name, c.replace)
		}
		if err := loadInlineServices(t, servicesYaml); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err=%v want %q", c.name, err, c.want)
		}
	}
}

// A claim is per protocol: one service may own udp 53 on a host while another
// owns tcp 53 there, since each dnats only its own protocol, and two dns edges
// on disjoint hosts each own both.
func TestLoadServicesConfigAcceptsExternalPortsOfOtherProtocolsOrHosts(t *testing.T) {
	otherProtocol := strings.Replace(externalTcpPortsDnsEdgeYaml,
		"        external_tcp_ports: [53]\n",
		"      dnsedge-tcp:\n        exposed: false\n        hosts:\n          - ns-a.example.com\n        external_tcp_ports: [53]\n",
		1,
	)
	if err := loadInlineServices(t, otherProtocol); err != nil {
		t.Errorf("udp and tcp 53 owned apart on one host: %v", err)
	}
	otherHost := strings.Replace(externalTcpPortsDnsEdgeYaml,
		"        external_tcp_ports: [53]\n",
		"        external_tcp_ports: [53]\n      dnsedge-b:\n        exposed: false\n        hosts:\n          - edge.example.com\n        external_udp_ports: [53]\n        external_tcp_ports: [53]\n",
		1,
	)
	if err := loadInlineServices(t, otherHost); err != nil {
		t.Errorf("53 owned on two hosts: %v", err)
	}
}

// The production main env lives in the sibling vault repository and is
// git-crypt encrypted at rest, so the assertions run only where a decrypted
// checkout is present, and only on request (WARP_VAULT_TESTS=1): a default
// run never reads the vault. The TestSyntheticMain tests run the same checks
// on synthetic configs. The shape, not the host names, is what is pinned.
func loadSiblingVaultServicesConfig(t *testing.T, env string) *ServicesConfig {
	t.Helper()
	if os.Getenv("WARP_VAULT_TESTS") != "1" {
		t.Skip("reads the sibling production vault; set WARP_VAULT_TESTS=1 to run")
	}
	vaultDir := filepath.Join("..", "..", "vault")
	data, err := os.ReadFile(filepath.Join(vaultDir, env, "services.yml"))
	if err != nil {
		t.Skipf("no sibling vault checkout: %s", err)
	}
	if bytes.HasPrefix(data, []byte("\x00GITCRYPT")) {
		t.Skip("sibling vault checkout is locked")
	}
	servicesConfig, err := LoadServicesConfigFrom(vaultDir, env)
	if err != nil {
		t.Fatal(err)
	}
	return servicesConfig
}

// A synthetic main env with the shape the TestVaultMain checks pin: alt beside
// proxy on the proxy hosts with no lb in front, and connect behind the lb on
// udp 443 and 4053 with public udp 53 forwarded to 4053.
const syntheticMainServicesYaml = `
versions:
  - lb:
      interfaces:
        edge-0.example.com:
          eth0: {}
        proxy-0.example.com:
          eth0: {}
        proxy-1.example.com:
          eth0: {}
      udp_stream_port_services:
        443: connect
        4053: connect
      udp_forward_ports:
        53: 4053
    host_services:
      edge-0.example.com: [connect]
      proxy-0.example.com: [proxy, alt]
      proxy-1.example.com: [proxy, alt]
    services:
      connect:
        ports: [80, 5080, 5090]
        udp_stream_ports: [443, 4053]
      proxy:
        hosts: [proxy-0.example.com, proxy-1.example.com]
        ports: [80]
      alt:
        hosts: [proxy-0.example.com, proxy-1.example.com]
        exposed: false
        ports: [80, 5080, 5090]
        external_udp_ports: [443, 4053]
        blocks:
          - main: 1
`

func loadSyntheticMainServicesConfig(t *testing.T) *ServicesConfig {
	t.Helper()
	servicesConfig, err := loadInlineServicesConfig(t, syntheticMainServicesYaml)
	if err != nil {
		t.Fatal(err)
	}
	return servicesConfig
}

// The alt service runs on the proxy hosts with no lb in front and owns public
// udp 443 and 4053 there (connect/EXTENDER.md 3.L1, 3.L2).
func TestVaultMainAltService(t *testing.T) {
	checkMainAltService(t, loadSiblingVaultServicesConfig(t, "main").Latest())
}

func TestSyntheticMainAltService(t *testing.T) {
	checkMainAltService(t, loadSyntheticMainServicesConfig(t).Latest())
}

func checkMainAltService(t *testing.T, version *ServicesConfigVersion) {
	t.Helper()
	altConfig, ok := version.Services["alt"]
	if !ok {
		t.Fatal("the main env has no alt service")
	}
	proxyConfig, ok := version.Services["proxy"]
	if !ok {
		t.Fatal("the main env has no proxy service")
	}

	if !slices.Equal(altConfig.Hosts, proxyConfig.Hosts) {
		t.Fatalf("alt hosts=%v want the proxy hosts=%v", altConfig.Hosts, proxyConfig.Hosts)
	}
	// host_services must list alt, or it is pinned to hosts it never runs on
	if got := HostsForService(version, "alt"); !slices.Equal(got, slices.Sorted(slices.Values(altConfig.Hosts))) {
		t.Fatalf("alt is placed on %v want=%v", got, altConfig.Hosts)
	}
	if altConfig.IsExposed() {
		t.Fatal("alt is exposed through the lb")
	}
	if 0 < len(altConfig.ExposeAliases) {
		t.Fatalf("alt has lb aliases=%v; the alt names are static dns records", altConfig.ExposeAliases)
	}
	if altConfig.CapNetAdmin {
		t.Fatal("alt requests cap_net_admin, which only the proxy egress path needs")
	}
	if altConfig.IsWebsocket() {
		t.Fatal("alt is marked websocket; the h1 websocket stays on the connect service")
	}
	if got := len(altConfig.Blocks); got != 1 {
		t.Fatalf("alt blocks=%d want 1, so one alt owns the public ports per host", got)
	}

	if got := altConfig.ExternalUdpPorts; !slices.Equal(got, []int{443, 4053}) {
		t.Fatalf("alt external udp ports=%v want=[443 4053]", got)
	}
	if slices.Contains(altConfig.ExternalUdpPorts, 53) {
		t.Fatal("alt claims public udp 53; the router in front forwards 53 to 4053")
	}
	if got := altConfig.AllStreamPorts()["udp"]; len(got) != 0 {
		t.Fatalf("alt udp stream ports=%v want none; alt has no lb in front", got)
	}

	// the exchange allocation and the status port, copied from connect
	connectConfig, ok := version.Services["connect"]
	if !ok {
		t.Fatal("the main env has no connect service")
	}
	altHttpPorts := altConfig.AllHttpPorts()["tcp"]
	if !slices.Equal(altHttpPorts, connectConfig.AllHttpPorts()["tcp"]) {
		t.Fatalf("alt http ports=%v want the connect http ports=%v", altHttpPorts, connectConfig.AllHttpPorts()["tcp"])
	}
	if !slices.Contains(altHttpPorts, 80) {
		t.Fatalf("alt http ports=%v have no status port", altHttpPorts)
	}
	if !slices.Contains(altHttpPorts, 5080) || !slices.Contains(altHttpPorts, 5090) {
		t.Fatalf("alt http ports=%v do not carry the exchange allocation", altHttpPorts)
	}
}

// The whodis port is 4053 everywhere from now on: the lb forwards public 53 to
// it (connect/EXTENDER.md 3.L2). The 8053 listener that the draining lb
// generations forwarded to was dropped in v23, so it is no longer mapped and
// the routers in front of the lb interfaces no longer open it.
func TestVaultMainConnectDnsPortStaysOn4053(t *testing.T) {
	checkMainConnectDnsPort(t, loadSiblingVaultServicesConfig(t, "main").Latest())
}

func TestSyntheticMainConnectDnsPortStaysOn4053(t *testing.T) {
	checkMainConnectDnsPort(t, loadSyntheticMainServicesConfig(t).Latest())
}

func checkMainConnectDnsPort(t *testing.T, version *ServicesConfigVersion) {
	t.Helper()
	udpStreamPortServices := version.Lb.UdpStreamPortServices
	for _, servicePort := range []int{443, 4053} {
		if got := udpStreamPortServices[servicePort]; got != "connect" {
			t.Fatalf("lb udp %d is served by %q want connect", servicePort, got)
		}
	}
	if _, mapped := udpStreamPortServices[8053]; mapped {
		t.Fatal("lb udp 8053 is still mapped; the pre-4053 lb generation has drained")
	}
	if got := version.Lb.UdpForwardPorts[53]; got != 4053 {
		t.Fatalf("lb forwards public udp 53 to %d want 4053", got)
	}

	connectUdpPorts := version.Services["connect"].AllStreamPorts()["udp"]
	for _, servicePort := range []int{443, 4053} {
		if !slices.Contains(connectUdpPorts, servicePort) {
			t.Fatalf("connect udp stream ports=%v have no %d listener", connectUdpPorts, servicePort)
		}
	}
	if slices.Contains(connectUdpPorts, 8053) {
		t.Fatalf("connect udp stream ports=%v still carry 8053", connectUdpPorts)
	}
}

// Every lb interface behind a generated router names its router and port,
// so the routers open exactly what warp publishes there.
func TestVaultMainRouterAttachments(t *testing.T) {
	servicesConfig := loadSiblingVaultServicesConfig(t, "main")
	if got := servicesConfig.RouterNames(); !slices.Equal(got, []string{"by-us-fmt-5-1", "by-us-fmt-5-2", "by-us-fmt-5-3", "by-us-fmt-5-4", "by-us-fmt-5-5", "by-us-fmt-5-6", "by-us-fmt-5-7", "by-us-fmt-5-8", "by-us-fmt-5-9", "by-us-fmt-5-gateway-3"}) {
		t.Fatalf("routers=%v", got)
	}
	// the gateways: two of hurricane electric's, one of ours (planned)
	if got := servicesConfig.GatewayNames(); !slices.Equal(got, []string{"by-us-fmt-5-gateway-1", "by-us-fmt-5-gateway-2", "by-us-fmt-5-gateway-3"}) {
		t.Fatalf("gateways=%v", got)
	}
	for name, want := range map[string][4]string{
		"by-us-fmt-5-gateway-1": {"65.19.157.32/27", "65.19.157.33", "2001:470:173::/48", "2001:470:173::1"},
		"by-us-fmt-5-gateway-2": {"65.49.70.64/27", "65.49.70.65", "2001:470:99::/48", "2001:470:99::1"},
		"by-us-fmt-5-gateway-3": {"72.52.72.192/27", "72.52.72.193", "2001:470:535::/48", "2001:470:535::1"},
	} {
		gateway := servicesConfig.Gateways[name]
		if got := [4]string{gateway.Ipv4, gateway.Ipv4Gateway, gateway.Ipv6, gateway.Ipv6Gateway}; got != want {
			t.Errorf("%s = %v want %v", name, got, want)
		}
	}
	if servicesConfig.IsManagedGateway("by-us-fmt-5-gateway-1") || servicesConfig.IsManagedGateway("by-us-fmt-5-gateway-2") || !servicesConfig.IsManagedGateway("by-us-fmt-5-gateway-3") {
		t.Fatal("only gateway-3 is ours")
	}
	ours := servicesConfig.Routers["by-us-fmt-5-gateway-3"]
	if !ours.Planned || ours.IspInterface != "eth1" || ours.IspIpv6 != "2001:470:3c3:1::/126" || ours.WanIpv4 != "72.52.72.194/27" || ours.WanGatewayIpv4 != "72.52.72.193" || ours.WanIpv6Prefix != "2001:470:535::/48" || !slices.Equal(ours.BlockInterfaces, []string{"eth3", "eth4", "eth5", "eth6", "eth7", "eth8"}) || !slices.Equal(ours.BridgeInterfaces, []string{"eth2"}) || ours.LanIpv4 != "192.168.203.1/24" || ours.Unms != UnmsPending {
		t.Fatalf("gateway-3 = %+v", ours)
	}
	if got := servicesConfig.RoutersBehind("by-us-fmt-5-gateway-2"); !slices.Equal(got, []string{"by-us-fmt-5-1", "by-us-fmt-5-6", "by-us-fmt-5-7", "by-us-fmt-5-8", "by-us-fmt-5-9"}) {
		t.Fatalf("behind gateway-2 = %v", got)
	}
	if got := servicesConfig.RoutersBehind("by-us-fmt-5-gateway-1"); !slices.Equal(got, []string{"by-us-fmt-5-2", "by-us-fmt-5-3", "by-us-fmt-5-4", "by-us-fmt-5-5"}) {
		t.Fatalf("behind gateway-1 = %v", got)
	}
	if got := servicesConfig.RoutersBehind("by-us-fmt-5-gateway-3"); len(got) != 0 {
		t.Fatalf("behind gateway-3 = %v", got)
	}
	// the derived fields
	if r := servicesConfig.Routers["by-us-fmt-5-8"]; r.WanGatewayIpv4 != "65.49.70.65" || r.WanIpv6Prefix != "2001:470:99::/48" || r.WanGatewayIpv6 != "2001:470:99::1" {
		t.Fatalf("5-8 derived fields = %+v", r)
	}
	// the regional lan router: the planetoid backup pulls are its public ports
	lan := servicesConfig.Routers["by-us-fmt-5-1"]
	if lan.GetClass() != RouterClassLan || lan.WanIpv4 != "65.49.70.73/27" || len(lan.LanInterfaces) != 0 || !slices.Equal(lan.BridgeInterfaces, []string{"eth0", "eth2", "eth3", "eth4", "eth5", "eth6", "eth7", "eth8"}) {
		t.Fatalf("lan router = %+v", lan)
	}
	if got := lan.PublicPorts; len(got) != 2 || got[8022] == nil || got[8022].Host != "by-us-fmt-5-edge-2" || got[8022].Port != 22 || got[8023] == nil || got[8023].Host != "by-us-fmt-5-edge-6" || got[8023].Port != 22 || got[8023].GetProtocol() != "tcp" {
		t.Fatalf("lan public ports = %+v", got)
	}
	for _, router := range servicesConfig.RouterNames() {
		if router != "by-us-fmt-5-1" && router != "by-us-fmt-5-gateway-3" && servicesConfig.Routers[router].GetClass() != RouterClassEdge {
			t.Errorf("%s is not an edge router", router)
		}
	}
	// the EdgeRouter 4s keep the platform conntrack sizing, the Infinities
	// carry the larger table; every router runs the same firmware and is
	// attached to uisp
	for _, router := range servicesConfig.RouterNames() {
		routerConfig := servicesConfig.Routers[router]
		if !strings.HasPrefix(routerConfig.Unms, "wss://bringyour.uisp.com:443+") && !(routerConfig.Planned && routerConfig.Unms == UnmsPending) {
			t.Errorf("%s unms = %q", router, routerConfig.Unms)
		}
		infinity := slices.Contains([]string{"by-us-fmt-5-1", "by-us-fmt-5-6", "by-us-fmt-5-7", "by-us-fmt-5-8", "by-us-fmt-5-9", "by-us-fmt-5-gateway-3"}, router)
		if infinity != (routerConfig.ConntrackTableSize == 1048576 && routerConfig.ConntrackHashSize == 131072) {
			t.Errorf("%s conntrack sizing = %d/%d", router, routerConfig.ConntrackTableSize, routerConfig.ConntrackHashSize)
		}
		if routerConfig.EdgeosRelease != "v3.0.1.5862409.250924.1408" {
			t.Errorf("%s edgeos_release = %s", router, routerConfig.EdgeosRelease)
		}
		if routerConfig.MasqueradeWanBlock || routerConfig.OffloadsIpv6Forwarding() || !routerConfig.OffloadsIpv4Forwarding() {
			t.Errorf("%s has unexpected nat or offload toggles", router)
		}
	}
	// the four port routers: WAN eth3, the host on eth0, eth1/eth2 bridged
	for _, router := range []string{"by-us-fmt-5-2", "by-us-fmt-5-3", "by-us-fmt-5-4", "by-us-fmt-5-5"} {
		routerConfig := servicesConfig.Routers[router]
		if routerConfig.WanInterface != "eth3" || !slices.Equal(routerConfig.LanInterfaces, []string{"eth0"}) || !slices.Equal(routerConfig.BridgeInterfaces, []string{"eth1", "eth2"}) {
			t.Errorf("%s port layout = wan %s lan %v bridge %v", router, routerConfig.WanInterface, routerConfig.LanInterfaces, routerConfig.BridgeInterfaces)
		}
		if routerConfig.Gateway != "by-us-fmt-5-gateway-1" || routerConfig.WanIpv6Prefix != "2001:470:173::/48" || routerConfig.WanGatewayIpv4 != "65.19.157.33" {
			t.Errorf("%s is not behind gateway-1", router)
		}
	}
	// the routers' own WAN addresses: the router id as the last octet on the
	// first block, .76/.77 on the second; the hosts keep the addresses dns
	// already names
	for router, wan := range map[string]string{"by-us-fmt-5-2": "65.19.157.52/27", "by-us-fmt-5-3": "65.19.157.53/27", "by-us-fmt-5-4": "65.19.157.54/27", "by-us-fmt-5-5": "65.19.157.55/27", "by-us-fmt-5-6": "65.49.70.76/27", "by-us-fmt-5-7": "65.49.70.78/27"} {
		if got := servicesConfig.Routers[router].WanIpv4; got != wan {
			t.Errorf("%s wan_ipv4 = %s want %s", router, got, wan)
		}
	}
	// the interfaces behind a router that runs the generated configuration.
	// edge-0 and edge-1 sit behind by-us-fmt-5-2 to 5-7, which still run
	// their legacy configuration, so they stay legacy attachments (below)
	// until the cutover attaches them
	want := map[string]string{
		"by-us-fmt-5-edge-3.bringyour.com eno1np0": "by-us-fmt-5-8 eth8",
		"by-us-fmt-5-edge-3.bringyour.com eno2np1": "by-us-fmt-5-8 eth6",
		"by-us-fmt-5-edge-4.bringyour.com eno3":    "by-us-fmt-5-8 eth7",
		"by-us-fmt-5-edge-4.bringyour.com eno4":    "by-us-fmt-5-8 eth5",
		"fireside.bringyour.com eno1np0":           "by-us-fmt-5-9 eth6",
		"crisp.bringyour.com eno1np0":              "by-us-fmt-5-9 eth4",
	}
	// edge-5 left the lb set in v25 to become the MinIO host, freeing
	// by-us-fmt-5-9 eth3
	if _, ok := servicesConfig.Latest().Lb.Interfaces["by-us-fmt-5-edge-5.bringyour.com"]; ok {
		t.Errorf("by-us-fmt-5-edge-5 still has lb interfaces")
	}
	got := map[string]string{}
	for host, lbBlocks := range servicesConfig.Latest().Lb.Interfaces {
		for interfaceName, lbBlock := range lbBlocks {
			if lbBlock.Router != "" {
				got[host+" "+interfaceName] = lbBlock.Router + " " + lbBlock.RouterInterface
			}
		}
	}
	for hostInterface, attachment := range want {
		if got[hostInterface] != attachment {
			t.Errorf("%s is attached to %q want %q", hostInterface, got[hostInterface], attachment)
		}
	}
	if len(got) != len(want) {
		t.Errorf("attachments=%v want exactly the %d interfaces behind the generated routers", got, len(want))
	}
	// the legacy attachments: no router, and an ipv6 only where the legacy
	// router advertises one, from its pre-convention /64 (the bare router id
	// in the fourth hextet); by-us-fmt-5-3 and 5-5 advertise none. A
	// convention address here would name an address no host holds, which dns
	// would publish and the edge-ipv6 signal would page on.
	legacy := map[string]string{
		"by-us-fmt-5-edge-0.bringyour.com eno2": "by-us-fmt-5-2",
		"by-us-fmt-5-edge-0.bringyour.com eno3": "by-us-fmt-5-3",
		"by-us-fmt-5-edge-0.bringyour.com eno4": "by-us-fmt-5-7",
		"by-us-fmt-5-edge-1.bringyour.com eno2": "by-us-fmt-5-6",
		"by-us-fmt-5-edge-1.bringyour.com eno3": "by-us-fmt-5-4",
		"by-us-fmt-5-edge-1.bringyour.com eno4": "by-us-fmt-5-5",
	}
	for hostInterface, router := range legacy {
		host, interfaceName, _ := strings.Cut(hostInterface, " ")
		lbBlock := servicesConfig.Latest().Lb.Interfaces[host][interfaceName]
		if lbBlock == nil {
			t.Errorf("%s is not an lb interface", hostInterface)
			continue
		}
		if lbBlock.Router != "" || lbBlock.RouterInterface != "" {
			t.Errorf("%s is attached to %s %s, but %s runs its legacy configuration", hostInterface, lbBlock.Router, lbBlock.RouterInterface, router)
		}
		if lbBlock.Ipv6 == "" {
			continue
		}
		legacyPrefix, err := RouterLegacyIpv6Prefix(router, servicesConfig.Routers[router])
		if err != nil {
			t.Fatal(err)
		}
		if ipv6, err := netip.ParseAddr(lbBlock.Ipv6); err != nil || !legacyPrefix.Contains(ipv6) {
			t.Errorf("%s ipv6 %s is outside %s, the /64 the legacy %s advertises", hostInterface, lbBlock.Ipv6, legacyPrefix, router)
		}
	}
	// the addresses the hosts hold: the ipv4 dns names (a legacy router
	// holds it in front of the host), the ipv6 by slaac from the /64 of the
	// port and the interface MAC (EUI-64), and the main-lb weights by lb
	// capacity approved on 2026-10-11: 150 on edge-0 eno4 and edge-1 eno2,
	// 50 on edge-3 and edge-4, 10 on the 1G links behind an EdgeRouter 4
	addresses := map[string][]string{
		"by-us-fmt-5-edge-0.bringyour.com eno2":    {"65.19.157.62", "2001:470:173:52:e643:4bff:fe23:a341", "10"},
		"by-us-fmt-5-edge-0.bringyour.com eno3":    {"65.19.157.42", "", "10"},
		"by-us-fmt-5-edge-0.bringyour.com eno4":    {"65.49.70.71", "2001:470:99:57:e643:4bff:fe23:a343", "150"},
		"by-us-fmt-5-edge-1.bringyour.com eno2":    {"65.49.70.70", "2001:470:99:56:e643:4bff:fec3:8446", "150"},
		"by-us-fmt-5-edge-1.bringyour.com eno3":    {"65.19.157.41", "2001:470:173:54:e643:4bff:fec3:8464", "10"},
		"by-us-fmt-5-edge-1.bringyour.com eno4":    {"65.19.157.40", "", "10"},
		"by-us-fmt-5-edge-3.bringyour.com eno1np0": {"65.49.70.84", "2001:470:99:5880:e643:4bff:fe94:e380", "50"},
		"by-us-fmt-5-edge-3.bringyour.com eno2np1": {"65.49.70.85", "2001:470:99:5860:e643:4bff:fe94:e381", "50"},
		"by-us-fmt-5-edge-4.bringyour.com eno3":    {"65.49.70.82", "2001:470:99:5870:e643:4bff:fe89:2bca", "50"},
		"by-us-fmt-5-edge-4.bringyour.com eno4":    {"65.49.70.83", "2001:470:99:5850:e643:4bff:fe89:2bcb", "50"},
	}
	for hostInterface, wantAddresses := range addresses {
		host, interfaceName, _ := strings.Cut(hostInterface, " ")
		lbBlock := servicesConfig.Latest().Lb.Interfaces[host][interfaceName]
		if got := []string{lbBlock.Ipv4, lbBlock.Ipv6, strconv.Itoa(lbBlock.GetDnsWeight())}; !slices.Equal(got, wantAddresses) {
			t.Errorf("%s = %v want %v", hostInterface, got, wantAddresses)
		}
	}
	if got := servicesConfig.Latest().Services["alt"].DnsAliases; !slices.Equal(got, []string{"alt.bringyour.com", "alt-v4.bringyour.com", "alt-v6.bringyour.com"}) {
		t.Errorf("alt dns aliases = %v", got)
	}
	if servicesConfig.Dns == nil || servicesConfig.Dns.Ttl != 60 || !slices.Equal(servicesConfig.Dns.Unmanaged, []string{"bringyour.com", "www.bringyour.com"}) || !slices.Equal(servicesConfig.DnsOtherDomainServices(), []string{"web", "mmm"}) {
		t.Errorf("dns block = %+v", servicesConfig.Dns)
	}
	proxy := servicesConfig.Latest().Services["proxy"]
	if got := proxy.PublicPorts; len(got) != 5 || got[8080] != "socks" || got[8084] != "wg" {
		t.Fatalf("proxy public ports=%v", got)
	}
}

// The derivations TestVaultMainRouterAttachments pins on the production
// topology, on the synthetic router-safety fixture: the router and gateway
// names, which gateway is ours, the routers behind each gateway, the fields a
// router takes from its gateway, the classes, the release and offload
// defaults, and the lb interface attachments and addresses.
func TestSyntheticRouterAttachments(t *testing.T) {
	servicesConfig, err := loadRouterSafetyConfig(t, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := servicesConfig.RouterNames(); !slices.Equal(got, []string{"r-test-1-1", "r-test-1-2", "r-test-1-3", "r-test-1-gateway-1"}) {
		t.Fatalf("routers=%v", got)
	}
	if got := servicesConfig.GatewayNames(); !slices.Equal(got, []string{"r-test-1-gateway-1", "r-test-1-gateway-2"}) {
		t.Fatalf("gateways=%v", got)
	}
	if !servicesConfig.IsManagedGateway("r-test-1-gateway-1") || servicesConfig.IsManagedGateway("r-test-1-gateway-2") {
		t.Fatal("only gateway-1 is ours")
	}
	if got := servicesConfig.RoutersBehind("r-test-1-gateway-1"); !slices.Equal(got, []string{"r-test-1-1", "r-test-1-2", "r-test-1-3"}) {
		t.Fatalf("behind gateway-1 = %v", got)
	}
	if got := servicesConfig.RoutersBehind("r-test-1-gateway-2"); len(got) != 0 {
		t.Fatalf("behind gateway-2 = %v", got)
	}
	// the derived fields: the routers behind gateway-1 and the gateway router
	// itself all take them from gateway-1's entry
	for _, router := range servicesConfig.RouterNames() {
		routerConfig := servicesConfig.Routers[router]
		if routerConfig.WanGatewayIpv4 != "203.0.113.1" || routerConfig.WanIpv6Prefix != "2001:db8:10::/48" || routerConfig.WanGatewayIpv6 != "2001:db8:10::1" {
			t.Errorf("%s derived fields = %+v", router, routerConfig)
		}
		if routerConfig.EdgeosRelease != "synthetic" || routerConfig.MasqueradeWanBlock || routerConfig.OffloadsIpv6Forwarding() || !routerConfig.OffloadsIpv4Forwarding() {
			t.Errorf("%s has unexpected release, nat or offload toggles", router)
		}
	}
	for router, class := range map[string]string{"r-test-1-1": RouterClassEdge, "r-test-1-2": RouterClassEdge, "r-test-1-3": RouterClassLan, "r-test-1-gateway-1": RouterClassGateway} {
		if got := servicesConfig.Routers[router].GetClass(); got != class {
			t.Errorf("%s class = %s want %s", router, got, class)
		}
	}
	want := map[string]string{
		"alpha.example eth0": "r-test-1-1 eth2",
		"alpha.example eth1": "r-test-1-1 eth3",
		"bravo.example eth0": "r-test-1-2 eth2",
	}
	got := map[string]string{}
	for host, lbBlocks := range servicesConfig.Latest().Lb.Interfaces {
		for interfaceName, lbBlock := range lbBlocks {
			if lbBlock.Router != "" {
				got[host+" "+interfaceName] = lbBlock.Router + " " + lbBlock.RouterInterface
			}
		}
	}
	for hostInterface, attachment := range want {
		if got[hostInterface] != attachment {
			t.Errorf("%s is attached to %q want %q", hostInterface, got[hostInterface], attachment)
		}
	}
	if len(got) != len(want) {
		t.Fatalf("attachments=%v want exactly the %d interfaces behind the routers", got, len(want))
	}
	lbBlock := servicesConfig.Latest().Lb.Interfaces["alpha.example"]["eth0"]
	if got := []string{lbBlock.Ipv4, lbBlock.Ipv6, strconv.Itoa(lbBlock.GetDnsWeight())}; !slices.Equal(got, []string{"203.0.113.10", "2001:db8:10:1120::2", "100"}) {
		t.Errorf("alpha.example eth0 = %v", got)
	}
}

// The document-level `default_rate_limit` block is parsed. The lb blocks
// alias it, and a service that runs with no lb in front of it applies the
// same limits itself (connect/EXTENDER.md 3.L5).
func TestServicesConfigParsesTheDefaultRateLimit(t *testing.T) {
	servicesConfig := &ServicesConfig{}
	err := yaml.Unmarshal([]byte(`
default_rate_limit: &default_rate_limit
    requests_per_minute: 450
    burst: 150
    net_connections: 50
    exclude_subnets:
        - "192.0.2.0/24"
        - "2001:db8::/32"

versions:
-   lb:
        interfaces:
            host0:
                eth0:
                    rate_limit: *default_rate_limit
    services: {}
`), servicesConfig)
	if err != nil {
		t.Fatal(err)
	}

	rateLimit := servicesConfig.GetDefaultRateLimit()
	if rateLimit != servicesConfig.DefaultRateLimit {
		t.Fatal("the parsed block is not the effective default rate limit")
	}
	if rateLimit.RequestsPerMinute != 450 || rateLimit.Burst != 150 || rateLimit.NetConnections != 50 {
		t.Fatalf("default rate limit = %+v", rateLimit)
	}
	wantPrefixes := []netip.Prefix{
		netip.MustParsePrefix("192.0.2.0/24"),
		netip.MustParsePrefix("2001:db8::/32"),
	}
	if !slices.Equal(rateLimit.ExcludePrefixes(), wantPrefixes) {
		t.Fatalf("exclude prefixes = %v want %v", rateLimit.ExcludePrefixes(), wantPrefixes)
	}

	// an lb block that aliases the anchor gets the same values
	lbRateLimit := servicesConfig.Latest().Lb.Interfaces["host0"]["eth0"].GetRateLimit()
	if lbRateLimit.RequestsPerMinute != rateLimit.RequestsPerMinute ||
		lbRateLimit.Burst != rateLimit.Burst ||
		lbRateLimit.NetConnections != rateLimit.NetConnections ||
		!slices.Equal(lbRateLimit.ExcludeSubnets, rateLimit.ExcludeSubnets) {
		t.Fatalf("lb rate limit = %+v want %+v", lbRateLimit, rateLimit)
	}
	// the checks TestVaultMainDefaultRateLimit pins on the production main env
	checkMainDefaultRateLimit(t, servicesConfig)
}

// A document with no block falls back to the same defaults an lb block with
// no rate limit of its own gets, so a caller never has to special-case it.
func TestServicesConfigDefaultRateLimitFallsBackToTheWarpDefault(t *testing.T) {
	servicesConfig := &ServicesConfig{}
	if err := yaml.Unmarshal([]byte("versions:\n-   services: {}\n"), servicesConfig); err != nil {
		t.Fatal(err)
	}
	if servicesConfig.DefaultRateLimit != nil {
		t.Fatalf("absent block parsed as %+v", servicesConfig.DefaultRateLimit)
	}
	fallback := servicesConfig.GetDefaultRateLimit()
	warpDefault := DefaultRateLimit()
	if fallback.RequestsPerMinute != warpDefault.RequestsPerMinute ||
		fallback.Burst != warpDefault.Burst ||
		fallback.Delay != warpDefault.Delay ||
		fallback.NetConnections != warpDefault.NetConnections {
		t.Fatalf("fallback = %+v want %+v", fallback, warpDefault)
	}
}

// The production block reaches a service that has no lb in front of it.
func TestVaultMainDefaultRateLimit(t *testing.T) {
	checkMainDefaultRateLimit(t, loadSiblingVaultServicesConfig(t, "main"))
}

func checkMainDefaultRateLimit(t *testing.T, servicesConfig *ServicesConfig) {
	t.Helper()
	rateLimit := servicesConfig.DefaultRateLimit
	if rateLimit == nil {
		t.Fatal("the main env has no default_rate_limit")
	}
	if rateLimit.RequestsPerMinute <= 0 || rateLimit.Burst <= 0 || rateLimit.NetConnections <= 0 {
		t.Fatalf("main default rate limit = %+v", rateLimit)
	}
	if len(rateLimit.ExcludePrefixes()) == 0 {
		t.Fatal("the main default rate limit excludes no subnet")
	}
}

// streamable_paths is a list of api-router-style patterns: service-relative,
// beginning with /, valid regex, on a plain http service. It does not make the
// service `streamable`.
func TestLoadServicesConfigAcceptsStreamablePaths(t *testing.T) {
	servicesConfig, err := loadInlineServicesConfig(t, `
versions:
  - services:
      api:
        streamable_paths:
          - /sn/attempt-artifact
          - /log/[^/]+/upload
`)
	if err != nil {
		t.Fatal(err)
	}
	api := servicesConfig.Versions[0].Services["api"]
	if got := api.GetStreamablePaths(); !slices.Equal(got, []string{"/sn/attempt-artifact", "/log/[^/]+/upload"}) {
		t.Fatalf("streamable paths = %v", got)
	}
	if api.IsStreamable() {
		t.Fatal("streamable_paths does not stream the whole service")
	}
}

// The anchors are implied, so a pattern begins with / and never with ^.
func TestLoadServicesConfigRejectsStreamablePathWithoutLeadingSlash(t *testing.T) {
	for _, streamablePath := range []string{"^/upload/.*", "upload/.*", ""} {
		err := loadInlineServices(t, fmt.Sprintf(`
versions:
  - services:
      api:
        streamable_paths:
          - %q
`, streamablePath))
		if err == nil {
			t.Fatalf("expected streamable path %q to be rejected", streamablePath)
		}
	}
}

func TestLoadServicesConfigRejectsStreamablePathRegexError(t *testing.T) {
	err := loadInlineServices(t, `
versions:
  - services:
      api:
        streamable_paths:
          - "/upload/(.*"
`)
	if err == nil {
		t.Fatal("expected an unbalanced pattern to be rejected")
	}
}

// A `streamable` service streams every path already, and a websocket
// location carries the upgrade headers a nested location would not.
func TestLoadServicesConfigRejectsStreamablePathsOnStreamingOrWebsocketService(t *testing.T) {
	for _, mode := range []string{"streamable: true", "websocket: true"} {
		err := loadInlineServices(t, fmt.Sprintf(`
versions:
  - services:
      api:
        %s
        streamable_paths:
          - /upload/.*
`, mode))
		if err == nil {
			t.Fatalf("expected streamable_paths with %s to be rejected", mode)
		}
	}
}

// The lb compares no_access_log with nginx's $host, which is lowercase with no
// trailing dot, so an entry is spelled the same way before the comparison.
func TestNoAccessLogHostsSpellHostsAsNginxHost(t *testing.T) {
	servicesConfig, err := loadInlineServicesConfig(t, `
no_access_log:
  - www.lag.dev
  - LAG.dev.
  - lag.dev
versions:
  - services:
      mmm:
        expose_aliases: [lag.dev, www.lag.dev]
`)
	if err != nil {
		t.Fatal(err)
	}
	if got := servicesConfig.NoAccessLogHosts(); !slices.Equal(got, []string{"lag.dev", "www.lag.dev"}) {
		t.Fatalf("no_access_log hosts = %v", got)
	}
}

// An entry that can never equal a request's $host would leave the host it was
// meant for logged, so the config does not load.
func TestLoadServicesConfigRejectsInexactNoAccessLogHost(t *testing.T) {
	for _, host := range []string{"*.lag.dev", ".lag.dev", "https://lag.dev", "lag.dev:443", "lag.dev/r/", "lag", ""} {
		err := loadInlineServices(t, fmt.Sprintf(`
no_access_log:
  - %q
versions:
  - services:
      mmm:
        expose_aliases: [lag.dev]
`, host))
		if err == nil || !strings.Contains(err.Error(), "no_access_log") {
			t.Fatalf("no_access_log entry %q: err = %v, want it rejected", host, err)
		}
	}
}

// A document with §13.4's split: two lb hosts, tlsedge on both with stream
// ports 443 and 8443, the lb's http ports 80 and 443.
const tlsSplitServicesYaml = `
versions:
  - lb:
      ports: [80, 443]
      tls_split:
        roots: [root.example]
        service: tlsedge
        proxy_buffer_size: 32kib
        client_hello: {timeout_s: 10, max_bytes: 16384}
      tcp_stream_port_services:
        8443: tlsedge
      interfaces:
        edge-0.example.com:
          eth0: {}
        edge-1.example.com:
          eth0: {}
    services:
      web:
        ports: [80]
      tlsedge:
        ports: [80]
        tcp_stream_ports: [443, 8443]
`

// The split loads, with its values and its defaults read back.
func TestLoadServicesConfigAcceptsATlsSplit(t *testing.T) {
	servicesConfig, err := loadInlineServicesConfig(t, tlsSplitServicesYaml)
	if err != nil {
		t.Fatal(err)
	}
	split := servicesConfig.Latest().Lb.TlsSplit
	if split == nil || !slices.Equal(split.GetRoots(), []string{"root.example"}) || split.GetService() != "tlsedge" {
		t.Fatalf("split %+v", split)
	}
	if byteCount, err := split.GetProxyBufferByteCount(); err != nil || byteCount != 32*1024 {
		t.Errorf("proxy buffer %d, %v", byteCount, err)
	}
	if split.GetClientHelloTimeoutSeconds() != 10 || split.GetClientHelloMaxBytes() != 16384 {
		t.Errorf("client hello %d s, %d bytes", split.GetClientHelloTimeoutSeconds(), split.GetClientHelloMaxBytes())
	}

	// unset: the service is tlsedge, the buffer nginx's, the hello bounds §13.5's
	defaults, err := loadInlineServicesConfig(t, strings.NewReplacer(
		"        service: tlsedge\n", "",
		"        proxy_buffer_size: 32kib\n", "",
		"        client_hello: {timeout_s: 10, max_bytes: 16384}\n", "",
	).Replace(tlsSplitServicesYaml))
	if err != nil {
		t.Fatal(err)
	}
	split = defaults.Latest().Lb.TlsSplit
	if byteCount, err := split.GetProxyBufferByteCount(); err != nil || byteCount != 0 {
		t.Errorf("unset proxy buffer %d, %v", byteCount, err)
	}
	if split.GetService() != TlsEdgeService || split.GetClientHelloTimeoutSeconds() != 10 || split.GetClientHelloMaxBytes() != 16384 {
		t.Errorf("defaults %s %d %d", split.GetService(), split.GetClientHelloTimeoutSeconds(), split.GetClientHelloMaxBytes())
	}
}

// Each split the lb cannot render is refused at load, with its positive twin
// the document above.
func TestLoadServicesConfigRejectsABrokenTlsSplit(t *testing.T) {
	for _, c := range []struct {
		name    string
		old     string
		new     string
		message string
	}{
		{name: "no roots", old: "        roots: [root.example]\n", new: "        roots: []\n", message: "names no roots"},
		{name: "root not a name", old: "roots: [root.example]", new: "roots: [\"*.root.example\"]", message: "not a lowercase dns name"},
		{name: "one label root", old: "roots: [root.example]", new: "roots: [example]", message: "not a lowercase dns name"},
		{name: "nested roots", old: "roots: [root.example]", new: "roots: [root.example, sub.root.example]", message: "is under root"},
		{name: "repeated root", old: "roots: [root.example]", new: "roots: [root.example, root.example]", message: "repeats"},
		{name: "unknown service", old: "        service: tlsedge\n", new: "        service: nothing\n", message: "is not a service"},
		{name: "service without tcp 443", old: "tcp_stream_ports: [443, 8443]", new: "tcp_stream_ports: [8443]", message: "declares no tcp stream port 443"},
		{name: "service missing from an lb host", old: "    services:\n", new: "    host_services:\n      edge-1.example.com: [web]\n    services:\n", message: "does not run on lb host edge-1.example.com"},
		{name: "no http 443", old: "      ports: [80, 443]\n", new: "      ports: [80]\n", message: "needs 443 among the lb's ports"},
		{name: "443 given to a stream service", old: "        8443: tlsedge\n", new: "        8443: tlsedge\n        443: tlsedge\n", message: "tcp_stream_port_services gives"},
		{name: "443 given on an interface", old: "          eth0: {}\n        edge-1", new: "          eth0: {tcp_stream_port_services: {443: tlsedge}}\n        edge-1", message: "edge-0.example.com eth0's tcp_stream_port_services"},
		{name: "proxy buffer not a byte count", old: "proxy_buffer_size: 32kib", new: "proxy_buffer_size: lots", message: "not a positive byte count"},
		{name: "proxy buffer zero", old: "proxy_buffer_size: 32kib", new: "proxy_buffer_size: 0kib", message: "not a positive byte count"},
		{name: "negative hello timeout", old: "timeout_s: 10", new: "timeout_s: -1", message: "client_hello bounds must be positive"},
		{name: "negative hello bytes", old: "max_bytes: 16384", new: "max_bytes: -1", message: "client_hello bounds must be positive"},
	} {
		servicesYaml := strings.Replace(tlsSplitServicesYaml, c.old, c.new, 1)
		if servicesYaml == tlsSplitServicesYaml {
			t.Fatalf("%s: the document lacks %q", c.name, c.old)
		}
		_, err := loadInlineServicesConfig(t, servicesYaml)
		if err == nil || !strings.Contains(err.Error(), c.message) {
			t.Errorf("%s: %v", c.name, err)
		}
	}
}

// tlsedge takes 443, 8443, 8883 and 5671 and nothing else (§22.5): a fifth tcp
// stream port, a udp one, a public port of its own, or a stream port service
// entry giving it another port is refused, and the four load.
func TestLoadServicesConfigHoldsTheTlsEdgeToItsPorts(t *testing.T) {
	fourPorts := strings.NewReplacer(
		"        8443: tlsedge\n", "        8443: tlsedge\n        8883: tlsedge\n        5671: tlsedge\n",
		"tcp_stream_ports: [443, 8443]", "tcp_stream_ports: [443, 8443, 8883, 5671]",
	).Replace(tlsSplitServicesYaml)
	if _, err := loadInlineServicesConfig(t, fourPorts); err != nil {
		t.Fatalf("the four ports: %v", err)
	}
	for _, c := range []struct {
		name    string
		old     string
		new     string
		message string
	}{
		{name: "a fifth tcp stream port", old: "tcp_stream_ports: [443, 8443, 8883, 5671]", new: "tcp_stream_ports: [443, 8443, 8883, 5671, 9443]", message: "declares tcp stream port 9443"},
		{name: "a udp stream port", old: "tcp_stream_ports: [443, 8443, 8883, 5671]\n", new: "tcp_stream_ports: [443, 8443, 8883, 5671]\n        udp_stream_ports: [443]\n", message: "declares udp stream ports"},
		{name: "an external port", old: "tcp_stream_ports: [443, 8443, 8883, 5671]\n", new: "tcp_stream_ports: [443, 8443, 8883, 5671]\n        hosts: [edge-0.example.com, edge-1.example.com]\n        external_tcp_ports: [9000]\n", message: "declares external tcp ports [9000]"},
		{name: "the lb giving it another port", old: "        5671: tlsedge\n", new: "        5671: tlsedge\n        8080: tlsedge\n", message: "gives tls edge \"tlsedge\" tcp port 8080"},
		{name: "the lb giving it a udp port", old: "      tcp_stream_port_services:\n", new: "      udp_stream_port_services:\n        8443: tlsedge\n      tcp_stream_port_services:\n", message: "udp port 8443"},
		{name: "an interface giving it another port", old: "          eth0: {}\n        edge-1", new: "          eth0: {tcp_stream_port_services: {2376: tlsedge}}\n        edge-1", message: "edge-0.example.com eth0 gives"},
	} {
		servicesYaml := strings.Replace(fourPorts, c.old, c.new, 1)
		if servicesYaml == fourPorts {
			t.Fatalf("%s: the document lacks %q", c.name, c.old)
		}
		_, err := loadInlineServicesConfig(t, servicesYaml)
		if err == nil || !strings.Contains(err.Error(), c.message) {
			t.Errorf("%s: %v", c.name, err)
		}
	}

	// a split naming another service holds that one to the same ports
	renamed := strings.NewReplacer("service: tlsedge", "service: edge2", "      tlsedge:\n", "      edge2:\n", ": tlsedge\n", ": edge2\n").Replace(fourPorts)
	if _, err := loadInlineServicesConfig(t, renamed); err != nil {
		t.Fatalf("a renamed edge: %v", err)
	}
	if _, err := loadInlineServicesConfig(t, strings.Replace(renamed, "tcp_stream_ports: [443, 8443, 8883, 5671]", "tcp_stream_ports: [443, 8443, 8883, 5671, 6443]", 1)); err == nil || !strings.Contains(err.Error(), `"edge2" declares tcp stream port 6443`) {
		t.Errorf("a renamed edge on a fifth port: %v", err)
	}
}

// sidecar.yml's drained list: absent file, none; the env's own and the newest
// version's layouts read; a repeated or empty entry and a file that does not
// parse refused.
func TestLoadSidecarDrainedFrom(t *testing.T) {
	configDir := t.TempDir()
	if drained, err := LoadSidecarDrainedFrom(configDir, "test"); err != nil || drained != nil {
		t.Fatalf("absent: %v, %v", drained, err)
	}
	if drained, err := LoadSidecarDrainedFrom(filepath.Join(configDir, "missing"), "test"); err != nil || drained != nil {
		t.Fatalf("no config dir: %v, %v", drained, err)
	}
	envDir := filepath.Join(configDir, "test")
	if err := os.MkdirAll(envDir, 0755); err != nil {
		t.Fatal(err)
	}
	write := func(content string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(envDir, "sidecar.yml"), []byte(content), 0644); err != nil {
			t.Fatal(err)
		}
	}
	write("sidecar:\n  dns: {enabled: false}\n  drained: [edge-3-eno1np0, edge-0-eno2]\n  preview_networks: []\n")
	drained, err := LoadSidecarDrainedFrom(configDir, "test")
	if err != nil || !slices.Equal(drained, []string{"edge-3-eno1np0", "edge-0-eno2"}) {
		t.Fatalf("drained %v, %v", drained, err)
	}
	write("sidecar:\n  dns: {enabled: false}\n")
	if drained, err := LoadSidecarDrainedFrom(configDir, "test"); err != nil || len(drained) != 0 {
		t.Fatalf("none listed: %v, %v", drained, err)
	}
	for _, broken := range []string{
		"sidecar:\n  drained: [edge-3-eno1np0, edge-3-eno1np0]\n",
		"sidecar:\n  drained: [\"\"]\n",
		"sidecar: [\n",
	} {
		write(broken)
		if _, err := LoadSidecarDrainedFrom(configDir, "test"); err == nil {
			t.Errorf("%q loaded", broken)
		}
	}
}
