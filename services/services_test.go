package services

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
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
