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

func TestLatest(t *testing.T) {
	servicesConfig := mustLoad(t)
	if servicesConfig.Latest() != servicesConfig.Versions[0] {
		t.Error("Latest() should be Versions[0]")
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
