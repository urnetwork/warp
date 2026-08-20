package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"embed"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-playground/assert/v2"
	"gopkg.in/yaml.v3"

	"github.com/urnetwork/warp/services"
)

//go:embed testdata/services.yml
var testServicesFS embed.FS

type portAssignment struct {
	externalPort  int
	internalPorts []int
}

type portAssignmentKey struct {
	host    string
	service string
	block   string
	port    int
}

func setupTestVault(t *testing.T, servicesYaml []byte) string {
	t.Helper()
	tmpDir := t.TempDir()
	warpHome := tmpDir
	vaultDir := filepath.Join(warpHome, "vault", "test")
	if err := os.MkdirAll(vaultDir, 0755); err != nil {
		t.Fatal(err)
	}
	warpSettingsPath := filepath.Join(warpHome, "warp.json")
	if err := os.WriteFile(warpSettingsPath, []byte(`{}`), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(vaultDir, "services.yml"), servicesYaml, 0644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("WARP_HOME", warpHome)
	return "test"
}

func generateTestTLSFiles(t *testing.T, dir string, domain string, wildcard bool) {
	t.Helper()

	var keyDirName, pemFileName, keyFileName string
	if wildcard {
		keyDirName = fmt.Sprintf("star.%s", domain)
		pemFileName = fmt.Sprintf("star.%s.pem", domain)
		keyFileName = fmt.Sprintf("star.%s.key", domain)
	} else {
		keyDirName = domain
		pemFileName = fmt.Sprintf("%s.pem", domain)
		keyFileName = fmt.Sprintf("%s.key", domain)
	}

	certDir := filepath.Join(dir, keyDirName)
	if err := os.MkdirAll(certDir, 0755); err != nil {
		t.Fatal(err)
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: domain},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
		DNSNames:     []string{domain},
	}
	if wildcard {
		template.DNSNames = append(template.DNSNames, "*."+domain)
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	if err := os.WriteFile(filepath.Join(certDir, pemFileName), certPEM, 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(certDir, keyFileName), keyPEM, 0600); err != nil {
		t.Fatal(err)
	}
}

func setupTestVaultWithTLS(t *testing.T, servicesYaml []byte) (env string, vaultDir string) {
	t.Helper()
	tmpDir := t.TempDir()
	warpHome := tmpDir
	vaultDir = filepath.Join(warpHome, "vault", "test")
	if err := os.MkdirAll(vaultDir, 0755); err != nil {
		t.Fatal(err)
	}
	warpSettingsPath := filepath.Join(warpHome, "warp.json")
	if err := os.WriteFile(warpSettingsPath, []byte(`{}`), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(vaultDir, "services.yml"), servicesYaml, 0644); err != nil {
		t.Fatal(err)
	}

	tlsDir := filepath.Join(vaultDir, "tls", "1.0.0")
	if err := os.MkdirAll(tlsDir, 0755); err != nil {
		t.Fatal(err)
	}
	generateTestTLSFiles(t, tlsDir, "example.com", true)
	generateTestTLSFiles(t, tlsDir, "example.com", false)

	t.Setenv("WARP_HOME", warpHome)
	return "test", vaultDir
}

func collectPortAssignments(hostPortBlocks map[string]map[string]map[string]map[int]*PortBlock) map[portAssignmentKey]portAssignment {
	assignments := map[portAssignmentKey]portAssignment{}
	for host, services := range hostPortBlocks {
		for service, blocks := range services {
			for block, ports := range blocks {
				for port, pb := range ports {
					key := portAssignmentKey{
						host:    host,
						service: service,
						block:   block,
						port:    port,
					}
					internalCopy := make([]int, len(pb.internalPorts))
					copy(internalCopy, pb.internalPorts)
					assignments[key] = portAssignment{
						externalPort:  pb.externalPort,
						internalPorts: internalCopy,
					}
				}
			}
		}
	}
	return assignments
}

// buildVersionedConfig creates a services.yml containing only the last numVersions
// versions from the base config. It does this by parsing the YAML into a generic
// structure to avoid round-trip issues with typed fields.
func buildVersionedConfig(t *testing.T, baseYaml []byte, numVersions int) []byte {
	t.Helper()

	var raw map[string]any
	if err := yaml.Unmarshal(baseYaml, &raw); err != nil {
		t.Fatalf("failed to parse base config: %v", err)
	}

	versions, ok := raw["versions"].([]any)
	if !ok {
		t.Fatal("versions field missing or wrong type")
	}

	totalVersions := len(versions)
	raw["versions"] = versions[totalVersions-numVersions:]

	out, err := yaml.Marshal(raw)
	if err != nil {
		t.Fatalf("failed to marshal config: %v", err)
	}
	return out
}

func TestPortBlockStabilityAcrossVersions(t *testing.T) {
	baseYaml, err := testServicesFS.ReadFile("testdata/services.yml")
	assert.Equal(t, err, nil)

	var fullConfig services.ServicesConfig
	err = yaml.Unmarshal(baseYaml, &fullConfig)
	assert.Equal(t, err, nil)
	totalVersions := len(fullConfig.Versions)
	assert.Equal(t, totalVersions >= 2, true)

	var prevAssignments map[portAssignmentKey]portAssignment

	for numVersions := 1; numVersions <= totalVersions; numVersions++ {
		configYaml := buildVersionedConfig(t, baseYaml, numVersions)
		env := setupTestVault(t, configYaml)
		hostPortBlocks := getPortBlocks(env)
		currentAssignments := collectPortAssignments(hostPortBlocks)

		if prevAssignments != nil {
			for key, prevAssign := range prevAssignments {
				curAssign, ok := currentAssignments[key]
				if !ok {
					continue
				}

				assert.Equal(t, curAssign.externalPort, prevAssign.externalPort)

				prevInternals := map[int]bool{}
				for _, p := range prevAssign.internalPorts {
					prevInternals[p] = true
				}
				for _, p := range curAssign.internalPorts {
					delete(prevInternals, p)
				}
				assert.Equal(t, len(prevInternals), 0)
			}
		}

		prevAssignments = currentAssignments
	}
}

func TestPortBlockNoOverlap(t *testing.T) {
	baseYaml, err := testServicesFS.ReadFile("testdata/services.yml")
	assert.Equal(t, err, nil)

	env := setupTestVault(t, baseYaml)
	hostPortBlocks := getPortBlocks(env)

	for _, services := range hostPortBlocks {
		externalToOwner := map[int]string{}
		internalToOwner := map[int]string{}

		for service, blocks := range services {
			for block, ports := range blocks {
				for port, pb := range ports {
					owner := fmt.Sprintf("%s/%s/%d", service, block, port)

					_, externalClaimed := externalToOwner[pb.externalPort]
					assert.Equal(t, externalClaimed, false)
					externalToOwner[pb.externalPort] = owner

					for _, ip := range pb.internalPorts {
						_, internalClaimed := internalToOwner[ip]
						assert.Equal(t, internalClaimed, false)
						internalToOwner[ip] = owner

						_, usedAsExternal := externalToOwner[ip]
						assert.Equal(t, usedAsExternal, false)
					}

					_, usedAsInternal := internalToOwner[pb.externalPort]
					assert.Equal(t, usedAsInternal, false)
				}
			}
		}
	}
}

func TestPortBlockForcedExternalPorts(t *testing.T) {
	baseYaml, err := testServicesFS.ReadFile("testdata/services.yml")
	assert.Equal(t, err, nil)

	env := setupTestVault(t, baseYaml)
	hostPortBlocks := getPortBlocks(env)

	expected := map[string]map[int]int{
		"edge-0.example.com-eth0": {80: 7080, 443: 7443},
		"edge-0.example.com-eth1": {80: 7081, 443: 7444},
		"edge-1.example.com-eth0": {80: 7082, 443: 7445},
		"edge-1.example.com-eth1": {80: 7083, 443: 7446},
	}

	for _, services := range hostPortBlocks {
		lbBlocks, ok := services["lb"]
		if !ok {
			continue
		}
		for block, ports := range lbBlocks {
			if expectedPorts, ok := expected[block]; ok {
				for servicePort, expectedExternal := range expectedPorts {
					if pb, ok := ports[servicePort]; ok {
						assert.Equal(t, pb.externalPort, expectedExternal)
					}
				}
			}
		}
	}
}

func TestPortBlockInternalPortCount(t *testing.T) {
	baseYaml, err := testServicesFS.ReadFile("testdata/services.yml")
	assert.Equal(t, err, nil)

	env := setupTestVault(t, baseYaml)
	hostPortBlocks := getPortBlocks(env)

	var fullConfig services.ServicesConfig
	err = yaml.Unmarshal(baseYaml, &fullConfig)
	assert.Equal(t, err, nil)
	expectedParallelBlockCount := fullConfig.Versions[0].ParallelBlockCount

	for _, services := range hostPortBlocks {
		for _, blocks := range services {
			for _, ports := range blocks {
				for _, pb := range ports {
					assert.Equal(t, len(pb.internalPorts), expectedParallelBlockCount)
				}
			}
		}
	}
}

func TestGetBlocksSummaryTransparent(t *testing.T) {
	servicesYaml := []byte(`
domain: example.com
domains:
    example.com: route53

versions:
-   external_ports: 7000-7200,7443-7449
    internal_ports: 7201-7442,7450-10000
    routing_tables: 100-120
    parallel_block_count: 30
    services_docker_network: testservices
    lb:
        ports:
            - 80
            - 443
        interfaces:
            edge-0.example.com:
                eth0:
                    docker_network: warpeth0
                    concurrent_clients: 786432
                    cores: 24
                    ipv4: 10.0.0.1
                    ipv6: "fd00::1"
            metrics-0.example.com:
                eth0:
                    transparent: true
                    docker_network: warpeth0
                    ipv4: 10.0.0.2
                    ipv6: "fd00::2"
    host_services:
        metrics-0.example.com:
            - svc-everywhere
            - svc-direct
    services:
        svc-everywhere:
            ports:
                - 80
            blocks:
                - g1: 1
        svc-direct:
            hosts:
                - metrics-0.example.com
            ports:
                - 80
            blocks:
                - g1: 1
        svc-normal:
            ports:
                - 80
            blocks:
                - g1: 1
`)

	env := setupTestVault(t, servicesYaml)

	// routed by both the normal lb and the transparent host, so pollable via the lb
	_, transparent := getBlocksSummary(env, "svc-everywhere")
	assert.Equal(t, transparent, false)

	// only on the transparent host, so not pollable via the lb
	_, transparent = getBlocksSummary(env, "svc-direct")
	assert.Equal(t, transparent, true)

	_, transparent = getBlocksSummary(env, "svc-normal")
	assert.Equal(t, transparent, false)

	// the lb blocks are themselves the lb, and not all of them are transparent
	_, transparent = getBlocksSummary(env, "lb")
	assert.Equal(t, transparent, false)
}

func TestNginxConfigValidation(t *testing.T) {
	nginxBinary := ""
	if configuredBinary := os.Getenv("NGINX_UDP_PROXY_V2_BINARY"); configuredBinary != "" {
		resolvedBinary, err := exec.LookPath(configuredBinary)
		if err != nil {
			t.Fatalf("NGINX_UDP_PROXY_V2_BINARY=%q is not executable: %v", configuredBinary, err)
		}
		nginxBinary = resolvedBinary
	} else {
		candidates := []string{
			filepath.Join("..", "lb", "build", "nginx-local", "sbin", "nginx"),
			"/tmp/urnetwork-nginx-udp-v2-full/sbin/nginx",
			"nginx",
		}
		for _, candidate := range candidates {
			if resolvedBinary, err := exec.LookPath(candidate); err == nil {
				nginxBinary = resolvedBinary
				break
			}
		}
	}
	if nginxBinary == "" {
		t.Skip("NGINX not found; run `make nginx_local` in warp/lb")
	}
	versionOutput, err := exec.Command(nginxBinary, "-v").CombinedOutput()
	if err != nil {
		t.Fatalf("read nginx version: %v: %s", err, versionOutput)
	}
	var major int
	var minor int
	var patch int
	if _, err := fmt.Sscanf(string(versionOutput), "nginx version: nginx/%d.%d.%d", &major, &minor, &patch); err != nil {
		t.Fatalf("parse nginx version %q: %v", versionOutput, err)
	}
	if major < 1 || (major == 1 && (minor < 31 || (minor == 31 && patch < 4))) {
		t.Skipf("nginx %d.%d.%d cannot parse UDP upstream PROXY protocol v2; set NGINX_UDP_PROXY_V2_BINARY", major, minor, patch)
	}

	baseYaml, err := testServicesFS.ReadFile("testdata/services.yml")
	assert.Equal(t, err, nil)

	env, vaultDir := setupTestVaultWithTLS(t, baseYaml)

	nginxConfig, err := NewNginxConfig(env, nil)
	assert.Equal(t, err, nil)

	blockConfigs := nginxConfig.Generate()
	assert.NotEqual(t, len(blockConfigs), 0)

	for block, config := range blockConfigs {
		config = strings.ReplaceAll(config, "/srv/warp/vault/", vaultDir+"/")

		config = strings.ReplaceAll(config, "user www-data;", "")
		config = strings.ReplaceAll(config, "pid /run/nginx.pid;", "")
		config = strings.ReplaceAll(config, "include /etc/nginx/modules-enabled/*.conf;", "")
		config = strings.ReplaceAll(config, "use epoll;", "")

		mimeTypesLocations := []string{
			"/opt/homebrew/etc/nginx/mime.types",
			"/usr/local/etc/nginx/mime.types",
			"/etc/nginx/mime.types",
		}
		localMimeTypes := ""
		for _, p := range mimeTypesLocations {
			if _, err := os.Stat(p); err == nil {
				localMimeTypes = p
				break
			}
		}
		if localMimeTypes != "" {
			config = strings.ReplaceAll(config, "include /etc/nginx/mime.types;", "include "+localMimeTypes+";")
		} else {
			config = strings.ReplaceAll(config, "include /etc/nginx/mime.types;", "")
		}

		config = strings.ReplaceAll(config, "server testservices:", "server 127.0.0.1:")

		lines := strings.Split(config, "\n")
		filtered := make([]string, 0, len(lines))
		for _, line := range lines {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "ssl_dhparam") {
				continue
			}
			if strings.HasPrefix(trimmed, "resolver ") {
				continue
			}
			if strings.HasPrefix(trimmed, "ssl_stapling") {
				continue
			}
			filtered = append(filtered, line)
		}
		config = strings.Join(filtered, "\n")

		tmpDir := t.TempDir()
		confPath := filepath.Join(tmpDir, "nginx.conf")
		err := os.WriteFile(confPath, []byte(config), 0644)
		assert.Equal(t, err, nil)

		for _, dir := range []string{"logs", "run"} {
			os.MkdirAll(filepath.Join(tmpDir, dir), 0755)
		}

		cmd := exec.Command(nginxBinary, "-t", "-c", confPath, "-p", tmpDir, "-e", filepath.Join(tmpDir, "error.log"))
		output, err := cmd.CombinedOutput()
		if err != nil {
			t.Errorf("nginx config validation failed for block %s:\n%s\n\nConfig written to: %s", block, string(output), confPath)
		}
	}
}

func TestVS2023CorsWildcardNeverAllowsCredentials(t *testing.T) {
	baseYaml := []byte(`
domain: example.com
domains:
  example.com: test
versions:
  - external_ports: 7000-7100
    internal_ports: 7200-7300
    routing_tables: 100-110
    parallel_block_count: 1
    services_docker_network: testservices
    lb:
      ports:
        - 80
        - 443
      interfaces:
        edge.example.com:
          eth0:
            docker_network: warpeth0
            concurrent_clients: 1
            cores: 1
            ipv4: 192.0.2.1
    services:
      api:
        cors_origins:
          - https://example.com
        ports:
          - 80
        blocks:
          - g1: 1
      mcp:
        cors_origins_from: api
        ports:
          - 80
        blocks:
          - g1: 1
`)

	generate := func(servicesYaml []byte) string {
		t.Helper()
		env, _ := setupTestVaultWithTLS(t, servicesYaml)
		nginxConfig, err := NewNginxConfig(env, nil)
		if err != nil {
			t.Fatal(err)
		}
		blockConfigs := nginxConfig.Generate()
		configs := make([]string, 0, len(blockConfigs))
		for _, config := range blockConfigs {
			configs = append(configs, config)
		}
		return strings.Join(configs, "\n")
	}

	exactConfig := generate(baseYaml)
	if !strings.Contains(exactConfig, "add_header 'Access-Control-Allow-Credentials' 'true' always;") {
		t.Fatal("exact-origin CORS did not permit credentialed requests")
	}
	if !strings.Contains(exactConfig, "add_header 'Vary' 'Origin' always;") {
		t.Fatal("exact-origin CORS did not vary caches by Origin")
	}

	wildcardYaml := []byte(strings.ReplaceAll(string(baseYaml), "https://example.com", `"*"`))
	wildcardConfig := generate(wildcardYaml)
	if !strings.Contains(wildcardConfig, "set $cors_origin '*';") {
		t.Fatal("wildcard CORS origin was not rendered")
	}
	if strings.Contains(wildcardConfig, "Access-Control-Allow-Credentials") {
		t.Fatal("wildcard CORS was combined with credential permission")
	}
	if strings.Contains(wildcardConfig, "add_header 'Vary' 'Origin'") {
		t.Fatal("wildcard CORS unnecessarily varied caches by Origin")
	}
}

// A stream port declared for BOTH tcp and udp (e.g. a memberlist gossip port)
// must produce exactly one nginx `upstream stream-service-block-<svc>-<port>`
// block. Emitting it once per protocol makes nginx fail with a "duplicate
// upstream" emerg that aborts the entire lb config (regression:
// config.go addStreamUpstreamBlocks). svc-c declares 5353 as both a tcp and a
// udp stream port in testdata/services.yml. Unlike TestNginxConfigValidation
// this needs no nginx binary -- it inspects the generated config directly.
func TestNginxStreamUpstreamDedupedForTcpUdpPort(t *testing.T) {
	baseYaml, err := testServicesFS.ReadFile("testdata/services.yml")
	assert.Equal(t, err, nil)

	env, _ := setupTestVaultWithTLS(t, baseYaml)

	nginxConfig, err := NewNginxConfig(env, nil)
	assert.Equal(t, err, nil)

	blockConfigs := nginxConfig.Generate()
	assert.NotEqual(t, len(blockConfigs), 0)

	// the `upstream ` prefix matches the upstream declaration, not the
	// `proxy_pass stream-service-block-...` references, so the count is the
	// number of upstream blocks for this port.
	upstreamDecl := "upstream stream-service-block-svc-c-5353"
	sawUpstream := false
	for block, config := range blockConfigs {
		count := strings.Count(config, upstreamDecl)
		if count > 0 {
			sawUpstream = true
		}
		if count > 1 {
			t.Errorf("duplicate stream upstream for a tcp+udp port in block %s: %q appears %d times (want 1)", block, upstreamDecl, count)
		}
	}
	assert.Equal(t, sawUpstream, true)
}

// UDP needs PPv2 source metadata while existing TCP backends retain PPv1.
func TestNginxStreamProxyProtocolVersionMatchesTransport(t *testing.T) {
	baseYaml, err := testServicesFS.ReadFile("testdata/services.yml")
	assert.Equal(t, err, nil)

	env, _ := setupTestVaultWithTLS(t, baseYaml)
	nginxConfig, err := NewNginxConfig(env, nil)
	assert.Equal(t, err, nil)

	blockConfigs := nginxConfig.Generate()
	assert.NotEqual(t, len(blockConfigs), 0)

	udpServerCount := 0
	tcpServerCount := 0
	for blockName, config := range blockConfigs {
		for _, port := range []int{443, 5353} {
			listen := fmt.Sprintf("listen %d udp reuseport;", port)
			searchAt := 0
			for {
				listenAt := strings.Index(config[searchAt:], listen)
				if listenAt < 0 {
					break
				}
				listenAt += searchAt
				endAt := strings.Index(config[listenAt:], "}")
				if endAt < 0 {
					t.Fatalf("block %s UDP/%d server has no closing brace", blockName, port)
				}
				serverBlock := config[listenAt : listenAt+endAt]
				for _, required := range []string{
					fmt.Sprintf("listen [::]:%d udp reuseport;", port),
					"proxy_protocol v2;",
					"proxy_timeout 30s;",
					"proxy_requests 0;",
					fmt.Sprintf("proxy_pass stream-service-block-svc-c-%d;", port),
				} {
					if !strings.Contains(serverBlock, required) {
						t.Fatalf("block %s UDP/%d server omits %q:\n%s", blockName, port, required, serverBlock)
					}
				}
				udpServerCount += 1
				searchAt = listenAt + len(listen)
			}
		}

		for _, port := range []int{444, 1080, 5353} {
			listen := fmt.Sprintf("listen %d;", port)
			searchAt := 0
			for {
				listenAt := strings.Index(config[searchAt:], listen)
				if listenAt < 0 {
					break
				}
				listenAt += searchAt
				endAt := strings.Index(config[listenAt:], "}")
				if endAt < 0 {
					t.Fatalf("block %s TCP/%d server has no closing brace", blockName, port)
				}
				serverBlock := config[listenAt : listenAt+endAt]
				if !strings.Contains(serverBlock, "proxy_protocol on;") {
					t.Fatalf("block %s TCP/%d server does not preserve PROXY protocol v1:\n%s", blockName, port, serverBlock)
				}
				tcpServerCount += 1
				searchAt = listenAt + len(listen)
			}
		}
	}

	if udpServerCount == 0 || tcpServerCount == 0 {
		t.Fatalf("did not find both UDP and TCP stream servers: udp=%d tcp=%d", udpServerCount, tcpServerCount)
	}
}

// Legacy edge blocks without sizing still need a syntactically valid config.
func TestNginxConfigWithoutCapacitySizingRetainsRequiredEventsBlock(t *testing.T) {
	baseYaml, err := testServicesFS.ReadFile("testdata/services.yml")
	assert.Equal(t, err, nil)

	servicesYaml := strings.ReplaceAll(
		string(baseYaml),
		"                    concurrent_clients: 786432\n",
		"",
	)
	servicesYaml = strings.ReplaceAll(
		servicesYaml,
		"                    cores: 24\n",
		"",
	)
	env, _ := setupTestVaultWithTLS(t, []byte(servicesYaml))
	nginxConfig, err := NewNginxConfig(env, nil)
	assert.Equal(t, err, nil)

	blockConfigs := nginxConfig.Generate()
	assert.NotEqual(t, len(blockConfigs), 0)
	for blockName, config := range blockConfigs {
		if !strings.Contains(config, "events {") {
			t.Fatalf("block %s omits the required events section", blockName)
		}
		if !strings.Contains(config, "worker_connections 512;") {
			t.Fatalf("block %s does not retain the nginx default worker connection capacity", blockName)
		}
	}
}

// The lb terminates user traffic, so it must not write down who its users are.
// nginx makes that easy to lose by accident: an `access_log` with no format
// name silently falls back to the built-in "combined", which leads with
// $remote_addr, and a missing main level `error_log` sends stream errors --
// which carry the client address -- to a file inside the container rather than
// through the lb process that scrubs them (see warp.ClientAddrScrubber).
func TestNginxLogsOmitClientAddr(t *testing.T) {
	baseYaml, err := testServicesFS.ReadFile("testdata/services.yml")
	assert.Equal(t, err, nil)

	env, _ := setupTestVaultWithTLS(t, baseYaml)

	nginxConfig, err := NewNginxConfig(env, nil)
	assert.Equal(t, err, nil)

	blockConfigs := nginxConfig.Generate()
	assert.NotEqual(t, len(blockConfigs), 0)

	// every variable that resolves to the address of the peer on the other end
	// of the connection, directly or via a header it forwarded
	clientAddrVars := []string{
		"$remote_addr",
		"$binary_remote_addr",
		"$realip_remote_addr",
		"$proxy_protocol_addr",
		"$proxy_add_x_forwarded_for",
		"$http_x_forwarded_for",
		"$http_x_real_ip",
		"$http_x_ur_forwarded_for",
	}

	for block, config := range blockConfigs {
		sawLogFormat := false
		sawAccessLog := false
		sawMainErrorLog := false

		// a log_format wraps across lines, so collect each statement through to
		// its terminating `;` before looking for addresses in it
		statement := ""

		for _, line := range strings.Split(config, "\n") {
			trimmed := strings.TrimSpace(line)

			// main level directives are the only ones generated unindented, and
			// the main level is what the stream block inherits
			if line == "error_log stderr;" {
				sawMainErrorLog = true
			}

			if statement != "" || strings.HasPrefix(trimmed, "log_format ") {
				statement += " " + trimmed
				if !strings.HasSuffix(trimmed, ";") {
					continue
				}
				sawLogFormat = true
				for _, clientAddrVar := range clientAddrVars {
					if strings.Contains(statement, clientAddrVar) {
						t.Errorf("block %s logs the client address (%s): %q", block, clientAddrVar, strings.TrimSpace(statement))
					}
				}
				statement = ""
				continue
			}

			if strings.HasPrefix(trimmed, "access_log ") {
				sawAccessLog = true
				fields := strings.Fields(strings.TrimSuffix(trimmed, ";"))
				// `access_log <target>;` names no format, so nginx uses
				// "combined" -- $remote_addr first
				if len(fields) < 3 && fields[1] != "off" {
					t.Errorf("block %s access_log names no format, so nginx logs the client address via \"combined\": %q", block, trimmed)
				}
			}
		}

		assert.Equal(t, sawLogFormat, true)
		assert.Equal(t, sawAccessLog, true)
		assert.Equal(t, sawMainErrorLog, true)
	}
}

// Production unit rendering must keep the proxy capability exception narrow
// while giving Grafana only its fixed uid, scoped secret, and computed peers.
func TestSystemdUnitsRenderContainerIsolationContract(t *testing.T) {
	servicesYaml := []byte(`
domain: example.com
versions:
  - external_ports: 7000-7200
    internal_ports: 7201-7400
    routing_tables: 100-120
    parallel_block_count: 4
    services_docker_network: services
    lb:
      ports: [80]
      interfaces:
        edge-a.example.com:
          eth0:
            docker_network: warpeth0
    services:
      grafana:
        user: "65532:65532"
        secret_files: [grafana.yml]
        mount:
          vault: no
          config: yes
          docker: no
        ports: [80, 3000, 3101, 3201]
        tcp_stream_ports: [6490, 6491, 6492, 6493]
        udp_stream_ports: [6492, 6493]
        blocks:
          - g1: 1
      proxy:
        cap_net_admin: true
        ports: [8080]
        blocks:
          - g1: 1
`)
	env := setupTestVault(t, servicesYaml)
	hostUnits := NewSystemdUnits(env, "/srv/warp/main", "/usr/local/bin/warpctl", true).Generate()["edge-a.example.com"]

	proxyUnit := hostUnits["proxy"]["g1"].serviceUnit
	if !strings.Contains(proxyUnit, "--cap_net_admin=yes") {
		t.Fatalf("proxy unit omits capability exception:\n%s", proxyUnit)
	}

	grafanaUnit := hostUnits["grafana"]["g1"].serviceUnit
	for _, required := range []string{
		"--cap_net_admin=no",
		"--mount_vault=no",
		"--mount_docker=no",
		"--user=65532:65532",
		"--secret-file=grafana.yml",
		"--envvar=WARP_RING_HOSTS:edge-a.example.com",
	} {
		if !strings.Contains(grafanaUnit, required) {
			t.Fatalf("grafana unit omits %q:\n%s", required, grafanaUnit)
		}
	}
}

func TestSystemdUnitsPropagateForwardPortsOnlyToLoadBalancer(t *testing.T) {
	baseYaml, err := testServicesFS.ReadFile("testdata/services.yml")
	if err != nil {
		t.Fatal(err)
	}
	env := setupTestVault(t, baseYaml)
	hostUnits := NewSystemdUnits(env, "/srv/warp/main", "/usr/local/bin/warpctl", true).Generate()

	lbCount := 0
	for _, serviceUnits := range hostUnits {
		for service, blockUnits := range serviceUnits {
			for _, units := range blockUnits {
				hasForwardPorts := strings.Contains(units.serviceUnit, `--forwardports="udp:53:5353"`)
				if service == "lb" {
					lbCount++
					if !hasForwardPorts {
						t.Fatalf("lb unit omits forward-port configuration:\n%s", units.serviceUnit)
					}
				} else if hasForwardPorts {
					t.Fatalf("non-lb unit %s received forward-port configuration", service)
				}
			}
		}
	}
	if lbCount == 0 {
		t.Fatal("test generated no load-balancer units")
	}
}

func TestForwardPortEncodingIsDeterministicAndRoundTrips(t *testing.T) {
	forwardPorts := newForwardPorts()
	forwardPorts["udp"][443] = 8443
	forwardPorts["tcp"][25] = 2525
	forwardPorts["udp"][53] = 8053

	encoded := formatForwardPorts(forwardPorts)
	if want := "tcp:25:2525;udp:53:8053;udp:443:8443"; encoded != want {
		t.Fatalf("encoded=%q want=%q", encoded, want)
	}
	if got := fmt.Sprint(parseForwardPorts(encoded)); got != fmt.Sprint(forwardPorts) {
		t.Fatalf("round trip=%s want=%v", got, forwardPorts)
	}
}

// Keeps rolling privacy bounded to the immediately preceding generation and
// ignores a former target that is absent from the current LB allocation.
func TestRollingPrivateForwardTargetPortsKeepsOnlyPreviousActiveTargets(t *testing.T) {
	config := &services.ServicesConfig{Versions: []*services.ServicesConfigVersion{
		{
			Lb: &services.LbConfig{
				StreamPortServiceConfig: services.StreamPortServiceConfig{
					UdpStreamPortServices: map[int]string{443: "connect", 4053: "connect", 8053: "connect"},
				},
				ForwardPortConfig: services.ForwardPortConfig{UdpForwardPorts: map[int]int{53: 4053}},
			},
		},
		{
			Lb: &services.LbConfig{
				StreamPortServiceConfig: services.StreamPortServiceConfig{
					UdpStreamPortServices: map[int]string{443: "connect", 8053: "connect", 9053: "connect"},
				},
				ForwardPortConfig: services.ForwardPortConfig{
					UdpForwardPorts: map[int]int{53: 8053},
					TcpForwardPorts: map[int]int{54: 9053},
				},
			},
		},
		{
			Lb: &services.LbConfig{
				StreamPortServiceConfig: services.StreamPortServiceConfig{
					UdpStreamPortServices: map[int]string{7053: "connect"},
				},
				ForwardPortConfig: services.ForwardPortConfig{UdpForwardPorts: map[int]int{53: 7053}},
			},
		},
	}}

	if got, want := fmt.Sprint(rollingPrivateForwardTargetPorts(config)), "[8053]"; got != want {
		t.Fatalf("rolling private targets=%s want=%s", got, want)
	}
}

// Proves the migration metadata crosses the configuration/runtime boundary;
// helper-only tests would miss an omitted systemd argument.
func TestSystemdUnitsCarryPreviousForwardTargetAsPrivatePort(t *testing.T) {
	servicesYaml := []byte(`
domain: example.com
versions:
  - external_ports: 7000-7200,7443-7449
    internal_ports: 7201-7442,7450-7600
    routing_tables: 100-120
    parallel_block_count: 4
    services_docker_network: services
    lb:
      ports: [80, 443]
      udp_stream_port_services:
        443: connect
        4053: connect
        8053: connect
      udp_forward_ports:
        53: 4053
      interfaces:
        edge-a.example.com:
          eth0:
            docker_network: warpeth0
            ipv4: 10.0.0.1
    services:
      connect:
        ports: [80]
        udp_stream_ports: [443, 4053, 8053]
        blocks:
          - g1: 1
  - external_ports: 7000-7200,7443-7449
    internal_ports: 7201-7442,7450-7600
    routing_tables: 100-120
    parallel_block_count: 4
    services_docker_network: services
    lb:
      ports: [80, 443]
      udp_stream_port_services:
        443: connect
        8053: connect
      udp_forward_ports:
        53: 8053
      interfaces:
        edge-a.example.com:
          eth0:
            docker_network: warpeth0
            ipv4: 10.0.0.1
    services:
      connect:
        ports: [80]
        udp_stream_ports: [443, 8053]
        blocks:
          - g1: 1
`)
	env := setupTestVault(t, servicesYaml)
	hostUnits := NewSystemdUnits(env, "/srv/warp/main", "/usr/local/bin/warpctl", true).Generate()["edge-a.example.com"]

	lbCount := 0
	for service, blockUnits := range hostUnits {
		for _, units := range blockUnits {
			hasPrivatePort := strings.Contains(units.serviceUnit, `--privateports="8053"`)
			if service == "lb" {
				lbCount++
				if !hasPrivatePort {
					t.Fatalf("lb unit omits previous private target:\n%s", units.serviceUnit)
				}
			} else if hasPrivatePort {
				t.Fatalf("non-lb unit %s received private-port configuration", service)
			}
		}
	}
	if lbCount == 0 {
		t.Fatal("test generated no load-balancer units")
	}
}
