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

	"gopkg.in/yaml.v3"
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
	if err != nil {
		t.Fatal(err)
	}

	var fullConfig ServicesConfig
	if err := yaml.Unmarshal(baseYaml, &fullConfig); err != nil {
		t.Fatal(err)
	}
	totalVersions := len(fullConfig.Versions)
	if totalVersions < 2 {
		t.Fatal("Need at least 2 versions to test stability")
	}

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

				if curAssign.externalPort != prevAssign.externalPort {
					t.Errorf(
						"version %d: external port changed for %s/%s/%s port %d: %d -> %d",
						numVersions, key.host, key.service, key.block, key.port,
						prevAssign.externalPort, curAssign.externalPort,
					)
				}

				prevInternals := map[int]bool{}
				for _, p := range prevAssign.internalPorts {
					prevInternals[p] = true
				}
				for _, p := range curAssign.internalPorts {
					delete(prevInternals, p)
				}
				if len(prevInternals) > 0 {
					t.Errorf(
						"version %d: internal ports lost for %s/%s/%s port %d: previously had %v, now has %v",
						numVersions, key.host, key.service, key.block, key.port,
						prevAssign.internalPorts, curAssign.internalPorts,
					)
				}
			}
		}

		prevAssignments = currentAssignments
	}
}

func TestPortBlockNoOverlap(t *testing.T) {
	baseYaml, err := testServicesFS.ReadFile("testdata/services.yml")
	if err != nil {
		t.Fatal(err)
	}

	env := setupTestVault(t, baseYaml)
	hostPortBlocks := getPortBlocks(env)

	for host, services := range hostPortBlocks {
		externalToOwner := map[int]string{}
		internalToOwner := map[int]string{}

		for service, blocks := range services {
			for block, ports := range blocks {
				for port, pb := range ports {
					owner := fmt.Sprintf("%s/%s/%d", service, block, port)

					if existing, ok := externalToOwner[pb.externalPort]; ok {
						t.Errorf(
							"host %s: external port %d claimed by both %s and %s",
							host, pb.externalPort, existing, owner,
						)
					}
					externalToOwner[pb.externalPort] = owner

					for _, ip := range pb.internalPorts {
						if existing, ok := internalToOwner[ip]; ok {
							t.Errorf(
								"host %s: internal port %d claimed by both %s and %s",
								host, ip, existing, owner,
							)
						}
						internalToOwner[ip] = owner

						if _, ok := externalToOwner[ip]; ok {
							t.Errorf(
								"host %s: port %d used as both external and internal",
								host, ip,
							)
						}
					}

					if _, ok := internalToOwner[pb.externalPort]; ok {
						t.Errorf(
							"host %s: port %d used as both external (%s) and internal",
							host, pb.externalPort, owner,
						)
					}
				}
			}
		}
	}
}

func TestPortBlockForcedExternalPorts(t *testing.T) {
	baseYaml, err := testServicesFS.ReadFile("testdata/services.yml")
	if err != nil {
		t.Fatal(err)
	}

	env := setupTestVault(t, baseYaml)
	hostPortBlocks := getPortBlocks(env)

	expected := map[string]map[int]int{
		"edge-0.example.com-eth0": {80: 7080, 443: 7443},
		"edge-0.example.com-eth1": {80: 7081, 443: 7444},
		"edge-1.example.com-eth0": {80: 7082, 443: 7445},
		"edge-1.example.com-eth1": {80: 7083, 443: 7446},
	}

	for host, services := range hostPortBlocks {
		lbBlocks, ok := services["lb"]
		if !ok {
			continue
		}
		for block, ports := range lbBlocks {
			if expectedPorts, ok := expected[block]; ok {
				for servicePort, expectedExternal := range expectedPorts {
					if pb, ok := ports[servicePort]; ok {
						if pb.externalPort != expectedExternal {
							t.Errorf(
								"host %s block %s: forced external port for service port %d: want %d, got %d",
								host, block, servicePort, expectedExternal, pb.externalPort,
							)
						}
					}
				}
			}
		}
	}
}

func TestPortBlockInternalPortCount(t *testing.T) {
	baseYaml, err := testServicesFS.ReadFile("testdata/services.yml")
	if err != nil {
		t.Fatal(err)
	}

	env := setupTestVault(t, baseYaml)
	hostPortBlocks := getPortBlocks(env)

	var fullConfig ServicesConfig
	if err := yaml.Unmarshal(baseYaml, &fullConfig); err != nil {
		t.Fatal(err)
	}
	expectedParallelBlockCount := fullConfig.Versions[0].ParallelBlockCount

	for host, services := range hostPortBlocks {
		for service, blocks := range services {
			for block, ports := range blocks {
				for port, pb := range ports {
					if len(pb.internalPorts) != expectedParallelBlockCount {
						t.Errorf(
							"host %s service %s block %s port %d: want %d internal ports, got %d",
							host, service, block, port,
							expectedParallelBlockCount, len(pb.internalPorts),
						)
					}
				}
			}
		}
	}
}

func TestNginxConfigValidation(t *testing.T) {
	if _, err := exec.LookPath("nginx"); err != nil {
		t.Skip("nginx not found in PATH")
	}

	baseYaml, err := testServicesFS.ReadFile("testdata/services.yml")
	if err != nil {
		t.Fatal(err)
	}

	env, vaultDir := setupTestVaultWithTLS(t, baseYaml)

	nginxConfig, err := NewNginxConfig(env, nil)
	if err != nil {
		t.Fatal(err)
	}

	blockConfigs := nginxConfig.Generate()
	if len(blockConfigs) == 0 {
		t.Fatal("no nginx configs generated")
	}

	for block, config := range blockConfigs {
		t.Run(block, func(t *testing.T) {
			// rewrite paths for local validation
			config = strings.ReplaceAll(config, "/srv/warp/vault/", vaultDir+"/")

			// strip directives that require root or linux-specific paths
			config = strings.ReplaceAll(config, "user www-data;", "")
			config = strings.ReplaceAll(config, "pid /run/nginx.pid;", "")
			config = strings.ReplaceAll(config, "include /etc/nginx/modules-enabled/*.conf;", "")
			config = strings.ReplaceAll(config, "use epoll;", "")

			// replace linux-specific paths with local equivalents
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

			// replace docker network hostnames with localhost so nginx can resolve them
			config = strings.ReplaceAll(config, "server testservices:", "server 127.0.0.1:")

			// strip directives that won't work locally
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
			if err := os.WriteFile(confPath, []byte(config), 0644); err != nil {
				t.Fatal(err)
			}

			// create required directories for nginx
			for _, dir := range []string{"logs", "run"} {
				os.MkdirAll(filepath.Join(tmpDir, dir), 0755)
			}

			cmd := exec.Command("nginx", "-t", "-c", confPath, "-p", tmpDir, "-e", filepath.Join(tmpDir, "error.log"))
			output, err := cmd.CombinedOutput()
			if err != nil {
				t.Errorf("nginx config validation failed for block %s:\n%s\n\nConfig written to: %s", block, string(output), confPath)
			}
		})
	}
}
