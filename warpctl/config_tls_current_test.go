package main

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/coreos/go-semver/semver"
)

// A vault with versions of the fixture's wildcard and top names, and with the
// newest version named by the returned value.
func setupTlsCurrentVault(t *testing.T) (env string, vaultDir string, newestVersion string) {
	t.Helper()
	servicesYaml, err := testServicesFS.ReadFile("testdata/services.yml")
	if err != nil {
		t.Fatal(err)
	}
	env, vaultDir = setupTestVaultWithTLS(t, servicesYaml)
	newestVersion = "2.0.0"
	generateTestTLSFiles(t, filepath.Join(vaultDir, "tls", newestVersion), "example.com", true)
	generateTestTLSFiles(t, filepath.Join(vaultDir, "tls", newestVersion), "example.com", false)
	return env, vaultDir, newestVersion
}

func linkTlsCurrent(t *testing.T, vaultDir string, name string, version string) {
	t.Helper()
	currentDir := filepath.Join(vaultDir, "tls", tlsCurrentDirName)
	if err := os.MkdirAll(currentDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join("..", version, name), filepath.Join(currentDir, name)); err != nil {
		t.Fatal(err)
	}
}

func generateTlsConfigs(t *testing.T, env string) map[string]string {
	t.Helper()
	nginxConfig, err := NewNginxConfig(env, nil)
	if err != nil {
		t.Fatal(err)
	}
	return nginxConfig.Generate()
}

// The value of each ssl_certificate and ssl_certificate_key directive, across
// every generated block.
func tlsDirectivePaths(blockConfigs map[string]string) map[string]bool {
	paths := map[string]bool{}
	for _, config := range blockConfigs {
		for _, line := range strings.Split(config, "\n") {
			fields := strings.Fields(strings.TrimSuffix(strings.TrimSpace(line), ";"))
			if len(fields) == 2 && (fields[0] == "ssl_certificate" || fields[0] == "ssl_certificate_key") {
				paths[fields[1]] = true
			}
		}
	}
	return paths
}

func requireTlsPaths(t *testing.T, blockConfigs map[string]string, wantPaths ...string) {
	t.Helper()
	paths := tlsDirectivePaths(blockConfigs)
	for _, wantPath := range wantPaths {
		if !paths[wantPath] {
			t.Errorf("generated config never names %s; it names %v", wantPath, paths)
		}
	}
	if len(paths) != len(wantPaths) {
		t.Errorf("generated config names %d tls paths, want %d: %v", len(paths), len(wantPaths), paths)
	}
}

// What is deployed today: no vault holds tls/current, so the lb must keep
// reading the newest version, as every host holds it. Reading tls/current here
// would stop nginx starting on all of them.
func TestNginxConfigKeepsVersionedTlsPathsWithoutCurrent(t *testing.T) {
	env, _, newestVersion := setupTlsCurrentVault(t)

	requireTlsPaths(t, generateTlsConfigs(t, env),
		fmt.Sprintf("/srv/warp/vault/tls/%s/star.example.com/star.example.com.pem", newestVersion),
		fmt.Sprintf("/srv/warp/vault/tls/%s/star.example.com/star.example.com.key", newestVersion),
	)
}

func TestNginxConfigReadsTlsCurrent(t *testing.T) {
	env, vaultDir, newestVersion := setupTlsCurrentVault(t)
	linkTlsCurrent(t, vaultDir, "star.example.com", newestVersion)

	requireTlsPaths(t, generateTlsConfigs(t, env),
		"/srv/warp/vault/tls/current/star.example.com/star.example.com.pem",
		"/srv/warp/vault/tls/current/star.example.com/star.example.com.key",
	)
}

// Generate walks maps, so two runs over one vault can order their lines
// differently. What a block says is the same if its sorted lines are.
func sortedConfigLines(config string) string {
	lines := strings.Split(config, "\n")
	slices.Sort(lines)
	return strings.Join(lines, "\n")
}

// The reason for tls/current: its paths carry no version, so moving a link
// needs no new lb image.
func TestNginxConfigIsTheSameWhereverCurrentPoints(t *testing.T) {
	env, vaultDir, newestVersion := setupTlsCurrentVault(t)
	linkTlsCurrent(t, vaultDir, "star.example.com", newestVersion)
	atNewest := generateTlsConfigs(t, env)

	link := filepath.Join(vaultDir, "tls", tlsCurrentDirName, "star.example.com")
	if err := os.Remove(link); err != nil {
		t.Fatal(err)
	}
	linkTlsCurrent(t, vaultDir, "star.example.com", "1.0.0")
	atOldest := generateTlsConfigs(t, env)

	if len(atNewest) == 0 {
		t.Fatal("generated no blocks")
	}
	for block, config := range atNewest {
		if sortedConfigLines(config) != sortedConfigLines(atOldest[block]) {
			t.Errorf("block %s changed with the link's target", block)
		}
	}
}

// Links are one form of a tls/current entry. The lb must load the same paths
// from a real directory, and from a tls/current that is itself one link.
func TestNginxConfigReadsTlsCurrentRealDirectory(t *testing.T) {
	env, vaultDir, _ := setupTlsCurrentVault(t)
	generateTestTLSFiles(t, filepath.Join(vaultDir, "tls", tlsCurrentDirName), "example.com", true)

	requireTlsPaths(t, generateTlsConfigs(t, env),
		"/srv/warp/vault/tls/current/star.example.com/star.example.com.pem",
		"/srv/warp/vault/tls/current/star.example.com/star.example.com.key",
	)
}

func TestNginxConfigReadsTlsCurrentThatIsOneLink(t *testing.T) {
	env, vaultDir, newestVersion := setupTlsCurrentVault(t)
	if err := os.Symlink(newestVersion, filepath.Join(vaultDir, "tls", tlsCurrentDirName)); err != nil {
		t.Fatal(err)
	}

	requireTlsPaths(t, generateTlsConfigs(t, env),
		"/srv/warp/vault/tls/current/star.example.com/star.example.com.pem",
		"/srv/warp/vault/tls/current/star.example.com/star.example.com.key",
	)
}

// Names move to tls/current one at a time, so a name without an entry keeps its
// version, and the exact-host-first order holds across the two.
func TestNginxConfigFallsBackToVersionsPerName(t *testing.T) {
	baseYaml, err := testServicesFS.ReadFile("testdata/services.yml")
	if err != nil {
		t.Fatal(err)
	}
	servicesYaml := strings.Replace(
		string(baseYaml),
		"        svc-a:\n",
		"        svc-a:\n            expose_aliases:\n                - manager.example.com\n",
		1,
	)
	env, vaultDir := setupTestVaultWithTLS(t, []byte(servicesYaml))
	exactVersion := "1.5.0"
	generateTestTLSFiles(t, filepath.Join(vaultDir, "tls", exactVersion), "manager.example.com", false)
	linkTlsCurrent(t, vaultDir, "star.example.com", "1.0.0")

	requireTlsPaths(t, generateTlsConfigs(t, env),
		"/srv/warp/vault/tls/current/star.example.com/star.example.com.pem",
		"/srv/warp/vault/tls/current/star.example.com/star.example.com.key",
		fmt.Sprintf("/srv/warp/vault/tls/%s/manager.example.com/manager.example.com.pem", exactVersion),
		fmt.Sprintf("/srv/warp/vault/tls/%s/manager.example.com/manager.example.com.key", exactVersion),
	)
}

// vault/<env> outranks vault/all for tls/current as it does for versions.
func TestNginxConfigKeepsEnvOverAllForTlsCurrent(t *testing.T) {
	env, vaultDir, newestVersion := setupTlsCurrentVault(t)
	allDir := filepath.Join(filepath.Dir(vaultDir), "all")
	generateTestTLSFiles(t, filepath.Join(allDir, "tls", newestVersion), "example.com", true)
	linkTlsCurrent(t, allDir, "star.example.com", newestVersion)

	requireTlsPaths(t, generateTlsConfigs(t, env),
		fmt.Sprintf("/srv/warp/vault/tls/%s/star.example.com/star.example.com.pem", newestVersion),
		fmt.Sprintf("/srv/warp/vault/tls/%s/star.example.com/star.example.com.key", newestVersion),
	)
}

func TestNginxConfigReadsTlsCurrentFromAll(t *testing.T) {
	baseYaml, err := testServicesFS.ReadFile("testdata/services.yml")
	if err != nil {
		t.Fatal(err)
	}
	env := setupTestVault(t, baseYaml)
	allDir := filepath.Join(os.Getenv("WARP_HOME"), "vault", "all")
	generateTestTLSFiles(t, filepath.Join(allDir, "tls", "1.0.0"), "example.com", true)
	generateTestTLSFiles(t, filepath.Join(allDir, "tls", "1.0.0"), "example.com", false)
	linkTlsCurrent(t, allDir, "star.example.com", "1.0.0")

	requireTlsPaths(t, generateTlsConfigs(t, env),
		"/srv/warp/vault/tls/current/star.example.com/star.example.com.pem",
		"/srv/warp/vault/tls/current/star.example.com/star.example.com.key",
	)
}

// A broken entry must not read as an absent one. That would bake the name's
// version into the lb image, and the next swap would quietly miss it until the
// certificate expired.
func TestNginxConfigRefusesDanglingTlsCurrent(t *testing.T) {
	env, vaultDir, _ := setupTlsCurrentVault(t)
	linkTlsCurrent(t, vaultDir, "star.example.com", "9.9.9")

	_, err := NewNginxConfig(env, nil)
	if err == nil || !strings.Contains(err.Error(), "star.example.com") {
		t.Fatalf("NewNginxConfig error = %v, want one naming the broken entry", err)
	}
}

func TestNginxConfigRefusesTlsCurrentMissingItsKey(t *testing.T) {
	env, vaultDir, newestVersion := setupTlsCurrentVault(t)
	keyPath := filepath.Join(vaultDir, "tls", newestVersion, "star.example.com", "star.example.com.key")
	if err := os.Remove(keyPath); err != nil {
		t.Fatal(err)
	}
	linkTlsCurrent(t, vaultDir, "star.example.com", newestVersion)

	if _, err := NewNginxConfig(env, nil); err == nil {
		t.Fatal("NewNginxConfig accepted a tls/current entry with no key")
	}
}

func TestNginxConfigRefusesDanglingTlsCurrentLink(t *testing.T) {
	env, vaultDir, _ := setupTlsCurrentVault(t)
	if err := os.Symlink("9.9.9", filepath.Join(vaultDir, "tls", tlsCurrentDirName)); err != nil {
		t.Fatal(err)
	}

	if _, err := NewNginxConfig(env, nil); err == nil {
		t.Fatal("NewNginxConfig accepted a tls/current that is a dangling link")
	}
}

// A swap leaves its temporary link beside the entries only if it died midway,
// and an operator's finder leaves files there. Neither is a name.
func TestNginxConfigIgnoresHiddenTlsCurrentEntries(t *testing.T) {
	env, vaultDir, newestVersion := setupTlsCurrentVault(t)
	linkTlsCurrent(t, vaultDir, "star.example.com", newestVersion)
	hiddenPath := filepath.Join(vaultDir, "tls", tlsCurrentDirName, ".star.example.com.swap")
	if err := os.Symlink("../9.9.9/star.example.com", hiddenPath); err != nil {
		t.Fatal(err)
	}

	if _, err := NewNginxConfig(env, nil); err != nil {
		t.Fatal(err)
	}
}

// Every reader that walks tls/ for versions, here and in server's resolver,
// skips what does not parse as a semver, and that is all that keeps tls/current
// out of their results: server's jwt keyring treats each key it finds as a
// signing key version. Those readers never see this name while it stays this
// way.
func TestTlsCurrentIsNotAVersion(t *testing.T) {
	if _, err := semver.NewVersion(tlsCurrentDirName); err == nil {
		t.Fatalf("%q parses as a version", tlsCurrentDirName)
	}
}

// Let's Encrypt certificates no longer name an OCSP responder, so stapling has
// nothing to do, and nginx warns of that at every start and reload.
func TestNginxConfigDoesNotStaple(t *testing.T) {
	env, _, _ := setupTlsCurrentVault(t)

	blockConfigs := generateTlsConfigs(t, env)
	if len(blockConfigs) == 0 {
		t.Fatal("generated no blocks")
	}
	for block, config := range blockConfigs {
		if strings.Contains(config, "ssl_stapling") {
			t.Errorf("block %s still staples", block)
		}
	}
}

// The real nginx loads the generated paths through a link, which is what the
// config tests above cannot show.
func TestNginxConfigValidationThroughTlsCurrent(t *testing.T) {
	nginxBinary := nginxConfigValidationBinary(t)

	env, vaultDir, newestVersion := setupTlsCurrentVault(t)
	linkTlsCurrent(t, vaultDir, "star.example.com", newestVersion)

	for block, config := range generateTlsConfigs(t, env) {
		if !strings.Contains(config, "/srv/warp/vault/tls/current/star.example.com/") {
			t.Fatalf("block %s does not read tls/current", block)
		}
		tmpDir := t.TempDir()
		confPath := filepath.Join(tmpDir, "nginx.conf")
		if err := os.WriteFile(confPath, []byte(localNginxConfig(config, vaultDir)), 0644); err != nil {
			t.Fatal(err)
		}
		for _, dir := range []string{"logs", "run"} {
			if err := os.MkdirAll(filepath.Join(tmpDir, dir), 0755); err != nil {
				t.Fatal(err)
			}
		}
		output, err := runNginxConfigTest(nginxBinary, confPath, tmpDir)
		if err != nil {
			t.Errorf("nginx refused block %s: %v\n%s", block, err, output)
		}
	}
}
