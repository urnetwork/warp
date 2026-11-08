// Tests for how an lb build resolves tls paths once a vault can hold tls/current:
// which paths it bakes, which vaults it refuses, and that a vault without
// tls/current bakes what it always did.

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
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

// Links tls/current/<name> to one version, relatively, as sidecarctl's certs swap
// writes it.
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

// Every block's config, as `warpctl lb create-config` would write it.
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

// Fails unless the configs name exactly these tls paths, so that a stray versioned
// path fails as a missing one does.
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

// W5 itself: a name the vault holds in tls/current is read from there, whatever
// versions hold it too.
func TestNginxConfigReadsTlsCurrent(t *testing.T) {
	env, vaultDir, newestVersion := setupTlsCurrentVault(t)
	linkTlsCurrent(t, vaultDir, "star.example.com", newestVersion)

	requireTlsPaths(t, generateTlsConfigs(t, env),
		"/srv/warp/vault/tls/current/star.example.com/star.example.com.pem",
		"/srv/warp/vault/tls/current/star.example.com/star.example.com.key",
	)
}

// A pair line as sidecarctl's certs swap reads an lb's paths from it
// (lbTlsPathRegex in sidecar/sidecarctl/cmd_certs_swap.go): the directive, then a
// path holding no space or semicolon, then the semicolon. The swap reads only
// lines of this shape, so a line it could not read would leave it seeing no name
// there and refusing every swap.
var swapTlsLineRegex = regexp.MustCompile(`^\s*ssl_certificate(?:_key)?\s+([^\s;]+)\s*;\s*$`)

// The other half of the swap's reading: every pair line the build writes has the
// swap's shape, and names the path the swap looks for, the vault mount's
// tls/current/<name>/<name>.pem or .key, for a name the vault holds there.
func TestNginxConfigWritesTlsLinesTheSwapReads(t *testing.T) {
	env, vaultDir, newestVersion := setupTlsCurrentVault(t)
	linkTlsCurrent(t, vaultDir, "star.example.com", newestVersion)
	wantPaths := []string{
		"/srv/warp/vault/tls/current/star.example.com/star.example.com.pem",
		"/srv/warp/vault/tls/current/star.example.com/star.example.com.key",
	}

	lineCount := 0
	for block, config := range generateTlsConfigs(t, env) {
		for _, line := range strings.Split(config, "\n") {
			trimmed := strings.TrimSpace(line)
			if !strings.Contains(line, "ssl_certificate") || strings.HasPrefix(trimmed, "#") {
				continue
			}
			lineCount += 1
			match := swapTlsLineRegex.FindStringSubmatch(line)
			if match == nil {
				t.Errorf("block %s writes %q, a pair line the swap cannot read", block, line)
				continue
			}
			if !slices.Contains(wantPaths, match[1]) {
				t.Errorf("block %s reads %s, not a path the swap moves", block, match[1])
			}
		}
	}
	if lineCount == 0 {
		t.Fatal("the build wrote no pair line, so this read nothing")
	}
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

// tls/current as one link to a version, rather than a directory of links.
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

// vault/all holds the certificates, so tls/current has to work there.
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

// Both homes an lb build reads tls from: vault/<env>, and vault/all, where the
// certificates live.
func tlsHomeDirs(vaultDir string) []string {
	return []string{vaultDir, filepath.Join(filepath.Dir(vaultDir), "all")}
}

// A broken entry must not read as an absent one. That would bake the name's
// version into the lb image, and the next swap would quietly miss it until the
// certificate expired.
func TestNginxConfigRefusesDanglingTlsCurrent(t *testing.T) {
	for homeIndex := range 2 {
		env, vaultDir, _ := setupTlsCurrentVault(t)
		linkTlsCurrent(t, tlsHomeDirs(vaultDir)[homeIndex], "star.example.com", "9.9.9")

		_, err := NewNginxConfig(env, nil)
		if err == nil || !strings.Contains(err.Error(), "star.example.com") {
			t.Errorf("home %d: NewNginxConfig error = %v, want one naming the broken entry", homeIndex, err)
		}
	}
}

// A pair needs both its files, in either home. In each case the name still
// resolves to a good pair in a version, so nothing but the check refuses it.
func TestNginxConfigRefusesTlsCurrentMissingAFile(t *testing.T) {
	for homeIndex := range 2 {
		for _, fileName := range []string{"star.example.com.pem", "star.example.com.key"} {
			env, vaultDir, _ := setupTlsCurrentVault(t)
			homeDir := tlsHomeDirs(vaultDir)[homeIndex]
			generateTestTLSFiles(t, filepath.Join(homeDir, "tls", "3.0.0"), "example.com", true)
			if err := os.Remove(filepath.Join(homeDir, "tls", "3.0.0", "star.example.com", fileName)); err != nil {
				t.Fatal(err)
			}
			linkTlsCurrent(t, homeDir, "star.example.com", "3.0.0")

			_, err := NewNginxConfig(env, nil)
			if err == nil || !strings.Contains(err.Error(), fileName) {
				t.Errorf("home %d: NewNginxConfig error = %v, want one naming %s", homeIndex, err, fileName)
			}
		}
	}
}

// A tls/current that is one dangling link holds no entry to refuse, and is still
// not an absence.
func TestNginxConfigRefusesDanglingTlsCurrentLink(t *testing.T) {
	for homeIndex := range 2 {
		env, vaultDir, _ := setupTlsCurrentVault(t)
		tlsDir := filepath.Join(tlsHomeDirs(vaultDir)[homeIndex], "tls")
		if err := os.MkdirAll(tlsDir, 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("9.9.9", filepath.Join(tlsDir, tlsCurrentDirName)); err != nil {
			t.Fatal(err)
		}

		if _, err := NewNginxConfig(env, nil); err == nil {
			t.Errorf("home %d: NewNginxConfig accepted a tls/current that is a dangling link", homeIndex)
		}
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
