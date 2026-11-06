package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"
)

// Stands in for the docker cli through outAndLogFunc, so that no test here can
// reach a real daemon. It answers the census with lines and records each exec.
type fakeLbDocker struct {
	// what `docker ps` prints, one `<id> <block>` per line
	lines []string
	// fails the census
	censusErr error
	// fails the reload of these container ids
	reloadErrs map[string]error
	// runs at each reload, and answers it when it fails
	onReload func(containerId string) error

	censusArgs [][]string
	reloadArgs [][]string
}

func (self *fakeLbDocker) install(t *testing.T) {
	t.Helper()
	previous := outAndLogFunc
	t.Cleanup(func() { outAndLogFunc = previous })
	outAndLogFunc = func(cmd *exec.Cmd) ([]byte, error) {
		// on linux docker() runs through sudo
		args := cmd.Args[slices.Index(cmd.Args, "docker")+1:]
		switch args[0] {
		case "ps":
			self.censusArgs = append(self.censusArgs, args)
			if self.censusErr != nil {
				return nil, self.censusErr
			}
			return []byte(strings.Join(self.lines, "\n") + "\n"), nil
		case "exec":
			self.reloadArgs = append(self.reloadArgs, args)
			containerId := args[1]
			if self.onReload != nil {
				if err := self.onReload(containerId); err != nil {
					return nil, err
				}
			}
			return nil, self.reloadErrs[containerId]
		}
		t.Errorf("unexpected docker command %v", args)
		return nil, errors.New("unexpected docker command")
	}
}

func newFakeLbDocker(t *testing.T) *fakeLbDocker {
	t.Helper()
	fake := &fakeLbDocker{
		lines: []string{"aaaa11 edge-0.example.com-eth0"},
	}
	fake.install(t)
	return fake
}

// A flat vault home, as a host holds it, with versions 1.0.0 and 2.0.0 of the
// wildcard and top names.
func setupCertsSwapVault(t *testing.T) string {
	t.Helper()
	vaultHome := t.TempDir()
	for _, version := range []string{"1.0.0", "2.0.0"} {
		versionHome := filepath.Join(vaultHome, "tls", version)
		generateTestTLSFiles(t, versionHome, "example.com", true)
		generateTestTLSFiles(t, versionHome, "example.com", false)
	}
	return vaultHome
}

func tlsCurrentLinkPath(vaultHome string, name string) string {
	return filepath.Join(vaultHome, "tls", tlsCurrentDirName, name)
}

func requireTlsLink(t *testing.T, vaultHome string, name string, wantTarget string) {
	t.Helper()
	target, err := os.Readlink(tlsCurrentLinkPath(vaultHome, name))
	if err != nil {
		t.Fatal(err)
	}
	if target != wantTarget {
		t.Fatalf("%s links to %q, want %q", name, target, wantTarget)
	}
}

// Replaces a name's key in a version with one that does not match its
// certificate.
func mismatchTlsPair(t *testing.T, vaultHome string, version string, name string, otherVersion string) {
	t.Helper()
	otherKey, err := os.ReadFile(filepath.Join(vaultHome, "tls", otherVersion, name, name+".key"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(vaultHome, "tls", version, name, name+".key"), otherKey, 0600); err != nil {
		t.Fatal(err)
	}
}

// The state a refused swap must leave: nothing moved and nothing reloaded.
func requireNothingSwapped(t *testing.T, vaultHome string, fake *fakeLbDocker) {
	t.Helper()
	if _, err := os.Lstat(filepath.Join(vaultHome, "tls", tlsCurrentDirName)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("tls/current exists after a refused swap: %v", err)
	}
	if len(fake.reloadArgs) != 0 {
		t.Errorf("a refused swap reloaded nginx: %v", fake.reloadArgs)
	}
}

func TestCertsSwapPointsCurrentAtVersion(t *testing.T) {
	vaultHome := setupCertsSwapVault(t)
	newFakeLbDocker(t)

	if err := swapTlsCurrent(vaultHome, "main", "2.0.0", defaultCertsSwapSettings()); err != nil {
		t.Fatal(err)
	}

	for _, name := range []string{"example.com", "star.example.com"} {
		requireTlsLink(t, vaultHome, name, filepath.Join("..", "2.0.0", name))
		for _, fileName := range []string{name + ".pem", name + ".key"} {
			want, err := os.ReadFile(filepath.Join(vaultHome, "tls", "2.0.0", name, fileName))
			if err != nil {
				t.Fatal(err)
			}
			got, err := os.ReadFile(filepath.Join(tlsCurrentLinkPath(vaultHome, name), fileName))
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, want) {
				t.Errorf("tls/current/%s/%s is not version 2.0.0's", name, fileName)
			}
		}
	}
}

// The vault mounts at another path in the container, so a link that named the
// host's path would dangle there, and nginx would fail to load it.
func TestCertsSwapLinksAreRelative(t *testing.T) {
	vaultHome := setupCertsSwapVault(t)
	newFakeLbDocker(t)

	if err := swapTlsCurrent(vaultHome, "main", "2.0.0", defaultCertsSwapSettings()); err != nil {
		t.Fatal(err)
	}

	mountedHome := filepath.Join(t.TempDir(), "mounted")
	if err := os.Rename(vaultHome, mountedHome); err != nil {
		t.Fatal(err)
	}
	pemPath := filepath.Join(tlsCurrentLinkPath(mountedHome, "star.example.com"), "star.example.com.pem")
	if _, err := os.Stat(pemPath); err != nil {
		t.Fatalf("the link does not resolve from another mount: %v", err)
	}
}

// W5's order: the reload must find every link already moved.
func TestCertsSwapMovesLinksBeforeReload(t *testing.T) {
	vaultHome := setupCertsSwapVault(t)
	fake := newFakeLbDocker(t)
	if err := swapTlsCurrent(vaultHome, "main", "1.0.0", defaultCertsSwapSettings()); err != nil {
		t.Fatal(err)
	}
	fake.reloadArgs = nil

	reloads := 0
	fake.onReload = func(containerId string) error {
		reloads += 1
		for _, name := range []string{"example.com", "star.example.com"} {
			requireTlsLink(t, vaultHome, name, filepath.Join("..", "2.0.0", name))
		}
		return nil
	}

	if err := swapTlsCurrent(vaultHome, "main", "2.0.0", defaultCertsSwapSettings()); err != nil {
		t.Fatal(err)
	}
	if reloads != 1 {
		t.Fatalf("reloaded %d times, want 1", reloads)
	}
}

// A pair moves in one rename: a reader sees the old pair up to that call and
// the new pair after it, and never one of each.
func TestCertsSwapMovesEachLinkInOneStep(t *testing.T) {
	vaultHome := setupCertsSwapVault(t)
	newFakeLbDocker(t)
	if err := swapTlsCurrent(vaultHome, "main", "1.0.0", defaultCertsSwapSettings()); err != nil {
		t.Fatal(err)
	}

	settings := defaultCertsSwapSettings()
	moved := []string{}
	settings.rename = func(oldPath string, newPath string) error {
		name := filepath.Base(newPath)
		requireTlsLink(t, vaultHome, name, filepath.Join("..", "1.0.0", name))
		if filepath.Dir(oldPath) != filepath.Dir(newPath) {
			t.Errorf("the temporary link %s is not beside %s, so a rename may not be atomic", oldPath, newPath)
		}
		if err := os.Rename(oldPath, newPath); err != nil {
			return err
		}
		requireTlsLink(t, vaultHome, name, filepath.Join("..", "2.0.0", name))
		moved = append(moved, name)
		return nil
	}

	if err := swapTlsCurrent(vaultHome, "main", "2.0.0", settings); err != nil {
		t.Fatal(err)
	}
	if want := []string{"example.com", "star.example.com"}; !slices.Equal(moved, want) {
		t.Fatalf("moved %v, want %v", moved, want)
	}

	entries, err := os.ReadDir(filepath.Join(vaultHome, "tls", tlsCurrentDirName))
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".") {
			t.Errorf("left %s behind", entry.Name())
		}
	}
}

func TestCertsSwapReloadsEachBlockWithItsOwnConfig(t *testing.T) {
	vaultHome := setupCertsSwapVault(t)
	fake := newFakeLbDocker(t)
	fake.lines = []string{
		"aaaa11 edge-0.example.com-eth0",
		"bbbb22 edge-0.example.com-eth1",
	}

	if err := swapTlsCurrent(vaultHome, "main", "2.0.0", defaultCertsSwapSettings()); err != nil {
		t.Fatal(err)
	}

	want := [][]string{
		{"exec", "aaaa11", "nginx", "-c", "/srv/warp/nginx.conf/edge-0.example.com-eth0.conf", "-s", "reload"},
		{"exec", "bbbb22", "nginx", "-c", "/srv/warp/nginx.conf/edge-0.example.com-eth1.conf", "-s", "reload"},
	}
	if !slices.EqualFunc(fake.reloadArgs, want, slices.Equal[[]string]) {
		t.Fatalf("reloads %v, want %v", fake.reloadArgs, want)
	}
}

// Only the named env's lb on this host: another service's nginx, or another
// env's, is none of this swap's business.
func TestCertsSwapFindsOnlyThisEnvsLb(t *testing.T) {
	vaultHome := setupCertsSwapVault(t)
	fake := newFakeLbDocker(t)

	if err := swapTlsCurrent(vaultHome, "main", "2.0.0", defaultCertsSwapSettings()); err != nil {
		t.Fatal(err)
	}

	if len(fake.censusArgs) != 1 {
		t.Fatalf("ran %d censuses, want 1", len(fake.censusArgs))
	}
	census := strings.Join(fake.censusArgs[0], " ")
	for _, want := range []string{"--filter label=warp.env=main", "--filter label=warp.service=lb"} {
		if !strings.Contains(census, want) {
			t.Errorf("census %q lacks %q", census, want)
		}
	}
}

func TestCertsSwapRefusesMismatchedPair(t *testing.T) {
	vaultHome := setupCertsSwapVault(t)
	fake := newFakeLbDocker(t)
	mismatchTlsPair(t, vaultHome, "2.0.0", "star.example.com", "1.0.0")

	err := swapTlsCurrent(vaultHome, "main", "2.0.0", defaultCertsSwapSettings())
	if err == nil || !strings.Contains(err.Error(), "star.example.com") {
		t.Fatalf("swap error = %v, want one naming the bad pair", err)
	}
	requireNothingSwapped(t, vaultHome, fake)
}

// The check of every name comes before the first move, so the good names of a
// bad version stay where they were. The bad name sorts last to prove it.
func TestCertsSwapChecksEveryNameBeforeMovingAny(t *testing.T) {
	vaultHome := setupCertsSwapVault(t)
	fake := newFakeLbDocker(t)
	if err := swapTlsCurrent(vaultHome, "main", "1.0.0", defaultCertsSwapSettings()); err != nil {
		t.Fatal(err)
	}
	fake.reloadArgs = nil
	mismatchTlsPair(t, vaultHome, "2.0.0", "star.example.com", "1.0.0")

	if err := swapTlsCurrent(vaultHome, "main", "2.0.0", defaultCertsSwapSettings()); err == nil {
		t.Fatal("swap accepted a version with a bad pair")
	}

	for _, name := range []string{"example.com", "star.example.com"} {
		requireTlsLink(t, vaultHome, name, filepath.Join("..", "1.0.0", name))
	}
	if len(fake.reloadArgs) != 0 {
		t.Errorf("a refused swap reloaded nginx: %v", fake.reloadArgs)
	}
}

func TestCertsSwapRefusesCertificateOutsideItsValidity(t *testing.T) {
	cases := []struct {
		label  string
		offset time.Duration
	}{
		{label: "expired", offset: 48 * time.Hour},
		{label: "not yet valid", offset: -48 * time.Hour},
	}
	for _, c := range cases {
		vaultHome := setupCertsSwapVault(t)
		fake := newFakeLbDocker(t)
		settings := defaultCertsSwapSettings()
		settings.now = func() time.Time { return time.Now().Add(c.offset) }

		if err := swapTlsCurrent(vaultHome, "main", "2.0.0", settings); err == nil {
			t.Errorf("swap accepted a certificate that is %s", c.label)
		}
		requireNothingSwapped(t, vaultHome, fake)
	}
}

// A mis-filed certificate parses and matches its key, and would still fail
// every visitor to the name once nginx reloaded it.
func TestCertsSwapRefusesCertificateForAnotherName(t *testing.T) {
	vaultHome := setupCertsSwapVault(t)
	fake := newFakeLbDocker(t)
	versionHome := filepath.Join(vaultHome, "tls", "3.0.0")
	generateTestTLSFiles(t, versionHome, "other.example", false)
	if err := os.Rename(filepath.Join(versionHome, "other.example"), filepath.Join(versionHome, "mine.example")); err != nil {
		t.Fatal(err)
	}
	for _, suffix := range []string{".pem", ".key"} {
		err := os.Rename(
			filepath.Join(versionHome, "mine.example", "other.example"+suffix),
			filepath.Join(versionHome, "mine.example", "mine.example"+suffix),
		)
		if err != nil {
			t.Fatal(err)
		}
	}

	err := swapTlsCurrent(vaultHome, "main", "3.0.0", defaultCertsSwapSettings())
	if err == nil || !strings.Contains(err.Error(), "mine.example") {
		t.Fatalf("swap error = %v, want one naming the mis-filed name", err)
	}
	requireNothingSwapped(t, vaultHome, fake)
}

func TestCertsSwapRefusesNameMissingItsKey(t *testing.T) {
	vaultHome := setupCertsSwapVault(t)
	fake := newFakeLbDocker(t)
	if err := os.Remove(filepath.Join(vaultHome, "tls", "2.0.0", "example.com", "example.com.key")); err != nil {
		t.Fatal(err)
	}

	if err := swapTlsCurrent(vaultHome, "main", "2.0.0", defaultCertsSwapSettings()); err == nil {
		t.Fatal("swap accepted a name with no key")
	}
	requireNothingSwapped(t, vaultHome, fake)
}

// A version names one directory under tls/, so nothing here may walk out of it
// or name tls/current itself.
func TestCertsSwapRefusesBadVersions(t *testing.T) {
	for _, version := range []string{"", "current", "latest", "..", "../..", "2.0.0/../1.0.0", "/etc", "9.9.9"} {
		vaultHome := setupCertsSwapVault(t)
		fake := newFakeLbDocker(t)

		if err := swapTlsCurrent(vaultHome, "main", version, defaultCertsSwapSettings()); err == nil {
			t.Errorf("swap accepted version %q", version)
		}
		requireNothingSwapped(t, vaultHome, fake)
	}
}

func TestCertsSwapRefusesVersionHoldingNoNames(t *testing.T) {
	vaultHome := setupCertsSwapVault(t)
	fake := newFakeLbDocker(t)
	if err := os.MkdirAll(filepath.Join(vaultHome, "tls", "3.0.0"), 0700); err != nil {
		t.Fatal(err)
	}

	if err := swapTlsCurrent(vaultHome, "main", "3.0.0", defaultCertsSwapSettings()); err == nil {
		t.Fatal("swap accepted an empty version")
	}
	requireNothingSwapped(t, vaultHome, fake)
}

// A real directory cannot be replaced in one step, and something other than
// this command put it there.
func TestCertsSwapRefusesEntryThatIsNotALink(t *testing.T) {
	vaultHome := setupCertsSwapVault(t)
	fake := newFakeLbDocker(t)
	generateTestTLSFiles(t, filepath.Join(vaultHome, "tls", tlsCurrentDirName), "example.com", true)

	err := swapTlsCurrent(vaultHome, "main", "2.0.0", defaultCertsSwapSettings())
	if err == nil || !strings.Contains(err.Error(), "star.example.com") {
		t.Fatalf("swap error = %v, want one naming the real directory", err)
	}
	if len(fake.reloadArgs) != 0 {
		t.Errorf("a refused swap reloaded nginx: %v", fake.reloadArgs)
	}
	if _, err := os.Lstat(tlsCurrentLinkPath(vaultHome, "example.com")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a refused swap moved a link: %v", err)
	}
}

// With tls/current a link to a version, a swap would write its links into that
// version's directory, where server's resolver and the jwt keyring look. The
// version shares no name with the swap, so no check of a name can refuse it.
func TestCertsSwapRefusesCurrentThatIsALink(t *testing.T) {
	vaultHome := setupCertsSwapVault(t)
	fake := newFakeLbDocker(t)
	generateTestTLSFiles(t, filepath.Join(vaultHome, "tls", "3.0.0"), "other.example", false)
	if err := os.Symlink("3.0.0", filepath.Join(vaultHome, "tls", tlsCurrentDirName)); err != nil {
		t.Fatal(err)
	}

	if err := swapTlsCurrent(vaultHome, "main", "2.0.0", defaultCertsSwapSettings()); err == nil {
		t.Fatal("swap accepted a tls/current that is a link")
	}
	if len(fake.reloadArgs) != 0 {
		t.Errorf("a refused swap reloaded nginx: %v", fake.reloadArgs)
	}
	entries, err := os.ReadDir(filepath.Join(vaultHome, "tls", "3.0.0"))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Errorf("the swap wrote into the version tls/current links to: %v", entries)
	}
}

// Moving links on a host with nothing to reload would read as a rotation that
// happened, so a swap on the wrong host changes nothing.
func TestCertsSwapRefusesHostWithoutLbContainers(t *testing.T) {
	vaultHome := setupCertsSwapVault(t)
	fake := newFakeLbDocker(t)
	fake.lines = nil

	if err := swapTlsCurrent(vaultHome, "main", "2.0.0", defaultCertsSwapSettings()); err == nil {
		t.Fatal("swap succeeded with no lb container to reload")
	}
	requireNothingSwapped(t, vaultHome, fake)
}

func TestCertsSwapRefusesWhenTheCensusFails(t *testing.T) {
	vaultHome := setupCertsSwapVault(t)
	fake := newFakeLbDocker(t)
	fake.censusErr = errors.New("daemon unavailable")

	err := swapTlsCurrent(vaultHome, "main", "2.0.0", defaultCertsSwapSettings())
	if !errors.Is(err, fake.censusErr) {
		t.Fatalf("swap error = %v, want the census failure", err)
	}
	requireNothingSwapped(t, vaultHome, fake)
}

func TestCertsSwapRefusesCensusLineItCannotRead(t *testing.T) {
	vaultHome := setupCertsSwapVault(t)
	fake := newFakeLbDocker(t)
	fake.lines = []string{"aaaa11"}

	if err := swapTlsCurrent(vaultHome, "main", "2.0.0", defaultCertsSwapSettings()); err == nil {
		t.Fatal("swap accepted a container with no block")
	}
	requireNothingSwapped(t, vaultHome, fake)
}

// nginx keeps serving the old pair on a failed reload. One block's failure must
// not cost the others their reload, and must not read as success.
func TestCertsSwapReportsReloadFailureAndReloadsTheRest(t *testing.T) {
	vaultHome := setupCertsSwapVault(t)
	fake := newFakeLbDocker(t)
	fake.lines = []string{
		"aaaa11 edge-0.example.com-eth0",
		"bbbb22 edge-0.example.com-eth1",
		"cccc33 edge-0.example.com-eth2",
	}
	reloadErr := errors.New("nginx refused the reload")
	fake.reloadErrs = map[string]error{"bbbb22": reloadErr}

	err := swapTlsCurrent(vaultHome, "main", "2.0.0", defaultCertsSwapSettings())
	if !errors.Is(err, reloadErr) {
		t.Fatalf("swap error = %v, want the reload failure", err)
	}
	if !strings.Contains(err.Error(), "edge-0.example.com-eth1") {
		t.Errorf("swap error = %v, want one naming the block", err)
	}
	if len(fake.reloadArgs) != 3 {
		t.Errorf("attempted %d reloads, want 3", len(fake.reloadArgs))
	}
}

// A retry after a failed reload is how an operator recovers, so the links
// already at the version must not stop it reloading.
func TestCertsSwapRetryReloadsAfterFailure(t *testing.T) {
	vaultHome := setupCertsSwapVault(t)
	fake := newFakeLbDocker(t)
	fake.reloadErrs = map[string]error{"aaaa11": errors.New("nginx refused the reload")}
	if err := swapTlsCurrent(vaultHome, "main", "2.0.0", defaultCertsSwapSettings()); err == nil {
		t.Fatal("swap hid a failed reload")
	}

	fake.reloadErrs = nil
	fake.reloadArgs = nil
	if err := swapTlsCurrent(vaultHome, "main", "2.0.0", defaultCertsSwapSettings()); err != nil {
		t.Fatal(err)
	}
	if len(fake.reloadArgs) != 1 {
		t.Fatalf("retry reloaded %d times, want 1", len(fake.reloadArgs))
	}
}

// Rollback is a swap to the older version.
func TestCertsSwapMovesBackToAnOlderVersion(t *testing.T) {
	vaultHome := setupCertsSwapVault(t)
	newFakeLbDocker(t)
	for _, version := range []string{"2.0.0", "1.0.0"} {
		if err := swapTlsCurrent(vaultHome, "main", version, defaultCertsSwapSettings()); err != nil {
			t.Fatal(err)
		}
	}

	requireTlsLink(t, vaultHome, "star.example.com", filepath.Join("..", "1.0.0", "star.example.com"))
}

// One issuance need not hold every name, as with an exact certificate issued on
// its own, so the names it does not hold stay where they are.
func TestCertsSwapLeavesOtherNamesAlone(t *testing.T) {
	vaultHome := setupCertsSwapVault(t)
	newFakeLbDocker(t)
	if err := swapTlsCurrent(vaultHome, "main", "1.0.0", defaultCertsSwapSettings()); err != nil {
		t.Fatal(err)
	}
	generateTestTLSFiles(t, filepath.Join(vaultHome, "tls", "3.0.0"), "example.com", false)

	if err := swapTlsCurrent(vaultHome, "main", "3.0.0", defaultCertsSwapSettings()); err != nil {
		t.Fatal(err)
	}

	requireTlsLink(t, vaultHome, "example.com", filepath.Join("..", "3.0.0", "example.com"))
	requireTlsLink(t, vaultHome, "star.example.com", filepath.Join("..", "1.0.0", "star.example.com"))
}

// A swap that died between its two steps left a temporary link. The next one
// must finish, not fail on it.
func TestCertsSwapReplacesItsLeftoverTemporaryLink(t *testing.T) {
	vaultHome := setupCertsSwapVault(t)
	newFakeLbDocker(t)
	currentHome := filepath.Join(vaultHome, "tls", tlsCurrentDirName)
	if err := os.MkdirAll(currentHome, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../1.0.0/example.com", filepath.Join(currentHome, ".example.com.swap")); err != nil {
		t.Fatal(err)
	}

	if err := swapTlsCurrent(vaultHome, "main", "2.0.0", defaultCertsSwapSettings()); err != nil {
		t.Fatal(err)
	}

	requireTlsLink(t, vaultHome, "example.com", filepath.Join("..", "2.0.0", "example.com"))
	if _, err := os.Lstat(filepath.Join(currentHome, ".example.com.swap")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the leftover survived: %v", err)
	}
}

func TestCertsSwapReportsAFailedMove(t *testing.T) {
	vaultHome := setupCertsSwapVault(t)
	fake := newFakeLbDocker(t)
	settings := defaultCertsSwapSettings()
	renameErr := errors.New("disk failure")
	settings.rename = func(string, string) error { return renameErr }

	err := swapTlsCurrent(vaultHome, "main", "2.0.0", settings)
	if !errors.Is(err, renameErr) {
		t.Fatalf("swap error = %v, want the rename failure", err)
	}
	if len(fake.reloadArgs) != 0 {
		t.Errorf("a failed move reloaded nginx: %v", fake.reloadArgs)
	}
	entries, err := os.ReadDir(filepath.Join(vaultHome, "tls", tlsCurrentDirName))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Errorf("a failed move left %v", entries)
	}
}

// What a swap writes must satisfy the check an lb build runs on the same tree.
func TestCertsSwapLeavesATreeTheLbBuildAccepts(t *testing.T) {
	vaultHome := setupCertsSwapVault(t)
	newFakeLbDocker(t)
	if err := swapTlsCurrent(vaultHome, "main", "2.0.0", defaultCertsSwapSettings()); err != nil {
		t.Fatal(err)
	}

	if err := checkTlsCurrent(vaultHome); err != nil {
		t.Fatal(err)
	}
}

// An nginx serving star.example.com from tls/current under vaultHome, as the lb
// does, with the block config a reload names. The two configs differ only in
// their listen lines, as `<block>.conf` differs from the `_host.conf` that a
// host-networked lb starts from.
type tlsTestNginx struct {
	binary          string
	prefixDir       string
	address         string
	blockConfigPath string
	output          *bytes.Buffer
}

func startTlsTestNginx(t *testing.T, vaultHome string) *tlsTestNginx {
	t.Helper()
	nginxBinary := nginxConfigValidationBinary(t)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}

	prefixDir := t.TempDir()
	writeConfig := func(fileName string, listenAddress string) string {
		configPath := filepath.Join(prefixDir, fileName)
		config := fmt.Sprintf(`
pid %[1]s/nginx.pid;
error_log stderr;
events { worker_connections 64; }
http {
    access_log off;
    client_body_temp_path %[1]s/client_body;
    proxy_temp_path %[1]s/proxy;
    fastcgi_temp_path %[1]s/fastcgi;
    uwsgi_temp_path %[1]s/uwsgi;
    scgi_temp_path %[1]s/scgi;
    server {
        listen %[2]s ssl;
        server_name star.example.com;
        ssl_certificate     %[3]s/tls/current/star.example.com/star.example.com.pem;
        ssl_certificate_key %[3]s/tls/current/star.example.com/star.example.com.key;
    }
}
`, prefixDir, listenAddress, vaultHome)
		if err := os.WriteFile(configPath, []byte(config), 0644); err != nil {
			t.Fatal(err)
		}
		return configPath
	}
	hostConfigPath := writeConfig("block_host.conf", address)
	blockConfigPath := writeConfig("block.conf", "127.0.0.1:1")

	self := &tlsTestNginx{
		binary:          nginxBinary,
		prefixDir:       prefixDir,
		address:         address,
		blockConfigPath: blockConfigPath,
		output:          &bytes.Buffer{},
	}
	cmd := exec.Command(nginxBinary, "-g", "daemon off;", "-c", hostConfigPath, "-p", prefixDir)
	cmd.Stdout = self.output
	cmd.Stderr = self.output
	// workers inherit the output pipe, so Wait must not depend on them closing it
	cmd.WaitDelay = 5 * time.Second
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		// the master takes its workers down, where a kill would orphan them
		cmd.Process.Signal(syscall.SIGTERM)
		cmd.Wait()
	})
	return self
}

// The reload a swap asks for, run here rather than in a container.
func (self *tlsTestNginx) reload(string) error {
	output, err := exec.Command(self.binary, "-c", self.blockConfigPath, "-p", self.prefixDir, "-s", "reload").CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: %s", err, output)
	}
	return nil
}

// The leaf served now, nil while nginx is not answering.
func (self *tlsTestNginx) servedLeaf() *x509.Certificate {
	conn, err := tls.Dial("tcp", self.address, &tls.Config{ServerName: "star.example.com", InsecureSkipVerify: true})
	if err != nil {
		return nil
	}
	defer conn.Close()
	return conn.ConnectionState().PeerCertificates[0]
}

// A start and a reload finish after their callers return, so this retries a
// handshake until the wanted leaf answers. It ends at a deadline only on failure.
func (self *tlsTestNginx) waitForLeaf(t *testing.T, want *x509.Certificate) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if served := self.servedLeaf(); served != nil && served.Equal(want) {
			return
		}
	}
	t.Fatalf("nginx never served the wanted leaf:\n%s", self.output.String())
}

func tlsVersionLeaf(t *testing.T, vaultHome string, version string, name string) *x509.Certificate {
	t.Helper()
	pemBytes, err := os.ReadFile(filepath.Join(vaultHome, "tls", version, name, name+".pem"))
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(pemBytes)
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return leaf
}

// The whole of W5 against a real nginx, through the paths the lb reads: nginx
// serves the pair tls/current names, a moved link alone changes nothing, and the
// reload then serves the new pair, though nginx was started from another config
// than the one the reload names.
func TestCertsSwapServesTheNewPairThroughNginx(t *testing.T) {
	vaultHome := setupCertsSwapVault(t)
	fake := newFakeLbDocker(t)
	if err := swapTlsCurrent(vaultHome, "main", "1.0.0", defaultCertsSwapSettings()); err != nil {
		t.Fatal(err)
	}

	nginx := startTlsTestNginx(t, vaultHome)
	fake.onReload = nginx.reload

	oldLeaf := tlsVersionLeaf(t, vaultHome, "1.0.0", "star.example.com")
	newLeaf := tlsVersionLeaf(t, vaultHome, "2.0.0", "star.example.com")
	if oldLeaf.Equal(newLeaf) {
		t.Fatal("the fixture's two versions hold one certificate")
	}
	nginx.waitForLeaf(t, oldLeaf)

	settings := defaultCertsSwapSettings()
	settings.rename = func(oldPath string, newPath string) error {
		if err := os.Rename(oldPath, newPath); err != nil {
			return err
		}
		if served := nginx.servedLeaf(); served == nil || !served.Equal(oldLeaf) {
			t.Error("nginx stopped serving the old pair before any reload")
		}
		return nil
	}

	if err := swapTlsCurrent(vaultHome, "main", "2.0.0", settings); err != nil {
		t.Fatal(err)
	}
	nginx.waitForLeaf(t, newLeaf)
}

// nginx proves a config loads before it signals, so a pair that passed this
// command's checks and then broke is refused with the old pair still serving,
// and the refusal reaches the caller.
func TestCertsSwapSurfacesARefusedNginxReload(t *testing.T) {
	vaultHome := setupCertsSwapVault(t)
	fake := newFakeLbDocker(t)
	if err := swapTlsCurrent(vaultHome, "main", "1.0.0", defaultCertsSwapSettings()); err != nil {
		t.Fatal(err)
	}

	nginx := startTlsTestNginx(t, vaultHome)
	oldLeaf := tlsVersionLeaf(t, vaultHome, "1.0.0", "star.example.com")
	nginx.waitForLeaf(t, oldLeaf)

	fake.onReload = func(containerId string) error {
		mismatchTlsPair(t, vaultHome, "2.0.0", "star.example.com", "1.0.0")
		return nginx.reload(containerId)
	}

	err := swapTlsCurrent(vaultHome, "main", "2.0.0", defaultCertsSwapSettings())
	if err == nil || !strings.Contains(err.Error(), "SSL_CTX_use_PrivateKey") {
		t.Fatalf("swap error = %v, want nginx refusing the pair", err)
	}
	// refused before any signal, so this reads the settled state
	if served := nginx.servedLeaf(); served == nil || !served.Equal(oldLeaf) {
		t.Fatal("nginx stopped serving the old pair after refusing the reload")
	}
}
