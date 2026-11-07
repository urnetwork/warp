// Tests for `warpctl certs swap`. Most run swapTlsCurrent against fakeLbDocker,
// a few run the real nginx through the paths an lb reads, and the last group runs
// the command itself as a process, for the wiring and the exit status a job
// relies on.

package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"maps"
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

// What `docker top` prints for an lb draining its last connection, as a real
// nginx printed it after a QUIT.
const drainingLbTop = `PID                 COMMAND
1                   /usr/local/sbin/lb
7                   nginx: master process nginx -g daemon off; -c /srv/warp/nginx.conf/edge-0.example.com-eth0.conf
8                   nginx: worker process is shutting down
`

// Stands in for the docker cli through outAndLogFunc, so that no test here can
// reach a real daemon. It answers the census with lines, and each container as a
// healthy lb reading the fixture's names through tls/current, unless told
// otherwise. A reload that takes gives the container a new worker pid.
type fakeLbDocker struct {
	// the vault an lb mounts, unless told otherwise
	vaultHome string
	// what `docker ps` prints, one `<id> <block>` per line
	lines []string
	// fails the census
	censusErr error
	// what grep finds in a container's config, by container id
	tlsLines map[string][]string
	// fails the read of a container's tls paths
	tlsReadErrs map[string]error
	// what `docker top` prints for a container, in place of its one worker
	topOutputs map[string]string
	// fails `docker top` of a container
	topErrs map[string]error
	// what `readlink` prints for a container, in place of the links in vaultHome
	linkOutputs map[string]string
	// fails `readlink` in a container
	linkErrs map[string]error
	// containers that answer a reload and start no worker, as a draining nginx
	// does
	deafContainerIds map[string]bool
	// how many looks at a container's workers pass before a reload's new worker
	// shows
	slowReloadLooks int
	// fails the reload of these container ids
	reloadErrs map[string]error
	// runs at each reload, and answers it when it fails
	onReload func(containerId string) error

	censusArgs  [][]string
	tlsReadArgs [][]string
	reloadArgs  [][]string
	// the reloads that took, by container id
	reloadCounts map[string]int
	// each container's reloads still to show in `docker top`, and the looks they
	// wait for
	pendingLooks map[string]int
	// every docker command run, for the tests that must run none
	commandCount int
}

// Answers one docker command the way the real cli would.
func (self *fakeLbDocker) answer(t *testing.T, args []string) ([]byte, error) {
	self.commandCount += 1
	switch args[0] {
	case "ps":
		self.censusArgs = append(self.censusArgs, args)
		if self.censusErr != nil {
			return nil, self.censusErr
		}
		return []byte(strings.Join(self.lines, "\n") + "\n"), nil
	case "top":
		containerId := args[1]
		if err := self.topErrs[containerId]; err != nil {
			return nil, err
		}
		if out, ok := self.topOutputs[containerId]; ok {
			return []byte(out), nil
		}
		reloadCount := self.reloadCounts[containerId]
		if 0 < self.pendingLooks[containerId] {
			self.pendingLooks[containerId] -= 1
			reloadCount -= 1
		}
		top := "PID                 COMMAND\n"
		top += "1                   /usr/local/sbin/lb\n"
		top += "7                   nginx: master process nginx -g daemon off; -c /srv/warp/nginx.conf/edge-0.example.com-eth0.conf\n"
		top += fmt.Sprintf("%-20dnginx: worker process\n", 100+reloadCount)
		return []byte(top), nil
	case "exec":
		containerId := args[1]
		switch args[2] {
		case "grep":
			self.tlsReadArgs = append(self.tlsReadArgs, args)
			if err := self.tlsReadErrs[containerId]; err != nil {
				return nil, err
			}
			lines, ok := self.tlsLines[containerId]
			if !ok {
				lines = tlsCurrentLines("example.com", "star.example.com")
			}
			return []byte(strings.Join(lines, "\n") + "\n"), nil
		case "readlink":
			if err := self.linkErrs[containerId]; err != nil {
				return nil, err
			}
			if out, ok := self.linkOutputs[containerId]; ok {
				return []byte(out), nil
			}
			targets := []string{}
			for _, linkPath := range args[3:] {
				target, err := os.Readlink(filepath.Join(self.vaultHome, strings.TrimPrefix(linkPath, lbVaultMountPath)))
				if err != nil {
					return nil, err
				}
				targets = append(targets, target)
			}
			return []byte(strings.Join(targets, "\n") + "\n"), nil
		case "nginx":
			self.reloadArgs = append(self.reloadArgs, args)
			if self.onReload != nil {
				if err := self.onReload(containerId); err != nil {
					return nil, err
				}
			}
			if err := self.reloadErrs[containerId]; err != nil {
				return nil, err
			}
			if !self.deafContainerIds[containerId] {
				self.reloadCounts[containerId] += 1
				self.pendingLooks[containerId] = self.slowReloadLooks
			}
			return nil, nil
		}
	}
	t.Errorf("unexpected docker command %v", args)
	return nil, errors.New("unexpected docker command")
}

// Routes outAndLog to this fake until the test ends.
func (self *fakeLbDocker) install(t *testing.T) {
	t.Helper()
	previous := outAndLogFunc
	t.Cleanup(func() { outAndLogFunc = previous })
	outAndLogFunc = func(cmd *exec.Cmd) ([]byte, error) {
		// on linux docker() runs through sudo
		return self.answer(t, cmd.Args[slices.Index(cmd.Args, "docker")+1:])
	}
}

// One healthy lb on the host, mounting vaultHome, installed.
func newFakeLbDocker(t *testing.T, vaultHome string) *fakeLbDocker {
	t.Helper()
	fake := &fakeLbDocker{
		vaultHome:    vaultHome,
		lines:        []string{"aaaa11 edge-0.example.com-eth0"},
		reloadCounts: map[string]int{},
		pendingLooks: map[string]int{},
	}
	fake.install(t)
	return fake
}

// The lines a generated config holds for names read through tls/current.
func tlsCurrentLines(names ...string) []string {
	lines := []string{}
	for _, name := range names {
		lines = append(
			lines,
			fmt.Sprintf("                ssl_certificate     /srv/warp/vault/tls/current/%[1]s/%[1]s.pem;", name),
			fmt.Sprintf("                ssl_certificate_key /srv/warp/vault/tls/current/%[1]s/%[1]s.key;", name),
		)
	}
	return lines
}

// The lines a generated config holds for a name read from one version.
func tlsVersionLines(version string, name string) []string {
	return []string{
		fmt.Sprintf("                ssl_certificate     /srv/warp/vault/tls/%[1]s/%[2]s/%[2]s.pem;", version, name),
		fmt.Sprintf("                ssl_certificate_key /srv/warp/vault/tls/%[1]s/%[2]s/%[2]s.key;", version, name),
	}
}

// Keeps what the swap prints, until the test ends.
func captureSwapOutput(t *testing.T) *bytes.Buffer {
	t.Helper()
	output := &bytes.Buffer{}
	previous := Out
	Out = log.New(output, "", 0)
	t.Cleanup(func() { Out = previous })
	return output
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

// Where a swap puts a name's link.
func tlsCurrentLinkPath(vaultHome string, name string) string {
	return filepath.Join(vaultHome, "tls", tlsCurrentDirName, name)
}

// Fails unless the name's link holds exactly this target.
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

// Each name's link ends at that version's pair, read through the link as nginx
// reads it.
func TestCertsSwapPointsCurrentAtVersion(t *testing.T) {
	vaultHome := setupCertsSwapVault(t)
	newFakeLbDocker(t, vaultHome)

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
	newFakeLbDocker(t, vaultHome)

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
	fake := newFakeLbDocker(t, vaultHome)
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
	newFakeLbDocker(t, vaultHome)
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

// `-c` must name the block's own config, because nginx reads the pid file from it
// and every block on a host has its own master.
func TestCertsSwapReloadsEachBlockWithItsOwnConfig(t *testing.T) {
	vaultHome := setupCertsSwapVault(t)
	fake := newFakeLbDocker(t, vaultHome)
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

// The census is how a swap finds its lbs, so its arguments are pinned: the labels
// `warpctl run` stamps, keeping another service's nginx and another env's lb out,
// the format that gives `<id> <block>`, and no -a, since a stopped lb takes no
// reload.
func TestCertsSwapFindsOnlyThisEnvsRunningLb(t *testing.T) {
	vaultHome := setupCertsSwapVault(t)
	fake := newFakeLbDocker(t, vaultHome)

	if err := swapTlsCurrent(vaultHome, "main", "2.0.0", defaultCertsSwapSettings()); err != nil {
		t.Fatal(err)
	}

	want := [][]string{{
		"ps",
		"--no-trunc",
		"--filter", "label=warp.env=main",
		"--filter", "label=warp.service=lb",
		"--format", `{{.ID}} {{.Label "warp.block"}}`,
	}}
	if !slices.EqualFunc(fake.censusArgs, want, slices.Equal[[]string]) {
		t.Fatalf("census %v, want %v", fake.censusArgs, want)
	}
}

// One key that does not match refuses the version, and names the pair.
func TestCertsSwapRefusesMismatchedPair(t *testing.T) {
	vaultHome := setupCertsSwapVault(t)
	fake := newFakeLbDocker(t, vaultHome)
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
	fake := newFakeLbDocker(t, vaultHome)
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

// nginx loads a certificate at any date, so only this check stops a version that
// every visitor would reject.
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
		fake := newFakeLbDocker(t, vaultHome)
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
	fake := newFakeLbDocker(t, vaultHome)
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

// Half a pair moved behind a link would stop nginx at its next reload.
func TestCertsSwapRefusesNameMissingItsKey(t *testing.T) {
	vaultHome := setupCertsSwapVault(t)
	fake := newFakeLbDocker(t, vaultHome)
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
		fake := newFakeLbDocker(t, vaultHome)

		if err := swapTlsCurrent(vaultHome, "main", version, defaultCertsSwapSettings()); err == nil {
			t.Errorf("swap accepted version %q", version)
		}
		requireNothingSwapped(t, vaultHome, fake)
	}
}

// A swap that moves nothing must not read as a rotation.
func TestCertsSwapRefusesVersionHoldingNoNames(t *testing.T) {
	vaultHome := setupCertsSwapVault(t)
	fake := newFakeLbDocker(t, vaultHome)
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
	fake := newFakeLbDocker(t, vaultHome)
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
	fake := newFakeLbDocker(t, vaultHome)
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
// happened, so a swap on the wrong host, or under a mistyped env, changes nothing
// unless it asks for that. The refusal says how, since on a new host it is the
// right thing to ask.
func TestCertsSwapRefusesHostWithoutLbContainers(t *testing.T) {
	vaultHome := setupCertsSwapVault(t)
	fake := newFakeLbDocker(t, vaultHome)
	fake.lines = nil

	err := swapTlsCurrent(vaultHome, "main", "2.0.0", defaultCertsSwapSettings())
	if err == nil || !strings.Contains(err.Error(), "--no-reload") {
		t.Fatalf("swap error = %v, want one naming --no-reload", err)
	}
	requireNothingSwapped(t, vaultHome, fake)
}

// With no answer from docker a swap cannot know what it would reach.
func TestCertsSwapRefusesWhenTheCensusFails(t *testing.T) {
	vaultHome := setupCertsSwapVault(t)
	fake := newFakeLbDocker(t, vaultHome)
	fake.censusErr = errors.New("daemon unavailable")

	err := swapTlsCurrent(vaultHome, "main", "2.0.0", defaultCertsSwapSettings())
	if !errors.Is(err, fake.censusErr) {
		t.Fatalf("swap error = %v, want the census failure", err)
	}
	requireNothingSwapped(t, vaultHome, fake)
}

// Without a block a reload has no config to name.
func TestCertsSwapRefusesCensusLineItCannotRead(t *testing.T) {
	vaultHome := setupCertsSwapVault(t)
	fake := newFakeLbDocker(t, vaultHome)
	fake.lines = []string{"aaaa11"}

	if err := swapTlsCurrent(vaultHome, "main", "2.0.0", defaultCertsSwapSettings()); err == nil {
		t.Fatal("swap accepted a container with no block")
	}
	requireNothingSwapped(t, vaultHome, fake)
}

// What every lb is today: an image reading a name from anywhere but tls/current
// reloads happily and serves what it served. So is an image built after adoption
// for a name the builder's vault has no entry for, beside names it does. Every
// form of path the build can bake counts, read by itself or by a second server
// block, and nothing may move.
func TestCertsSwapRefusesLbReadingANameOutsideCurrent(t *testing.T) {
	cases := []struct {
		label    string
		tlsLines []string
	}{
		{
			label:    "from a version",
			tlsLines: tlsVersionLines("1.0.0", "star.example.com"),
		},
		{
			label: "from the top of the vault",
			tlsLines: []string{
				"ssl_certificate     /srv/warp/vault/star.example.com.pem;",
				"ssl_certificate_key /srv/warp/vault/star.example.com.key;",
			},
		},
		{
			label:    "from a version, beside another name in tls/current",
			tlsLines: append(tlsCurrentLines("example.com"), tlsVersionLines("1.0.0", "star.example.com")...),
		},
		{
			label:    "from tls/current and also a version",
			tlsLines: append(tlsCurrentLines("star.example.com"), tlsVersionLines("1.0.0", "star.example.com")...),
		},
	}
	for _, c := range cases {
		vaultHome := setupCertsSwapVault(t)
		fake := newFakeLbDocker(t, vaultHome)
		fake.tlsLines = map[string][]string{"aaaa11": c.tlsLines}

		err := swapTlsCurrent(vaultHome, "main", "2.0.0", defaultCertsSwapSettings())
		if err == nil || !strings.Contains(err.Error(), "star.example.com") || !strings.Contains(err.Error(), "edge-0.example.com-eth0") {
			t.Errorf("a name read %s: swap error = %v, want one naming the lb and the name", c.label, err)
		}
		requireNothingSwapped(t, vaultHome, fake)
	}
}

// Reloading an lb that reads nothing this version holds changes nothing a client
// sees, which must not read as a rotation.
func TestCertsSwapRefusesLbReadingNoNameOfTheVersion(t *testing.T) {
	cases := [][]string{
		tlsCurrentLines("other.example"),
		tlsVersionLines("1.0.0", "other.example"),
	}
	for _, tlsLines := range cases {
		vaultHome := setupCertsSwapVault(t)
		fake := newFakeLbDocker(t, vaultHome)
		fake.tlsLines = map[string][]string{"aaaa11": tlsLines}

		err := swapTlsCurrent(vaultHome, "main", "2.0.0", defaultCertsSwapSettings())
		if err == nil || !strings.Contains(err.Error(), "edge-0.example.com-eth0") {
			t.Errorf("swap error = %v, want one naming the lb", err)
		}
		requireNothingSwapped(t, vaultHome, fake)
	}
}

// One lb a swap cannot reach refuses the swap for the host, before any other lb
// reloads, as one bad pair refuses the version.
func TestCertsSwapChecksEveryLbBeforeMovingAnyLink(t *testing.T) {
	vaultHome := setupCertsSwapVault(t)
	fake := newFakeLbDocker(t, vaultHome)
	fake.lines = []string{
		"aaaa11 edge-0.example.com-eth0",
		"bbbb22 edge-0.example.com-eth1",
	}
	fake.tlsLines = map[string][]string{"bbbb22": tlsVersionLines("1.0.0", "star.example.com")}

	err := swapTlsCurrent(vaultHome, "main", "2.0.0", defaultCertsSwapSettings())
	if err == nil || !strings.Contains(err.Error(), "edge-0.example.com-eth1") {
		t.Fatalf("swap error = %v, want one naming the second lb", err)
	}
	requireNothingSwapped(t, vaultHome, fake)
}

// Not knowing what an lb reads is not knowing the swap reaches it.
func TestCertsSwapRefusesLbWhosePathsItCannotRead(t *testing.T) {
	vaultHome := setupCertsSwapVault(t)
	fake := newFakeLbDocker(t, vaultHome)
	readErr := errors.New("no such file")
	fake.tlsReadErrs = map[string]error{"aaaa11": readErr}

	err := swapTlsCurrent(vaultHome, "main", "2.0.0", defaultCertsSwapSettings())
	if !errors.Is(err, readErr) {
		t.Fatalf("swap error = %v, want the read failure", err)
	}
	requireNothingSwapped(t, vaultHome, fake)
}

// Every lb is read at the config its reload names, and with a read that prints
// only tls lines, because outAndLog logs what a command prints.
func TestCertsSwapReadsEachLbsOwnConfig(t *testing.T) {
	vaultHome := setupCertsSwapVault(t)
	fake := newFakeLbDocker(t, vaultHome)
	fake.lines = []string{
		"aaaa11 edge-0.example.com-eth0",
		"bbbb22 edge-0.example.com-eth1",
	}

	if err := swapTlsCurrent(vaultHome, "main", "2.0.0", defaultCertsSwapSettings()); err != nil {
		t.Fatal(err)
	}

	want := [][]string{
		{"exec", "aaaa11", "grep", "ssl_certificate", "/srv/warp/nginx.conf/edge-0.example.com-eth0.conf"},
		{"exec", "bbbb22", "grep", "ssl_certificate", "/srv/warp/nginx.conf/edge-0.example.com-eth1.conf"},
	}
	if !slices.EqualFunc(fake.tlsReadArgs, want, slices.Equal[[]string]) {
		t.Fatalf("read %v, want %v", fake.tlsReadArgs, want)
	}
}

// A version can hold a name this lb has no server for, which it does not read and
// a link for which harms nothing.
func TestCertsSwapMovesNamesTheLbDoesNotRead(t *testing.T) {
	vaultHome := setupCertsSwapVault(t)
	fake := newFakeLbDocker(t, vaultHome)
	fake.tlsLines = map[string][]string{"aaaa11": tlsCurrentLines("star.example.com")}

	if err := swapTlsCurrent(vaultHome, "main", "2.0.0", defaultCertsSwapSettings()); err != nil {
		t.Fatal(err)
	}

	for _, name := range []string{"example.com", "star.example.com"} {
		requireTlsLink(t, vaultHome, name, filepath.Join("..", "2.0.0", name))
	}
	if len(fake.reloadArgs) != 1 {
		t.Fatalf("reloaded %d times, want 1", len(fake.reloadArgs))
	}
}

// A name this version does not hold has nothing new to serve, so a versioned path
// for it does not stop the swap. No swap will ever move that path, though, so the
// operator is told.
func TestCertsSwapSaysWhichNamesItCanNeverMove(t *testing.T) {
	vaultHome := setupCertsSwapVault(t)
	fake := newFakeLbDocker(t, vaultHome)
	fake.tlsLines = map[string][]string{
		"aaaa11": append(tlsCurrentLines("star.example.com"), tlsVersionLines("1.0.0", "old.example")...),
	}
	output := captureSwapOutput(t)

	if err := swapTlsCurrent(vaultHome, "main", "2.0.0", defaultCertsSwapSettings()); err != nil {
		t.Fatal(err)
	}

	if !strings.Contains(output.String(), "edge-0.example.com-eth0 keeps reading old.example from /srv/warp/vault/tls/1.0.0/old.example/") {
		t.Fatalf("output %q does not name the path no swap moves", output.String())
	}
}

// A line nginx never acts on says nothing about what the lb reads.
func TestCertsSwapPassesOverACommentedOutPath(t *testing.T) {
	vaultHome := setupCertsSwapVault(t)
	fake := newFakeLbDocker(t, vaultHome)
	fake.tlsLines = map[string][]string{
		"aaaa11": append(
			tlsCurrentLines("star.example.com"),
			"# ssl_certificate /srv/warp/vault/tls/1.0.0/star.example.com/star.example.com.pem;",
		),
	}

	if err := swapTlsCurrent(vaultHome, "main", "2.0.0", defaultCertsSwapSettings()); err != nil {
		t.Fatal(err)
	}
}

// What `grep ssl_certificate` finds in a generated config.
func grepTlsLines(config string) []string {
	lines := []string{}
	for _, line := range strings.Split(config, "\n") {
		if strings.Contains(line, "ssl_certificate") {
			lines = append(lines, line)
		}
	}
	return lines
}

// A swap's reading of an lb config and the build's writing of one must agree, so
// this feeds it what the build generates. A vault without tls/current generates
// what every lb image bakes today, which no swap reaches.
func TestCertsSwapRefusesEveryBlockGeneratedWithoutCurrent(t *testing.T) {
	env, _, _ := setupTlsCurrentVault(t)
	blockConfigs := generateTlsConfigs(t, env)
	if len(blockConfigs) == 0 {
		t.Fatal("generated no blocks")
	}

	for block, config := range blockConfigs {
		vaultHome := setupCertsSwapVault(t)
		fake := newFakeLbDocker(t, vaultHome)
		fake.lines = []string{fmt.Sprintf("aaaa11 %s", block)}
		fake.tlsLines = map[string][]string{"aaaa11": grepTlsLines(config)}

		err := swapTlsCurrent(vaultHome, env, "2.0.0", defaultCertsSwapSettings())
		if err == nil || !strings.Contains(err.Error(), "star.example.com") {
			t.Errorf("block %s: swap error = %v, want one naming the versioned name", block, err)
		}
		requireNothingSwapped(t, vaultHome, fake)
	}
}

// The other half: a vault holding the entry generates paths a swap reaches.
func TestCertsSwapReachesEveryBlockGeneratedWithCurrent(t *testing.T) {
	env, vaultDir, newestVersion := setupTlsCurrentVault(t)
	linkTlsCurrent(t, vaultDir, "star.example.com", newestVersion)
	blockConfigs := generateTlsConfigs(t, env)
	if len(blockConfigs) == 0 {
		t.Fatal("generated no blocks")
	}

	for block, config := range blockConfigs {
		vaultHome := setupCertsSwapVault(t)
		fake := newFakeLbDocker(t, vaultHome)
		fake.lines = []string{fmt.Sprintf("aaaa11 %s", block)}
		fake.tlsLines = map[string][]string{"aaaa11": grepTlsLines(config)}

		if err := swapTlsCurrent(vaultHome, env, "2.0.0", defaultCertsSwapSettings()); err != nil {
			t.Errorf("block %s: %v", block, err)
		}
		if len(fake.reloadArgs) != 1 {
			t.Errorf("block %s reloaded %d times, want 1", block, len(fake.reloadArgs))
		}
	}
}

// After a deploy the old lb drains for up to an hour beside the new one. It takes
// no reload and no new connections, so the swap is for the new one alone, and the
// old one's image is no reason to refuse.
func TestCertsSwapPassesOverADrainingLb(t *testing.T) {
	vaultHome := setupCertsSwapVault(t)
	fake := newFakeLbDocker(t, vaultHome)
	fake.lines = []string{
		"aaaa11 edge-0.example.com-eth0",
		"bbbb22 edge-0.example.com-eth0",
	}
	fake.topOutputs = map[string]string{"aaaa11": drainingLbTop}
	fake.tlsLines = map[string][]string{"aaaa11": tlsVersionLines("1.0.0", "star.example.com")}
	output := captureSwapOutput(t)

	if err := swapTlsCurrent(vaultHome, "main", "2.0.0", defaultCertsSwapSettings()); err != nil {
		t.Fatal(err)
	}

	want := [][]string{
		{"exec", "bbbb22", "nginx", "-c", "/srv/warp/nginx.conf/edge-0.example.com-eth0.conf", "-s", "reload"},
	}
	if !slices.EqualFunc(fake.reloadArgs, want, slices.Equal[[]string]) {
		t.Fatalf("reloads %v, want %v", fake.reloadArgs, want)
	}
	if count := strings.Count(output.String(), "Reloaded edge-0.example.com-eth0"); count != 1 {
		t.Errorf("printed Reloaded %d times, want 1: %q", count, output.String())
	}
	if !strings.Contains(output.String(), "Passing over edge-0.example.com-eth0") {
		t.Errorf("output %q does not name the draining lb", output.String())
	}
}

// nginx answers 0 to a reload while it drains, then ignores it. A host whose only
// lb is draining has nothing to reload, the same as a host with none.
func TestCertsSwapRefusesHostWhoseOnlyLbIsDraining(t *testing.T) {
	vaultHome := setupCertsSwapVault(t)
	fake := newFakeLbDocker(t, vaultHome)
	fake.topOutputs = map[string]string{"aaaa11": drainingLbTop}

	err := swapTlsCurrent(vaultHome, "main", "2.0.0", defaultCertsSwapSettings())
	if err == nil || !strings.Contains(err.Error(), "--no-reload") {
		t.Fatalf("swap error = %v, want one naming --no-reload", err)
	}
	requireNothingSwapped(t, vaultHome, fake)
}

// An lb whose nginx has no workers at all may be starting, and may read the links
// before or after they move, so a swap cannot pass over it as it does a drain.
func TestCertsSwapRefusesLbWithNoWorkers(t *testing.T) {
	vaultHome := setupCertsSwapVault(t)
	fake := newFakeLbDocker(t, vaultHome)
	fake.topOutputs = map[string]string{"aaaa11": "PID COMMAND\n1 /usr/local/sbin/lb\n"}

	err := swapTlsCurrent(vaultHome, "main", "2.0.0", defaultCertsSwapSettings())
	if err == nil || !strings.Contains(err.Error(), "edge-0.example.com-eth0") {
		t.Fatalf("swap error = %v, want one naming the lb", err)
	}
	requireNothingSwapped(t, vaultHome, fake)
}

// An lb in a restart loop answers `docker top` with an error, and a swap cannot say
// what it would reach. --no-reload is the way out of that state.
func TestCertsSwapRefusesLbWhoseWorkersItCannotRead(t *testing.T) {
	vaultHome := setupCertsSwapVault(t)
	fake := newFakeLbDocker(t, vaultHome)
	topErr := errors.New("container is restarting")
	fake.topErrs = map[string]error{"aaaa11": topErr}

	err := swapTlsCurrent(vaultHome, "main", "2.0.0", defaultCertsSwapSettings())
	if !errors.Is(err, topErr) {
		t.Fatalf("swap error = %v, want the top failure", err)
	}
	requireNothingSwapped(t, vaultHome, fake)
}

// Old workers finish their connections for up to an hour after a reload, so one
// shutting down says nothing about an lb that has another serving.
func TestCertsSwapTakesAnLbWithOldWorkersForAServingOne(t *testing.T) {
	vaultHome := setupCertsSwapVault(t)
	fake := newFakeLbDocker(t, vaultHome)
	fake.topOutputs = map[string]string{"aaaa11": drainingLbTop + "9 nginx: worker process\n"}
	fake.onReload = func(containerId string) error {
		fake.topOutputs[containerId] = drainingLbTop + "9 nginx: worker process is shutting down\n10 nginx: worker process\n"
		return nil
	}

	if err := swapTlsCurrent(vaultHome, "main", "2.0.0", defaultCertsSwapSettings()); err != nil {
		t.Fatal(err)
	}
	if len(fake.reloadArgs) != 1 {
		t.Fatalf("reloaded %d times, want 1", len(fake.reloadArgs))
	}
}

// nginx exits 0 once the signal is sent, and a master that began draining after
// the census ignores it, so that exit proves nothing. `Reloaded` needs the new
// worker, and a swap without one has not happened.
func TestCertsSwapFailsAReloadThatStartsNoWorker(t *testing.T) {
	vaultHome := setupCertsSwapVault(t)
	fake := newFakeLbDocker(t, vaultHome)
	if err := swapTlsCurrent(vaultHome, "main", "1.0.0", defaultCertsSwapSettings()); err != nil {
		t.Fatal(err)
	}
	fake.deafContainerIds = map[string]bool{"aaaa11": true}
	output := captureSwapOutput(t)
	settings := defaultCertsSwapSettings()
	settings.reloadCheckCount = 3
	settings.reloadCheckInterval = 0

	err := swapTlsCurrent(vaultHome, "main", "2.0.0", settings)
	if err == nil || !strings.Contains(err.Error(), "edge-0.example.com-eth0") {
		t.Fatalf("swap error = %v, want one naming the lb", err)
	}
	if strings.Contains(output.String(), "Reloaded edge-0") {
		t.Errorf("printed Reloaded with no new worker: %q", output.String())
	}
	for _, name := range []string{"example.com", "star.example.com"} {
		requireTlsLink(t, vaultHome, name, filepath.Join("..", "1.0.0", name))
	}
}

// An lb mounting some other vault, such as a host's staged copy, reloads and shows
// new workers, and serves what it served, because the links moved somewhere it does
// not read. Its reload would prove nothing, so it never happens.
func TestCertsSwapFailsWhenAnLbDoesNotSeeTheLinks(t *testing.T) {
	vaultHome := setupCertsSwapVault(t)
	fake := newFakeLbDocker(t, vaultHome)
	if err := swapTlsCurrent(vaultHome, "main", "1.0.0", defaultCertsSwapSettings()); err != nil {
		t.Fatal(err)
	}
	fake.reloadArgs = nil
	fake.linkOutputs = map[string]string{"aaaa11": "../1.0.0/example.com\n../1.0.0/star.example.com\n"}

	err := swapTlsCurrent(vaultHome, "main", "2.0.0", defaultCertsSwapSettings())
	if err == nil || !strings.Contains(err.Error(), "edge-0.example.com-eth0") || !strings.Contains(err.Error(), vaultHome) {
		t.Fatalf("swap error = %v, want one naming the lb and this vault", err)
	}
	if len(fake.reloadArgs) != 0 {
		t.Errorf("reloaded an lb that cannot see the links: %v", fake.reloadArgs)
	}
	for _, name := range []string{"example.com", "star.example.com"} {
		requireTlsLink(t, vaultHome, name, filepath.Join("..", "1.0.0", name))
	}
}

// Not knowing what an lb sees is not knowing it sees the swap.
func TestCertsSwapFailsWhenItCannotReadAnLbsLinks(t *testing.T) {
	vaultHome := setupCertsSwapVault(t)
	fake := newFakeLbDocker(t, vaultHome)
	linkErr := errors.New("no such file")
	fake.linkErrs = map[string]error{"aaaa11": linkErr}

	err := swapTlsCurrent(vaultHome, "main", "2.0.0", defaultCertsSwapSettings())
	if !errors.Is(err, linkErr) {
		t.Fatalf("swap error = %v, want the read failure", err)
	}
	if len(fake.reloadArgs) != 0 {
		t.Errorf("reloaded an lb whose links it could not read: %v", fake.reloadArgs)
	}
}

// Only the names an lb reads have to show there: one this lb has no server for may
// have no link in a vault it mounts, and every lb is asked only for its own.
func TestCertsSwapLooksOnlyAtTheLinksAnLbReads(t *testing.T) {
	vaultHome := setupCertsSwapVault(t)
	fake := newFakeLbDocker(t, vaultHome)
	fake.tlsLines = map[string][]string{"aaaa11": tlsCurrentLines("star.example.com")}
	fake.linkOutputs = map[string]string{"aaaa11": "../2.0.0/star.example.com\n"}

	if err := swapTlsCurrent(vaultHome, "main", "2.0.0", defaultCertsSwapSettings()); err != nil {
		t.Fatal(err)
	}
}

// An lb can finish its drain and exit while a swap looks for its new worker. That
// is no reload either, and the failure says which step found it out.
func TestCertsSwapFailsAReloadItCannotConfirm(t *testing.T) {
	vaultHome := setupCertsSwapVault(t)
	fake := newFakeLbDocker(t, vaultHome)
	if err := swapTlsCurrent(vaultHome, "main", "1.0.0", defaultCertsSwapSettings()); err != nil {
		t.Fatal(err)
	}
	topErr := errors.New("container is not running")
	fake.onReload = func(containerId string) error {
		fake.topErrs = map[string]error{containerId: topErr}
		return nil
	}

	err := swapTlsCurrent(vaultHome, "main", "2.0.0", defaultCertsSwapSettings())
	if !errors.Is(err, topErr) || !strings.Contains(err.Error(), "after the signal") {
		t.Fatalf("swap error = %v, want the top failure, placed after the signal", err)
	}
	for _, name := range []string{"example.com", "star.example.com"} {
		requireTlsLink(t, vaultHome, name, filepath.Join("..", "1.0.0", name))
	}
}

// Without the workers from before the signal no new one can be told from them, so
// that lb is not signalled, and the lb already reloaded goes back.
func TestCertsSwapSignalsNoLbWhoseWorkersItCannotReadFirst(t *testing.T) {
	vaultHome := setupCertsSwapVault(t)
	fake := newFakeLbDocker(t, vaultHome)
	fake.lines = []string{
		"aaaa11 edge-0.example.com-eth0",
		"bbbb22 edge-0.example.com-eth1",
	}
	topErr := errors.New("container is not running")
	fake.onReload = func(containerId string) error {
		fake.topErrs = map[string]error{"bbbb22": topErr}
		return nil
	}

	err := swapTlsCurrent(vaultHome, "main", "2.0.0", defaultCertsSwapSettings())
	if !errors.Is(err, topErr) || !strings.Contains(err.Error(), "before the signal") {
		t.Fatalf("swap error = %v, want the top failure, placed before the signal", err)
	}
	reloadedIds := []string{}
	for _, reloadArgs := range fake.reloadArgs {
		reloadedIds = append(reloadedIds, reloadArgs[1])
	}
	if want := []string{"aaaa11", "aaaa11"}; !slices.Equal(reloadedIds, want) {
		t.Fatalf("reloaded %v, want %v", reloadedIds, want)
	}
}

// The master parses its config after the nginx that signalled it has exited, so
// a new worker can be some looks away, and the last look counts.
func TestCertsSwapLooksForTheNewWorkerUpToItsCount(t *testing.T) {
	cases := []struct {
		slowReloadLooks int
		wantErr         bool
	}{
		{slowReloadLooks: 0, wantErr: false},
		{slowReloadLooks: 2, wantErr: false},
		{slowReloadLooks: 3, wantErr: true},
	}
	for _, c := range cases {
		vaultHome := setupCertsSwapVault(t)
		fake := newFakeLbDocker(t, vaultHome)
		fake.slowReloadLooks = c.slowReloadLooks
		settings := defaultCertsSwapSettings()
		settings.reloadCheckCount = 3
		settings.reloadCheckInterval = 0

		err := swapTlsCurrent(vaultHome, "main", "2.0.0", settings)
		if (err != nil) != c.wantErr {
			t.Errorf("worker %d looks away: swap error = %v, want an error: %v", c.slowReloadLooks, err, c.wantErr)
		}
	}
}

// With no looks allowed no reload can be proven, which its doc says.
func TestCertsSwapFailsEveryReloadWithNoLooks(t *testing.T) {
	vaultHome := setupCertsSwapVault(t)
	newFakeLbDocker(t, vaultHome)
	settings := defaultCertsSwapSettings()
	settings.reloadCheckCount = 0

	if err := swapTlsCurrent(vaultHome, "main", "2.0.0", settings); err == nil {
		t.Fatal("swap succeeded with no look at the workers")
	}
}

// A version nginx refuses must not stay in the links, because the next lb start
// reads them and fails. The failure reaches the caller, nothing moved stays moved,
// and nothing is left to reload back.
func TestCertsSwapPutsLinksBackWhenAReloadFails(t *testing.T) {
	vaultHome := setupCertsSwapVault(t)
	fake := newFakeLbDocker(t, vaultHome)
	if err := swapTlsCurrent(vaultHome, "main", "1.0.0", defaultCertsSwapSettings()); err != nil {
		t.Fatal(err)
	}
	fake.reloadArgs = nil
	reloadErr := errors.New("nginx refused the reload")
	fake.reloadErrs = map[string]error{"aaaa11": reloadErr}

	err := swapTlsCurrent(vaultHome, "main", "2.0.0", defaultCertsSwapSettings())
	if !errors.Is(err, reloadErr) {
		t.Fatalf("swap error = %v, want the reload failure", err)
	}
	if !strings.Contains(err.Error(), "edge-0.example.com-eth0") {
		t.Errorf("swap error = %v, want one naming the block", err)
	}
	for _, name := range []string{"example.com", "star.example.com"} {
		requireTlsLink(t, vaultHome, name, filepath.Join("..", "1.0.0", name))
	}
	if len(fake.reloadArgs) != 1 {
		t.Errorf("attempted %d reloads, want 1", len(fake.reloadArgs))
	}
}

// A first swap has no links to go back to, so its links go.
func TestCertsSwapRemovesLinksItAddedWhenAReloadFails(t *testing.T) {
	vaultHome := setupCertsSwapVault(t)
	fake := newFakeLbDocker(t, vaultHome)
	fake.reloadErrs = map[string]error{"aaaa11": errors.New("nginx refused the reload")}

	if err := swapTlsCurrent(vaultHome, "main", "2.0.0", defaultCertsSwapSettings()); err == nil {
		t.Fatal("swap hid a failed reload")
	}

	entries, err := os.ReadDir(filepath.Join(vaultHome, "tls", tlsCurrentDirName))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("a failed swap left %v", entries)
	}
}

// Links that move back must take any lb already reloaded with them, or it alone
// serves the pair the swap gave up on. The block after the failure never reloads.
func TestCertsSwapReloadsBackTheLbsAlreadyReloaded(t *testing.T) {
	vaultHome := setupCertsSwapVault(t)
	fake := newFakeLbDocker(t, vaultHome)
	fake.lines = []string{
		"aaaa11 edge-0.example.com-eth0",
		"bbbb22 edge-0.example.com-eth1",
		"cccc33 edge-0.example.com-eth2",
	}
	if err := swapTlsCurrent(vaultHome, "main", "1.0.0", defaultCertsSwapSettings()); err != nil {
		t.Fatal(err)
	}
	fake.reloadArgs = nil
	reloadErr := errors.New("nginx refused the reload")
	fake.reloadErrs = map[string]error{"bbbb22": reloadErr}
	linkAtEachReload := map[string][]string{}
	fake.onReload = func(containerId string) error {
		target, err := os.Readlink(tlsCurrentLinkPath(vaultHome, "star.example.com"))
		if err != nil {
			t.Fatal(err)
		}
		linkAtEachReload[containerId] = append(linkAtEachReload[containerId], target)
		return nil
	}

	err := swapTlsCurrent(vaultHome, "main", "2.0.0", defaultCertsSwapSettings())
	if !errors.Is(err, reloadErr) {
		t.Fatalf("swap error = %v, want the reload failure", err)
	}

	newTarget := filepath.Join("..", "2.0.0", "star.example.com")
	oldTarget := filepath.Join("..", "1.0.0", "star.example.com")
	want := map[string][]string{
		"aaaa11": {newTarget, oldTarget},
		"bbbb22": {newTarget},
	}
	if !maps.EqualFunc(linkAtEachReload, want, slices.Equal[[]string]) {
		t.Fatalf("reloads read %v, want %v", linkAtEachReload, want)
	}
}

// A reload back needs a worker of its own: the first reload's new worker is no
// proof of the second, which the lb may ignore as it can any other.
func TestCertsSwapFailsAReloadBackThatStartsNoWorker(t *testing.T) {
	vaultHome := setupCertsSwapVault(t)
	fake := newFakeLbDocker(t, vaultHome)
	fake.lines = []string{
		"aaaa11 edge-0.example.com-eth0",
		"bbbb22 edge-0.example.com-eth1",
	}
	reloadErr := errors.New("nginx refused the reload")
	fake.reloadErrs = map[string]error{"bbbb22": reloadErr}
	fake.onReload = func(containerId string) error {
		if containerId == "bbbb22" {
			fake.deafContainerIds = map[string]bool{"aaaa11": true}
		}
		return nil
	}
	output := captureSwapOutput(t)
	settings := defaultCertsSwapSettings()
	settings.reloadCheckCount = 3
	settings.reloadCheckInterval = 0

	err := swapTlsCurrent(vaultHome, "main", "2.0.0", settings)
	if !errors.Is(err, reloadErr) || !strings.Contains(err.Error(), "reload edge-0.example.com-eth0 back") {
		t.Fatalf("swap error = %v, want the refused reload and the failed reload back", err)
	}
	if strings.Contains(output.String(), "Reloaded edge-0.example.com-eth0 back") {
		t.Errorf("claimed a reload back with no new worker: %q", output.String())
	}
}

// An lb that cannot be reloaded back serves the new pair until something reloads
// it, which the operator must hear of.
func TestCertsSwapReportsAnLbItCouldNotReloadBack(t *testing.T) {
	vaultHome := setupCertsSwapVault(t)
	fake := newFakeLbDocker(t, vaultHome)
	fake.lines = []string{
		"aaaa11 edge-0.example.com-eth0",
		"bbbb22 edge-0.example.com-eth1",
	}
	reloadErr := errors.New("nginx refused the reload")
	fake.reloadErrs = map[string]error{"bbbb22": reloadErr}
	reloadBackErr := errors.New("daemon unavailable")
	fake.onReload = func(containerId string) error {
		if containerId == "aaaa11" && 0 < fake.reloadCounts["aaaa11"] {
			return reloadBackErr
		}
		return nil
	}

	err := swapTlsCurrent(vaultHome, "main", "2.0.0", defaultCertsSwapSettings())
	if !errors.Is(err, reloadErr) || !errors.Is(err, reloadBackErr) {
		t.Fatalf("swap error = %v, want both failures", err)
	}
	if !strings.Contains(err.Error(), "edge-0.example.com-eth0") {
		t.Errorf("swap error = %v, want one naming the lb left on the new pair", err)
	}
}

// A retry after a failed reload is how an operator recovers, and it starts over.
func TestCertsSwapRetrySwapsAfterAFailure(t *testing.T) {
	vaultHome := setupCertsSwapVault(t)
	fake := newFakeLbDocker(t, vaultHome)
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
	requireTlsLink(t, vaultHome, "star.example.com", filepath.Join("..", "2.0.0", "star.example.com"))
}

// A first lb start needs the links, and the lb is what reads them, so a new host
// has none running to reload. Nothing here touches docker, which a new host may
// not have started.
func TestCertsSwapNoReloadSeedsANewHost(t *testing.T) {
	vaultHome := setupCertsSwapVault(t)
	fake := newFakeLbDocker(t, vaultHome)
	fake.lines = nil
	settings := defaultCertsSwapSettings()
	settings.noReload = true

	if err := swapTlsCurrent(vaultHome, "main", "2.0.0", settings); err != nil {
		t.Fatal(err)
	}

	for _, name := range []string{"example.com", "star.example.com"} {
		requireTlsLink(t, vaultHome, name, filepath.Join("..", "2.0.0", name))
	}
	if fake.commandCount != 0 {
		t.Errorf("ran %d docker commands, want none", fake.commandCount)
	}
	if err := checkTlsCurrent(vaultHome); err != nil {
		t.Error(err)
	}
}

// Recovery has to run when the lb is down and docker with it: the links are all
// that stand between the host and its next lb start.
func TestCertsSwapNoReloadRollsBackWithDockerDown(t *testing.T) {
	vaultHome := setupCertsSwapVault(t)
	fake := newFakeLbDocker(t, vaultHome)
	if err := swapTlsCurrent(vaultHome, "main", "2.0.0", defaultCertsSwapSettings()); err != nil {
		t.Fatal(err)
	}
	fake.censusErr = errors.New("daemon unavailable")
	if err := swapTlsCurrent(vaultHome, "main", "1.0.0", defaultCertsSwapSettings()); err == nil {
		t.Fatal("a plain swap succeeded with docker down")
	}
	requireTlsLink(t, vaultHome, "star.example.com", filepath.Join("..", "2.0.0", "star.example.com"))

	settings := defaultCertsSwapSettings()
	settings.noReload = true
	if err := swapTlsCurrent(vaultHome, "main", "1.0.0", settings); err != nil {
		t.Fatal(err)
	}

	requireTlsLink(t, vaultHome, "star.example.com", filepath.Join("..", "1.0.0", "star.example.com"))
}

// Skipping the lb skips nothing else: the pairs are all that judge the version.
func TestCertsSwapNoReloadStillChecksEveryPair(t *testing.T) {
	vaultHome := setupCertsSwapVault(t)
	fake := newFakeLbDocker(t, vaultHome)
	mismatchTlsPair(t, vaultHome, "2.0.0", "star.example.com", "1.0.0")
	settings := defaultCertsSwapSettings()
	settings.noReload = true

	if err := swapTlsCurrent(vaultHome, "main", "2.0.0", settings); err == nil {
		t.Fatal("swap accepted a bad pair")
	}
	requireNothingSwapped(t, vaultHome, fake)
}

// Links moved with nothing reloaded must not read as a rotation.
func TestCertsSwapNoReloadSaysNothingWasReloaded(t *testing.T) {
	vaultHome := setupCertsSwapVault(t)
	newFakeLbDocker(t, vaultHome)
	output := captureSwapOutput(t)
	settings := defaultCertsSwapSettings()
	settings.noReload = true

	if err := swapTlsCurrent(vaultHome, "main", "2.0.0", settings); err != nil {
		t.Fatal(err)
	}

	if !strings.Contains(output.String(), "Reloaded nothing") {
		t.Fatalf("output %q does not say nothing was reloaded", output.String())
	}
}

// Rollback is a swap to the older version.
func TestCertsSwapMovesBackToAnOlderVersion(t *testing.T) {
	vaultHome := setupCertsSwapVault(t)
	newFakeLbDocker(t, vaultHome)
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
	newFakeLbDocker(t, vaultHome)
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
	newFakeLbDocker(t, vaultHome)
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

// A move that fails reaches the caller, reloads nothing and leaves no link.
func TestCertsSwapReportsAFailedMove(t *testing.T) {
	vaultHome := setupCertsSwapVault(t)
	fake := newFakeLbDocker(t, vaultHome)
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

// A move that fails midway must not leave a version half in place: the name
// before it goes back, so the pair of names still agree.
func TestCertsSwapPutsLinksBackWhenAMoveFails(t *testing.T) {
	vaultHome := setupCertsSwapVault(t)
	fake := newFakeLbDocker(t, vaultHome)
	if err := swapTlsCurrent(vaultHome, "main", "1.0.0", defaultCertsSwapSettings()); err != nil {
		t.Fatal(err)
	}
	fake.reloadArgs = nil
	settings := defaultCertsSwapSettings()
	renameErr := errors.New("disk failure")
	settings.rename = func(oldPath string, newPath string) error {
		if filepath.Base(newPath) == "star.example.com" {
			return renameErr
		}
		return os.Rename(oldPath, newPath)
	}

	err := swapTlsCurrent(vaultHome, "main", "2.0.0", settings)
	if !errors.Is(err, renameErr) {
		t.Fatalf("swap error = %v, want the rename failure", err)
	}
	for _, name := range []string{"example.com", "star.example.com"} {
		requireTlsLink(t, vaultHome, name, filepath.Join("..", "1.0.0", name))
	}
	if len(fake.reloadArgs) != 0 {
		t.Errorf("a failed move reloaded nginx: %v", fake.reloadArgs)
	}
}

// A link that cannot go back leaves the host in a state only the operator can
// judge, so the failure names it.
func TestCertsSwapReportsALinkItCouldNotPutBack(t *testing.T) {
	vaultHome := setupCertsSwapVault(t)
	fake := newFakeLbDocker(t, vaultHome)
	if err := swapTlsCurrent(vaultHome, "main", "1.0.0", defaultCertsSwapSettings()); err != nil {
		t.Fatal(err)
	}
	reloadErr := errors.New("nginx refused the reload")
	fake.reloadErrs = map[string]error{"aaaa11": reloadErr}
	settings := defaultCertsSwapSettings()
	putBackErr := errors.New("disk failure")
	renameCount := 0
	settings.rename = func(oldPath string, newPath string) error {
		renameCount += 1
		if 2 < renameCount {
			return putBackErr
		}
		return os.Rename(oldPath, newPath)
	}

	err := swapTlsCurrent(vaultHome, "main", "2.0.0", settings)
	if !errors.Is(err, reloadErr) || !errors.Is(err, putBackErr) {
		t.Fatalf("swap error = %v, want both failures", err)
	}
	if !strings.Contains(err.Error(), "star.example.com") {
		t.Errorf("swap error = %v, want one naming the link", err)
	}
}

// A stray file in a version is not a name, so it gets no link and fails no check.
func TestCertsSwapPassesOverFilesInAVersion(t *testing.T) {
	vaultHome := setupCertsSwapVault(t)
	newFakeLbDocker(t, vaultHome)
	if err := os.WriteFile(filepath.Join(vaultHome, "tls", "2.0.0", "NOTES"), []byte("issued by hand"), 0600); err != nil {
		t.Fatal(err)
	}

	if err := swapTlsCurrent(vaultHome, "main", "2.0.0", defaultCertsSwapSettings()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(tlsCurrentLinkPath(vaultHome, "NOTES")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a stray file got a link: %v", err)
	}
}

// tls/current leads to private keys, so a swap creates it for its owner alone.
func TestCertsSwapCreatesCurrentForItsOwnerAlone(t *testing.T) {
	vaultHome := setupCertsSwapVault(t)
	newFakeLbDocker(t, vaultHome)

	if err := swapTlsCurrent(vaultHome, "main", "2.0.0", defaultCertsSwapSettings()); err != nil {
		t.Fatal(err)
	}

	info, err := os.Stat(filepath.Join(vaultHome, "tls", tlsCurrentDirName))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0700 {
		t.Fatalf("tls/current has mode %o, want 700", info.Mode().Perm())
	}
}

// A call past the timeout is a failure whatever docker answered, and a timeout
// that is not positive is past already, as its doc says. It stops the swap at
// the census.
func TestCertsSwapRefusesAtTheCensusWithNoTimeLeft(t *testing.T) {
	for _, dockerTimeout := range []time.Duration{0, -time.Second} {
		vaultHome := setupCertsSwapVault(t)
		fake := newFakeLbDocker(t, vaultHome)
		settings := defaultCertsSwapSettings()
		settings.dockerTimeout = dockerTimeout

		err := swapTlsCurrent(vaultHome, "main", "2.0.0", settings)
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("timeout %s: swap error = %v, want the deadline", dockerTimeout, err)
		}
		requireNothingSwapped(t, vaultHome, fake)
	}
}

// Writes a docker onto a new directory with a sudo that passes through, since
// docker() goes through sudo on linux, and returns the PATH that finds them.
func dockerScriptPath(t *testing.T, dockerScript string) (binDir string, path string) {
	t.Helper()
	binDir = t.TempDir()
	scripts := map[string]string{
		"docker": dockerScript,
		"sudo":   "#!/bin/sh\nexec \"$@\"\n",
	}
	for name, script := range scripts {
		if err := os.WriteFile(filepath.Join(binDir, name), []byte(script), 0755); err != nil {
			t.Fatal(err)
		}
	}
	return binDir, binDir + string(os.PathListSeparator) + os.Getenv("PATH")
}

// A daemon that never answers fails the swap instead of hanging the job that ran
// it. The sleep ends by itself, so that without the bound this fails, not hangs.
func TestCertsSwapGivesUpOnAHungDocker(t *testing.T) {
	vaultHome := setupCertsSwapVault(t)
	_, path := dockerScriptPath(t, "#!/bin/sh\nexec sleep 30\n")
	t.Setenv("PATH", path)
	settings := defaultCertsSwapSettings()
	settings.dockerTimeout = time.Millisecond

	err := swapTlsCurrent(vaultHome, "main", "2.0.0", settings)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("swap error = %v, want the deadline", err)
	}
	requireNothingSwapped(t, vaultHome, &fakeLbDocker{})
}

// What a swap writes must satisfy the check an lb build runs on the same tree.
func TestCertsSwapLeavesATreeTheLbBuildAccepts(t *testing.T) {
	vaultHome := setupCertsSwapVault(t)
	newFakeLbDocker(t, vaultHome)
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
	hostConfigPath  string
	blockConfigPath string
	output          *bytes.Buffer
}

// Starts one on a free port and stops it when the test ends. A caller waits for
// its first leaf, because nginx answers some time after it starts.
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
		hostConfigPath:  hostConfigPath,
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

// Whether an lb starting now would load what the links name. It is the check a
// start makes, run over the config this nginx started from.
func (self *tlsTestNginx) checkStart() error {
	output, err := exec.Command(self.binary, "-t", "-c", self.hostConfigPath, "-p", self.prefixDir).CombinedOutput()
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

// The leaf a version holds for a name.
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
	fake := newFakeLbDocker(t, vaultHome)
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

// nginx asks more of a pair than this command does, and proves a config loads
// before it signals. A pair that passed these checks is refused with the old pair
// still serving, the refusal reaches the caller, and the links go back, because a
// later lb start reads them and would fail where this reload did.
func TestCertsSwapSurfacesARefusedNginxReload(t *testing.T) {
	vaultHome := setupCertsSwapVault(t)
	fake := newFakeLbDocker(t, vaultHome)
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
	requireTlsLink(t, vaultHome, "star.example.com", filepath.Join("..", "1.0.0", "star.example.com"))
	if err := nginx.checkStart(); err != nil {
		t.Fatalf("an lb could not start from the links a refused swap left: %v", err)
	}
}

// Answers for the docker a warpctl process runs: one lb, with the tls lines and
// worker in the files beside this script, which a reload changes. A file named
// refuse-reload makes nginx refuse.
const fakeDockerScript = `#!/bin/sh
home=$(dirname "$0")
case "$1" in
ps)
	echo "aaaa11 edge-0.example.com-eth0"
	;;
top)
	echo "PID COMMAND"
	echo "$(cat "$home/worker") nginx: worker process"
	;;
exec)
	case "$3" in
	grep)
		cat "$home/tls-lines"
		;;
	readlink)
		shift 3
		for link in "$@"; do
			readlink "$WARP_VAULT_HOME${link#/srv/warp/vault}"
		done
		;;
	nginx)
		if [ -e "$home/refuse-reload" ]; then
			exit 1
		fi
		echo 200 > "$home/worker"
		;;
	esac
	;;
*)
	exit 64
	;;
esac
`

// Not a test: it is main, for the process runWarpctl starts.
func TestWarpctlMainHelper(t *testing.T) {
	args := os.Getenv("WARPCTL_MAIN_HELPER_ARGS")
	if args == "" {
		return
	}
	os.Args = append([]string{"warpctl"}, strings.Fields(args)...)
	main()
}

// Runs warpctl as a process against vaultHome, with the docker PATH finds, and
// returns all it printed with its exit status. The status is the whole of what
// D-OPS-12's job will see of a swap, and only a process has one.
func runWarpctl(t *testing.T, path string, vaultHome string, args ...string) (string, int) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestWarpctlMainHelper$")
	cmd.Env = append(
		os.Environ(),
		fmt.Sprintf("PATH=%s", path),
		fmt.Sprintf("WARP_HOME=%s", t.TempDir()),
		fmt.Sprintf("WARP_VAULT_HOME=%s", vaultHome),
		fmt.Sprintf("WARPCTL_MAIN_HELPER_ARGS=%s", strings.Join(args, " ")),
	)
	output, err := cmd.CombinedOutput()
	var exitErr *exec.ExitError
	if err != nil && !errors.As(err, &exitErr) {
		t.Fatal(err)
	}
	return string(output), cmd.ProcessState.ExitCode()
}

// A docker for runWarpctl whose one lb reads the fixture's names through
// tls/current, and the directory holding its files.
func setupWarpctlDocker(t *testing.T) (binDir string, path string) {
	t.Helper()
	binDir, path = dockerScriptPath(t, fakeDockerScript)
	files := map[string]string{
		"worker":    "100",
		"tls-lines": strings.Join(tlsCurrentLines("example.com", "star.example.com"), "\n"),
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(binDir, name), []byte(content), 0644); err != nil {
			t.Fatal(err)
		}
	}
	return binDir, path
}

// The command through main, from the usage line to the reload.
func TestCertsSwapCommandMovesLinksAndReloads(t *testing.T) {
	vaultHome := setupCertsSwapVault(t)
	_, path := setupWarpctlDocker(t)

	output, exitCode := runWarpctl(t, path, vaultHome, "certs", "swap", "main", "2.0.0")

	if exitCode != 0 {
		t.Fatalf("exited %d:\n%s", exitCode, output)
	}
	requireTlsLink(t, vaultHome, "star.example.com", filepath.Join("..", "2.0.0", "star.example.com"))
	if !strings.Contains(output, "Reloaded edge-0.example.com-eth0") {
		t.Fatalf("output does not say it reloaded:\n%s", output)
	}
}

// A swap nginx refused must exit non-zero, or the job that ran it reads a rotation
// that did not happen.
func TestCertsSwapCommandExitsNonZeroWhenNginxRefuses(t *testing.T) {
	vaultHome := setupCertsSwapVault(t)
	binDir, path := setupWarpctlDocker(t)
	if err := os.WriteFile(filepath.Join(binDir, "refuse-reload"), nil, 0644); err != nil {
		t.Fatal(err)
	}

	output, exitCode := runWarpctl(t, path, vaultHome, "certs", "swap", "main", "2.0.0")

	if exitCode == 0 {
		t.Fatalf("a refused swap exited 0:\n%s", output)
	}
	if _, err := os.Lstat(tlsCurrentLinkPath(vaultHome, "star.example.com")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a refused swap left its link: %v", err)
	}
}

// The same for a swap an lb's paths refuse, which is every lb's state today.
func TestCertsSwapCommandExitsNonZeroOnAVersionedLb(t *testing.T) {
	vaultHome := setupCertsSwapVault(t)
	binDir, path := setupWarpctlDocker(t)
	tlsLines := strings.Join(tlsVersionLines("1.0.0", "star.example.com"), "\n")
	if err := os.WriteFile(filepath.Join(binDir, "tls-lines"), []byte(tlsLines), 0644); err != nil {
		t.Fatal(err)
	}

	output, exitCode := runWarpctl(t, path, vaultHome, "certs", "swap", "main", "2.0.0")

	if exitCode == 0 {
		t.Fatalf("a swap that reaches nothing exited 0:\n%s", output)
	}
	if strings.Contains(output, "Reloaded") {
		t.Fatalf("a swap that reaches nothing printed Reloaded:\n%s", output)
	}
}

// The flag reaches the swap: with a docker that fails everything, it alone can
// move the links.
func TestCertsSwapCommandNoReloadNeedsNoDocker(t *testing.T) {
	vaultHome := setupCertsSwapVault(t)
	_, path := dockerScriptPath(t, "#!/bin/sh\nexit 1\n")

	output, exitCode := runWarpctl(t, path, vaultHome, "certs", "swap", "main", "2.0.0")
	if exitCode == 0 {
		t.Fatalf("a swap exited 0 with docker failing:\n%s", output)
	}

	output, exitCode = runWarpctl(t, path, vaultHome, "certs", "swap", "main", "2.0.0", "--no-reload")
	if exitCode != 0 {
		t.Fatalf("exited %d:\n%s", exitCode, output)
	}
	requireTlsLink(t, vaultHome, "star.example.com", filepath.Join("..", "2.0.0", "star.example.com"))
}
