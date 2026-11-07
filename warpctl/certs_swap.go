// `warpctl certs swap` is how a new certificate reaches a running lb without a
// new image. An lb image bakes its nginx config, so paths under tls/<version>
// can only change with a new image. Paths under tls/current name no version, so
// moving tls/current/<name> and reloading nginx is the whole rotation.
//
// It runs on one lb host, against that host's flat vault, after the version it
// names has reached the host. Links are relative, because the vault mounts at
// another path in the lb container, and there is one per name, because a pair
// has to change in one step and each name's newest version can differ. nginx
// reads the link only at start and reload, so a moved link changes nothing a
// client sees until the reload that follows it.
//
// Neither half of that is taken on trust. nginx reloads happily with a config
// that never reads tls/current, or from a vault that is not this one, and answers
// 0 to a reload it then ignores. So each lb's paths are read before a link moves,
// each lb must see the moved links, and `Reloaded` waits for a worker the lb did
// not have. nginx alone can say whether it will load a pair, and only once the
// links have moved, so a swap that fails puts them back: a refused version left
// in the links would stop the next lb start.
//
// tls/current must stay out of what the vault copy ships to a host, which
// follows links in the destination: it would overwrite the version a host's link
// points at, and a version's key is also a jwt key (see warp/README.md).

package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"maps"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/coreos/go-semver/semver"
	"github.com/docopt/docopt-go"
)

// Where the vault mounts in an lb container, which every tls path in its config
// starts with.
const lbVaultMountPath = "/srv/warp/vault"

// What nginx titles a worker in `docker top`, and what it retitles one that is
// finishing its connections. Both kinds run after a reload. A drain leaves only
// the second, and nginx's master ignores every reload from then on.
const (
	nginxWorkerTitle         = "nginx: worker process"
	nginxShutdownWorkerTitle = "nginx: worker process is shutting down"
)

// A tls path in an lb config. A line that is commented out does not match.
var lbTlsPathRegex = regexp.MustCompile(`(?m)^\s*ssl_certificate(?:_key)?\s+([^\s;]+)\s*;`)

// How one swap runs. Tests shorten the waits.
type certsSwapSettings struct {
	// Moves the links and touches no lb and no docker daemon, for a host with no
	// lb to reload: a new host before its first lb start, or a host whose lb is
	// down, where this is the rollback. Nothing but the pair checks judges the
	// version, and a running lb keeps its old pair until its next reload or start.
	noReload bool
	// Bounds each docker call, so that a wedged daemon fails the swap instead of
	// hanging the job that ran it. A reload parses the whole lb config first.
	// Non-positive expires every call at once, so the swap refuses at its census
	// with nothing moved.
	dockerTimeout time.Duration
	// How many times to look for a reload's new worker before failing the
	// reload. With the interval this bounds how long a master may take to parse
	// its config and start workers, which a minute covers many times over.
	// Non-positive never looks, so every reload fails.
	reloadCheckCount int
	// The wait between those looks, long enough to keep `docker top` calls few.
	// Non-positive looks again at once.
	reloadCheckInterval time.Duration
	// The time each certificate's validity is judged at.
	now func() time.Time
	// Moves one temporary link over its name. This is the one step that changes
	// what a name serves.
	rename func(oldPath string, newPath string) error
}

// The settings of a swap run on an lb host. A caller changes its own copy.
func defaultCertsSwapSettings() *certsSwapSettings {
	return &certsSwapSettings{
		noReload:            false,
		dockerTimeout:       60 * time.Second,
		reloadCheckCount:    120,
		reloadCheckInterval: 500 * time.Millisecond,
		now:                 time.Now,
		rename:              os.Rename,
	}
}

// One lb on this host that can take a reload.
type lbContainer struct {
	containerId string
	block       string
	// the names of this version the lb reads through tls/current
	reachedNames []string
}

// `warpctl certs swap <env> <version>`. A failed swap panics, which is this
// binary's non-zero exit: an operator and D-OPS-12's job both rely on it.
func certsSwap(opts docopt.Opts) {
	env, _ := opts.String("<env>")
	version, _ := opts.String("<version>")

	settings := defaultCertsSwapSettings()
	settings.noReload, _ = opts.Bool("--no-reload")

	err := swapTlsCurrent(
		getWarpState().warpSettings.RequireVaultHome(),
		env,
		version,
		settings,
	)
	if err != nil {
		panic(err)
	}
}

// Points tls/current/<name> at tls/<version>/<name> for every name the version
// holds, then reloads nginx in this host's lb containers. Names the version does
// not hold stay where they are, and swapping to an older version is a rollback.
//
// Every check comes before the first link moves, so a refusal changes nothing.
// That covers the lbs too: one reading a name of this version from anywhere but
// tls/current would reload and go on serving what it served, as would one reading
// none of them. A draining lb is passed over, since it takes no reload and no new
// connections, and with no lb left to reload the swap refuses, unless
// settings.noReload asks for the links alone.
//
// A move or reload that fails, or an lb that does not see the moved links, puts
// every link back and reloads any lb already reloaded, so a failed swap leaves the
// host as it was and can simply be run again. An lb whose reload failed goes on
// serving its old pair from memory.
func swapTlsCurrent(vaultHome string, env string, version string, settings *certsSwapSettings) error {
	// this also refuses tls/current and anything that is a path, not a name
	if _, err := semver.NewVersion(version); err != nil {
		return fmt.Errorf("%q is not a tls version: %w", version, err)
	}
	versionHome := filepath.Join(vaultHome, "tls", version)
	currentHome := filepath.Join(vaultHome, "tls", tlsCurrentDirName)

	// a pair must be one a visitor can trust: the key matches the certificate,
	// which is valid now and covers the name. star.<domain> is the wildcard's
	// name, which VerifyHostname matches against the wildcard. nginx asks more of
	// a pair than this, as its tls library refuses a key it finds too small, so
	// it has the last word at the reload.
	verifyPair := func(name string) error {
		pair, err := tls.LoadX509KeyPair(
			filepath.Join(versionHome, name, fmt.Sprintf("%s.pem", name)),
			filepath.Join(versionHome, name, fmt.Sprintf("%s.key", name)),
		)
		if err != nil {
			return err
		}
		leaf, err := x509.ParseCertificate(pair.Certificate[0])
		if err != nil {
			return err
		}
		now := settings.now()
		if now.Before(leaf.NotBefore) || now.After(leaf.NotAfter) {
			return fmt.Errorf("the certificate is valid from %s to %s", leaf.NotBefore, leaf.NotAfter)
		}
		return leaf.VerifyHostname(name)
	}
	// one bad name refuses them all: the version was meant to go live as a whole.
	// ReadDir returns names in order.
	entries, err := os.ReadDir(versionHome)
	if err != nil {
		return err
	}
	names := []string{}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		if err := verifyPair(entry.Name()); err != nil {
			return fmt.Errorf("refusing %s: %w", filepath.Join(versionHome, entry.Name()), err)
		}
		names = append(names, entry.Name())
	}
	if len(names) == 0 {
		return fmt.Errorf("%s holds no certificates", versionHome)
	}

	// a link moves in one step. A real directory cannot, and a tls/current that
	// is itself a link would take these links into a version's directory. Each
	// target is kept for putting the link back; a name not in here had no link.
	previousLinkTargets := map[string]string{}
	checkMovable := func() error {
		info, err := os.Lstat(currentHome)
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		if !info.IsDir() {
			return fmt.Errorf("%s is not a directory of links", currentHome)
		}
		for _, name := range names {
			linkPath := filepath.Join(currentHome, name)
			info, err := os.Lstat(linkPath)
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			if err != nil {
				return err
			}
			if info.Mode()&os.ModeSymlink == 0 {
				return fmt.Errorf("%s is not a link, so it cannot move in one step", linkPath)
			}
			target, err := os.Readlink(linkPath)
			if err != nil {
				return err
			}
			previousLinkTargets[name] = target
		}
		return nil
	}
	if err := checkMovable(); err != nil {
		return err
	}

	// the config the image baked for a block, in every lb image already deployed
	blockConfigPath := func(block string) string {
		return fmt.Sprintf("/srv/warp/nginx.conf/%s.conf", block)
	}

	// a draining container is listed too, and nginx answers 0 to a reload it then
	// ignores. Workers tell the two apart. With none of either kind nothing here
	// can say which state the lb is in, so that refuses like any unknown.
	findLbContainers := func() ([]*lbContainer, error) {
		out, err := dockerOutput(
			settings,
			"ps",
			"--no-trunc",
			"--filter", fmt.Sprintf("label=warp.env=%s", env),
			"--filter", "label=warp.service=lb",
			"--format", `{{.ID}} {{.Label "warp.block"}}`,
		)
		if err != nil {
			return nil, fmt.Errorf("find %s lb containers: %w", env, err)
		}
		lbContainers := []*lbContainer{}
		for _, line := range strings.Split(string(out), "\n") {
			fields := strings.Fields(line)
			if len(fields) == 0 {
				continue
			}
			if len(fields) != 2 {
				return nil, fmt.Errorf("cannot read lb container %q", line)
			}
			containerId, block := fields[0], fields[1]
			workerPids, shutdownWorkerCount, err := readLbWorkers(settings, containerId)
			if err != nil {
				return nil, fmt.Errorf("read the workers of %s: %w", block, err)
			}
			if len(workerPids) == 0 {
				if shutdownWorkerCount == 0 {
					return nil, fmt.Errorf("%s has no nginx workers, so it cannot take a reload yet", block)
				}
				Out.Printf("Passing over %s: it is draining\n", block)
				continue
			}
			lbContainers = append(lbContainers, &lbContainer{
				containerId: containerId,
				block:       block,
			})
		}
		return lbContainers, nil
	}

	// an image's paths are fixed when it is built, per name, so a name without a
	// tls/current entry in the builder's vault stays versioned in the image. A
	// swap can reach a name only through tls/current. A name this version does
	// not hold has nothing new to serve, so it costs this swap nothing.
	checkLbReads := func(lb *lbContainer) error {
		// not the whole config: outAndLog logs what a command prints
		out, err := dockerOutput(settings, "exec", lb.containerId, "grep", "ssl_certificate", blockConfigPath(lb.block))
		if err != nil {
			return fmt.Errorf("read the tls paths of %s: %w", lb.block, err)
		}
		currentNames := map[string]bool{}
		otherNamePaths := map[string]string{}
		for _, match := range lbTlsPathRegex.FindAllSubmatch(out, -1) {
			tlsPath := string(match[1])
			name := strings.TrimSuffix(path.Base(tlsPath), path.Ext(tlsPath))
			if path.Dir(tlsPath) == path.Join(lbVaultMountPath, "tls", tlsCurrentDirName, name) {
				currentNames[name] = true
			} else {
				otherNamePaths[name] = tlsPath
			}
		}
		for _, name := range names {
			if otherPath, ok := otherNamePaths[name]; ok {
				return fmt.Errorf(
					"%s reads %s from %s, so a swap cannot reach it: its lb image needs building from a vault holding tls/%s/%s",
					lb.block, name, otherPath, tlsCurrentDirName, name,
				)
			}
			if currentNames[name] {
				lb.reachedNames = append(lb.reachedNames, name)
			}
		}
		if len(lb.reachedNames) == 0 {
			return fmt.Errorf("%s reads none of %s's names from tls/%s, so a reload would change nothing", lb.block, version, tlsCurrentDirName)
		}
		for _, name := range slices.Sorted(maps.Keys(otherNamePaths)) {
			Out.Printf("%s keeps reading %s from %s, which no swap moves\n", lb.block, name, otherNamePaths[name])
		}
		return nil
	}

	lbContainers := []*lbContainer{}
	if !settings.noReload {
		var err error
		if lbContainers, err = findLbContainers(); err != nil {
			return err
		}
		if len(lbContainers) == 0 {
			return fmt.Errorf("no %s lb on this host can take a reload. To move the links alone, as on a new host or one whose lb is down, use --no-reload", env)
		}
		for _, lb := range lbContainers {
			if err := checkLbReads(lb); err != nil {
				return err
			}
		}
	}

	// the temporary link is hidden so that one left by a swap that died here is
	// not read as a name, and sits beside the name so that the rename is atomic
	pointLink := func(name string, target string) error {
		tempPath := filepath.Join(currentHome, fmt.Sprintf(".%s.swap", name))
		if err := os.Remove(tempPath); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if err := os.Symlink(target, tempPath); err != nil {
			return err
		}
		if err := settings.rename(tempPath, filepath.Join(currentHome, name)); err != nil {
			return errors.Join(err, os.Remove(tempPath))
		}
		return nil
	}

	// `-c` names the config the image baked for the block. nginx parses it only
	// to find the pid file and to prove it loads, refusing here and leaving the
	// master untouched if a pair does not. The master then rereads the config it
	// started with, a host-networked lb's `_host.conf`, which differs from this
	// one only in its listen lines. That happens after nginx here has exited 0,
	// so only a worker that was not there before the signal shows it did.
	reloadLb := func(lb *lbContainer) error {
		oldWorkerPids, _, err := readLbWorkers(settings, lb.containerId)
		if err != nil {
			return fmt.Errorf("read its workers before the signal: %w", err)
		}
		_, err = dockerOutput(
			settings,
			"exec",
			lb.containerId,
			"nginx",
			"-c", blockConfigPath(lb.block),
			"-s", "reload",
		)
		if err != nil {
			return err
		}
		for checkIndex := 0; checkIndex < settings.reloadCheckCount; checkIndex += 1 {
			if 0 < checkIndex {
				time.Sleep(settings.reloadCheckInterval)
			}
			workerPids, _, err := readLbWorkers(settings, lb.containerId)
			if err != nil {
				return fmt.Errorf("read its workers after the signal: %w", err)
			}
			for _, workerPid := range workerPids {
				if !slices.Contains(oldWorkerPids, workerPid) {
					return nil
				}
			}
		}
		return fmt.Errorf("nginx took the signal and started no new worker: it is draining, or its log says why")
	}

	// a vault home that is not the one an lb mounts moves links nothing there
	// reads, and the lb would reload what it had, with new workers to show for it
	checkLbSeesLinks := func(lb *lbContainer) error {
		args := []string{lb.containerId, "readlink"}
		wantTargets := []string{}
		for _, name := range lb.reachedNames {
			args = append(args, path.Join(lbVaultMountPath, "tls", tlsCurrentDirName, name))
			wantTargets = append(wantTargets, filepath.Join("..", version, name))
		}
		out, err := dockerOutput(settings, "exec", args...)
		if err != nil {
			return fmt.Errorf("read the links %s sees: %w", lb.block, err)
		}
		if targets := strings.Fields(string(out)); !slices.Equal(targets, wantTargets) {
			return fmt.Errorf("%s sees its links at %v, not %v, so it does not mount the vault at %s", lb.block, targets, wantTargets, vaultHome)
		}
		return nil
	}

	// a version left in the links after nginx refused it would stop the next lb
	// start, and an lb already reloaded would be alone on the new pair
	undoSwap := func(swapErr error, movedNames []string, reloadedLbContainers []*lbContainer) error {
		undoErrs := []error{swapErr}
		for _, name := range movedNames {
			var err error
			if target, ok := previousLinkTargets[name]; ok {
				err = pointLink(name, target)
			} else {
				err = os.Remove(filepath.Join(currentHome, name))
			}
			if err != nil {
				undoErrs = append(undoErrs, fmt.Errorf("put %s back: %w", name, err))
				continue
			}
			Out.Printf("Put %s back\n", filepath.Join(currentHome, name))
		}
		for _, lb := range reloadedLbContainers {
			if err := reloadLb(lb); err != nil {
				undoErrs = append(undoErrs, fmt.Errorf("reload %s back: %w", lb.block, err))
				continue
			}
			Out.Printf("Reloaded %s back\n", lb.block)
		}
		return errors.Join(undoErrs...)
	}

	if err := os.MkdirAll(currentHome, 0700); err != nil {
		return err
	}
	movedNames := []string{}
	for _, name := range names {
		if err := pointLink(name, filepath.Join("..", version, name)); err != nil {
			return undoSwap(fmt.Errorf("swap %s: %w", name, err), movedNames, nil)
		}
		movedNames = append(movedNames, name)
		Out.Printf("%s -> %s\n", filepath.Join(currentHome, name), version)
	}
	if settings.noReload {
		Out.Printf("Reloaded nothing: a running lb keeps its old pair until its next reload or start\n")
		return nil
	}

	for _, lb := range lbContainers {
		if err := checkLbSeesLinks(lb); err != nil {
			return undoSwap(err, movedNames, nil)
		}
	}
	for lbIndex, lb := range lbContainers {
		if err := reloadLb(lb); err != nil {
			return undoSwap(fmt.Errorf("reload %s: %w", lb.block, err), movedNames, lbContainers[:lbIndex])
		}
		Out.Printf("Reloaded %s\n", lb.block)
	}
	return nil
}

// Reads an lb container's nginx workers through `docker top`, which asks nothing
// of the image. Returns the pids of those serving, and how many are shutting
// down. A worker's title is all that tells the two apart from outside nginx.
func readLbWorkers(settings *certsSwapSettings, containerId string) ([]string, int, error) {
	out, err := dockerOutput(settings, "top", containerId, "-o", "pid,args")
	if err != nil {
		return nil, 0, err
	}
	workerPids := []string{}
	shutdownWorkerCount := 0
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		switch strings.Join(fields[1:], " ") {
		case nginxWorkerTitle:
			workerPids = append(workerPids, fields[0])
		case nginxShutdownWorkerTitle:
			shutdownWorkerCount += 1
		}
	}
	return workerPids, shutdownWorkerCount, nil
}

// Runs one docker command under the swap's timeout. A command that finished
// after the timeout is a failure too, whatever it answered.
func dockerOutput(settings *certsSwapSettings, name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), settings.dockerTimeout)
	defer cancel()
	out, err := outAndLog(retirementCommand(ctx, docker(name, args...)))
	if ctx.Err() != nil {
		return nil, errors.Join(ctx.Err(), err)
	}
	return out, err
}
