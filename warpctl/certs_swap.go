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
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/coreos/go-semver/semver"
	"github.com/docopt/docopt-go"
)

type certsSwapSettings struct {
	// Bounds each docker call, so that a wedged daemon fails the swap instead of
	// hanging the job that ran it. A reload parses the whole lb config first.
	dockerTimeout time.Duration
	// The time each certificate's validity is judged at.
	now func() time.Time
	// Moves one temporary link over its name. This is the one step that changes
	// what a name serves.
	rename func(oldPath string, newPath string) error
}

func defaultCertsSwapSettings() *certsSwapSettings {
	return &certsSwapSettings{
		dockerTimeout: 60 * time.Second,
		now:           time.Now,
		rename:        os.Rename,
	}
}

func certsSwap(opts docopt.Opts) {
	env, _ := opts.String("<env>")
	version, _ := opts.String("<version>")

	err := swapTlsCurrent(
		getWarpState().warpSettings.RequireVaultHome(),
		env,
		version,
		defaultCertsSwapSettings(),
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
// A failed reload leaves the links moved, with that block still serving the old
// pair from memory: running the swap again retries the reload.
func swapTlsCurrent(vaultHome string, env string, version string, settings *certsSwapSettings) error {
	// this also refuses tls/current and anything that is a path, not a name
	if _, err := semver.NewVersion(version); err != nil {
		return fmt.Errorf("%q is not a tls version: %w", version, err)
	}
	versionHome := filepath.Join(vaultHome, "tls", version)
	currentHome := filepath.Join(vaultHome, "tls", tlsCurrentDirName)

	// a pair must be what nginx can load and a visitor can trust: the key matches
	// the certificate, which is valid now and covers the name. star.<domain> is
	// the wildcard's name, which VerifyHostname matches against the wildcard.
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
	// is itself a link would take these links into a version's directory.
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
		}
		return nil
	}
	if err := checkMovable(); err != nil {
		return err
	}

	// a draining container is listed too: nginx ignores a reload while it shuts
	// down. Links moved on a host with nothing to reload would read as a rotation
	// that happened, so the census comes before them.
	out, err := dockerOutput(
		settings,
		"ps",
		"--no-trunc",
		"--filter", fmt.Sprintf("label=warp.env=%s", env),
		"--filter", "label=warp.service=lb",
		"--format", `{{.ID}} {{.Label "warp.block"}}`,
	)
	if err != nil {
		return fmt.Errorf("find %s lb containers: %w", env, err)
	}
	lbContainers := [][]string{}
	for _, line := range strings.Split(string(out), "\n") {
		lbContainer := strings.Fields(line)
		if len(lbContainer) == 0 {
			continue
		}
		if len(lbContainer) != 2 {
			return fmt.Errorf("cannot read lb container %q", line)
		}
		lbContainers = append(lbContainers, lbContainer)
	}
	if len(lbContainers) == 0 {
		return fmt.Errorf("no running %s lb container on this host to reload", env)
	}

	// the temporary link is hidden so that one left by a swap that died here is
	// not read as a name, and sits beside the name so that the rename is atomic
	swapLink := func(name string) error {
		tempPath := filepath.Join(currentHome, fmt.Sprintf(".%s.swap", name))
		if err := os.Remove(tempPath); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if err := os.Symlink(filepath.Join("..", version, name), tempPath); err != nil {
			return err
		}
		if err := settings.rename(tempPath, filepath.Join(currentHome, name)); err != nil {
			return errors.Join(err, os.Remove(tempPath))
		}
		return nil
	}
	if err := os.MkdirAll(currentHome, 0700); err != nil {
		return err
	}
	for _, name := range names {
		if err := swapLink(name); err != nil {
			return fmt.Errorf("swap %s: %w", name, err)
		}
		Out.Printf("%s -> %s\n", filepath.Join(currentHome, name), version)
	}

	// `-c` names the config the image baked for the block, in every lb image
	// already deployed. nginx parses it only to find the pid file and to prove it
	// loads, refusing here and leaving the master untouched if a pair does not.
	// The master then rereads the config it started with, a host-networked lb's
	// `_host.conf`, which differs from this one only in its listen lines.
	reloadErrs := []error{}
	for _, lbContainer := range lbContainers {
		containerId, block := lbContainer[0], lbContainer[1]
		_, err := dockerOutput(
			settings,
			"exec",
			containerId,
			"nginx",
			"-c", fmt.Sprintf("/srv/warp/nginx.conf/%s.conf", block),
			"-s", "reload",
		)
		if err != nil {
			reloadErrs = append(reloadErrs, fmt.Errorf("reload %s: %w", block, err))
			continue
		}
		Out.Printf("Reloaded %s\n", block)
	}
	return errors.Join(reloadErrs...)
}

func dockerOutput(settings *certsSwapSettings, name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), settings.dockerTimeout)
	defer cancel()
	out, err := outAndLog(retirementCommand(ctx, docker(name, args...)))
	if ctx.Err() != nil {
		return nil, errors.Join(ctx.Err(), err)
	}
	return out, err
}
