package main

import (
	"debug/buildinfo"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime/debug"
	"slices"
	"strings"
)

var gitRevisionPattern = regexp.MustCompile(`^[0-9a-f]{40}$`)

type binarySourceProvenance struct {
	revision string
	modified bool
}

var cleanBuildSourceRevision = cleanGitSourceRevision
var verifyBuiltBinarySource = verifyBuiltBinarySourceProvenance

// runBuildPipeline builds the service artifacts, checks every Linux binary
// that can be copied into a published image, and only then permits the
// Makefile's image target to run. Keeping the image step separate is important:
// a vulnerable artifact must never be pushed before govulncheck reports it.
//
// The whole pipeline runs against per-build ephemeral Go caches (see
// ephemeralGoCaches): the service Makefiles' `init` target runs
// `go clean -cache && go clean -modcache` for hermetic builds, which on a
// shared cache wipes the machine-global build and module caches out from
// under every OTHER go process — concurrent warp builds clobber each other,
// and tests running on the same machine fail with vanished cache entries
// ("package X is not in std", module files/embeds missing mid-compile).
// With the env pointing at fresh per-build dirs, `init` cleans an already
// empty cache (a no-op), the build is hermetic BY CONSTRUCTION, and the cost
// is identical to before (init always forced a cold build anyway).
func runBuildPipeline(makefileDirPath string, env []string) error {
	sourceRevision, err := cleanBuildSourceRevision(makefileDirPath, env)
	if err != nil {
		return fmt.Errorf("establish clean release source: %w", err)
	}

	buildEnv, cleanup, err := ephemeralGoCaches(makefileDirPath, env)
	if err != nil {
		return err
	}
	defer cleanup()
	env = buildEnv

	if err := runBuildMakeTarget(makefileDirPath, env, "all"); err != nil {
		return fmt.Errorf("build service binaries: %w", err)
	}

	if err := requireUnchangedBuildSource(makefileDirPath, env, sourceRevision); err != nil {
		return err
	}

	if err := checkBuiltServiceBinaries(makefileDirPath, env, sourceRevision); err != nil {
		return err
	}
	if err := requireUnchangedBuildSource(makefileDirPath, env, sourceRevision); err != nil {
		return err
	}

	if err := runBuildMakeTarget(makefileDirPath, env, "warp_build_image"); err != nil {
		return fmt.Errorf("build and publish service image: %w", err)
	}

	return nil
}

func runBuildMakeTarget(makefileDirPath string, env []string, target string) error {
	cmd := exec.Command("make", target)
	cmd.Dir = makefileDirPath
	cmd.Env = env
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return runAndLog(cmd)
}

func checkBuiltServiceBinaries(makefileDirPath string, env []string, sourceRevision string) error {
	govulncheckPath, err := exec.LookPath("govulncheck")
	if err != nil {
		return fmt.Errorf(
			"govulncheck is required for warp builds; install it with "+
				"`go install golang.org/x/vuln/cmd/govulncheck@latest`: %w",
			err,
		)
	}

	binaries, err := builtServiceBinaries(makefileDirPath)
	if err != nil {
		return err
	}
	if len(binaries) == 0 {
		return fmt.Errorf(
			"no Linux amd64 or arm64 Go binaries found under %s; "+
				"the Makefile's all target must build release binaries before the image target",
			filepath.Join(makefileDirPath, "build", "linux"),
		)
	}

	for _, binaryPath := range binaries {
		if err := verifyBuiltBinarySource(binaryPath, sourceRevision); err != nil {
			return err
		}
		cmd := exec.Command(govulncheckPath, "-mode=binary", binaryPath)
		cmd.Dir = makefileDirPath
		cmd.Env = env
		cmd.Stdin = os.Stdin
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := runAndLog(cmd); err != nil {
			return fmt.Errorf("govulncheck rejected %s: %w", binaryPath, err)
		}
	}

	return nil
}

// cleanGitSourceRevision returns the exact release source only when the Git
// worktree is clean and HEAD remains stable across the status check. Service
// binaries are built outside the Dockerfile, so BuildKit's context provenance
// cannot by itself prove which source produced the executable copied later.
func cleanGitSourceRevision(makefileDirPath string, env []string) (string, error) {
	revisionBefore, err := gitBuildOutput(makefileDirPath, env, "rev-parse", "--verify", "HEAD")
	if err != nil {
		return "", err
	}
	status, err := gitBuildOutput(
		makefileDirPath,
		env,
		"status",
		"--porcelain=v1",
		"--untracked-files=all",
	)
	if err != nil {
		return "", err
	}
	revisionAfter, err := gitBuildOutput(makefileDirPath, env, "rev-parse", "--verify", "HEAD")
	if err != nil {
		return "", err
	}
	if revisionBefore != revisionAfter {
		return "", fmt.Errorf(
			"Git HEAD changed while checking release source (%s -> %s)",
			revisionBefore,
			revisionAfter,
		)
	}
	if !gitRevisionPattern.MatchString(revisionBefore) {
		return "", fmt.Errorf("Git HEAD is not a full SHA-1 revision: %q", revisionBefore)
	}
	if status != "" {
		return "", fmt.Errorf("Git worktree is dirty; commit or remove changes before a release build")
	}
	return revisionBefore, nil
}

func gitBuildOutput(makefileDirPath string, env []string, args ...string) (string, error) {
	cmd := exec.Command("git", args...)
	cmd.Dir = makefileDirPath
	cmd.Env = env
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("git %s: %w", strings.Join(args, " "), err)
	}
	return strings.TrimSpace(string(out)), nil
}

func requireUnchangedBuildSource(makefileDirPath string, env []string, expected string) error {
	actual, err := cleanBuildSourceRevision(makefileDirPath, env)
	if err != nil {
		return fmt.Errorf("release source changed during build: %w", err)
	}
	if actual != expected {
		return fmt.Errorf(
			"release source changed during build (%s -> %s)",
			expected,
			actual,
		)
	}
	return nil
}

func verifyBuiltBinarySourceProvenance(binaryPath string, expectedRevision string) error {
	info, err := buildinfo.ReadFile(binaryPath)
	if err != nil {
		return fmt.Errorf("read Go build provenance from %s: %w", binaryPath, err)
	}
	provenance, err := binarySourceProvenanceFromSettings(info.Settings)
	if err != nil {
		return fmt.Errorf("read Go build provenance from %s: %w", binaryPath, err)
	}
	return validateBuiltBinarySourceProvenance(binaryPath, provenance, expectedRevision)
}

func validateBuiltBinarySourceProvenance(
	binaryPath string,
	provenance binarySourceProvenance,
	expectedRevision string,
) error {
	if provenance.modified {
		return fmt.Errorf("release binary %s was built from a modified source tree", binaryPath)
	}
	if provenance.revision != expectedRevision {
		return fmt.Errorf(
			"release binary %s source revision %s does not match release source %s",
			binaryPath,
			provenance.revision,
			expectedRevision,
		)
	}
	return nil
}

func binarySourceProvenanceFromSettings(settings []debug.BuildSetting) (binarySourceProvenance, error) {
	provenance := binarySourceProvenance{}
	hasModified := false
	for _, setting := range settings {
		switch setting.Key {
		case "vcs.revision":
			provenance.revision = setting.Value
		case "vcs.modified":
			switch setting.Value {
			case "true":
				provenance.modified = true
			case "false":
				provenance.modified = false
			default:
				return binarySourceProvenance{}, fmt.Errorf(
					"invalid vcs.modified setting %q",
					setting.Value,
				)
			}
			hasModified = true
		}
	}
	if !gitRevisionPattern.MatchString(provenance.revision) || !hasModified {
		return binarySourceProvenance{}, fmt.Errorf("complete Go VCS settings are unavailable")
	}
	return provenance, nil
}

// builtServiceBinaries returns Go executables for the two architectures that
// warp publishes in its Docker images. Non-Go files below the build tree are
// ignored; absence of a Go binary is handled as a fail-closed error above.
func builtServiceBinaries(makefileDirPath string) ([]string, error) {
	binaries := []string{}
	for _, arch := range []string{"amd64", "arm64"} {
		root := filepath.Join(makefileDirPath, "build", "linux", arch)
		if _, err := os.Stat(root); err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, fmt.Errorf("inspect build output %s: %w", root, err)
		}

		err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if entry.IsDir() || entry.Type()&os.ModeSymlink != 0 {
				return nil
			}
			info, err := entry.Info()
			if err != nil {
				return err
			}
			if !info.Mode().IsRegular() {
				return nil
			}
			if _, err := buildinfo.ReadFile(path); err == nil {
				binaries = append(binaries, path)
			}
			return nil
		})
		if err != nil {
			return nil, fmt.Errorf("inspect Go binaries under %s: %w", root, err)
		}
	}

	slices.Sort(binaries)
	return binaries, nil
}

// ephemeralGoCaches returns env with GOCACHE and GOMODCACHE pointed at fresh
// per-build temp directories, and a cleanup that removes them. Opt out with
// WARPCTL_SHARED_GO_CACHE=1 (uses the inherited caches unchanged — note the
// Makefiles' init target will then wipe the machine-global caches, the
// behavior this exists to prevent).
func ephemeralGoCaches(makefileDirPath string, env []string) (buildEnv []string, cleanup func(), returnErr error) {
	if os.Getenv("WARPCTL_SHARED_GO_CACHE") == "1" {
		return env, func() {}, nil
	}

	service := filepath.Base(makefileDirPath)
	cacheDir, err := os.MkdirTemp("", fmt.Sprintf("warpctl-build-%s-*", service))
	if err != nil {
		returnErr = fmt.Errorf("create ephemeral go cache dir: %w", err)
		return
	}
	goCache := filepath.Join(cacheDir, "gocache")
	goModCache := filepath.Join(cacheDir, "gomodcache")

	// drop any inherited values so the per-build dirs unambiguously win
	// (duplicate env keys have platform-dependent precedence)
	for _, envPair := range env {
		if key, _, ok := strings.Cut(envPair, "="); ok {
			switch key {
			case "GOCACHE", "GOMODCACHE":
				continue
			}
		}
		buildEnv = append(buildEnv, envPair)
	}
	buildEnv = append(buildEnv,
		fmt.Sprintf("GOCACHE=%s", goCache),
		fmt.Sprintf("GOMODCACHE=%s", goModCache),
	)

	cleanup = func() {
		// the module cache is written with read-only permissions by design;
		// `go clean -modcache` with the ephemeral env is the supported way to
		// remove it, with a chmod sweep as the fallback
		cleanCommand := exec.Command("go", "clean", "-modcache")
		cleanCommand.Env = buildEnv
		if err := cleanCommand.Run(); err != nil {
			filepath.WalkDir(cacheDir, func(path string, d fs.DirEntry, err error) error {
				if err == nil && d.IsDir() {
					os.Chmod(path, 0o755)
				}
				return nil
			})
		}
		os.RemoveAll(cacheDir)
	}
	return
}
