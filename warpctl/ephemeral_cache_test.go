package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The service Makefiles' init target runs `go clean -cache && go clean
// -modcache` for hermetic builds. Against a shared cache that wipes the
// machine-global Go caches out from under every other go process on the
// machine — concurrent warp builds clobber each other, and tests fail with
// vanished cache entries. ephemeralGoCaches points the whole pipeline at
// fresh per-build directories instead: init cleans an empty cache, and the
// host caches are untouched.
func TestEphemeralGoCachesIsolateTheBuild(t *testing.T) {
	dir := t.TempDir()
	makefileDirPath := filepath.Join(dir, "svc")
	if err := os.MkdirAll(makefileDirPath, 0o755); err != nil {
		t.Fatal(err)
	}

	env, cleanup, err := ephemeralGoCaches(makefileDirPath, os.Environ())
	if err != nil {
		t.Fatal(err)
	}

	var goCache, goModCache string
	for _, envPair := range env {
		if v, ok := strings.CutPrefix(envPair, "GOCACHE="); ok {
			goCache = v
		}
		if v, ok := strings.CutPrefix(envPair, "GOMODCACHE="); ok {
			goModCache = v
		}
	}
	hostGoCache := strings.TrimSpace(runGo(t, "env", "GOCACHE"))
	hostGoModCache := strings.TrimSpace(runGo(t, "env", "GOMODCACHE"))

	if goCache == "" || goCache == hostGoCache {
		t.Fatalf("build GOCACHE must be an ephemeral dir, got %q (host %q)", goCache, hostGoCache)
	}
	if goModCache == "" || goModCache == hostGoModCache {
		t.Fatalf("build GOMODCACHE must be an ephemeral dir, got %q (host %q)", goModCache, hostGoModCache)
	}

	// the hermetic-init behavior the Makefiles rely on now hits the
	// ephemeral dirs: cleaning is a safe no-op against the fresh cache and
	// MUST NOT touch the host caches
	cleanCommand := exec.Command("go", "clean", "-cache", "-modcache")
	cleanCommand.Env = env
	if out, err := cleanCommand.CombinedOutput(); err != nil {
		t.Fatalf("go clean against the ephemeral caches: %s: %s", err, out)
	}
	if _, err := os.Stat(hostGoCache); err != nil {
		t.Fatalf("host GOCACHE was disturbed: %s", err)
	}

	// a build against the ephemeral cache populates it, proving the env is
	// really applied to child processes
	buildDir := filepath.Join(dir, "mod")
	if err := os.MkdirAll(buildDir, 0o755); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(buildDir, "go.mod"), []byte("module ztest\n\ngo 1.26\n"), 0o644)
	os.WriteFile(filepath.Join(buildDir, "main.go"), []byte("package main\n\nfunc main() {}\n"), 0o644)
	buildCommand := exec.Command("go", "build", "./...")
	buildCommand.Dir = buildDir
	buildCommand.Env = env
	if out, err := buildCommand.CombinedOutput(); err != nil {
		t.Fatalf("build against ephemeral cache: %s: %s", err, out)
	}
	if entries, err := os.ReadDir(goCache); err != nil || len(entries) == 0 {
		t.Fatalf("ephemeral GOCACHE was not used by the child build (err=%v entries=%d)", err, len(entries))
	}

	cleanup()
	if _, err := os.Stat(goCache); !os.IsNotExist(err) {
		t.Fatalf("cleanup must remove the ephemeral caches: %v", err)
	}

	// opt-out: shared mode returns the env untouched
	t.Setenv("WARPCTL_SHARED_GO_CACHE", "1")
	sharedEnv, sharedCleanup, err := ephemeralGoCaches(makefileDirPath, os.Environ())
	if err != nil {
		t.Fatal(err)
	}
	defer sharedCleanup()
	for _, envPair := range sharedEnv {
		if strings.HasPrefix(envPair, "GOCACHE=") && !strings.Contains(envPair, hostGoCache) {
			t.Fatalf("shared mode must not rewrite GOCACHE: %s", envPair)
		}
	}
}

func runGo(t *testing.T, args ...string) string {
	t.Helper()
	out, err := exec.Command("go", args...).Output()
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}
