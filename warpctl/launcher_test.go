// Local-launcher tests keep operational commands on Makefile-built artifacts.
package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Contains one isolated repository-shaped launcher tree.
type localLauncherFixture struct {
	launcherPath  string
	canonicalPath string
	toolsDir      string
	unameOS       string
	unameArch     string
}

// Builds an isolated launcher tree with a stale root binary as a selection trap.
func newLocalLauncherFixture(
	t *testing.T,
	unameOS string,
	unameArch string,
	goos string,
	goarch string,
	canonicalMode os.FileMode,
) localLauncherFixture {
	t.Helper()

	launcherBytes, err := os.ReadFile("run.sh")
	if err != nil {
		t.Fatal(err)
	}
	fixtureRoot, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	launcherDir := filepath.Join(fixtureRoot, "warpctl")
	if err := os.MkdirAll(launcherDir, 0o755); err != nil {
		t.Fatal(err)
	}
	launcherPath := filepath.Join(launcherDir, "run.sh")
	if err := os.WriteFile(launcherPath, launcherBytes, 0o755); err != nil {
		t.Fatal(err)
	}
	stalePath := filepath.Join(launcherDir, "warpctl")
	if err := os.WriteFile(stalePath, []byte("#!/bin/sh\nprintf 'STALE\\n'\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	canonicalPath := filepath.Join(launcherDir, "build", goos, goarch, "warpctl")
	if canonicalMode != 0 {
		if err := os.MkdirAll(filepath.Dir(canonicalPath), 0o755); err != nil {
			t.Fatal(err)
		}
		canonicalScript := "#!/bin/sh\nprintf 'canonical argc=%s' \"$#\"\n" +
			"for arg in \"$@\"; do printf '|%s' \"$arg\"; done\n" +
			"printf '\\n'\nexit \"${LOCAL_LAUNCHER_EXIT:-0}\"\n"
		if err := os.WriteFile(canonicalPath, []byte(canonicalScript), canonicalMode); err != nil {
			t.Fatal(err)
		}
	}

	toolsDir := filepath.Join(fixtureRoot, "tools")
	if err := os.MkdirAll(toolsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	unameScript := `#!/bin/sh
case "$1" in
-s) printf '%s\n' "$LOCAL_LAUNCHER_UNAME_OS" ;;
-m) printf '%s\n' "$LOCAL_LAUNCHER_UNAME_ARCH" ;;
*) exit 2 ;;
esac
`
	if err := os.WriteFile(filepath.Join(toolsDir, "uname"), []byte(unameScript), 0o755); err != nil {
		t.Fatal(err)
	}

	return localLauncherFixture{
		launcherPath:  launcherPath,
		canonicalPath: canonicalPath,
		toolsDir:      toolsDir,
		unameOS:       unameOS,
		unameArch:     unameArch,
	}
}

// Runs the fixture while retaining system tools after the controlled uname shim.
func runLocalLauncher(
	t *testing.T,
	fixture localLauncherFixture,
	exitCode string,
	args ...string,
) (string, error) {
	t.Helper()
	command := exec.Command("sh", append([]string{fixture.launcherPath}, args...)...)
	command.Env = []string{}
	for _, value := range os.Environ() {
		if strings.HasPrefix(value, "PATH=") ||
			strings.HasPrefix(value, "LOCAL_LAUNCHER_") {
			continue
		}
		command.Env = append(command.Env, value)
	}
	command.Env = append(
		command.Env,
		"PATH="+fixture.toolsDir+string(os.PathListSeparator)+os.Getenv("PATH"),
		"LOCAL_LAUNCHER_UNAME_OS="+fixture.unameOS,
		"LOCAL_LAUNCHER_UNAME_ARCH="+fixture.unameArch,
		"LOCAL_LAUNCHER_EXIT="+exitCode,
	)
	output, err := command.CombinedOutput()
	return string(output), err
}

// Prevents a checkout from turning the tracked launcher into a non-runnable file.
func TestLocalLauncherIsExecutable(t *testing.T) {
	info, err := os.Stat("run.sh")
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0o111 != 0o111 {
		t.Fatalf("run.sh mode = %04o, want executable for user, group, and other", info.Mode().Perm())
	}
}

// Covers every supported uname spelling and the executable-identity operation.
func TestLocalLauncherMapsSupportedPlatformsAndPrintsExecutable(t *testing.T) {
	cases := []struct {
		unameOS   string
		unameArch string
		goos      string
		goarch    string
	}{
		{unameOS: "Darwin", unameArch: "arm64", goos: "darwin", goarch: "arm64"},
		{unameOS: "Darwin", unameArch: "x86_64", goos: "darwin", goarch: "amd64"},
		{unameOS: "Linux", unameArch: "aarch64", goos: "linux", goarch: "arm64"},
		{unameOS: "Linux", unameArch: "amd64", goos: "linux", goarch: "amd64"},
	}
	for _, testCase := range cases {
		fixture := newLocalLauncherFixture(
			t,
			testCase.unameOS,
			testCase.unameArch,
			testCase.goos,
			testCase.goarch,
			0o755,
		)
		output, err := runLocalLauncher(t, fixture, "0", "--print-executable")
		if err != nil {
			t.Errorf("%s/%s launcher failed: %v: %s", testCase.unameOS, testCase.unameArch, err, output)
			continue
		}
		if output != fixture.canonicalPath+"\n" {
			t.Errorf("%s/%s executable = %q, want %q", testCase.unameOS, testCase.unameArch, output, fixture.canonicalPath+"\n")
		}
	}
}

// Proves the ignored root binary is bypassed and exec preserves args and status.
func TestLocalLauncherExecutesCanonicalBinary(t *testing.T) {
	fixture := newLocalLauncherFixture(t, "Darwin", "arm64", "darwin", "arm64", 0o755)
	output, err := runLocalLauncher(t, fixture, "23", "alpha", "two words", "--sample")
	if err == nil {
		t.Fatalf("canonical exit 23 unexpectedly succeeded: %s", output)
	}
	exitError, ok := err.(*exec.ExitError)
	if !ok || exitError.ExitCode() != 23 {
		t.Fatalf("launcher exit = %v, want 23: %s", err, output)
	}
	if output != "canonical argc=3|alpha|two words|--sample\n" {
		t.Fatalf("canonical args output = %q", output)
	}
	if strings.Contains(output, "STALE") {
		t.Fatalf("launcher selected ignored root binary: %s", output)
	}
}

// Missing and non-executable canonical artifacts must not fall back to stale root.
func TestLocalLauncherFailsClosedWithoutExecutableCanonicalBinary(t *testing.T) {
	cases := []struct {
		name string
		mode os.FileMode
	}{
		{name: "missing", mode: 0},
		{name: "non-executable", mode: 0o644},
	}
	for _, testCase := range cases {
		fixture := newLocalLauncherFixture(t, "Linux", "x86_64", "linux", "amd64", testCase.mode)
		output, err := runLocalLauncher(t, fixture, "0", "ls", "versions")
		if err == nil {
			t.Errorf("%s canonical artifact unexpectedly succeeded: %s", testCase.name, output)
			continue
		}
		exitError, ok := err.(*exec.ExitError)
		if !ok || exitError.ExitCode() != 127 {
			t.Errorf("%s launcher exit = %v, want 127: %s", testCase.name, err, output)
		}
		if !strings.Contains(output, fixture.canonicalPath) || !strings.Contains(output, "missing or not executable") {
			t.Errorf("%s failure lacks canonical path: %s", testCase.name, output)
		}
		if strings.Contains(output, "STALE") {
			t.Errorf("%s failure fell back to ignored root binary: %s", testCase.name, output)
		}
	}
}

// Keeps the only top-level bare invocation on the guarded local launcher.
func TestLocalLauncherIsUsedByTopLevelMakefile(t *testing.T) {
	makefileBytes, err := os.ReadFile(filepath.Join("..", "Makefile"))
	if err != nil {
		t.Fatal(err)
	}
	makefile := string(makefileBytes)
	if !strings.Contains(makefile, "./warpctl/run.sh lb hosts local") {
		t.Fatal("top-level Makefile does not invoke the guarded local launcher")
	}
	if strings.Contains(makefile, "$(warpctl lb hosts local") {
		t.Fatal("top-level Makefile retains a bare Warpctl invocation")
	}
}
