package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The Makefile's warp_config_tree target assembles the config tree the image
// carries. It adds config-updater.yml only for WARP_CONFIG_RESTART=no, and
// removes it otherwise, so the build decides the restart behavior, not a file
// that happens to sit in the config repo. It runs from a scratch dir so the
// source tree's build/ stays untouched.
func TestWarpConfigTreeMarksRestartOnlyWhenAsked(t *testing.T) {
	if _, err := exec.LookPath("make"); err != nil {
		t.Skip("make is not installed")
	}
	makefile, err := filepath.Abs("Makefile")
	if err != nil {
		t.Fatal(err)
	}

	configHome := t.TempDir()
	for path, content := range map[string]string{
		"main/settings.yml":       "key: value\n",
		"main/nested/deep.yml":    "deep: true\n",
		"all/pro.yml":             "shared: true\n",
		"main/config-updater.yml": "restart: false\n", // must not survive a default build
	} {
		full := filepath.Join(configHome, path)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	workDir := t.TempDir()
	version := "2026.9.25+1055000000"
	tree := filepath.Join(workDir, "build", "main", "config", version)

	run := func(restart string) {
		t.Helper()
		cmd := exec.Command("make", "-C", workDir, "-f", makefile, "warp_config_tree")
		cmd.Env = append(os.Environ(),
			"WARP_ENV=main",
			"WARP_VERSION="+version,
			"WARP_CONFIG_HOME="+configHome,
			"WARP_CONFIG_RESTART="+restart,
		)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("make warp_config_tree (WARP_CONFIG_RESTART=%q): %v\n%s", restart, err, out)
		}
	}
	marker := func() (string, bool) {
		t.Helper()
		data, err := os.ReadFile(filepath.Join(tree, "config-updater.yml"))
		if os.IsNotExist(err) {
			return "", false
		}
		if err != nil {
			t.Fatal(err)
		}
		return string(data), true
	}

	run("no")
	for _, rel := range []string{"settings.yml", "nested/deep.yml", "pro.yml"} {
		if _, err := os.Stat(filepath.Join(tree, rel)); err != nil {
			t.Errorf("config tree is missing %s: %v", rel, err)
		}
	}
	if content, ok := marker(); !ok || !strings.Contains(content, "restart: false") {
		t.Fatalf("WARP_CONFIG_RESTART=no: config-updater.yml = %q, %v; want restart: false", content, ok)
	}

	// the same work dir again: the target rebuilds the tree and drops the file
	run("yes")
	if content, ok := marker(); ok {
		t.Fatalf("WARP_CONFIG_RESTART=yes: config-updater.yml present: %q", content)
	}

	run("")
	if content, ok := marker(); ok {
		t.Fatalf("WARP_CONFIG_RESTART unset: config-updater.yml present: %q", content)
	}
}
