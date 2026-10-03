package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Release wrappers may use umask 077 to protect logs and credentials. The
// configuration resource tree must still retain the reviewed source modes,
// including restrictive modes, rather than inheriting that wrapper's mask.
func TestWarpConfigTreePreservesModesUnderPrivateUmask(t *testing.T) {
	if _, err := exec.LookPath("make"); err != nil {
		t.Skip("make is not installed")
	}
	makefile, err := filepath.Abs("Makefile")
	if err != nil {
		t.Fatal(err)
	}
	for _, mask := range []string{"077", "022"} {
		t.Run(mask, func(t *testing.T) {
			source, work := t.TempDir(), t.TempDir()
			dirs := map[string]os.FileMode{"main": 0755, "main/nested": 0770, "all": 0700, "all/shared": 0750}
			for _, name := range []string{"main", "main/nested", "all", "all/shared"} {
				p := filepath.Join(source, name)
				if err := os.Mkdir(p, 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(p, dirs[name]); err != nil {
					t.Fatal(err)
				}
			}
			files := map[string]os.FileMode{"main/settings.yml": 0644, "main/nested/private.yml": 0600, "main/nested/reader.yml": 0640, "all/shared/resource.bin": 0444}
			for name, mode := range files {
				p := filepath.Join(source, name)
				if err := os.WriteFile(p, []byte(name), 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(p, mode); err != nil {
					t.Fatal(err)
				}
			}
			cmd := exec.Command("sh", "-c", "umask \"$1\"; shift; exec make \"$@\"", "mode-test", mask,
				"-C", work, "-f", makefile, "warp_config_tree")
			cmd.Env = append(os.Environ(), "WARP_ENV=main", "WARP_VERSION=1.2.3", "WARP_CONFIG_HOME="+source, "WARP_CONFIG_RESTART=no")
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("make: %v\n%s", err, out)
			}
			tree := filepath.Join(work, "build/main/config/1.2.3")
			for name, mode := range files {
				rel := strings.SplitN(name, "/", 2)[1]
				for _, p := range []string{filepath.Join(source, name), filepath.Join(tree, rel)} {
					info, err := os.Stat(p)
					if err != nil {
						t.Fatal(err)
					}
					if info.Mode().Perm() != mode {
						t.Errorf("%s mode %04o, want %04o", p, info.Mode().Perm(), mode)
					}
					data, err := os.ReadFile(p)
					if err != nil || string(data) != name {
						t.Fatalf("content changed: %s: %v", p, err)
					}
				}
			}
			for rel, mode := range map[string]os.FileMode{".": 0755, "nested": 0770, "shared": 0750, "config-updater.yml": 0644} {
				info, err := os.Stat(filepath.Join(tree, rel))
				if err != nil {
					t.Fatal(err)
				}
				if info.Mode().Perm() != mode {
					t.Error(fmt.Sprintf("%s mode %04o, want %04o", rel, info.Mode().Perm(), mode))
				}
			}
		})
	}
}

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
