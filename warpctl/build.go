package main

import (
	"debug/buildinfo"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
)

// runBuildPipeline builds the service artifacts, checks every Linux binary
// that can be copied into a published image, and only then permits the
// Makefile's image target to run. Keeping the image step separate is important:
// a vulnerable artifact must never be pushed before govulncheck reports it.
func runBuildPipeline(makefileDirPath string, env []string) error {
	if err := runBuildMakeTarget(makefileDirPath, env, "all"); err != nil {
		return fmt.Errorf("build service binaries: %w", err)
	}

	if err := checkBuiltServiceBinaries(makefileDirPath, env); err != nil {
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

func checkBuiltServiceBinaries(makefileDirPath string, env []string) error {
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
