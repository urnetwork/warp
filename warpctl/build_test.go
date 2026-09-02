package main

import (
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func copyTestExecutable(t *testing.T, target string) {
	t.Helper()

	source, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		t.Fatal(err)
	}

	in, err := os.Open(source)
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()

	out, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		t.Fatal(err)
	}
	if err := out.Close(); err != nil {
		t.Fatal(err)
	}
}

func installFakeGovulncheck(t *testing.T) {
	t.Helper()

	binDir := t.TempDir()
	path := filepath.Join(binDir, "govulncheck")
	if err := os.WriteFile(path, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

func TestBuiltServiceBinariesFindsOnlyReleaseGoExecutables(t *testing.T) {
	serviceDir := t.TempDir()
	amd64Binary := filepath.Join(serviceDir, "build", "linux", "amd64", "service")
	arm64Binary := filepath.Join(serviceDir, "build", "linux", "arm64", "nested", "helper")
	copyTestExecutable(t, amd64Binary)
	copyTestExecutable(t, arm64Binary)

	notGo := filepath.Join(serviceDir, "build", "linux", "amd64", "config.json")
	if err := os.WriteFile(notGo, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	otherPlatform := filepath.Join(serviceDir, "build", "darwin", "arm64", "service")
	copyTestExecutable(t, otherPlatform)

	binaries, err := builtServiceBinaries(serviceDir)
	if err != nil {
		t.Fatal(err)
	}
	expected := []string{amd64Binary, arm64Binary}
	slices.Sort(expected)
	if !slices.Equal(binaries, expected) {
		t.Fatalf("binaries = %v, want %v", binaries, expected)
	}
}

func TestRunBuildPipelineScansBeforePublishing(t *testing.T) {
	installFakeGovulncheck(t)
	serviceDir := t.TempDir()
	amd64Binary := filepath.Join(serviceDir, "build", "linux", "amd64", "service")
	arm64Binary := filepath.Join(serviceDir, "build", "linux", "arm64", "service")
	copyTestExecutable(t, amd64Binary)
	copyTestExecutable(t, arm64Binary)

	previousRunAndLog := runAndLogFunc
	defer func() { runAndLogFunc = previousRunAndLog }()

	calls := [][]string{}
	runAndLogFunc = func(cmd *exec.Cmd) error {
		calls = append(calls, slices.Clone(cmd.Args))
		return nil
	}

	if err := runBuildPipeline(serviceDir, os.Environ()); err != nil {
		t.Fatal(err)
	}

	if len(calls) != 4 {
		t.Fatalf("calls = %v, want build + two scans + image", calls)
	}
	if filepath.Base(calls[0][0]) != "make" || !slices.Equal(calls[0][1:], []string{"all"}) {
		t.Fatalf("first call = %v, want make all", calls[0])
	}
	for i, binary := range []string{amd64Binary, arm64Binary} {
		call := calls[i+1]
		if filepath.Base(call[0]) != "govulncheck" ||
			!slices.Equal(call[1:], []string{"-mode=binary", binary}) {
			t.Fatalf("scan call %d = %v", i, call)
		}
	}
	if filepath.Base(calls[3][0]) != "make" ||
		!slices.Equal(calls[3][1:], []string{"warp_build_image"}) {
		t.Fatalf("last call = %v, want make warp_build_image", calls[3])
	}
}

func TestRunBuildPipelineDoesNotPublishAfterVulnerability(t *testing.T) {
	installFakeGovulncheck(t)
	serviceDir := t.TempDir()
	copyTestExecutable(t, filepath.Join(serviceDir, "build", "linux", "amd64", "service"))

	previousRunAndLog := runAndLogFunc
	defer func() { runAndLogFunc = previousRunAndLog }()

	imageStarted := false
	runAndLogFunc = func(cmd *exec.Cmd) error {
		if filepath.Base(cmd.Args[0]) == "govulncheck" {
			return errors.New("known vulnerability")
		}
		if len(cmd.Args) == 2 && cmd.Args[1] == "warp_build_image" {
			imageStarted = true
		}
		return nil
	}

	if err := runBuildPipeline(serviceDir, os.Environ()); err == nil {
		t.Fatal("runBuildPipeline succeeded after govulncheck failed")
	}
	if imageStarted {
		t.Fatal("image target ran after govulncheck failed")
	}
}

func TestRunBuildPipelineDoesNotPublishWithoutReleaseBinary(t *testing.T) {
	installFakeGovulncheck(t)
	serviceDir := t.TempDir()

	previousRunAndLog := runAndLogFunc
	defer func() { runAndLogFunc = previousRunAndLog }()

	imageStarted := false
	runAndLogFunc = func(cmd *exec.Cmd) error {
		if len(cmd.Args) == 2 && cmd.Args[1] == "warp_build_image" {
			imageStarted = true
		}
		return nil
	}

	if err := runBuildPipeline(serviceDir, os.Environ()); err == nil {
		t.Fatal("runBuildPipeline succeeded without a release binary")
	}
	if imageStarted {
		t.Fatal("image target ran without a scanned release binary")
	}
}

func TestCheckBuiltServiceBinariesRequiresGovulncheck(t *testing.T) {
	serviceDir := t.TempDir()
	copyTestExecutable(t, filepath.Join(serviceDir, "build", "linux", "amd64", "service"))
	t.Setenv("PATH", t.TempDir())

	err := checkBuiltServiceBinaries(serviceDir, os.Environ())
	if err == nil || !strings.Contains(err.Error(), "govulncheck is required") {
		t.Fatalf("error = %v, want missing govulncheck error", err)
	}
}
