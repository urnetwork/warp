package main

import (
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime/debug"
	"slices"
	"strings"
	"testing"
)

const testReleaseRevision = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func installSyntheticReleaseProvenance(t *testing.T) {
	t.Helper()
	previousSourceRevision := cleanBuildSourceRevision
	previousBinarySource := verifyBuiltBinarySource
	t.Cleanup(func() {
		cleanBuildSourceRevision = previousSourceRevision
		verifyBuiltBinarySource = previousBinarySource
	})
	cleanBuildSourceRevision = func(string, []string) (string, error) {
		return testReleaseRevision, nil
	}
	verifyBuiltBinarySource = func(_ string, expected string) error {
		if expected != testReleaseRevision {
			return errors.New("unexpected release revision")
		}
		return nil
	}
}

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
	installSyntheticReleaseProvenance(t)
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
	installSyntheticReleaseProvenance(t)
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
	installSyntheticReleaseProvenance(t)
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

	err := checkBuiltServiceBinaries(serviceDir, os.Environ(), testReleaseRevision)
	if err == nil || !strings.Contains(err.Error(), "govulncheck is required") {
		t.Fatalf("error = %v, want missing govulncheck error", err)
	}
}

func TestBinarySourceProvenanceRequiresCleanMatchingRevision(t *testing.T) {
	settings := []debug.BuildSetting{
		{Key: "vcs.revision", Value: testReleaseRevision},
		{Key: "vcs.modified", Value: "false"},
	}
	provenance, err := binarySourceProvenanceFromSettings(settings)
	if err != nil {
		t.Fatal(err)
	}
	if provenance.revision != testReleaseRevision || provenance.modified {
		t.Fatalf("provenance = %+v", provenance)
	}
	if err := validateBuiltBinarySourceProvenance("service", provenance, testReleaseRevision); err != nil {
		t.Fatal(err)
	}

	provenance.modified = true
	if err := validateBuiltBinarySourceProvenance("service", provenance, testReleaseRevision); err == nil ||
		!strings.Contains(err.Error(), "modified source tree") {
		t.Fatalf("modified provenance error = %v", err)
	}
	provenance.modified = false
	if err := validateBuiltBinarySourceProvenance(
		"service",
		provenance,
		"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
	); err == nil || !strings.Contains(err.Error(), "does not match release source") {
		t.Fatalf("mismatched provenance error = %v", err)
	}

	for _, incomplete := range [][]debug.BuildSetting{
		{{Key: "vcs.modified", Value: "false"}},
		{{Key: "vcs.revision", Value: testReleaseRevision}},
		{{Key: "vcs.revision", Value: "short"}, {Key: "vcs.modified", Value: "false"}},
		{{Key: "vcs.revision", Value: testReleaseRevision}, {Key: "vcs.modified", Value: "invalid"}},
	} {
		if provenance, err := binarySourceProvenanceFromSettings(incomplete); err == nil {
			t.Fatalf("incomplete settings produced provenance %+v", provenance)
		}
	}
}

func TestCleanGitSourceRevisionRejectsDirtyWorktree(t *testing.T) {
	repository := t.TempDir()
	runGit := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = repository
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %s: %v: %s", strings.Join(args, " "), err, out)
		}
	}
	runGit("init", "-q")
	tracked := filepath.Join(repository, "service.go")
	if err := os.WriteFile(tracked, []byte("package service\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	runGit("add", "service.go")
	runGit(
		"-c", "user.name=Warp Test",
		"-c", "user.email=warp-test@example.invalid",
		"-c", "commit.gpgsign=false",
		"commit", "-q", "-m", "clean source",
	)

	revision, err := cleanGitSourceRevision(repository, os.Environ())
	if err != nil {
		t.Fatal(err)
	}
	if !gitRevisionPattern.MatchString(revision) {
		t.Fatalf("revision = %q", revision)
	}
	if err := os.WriteFile(tracked, []byte("package changed\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := cleanGitSourceRevision(repository, os.Environ()); err == nil ||
		!strings.Contains(err.Error(), "worktree is dirty") {
		t.Fatalf("dirty worktree error = %v", err)
	}
}

func TestRunBuildPipelineDoesNotPublishAfterSourceChanges(t *testing.T) {
	installFakeGovulncheck(t)
	serviceDir := t.TempDir()
	copyTestExecutable(t, filepath.Join(serviceDir, "build", "linux", "amd64", "service"))

	previousSourceRevision := cleanBuildSourceRevision
	previousBinarySource := verifyBuiltBinarySource
	previousRunAndLog := runAndLogFunc
	t.Cleanup(func() {
		cleanBuildSourceRevision = previousSourceRevision
		verifyBuiltBinarySource = previousBinarySource
		runAndLogFunc = previousRunAndLog
	})

	checks := 0
	cleanBuildSourceRevision = func(string, []string) (string, error) {
		checks++
		if checks == 1 {
			return testReleaseRevision, nil
		}
		return "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", nil
	}
	verifyBuiltBinarySource = func(string, string) error { return nil }
	imageStarted := false
	runAndLogFunc = func(cmd *exec.Cmd) error {
		if len(cmd.Args) == 2 && cmd.Args[1] == "warp_build_image" {
			imageStarted = true
		}
		return nil
	}

	err := runBuildPipeline(serviceDir, os.Environ())
	if err == nil || !strings.Contains(err.Error(), "release source changed during build") {
		t.Fatalf("source-change error = %v", err)
	}
	if imageStarted {
		t.Fatal("image target ran after release source changed")
	}
}
