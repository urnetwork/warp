package main

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Uses the native deployment fixture so the control traverses the same
// promotion, lease release, Docker retirement and return path as a run worker.
func TestRetirementStopFailureReachesDeploymentCaller(t *testing.T) {
	f := newPromotionLeaseFixture(t, false)
	want := errors.New("fixture Docker stop failure")
	runAndLogFunc = func(cmd *exec.Cmd) error {
		if strings.Contains(strings.Join(cmd.Args, " "), "docker container stop ") && cmd.Args[len(cmd.Args)-1] == "bbbb11" {
			return want
		}
		return f.run(cmd)
	}
	f.start(0)
	promotionLeaseAwait(t, f.started[0], "candidate did not start")
	f.allowReady[0]()
	select {
	case err := <-f.done[0]:
		f.startedRun[0] = false
		if !errors.Is(err, want) {
			t.Fatalf("retirement failure was lost: got %v, want %v", err, want)
		}
	case <-time.After(8 * time.Second):
		t.Fatal("retirement failure did not return to its deployment owner")
	}
	if f.killed.Load() != 0 {
		t.Fatal("retirement failure stopped the promoted candidate")
	}
}

func TestRetirementRestartDisableFailureReachesDeploymentCaller(t *testing.T) {
	f := newPromotionLeaseFixture(t, false)
	want := errors.New("fixture Docker restart disable failure")
	runAndLogFunc = func(cmd *exec.Cmd) error {
		if strings.Contains(strings.Join(cmd.Args, " "), "docker update ") && cmd.Args[len(cmd.Args)-1] == "bbbb11" {
			return want
		}
		return f.run(cmd)
	}
	f.finishDrain[0]()
	f.start(0)
	promotionLeaseAwait(t, f.started[0], "candidate did not start")
	f.allowReady[0]()
	select {
	case err := <-f.done[0]:
		f.startedRun[0] = false
		if !errors.Is(err, want) {
			t.Fatalf("restart-disable failure was lost: got %v, want %v", err, want)
		}
	case <-time.After(8 * time.Second):
		t.Fatal("restart-disable failure did not return to its deployment owner")
	}
	if f.killed.Load() != 0 {
		t.Fatal("restart-disable failure stopped the promoted candidate")
	}
}

func TestRetirementDiscoveryIncludesStoppedPredecessors(t *testing.T) {
	bin := t.TempDir()
	fixture := `#!/bin/sh
case "$*" in
  "docker ps -a "*) printf 'aaaa11\nbbbb11\n' ;;
  "docker ps "*) printf 'aaaa11\n' ;;
  *) exit 97 ;;
esac
`
	if err := os.WriteFile(filepath.Join(bin, "sudo"), []byte(fixture), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin)
	worker := &RunWorker{env: "test", service: "fixture", block: "g1"}
	ids, err := worker.findServiceBlockContainers()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(ids, ",") != "aaaa11,bbbb11" {
		t.Fatalf("stopped predecessor vanished from restart recovery: %v", ids)
	}
}
