package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coreos/go-semver/semver"
)

type deploymentVersionFuncs struct {
	get        func(context.Context) (string, error)
	consistent func(context.Context) (string, error)
}

func (c deploymentVersionFuncs) GetLatestVersion(ctx context.Context, _, _, _ string) (string, error) {
	return c.get(ctx)
}

func (c deploymentVersionFuncs) GetLatestVersionConsistent(ctx context.Context, _, _, _ string) (string, error) {
	return c.consistent(ctx)
}

func TestDeploymentTargetGuardsActualStart(t *testing.T) {
	for _, scenario := range []string{"read-error", "invalid-version", "changed-version", "pull-changes-version", "pull-changes-config", "pull-cancels", "final-read-error", "unchanged"} {
		t.Run(scenario, func(t *testing.T) {
			f := newPromotionLeaseFixture(t, false)
			worker := f.workers[0]
			version := "1.0.0"
			reads, pulls, starts := 0, 0, 0
			configHome := filepath.Join(f.home, "config")
			if scenario == "pull-changes-config" {
				if err := os.MkdirAll(filepath.Join(configHome, "1.0.0"), 0o700); err != nil {
					t.Fatal(err)
				}
				worker.warpState.warpSettings.ConfigHome = &configHome
				worker.configMountMode = MOUNT_MODE_YES
				worker.deployedConfigVersion = semver.New("1.0.0")
			}
			worker.dynamoClient = deploymentVersionFuncs{consistent: func(ctx context.Context) (string, error) {
				reads++
				if deadline, ok := ctx.Deadline(); !ok || time.Until(deadline) > WarpPollTimeout {
					t.Error("selector read has no existing poll-time bound")
				}
				switch scenario {
				case "read-error":
					return "", errors.New("fixture unavailable")
				case "invalid-version":
					return "not-semver", nil
				case "changed-version":
					return "2.0.0", nil
				case "final-read-error":
					if reads == 2 {
						return "", errors.New("fixture unavailable after pull")
					}
				}
				return version, ctx.Err()
			}}
			runAndLogFunc = func(cmd *exec.Cmd) error {
				if !strings.Contains(strings.Join(cmd.Args, " "), "docker pull ") {
					return fmt.Errorf("unexpected fixture operation %v", cmd.Args)
				}
				pulls++
				switch scenario {
				case "pull-changes-version":
					version = "2.0.0"
				case "pull-changes-config":
					if err := os.Mkdir(filepath.Join(configHome, "2.0.0"), 0o700); err != nil {
						return err
					}
				case "pull-cancels":
					worker.quitEvent.Set()
				}
				return nil
			}
			outAndLogFunc = func(cmd *exec.Cmd) ([]byte, error) {
				if strings.Contains(strings.Join(cmd.Args, " "), "docker run ") {
					starts++
				}
				return f.output(cmd)
			}
			id, err := worker.startContainer(map[int]int{80: 41080})
			if scenario == "unchanged" {
				if err != nil || id != "aaaa11" || reads != 2 || pulls != 1 || starts != 1 {
					t.Fatalf("healthy start id=%q err=%v reads/pulls/starts=%d/%d/%d", id, err, reads, pulls, starts)
				}
			} else if err == nil || id != "" || starts != 0 {
				t.Fatalf("obsolete/unknown target reached run id=%q err=%v starts=%d", id, err, starts)
			}
			if worker.deployedVersion.String() != "1.0.0" {
				t.Fatal("guard rewrote the owning selected generation")
			}
		})
	}
}

// After promotion the same-block owner must finish its predecessor's original
// graceful drain. A selector change during that drain is consumed by the next
// ordinary Run poll, with no duplicate candidate while retirement is pending.
func TestRunWorkerTargetChangesDuringPromotedDrain(t *testing.T) {
	f := newPromotionLeaseFixture(t, false)
	worker := f.workers[0]
	worker.deployedVersion = nil
	var selected atomic.Value
	selected.Store("1.0.0")
	get := func(ctx context.Context) (string, error) { return selected.Load().(string), ctx.Err() }
	worker.dynamoClient = deploymentVersionFuncs{get: get, consistent: get}
	stateFile := filepath.Join(f.home, "running-containers")
	if err := os.WriteFile(stateFile, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("FIXTURE_CID_STATE", stateFile)
	script := `#!/bin/sh
case "$*" in
  "docker ps "*) while IFS= read -r line; do printf '%s\n' "$line"; done < "$FIXTURE_CID_STATE" ;;
  "iptables "*" -L "*) exit 0 ;;
  *) exit 97 ;;
esac
`
	if err := os.WriteFile(filepath.Join(f.home, "bin", "sudo"), []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	var pulls atomic.Int32
	nextPull := make(chan string, 1)
	runAndLogFunc = func(cmd *exec.Cmd) error {
		args := strings.Join(cmd.Args, " ")
		if strings.Contains(args, "docker pull ") && pulls.Add(1) == 2 {
			nextPull <- cmd.Args[len(cmd.Args)-1]
			worker.quitEvent.Set()
			return errors.New("fixture joined after observing next target")
		}
		if strings.Contains(args, "docker container prune ") {
			return nil
		}
		err := f.run(cmd)
		if err == nil && strings.Contains(args, "docker container stop ") && cmd.Args[len(cmd.Args)-1] == "bbbb11" {
			err = os.WriteFile(stateFile, []byte("aaaa11\n"), 0o600)
		}
		return err
	}
	outAndLogFunc = func(cmd *exec.Cmd) ([]byte, error) {
		out, err := f.output(cmd)
		if err == nil && strings.Contains(strings.Join(cmd.Args, " "), "docker run ") {
			err = os.WriteFile(stateFile, []byte("aaaa11\nbbbb11\n"), 0o600)
		}
		return out, err
	}
	done := make(chan struct{})
	go func() { defer close(done); worker.Run() }()
	defer func() {
		f.allowReady[0]()
		f.finishDrain[0]()
		f.finishKill()
		select {
		case <-f.started[0]:
			worker.quitEvent.Set()
		default:
		}
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			panic("Run owner did not join after fixture release")
		}
	}()
	promotionLeaseAwait(t, f.started[0], "candidate A did not start")
	f.allowReady[0]()
	promotionLeaseAwait(t, f.draining[0], "candidate A did not promote before old drain")
	selected.Store("2.0.0")
	if pulls.Load() != 1 {
		t.Fatal("another candidate started before original drain completed")
	}
	probe := newHostDrainLock(f.home, "test", "connect")
	if !probe.lock(time.Second) {
		t.Fatal("promoted owner retained sibling lease during its old drain")
	}
	probe.unlock()
	f.finishDrain[0]()
	select {
	case image := <-nextPull:
		if image != "fixture/test-connect:2.0.0" {
			t.Fatalf("next ordinary poll pulled %s", image)
		}
	case <-time.After(8 * time.Second):
		t.Fatal("next ordinary poll did not observe selector changed during drain")
	}
	if f.killed.Load() != 0 {
		t.Fatal("selector change killed a healthy promoted candidate")
	}
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Run did not join after observing next target")
	}
}
