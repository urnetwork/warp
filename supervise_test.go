package warp

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// startCount reads how many times the child recorded a start.
func startCount(t *testing.T, path string) int {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read start log: %s", err)
	}
	return len(strings.Fields(string(data)))
}

func runChild(t *testing.T, settings *ChildSettings, runTime time.Duration) int {
	t.Helper()
	startLog := filepath.Join(t.TempDir(), "starts")
	if err := os.WriteFile(startLog, nil, 0644); err != nil {
		t.Fatalf("create start log: %s", err)
	}

	event := NewEvent()
	childWaitGroup := &sync.WaitGroup{}
	childWaitGroup.Add(1)
	go func() {
		defer childWaitGroup.Done()
		Child(
			event,
			"test",
			settings,
			"/bin/sh",
			"-c",
			fmt.Sprintf("echo start >> %s; sleep 60", startLog),
		)
	}()

	time.Sleep(runTime)
	event.Set()
	childWaitGroup.Wait()

	return startCount(t, startLog)
}

func testChildSettings() *ChildSettings {
	settings := DefaultChildSettings()
	settings.StopSignal = syscall.SIGTERM
	settings.StopTimeout = 1 * time.Second
	settings.RestartDelay = 10 * time.Millisecond
	settings.HealthCheckInterval = 50 * time.Millisecond
	settings.UnhealthyTimeout = 200 * time.Millisecond
	return settings
}

// Exit is not the only way a child stops working. On 2026-08-17 a loki ran for
// 16 hours with its query modules stuck in Starting: the process never exited,
// so nothing restarted it, and the host answered no log query the whole time
// (SIGNALS.md 11.13). A child that fails its health check for longer than the
// unhealthy timeout has to be restarted even though it is still running.
func TestChildRestartsARunningButUnhealthyChild(t *testing.T) {
	settings := testChildSettings()
	settings.HealthCheck = func(ctx context.Context) error {
		return errors.New("query modules stuck in Starting")
	}

	// long enough for the unhealthy timeout to fire at least twice
	starts := runChild(t, settings, 1500*time.Millisecond)
	if starts < 2 {
		t.Fatalf("a wedged child was never restarted (starts=%d)", starts)
	}
}

// The watchdog must not touch a child that is doing its job. A false restart
// here costs a loki chunk flush and a ring re-registration on every cycle.
func TestChildLeavesAHealthyChildAlone(t *testing.T) {
	settings := testChildSettings()
	settings.HealthCheck = func(ctx context.Context) error {
		return nil
	}

	starts := runChild(t, settings, 1500*time.Millisecond)
	if starts != 1 {
		t.Fatalf("a healthy child was restarted (starts=%d)", starts)
	}
}

// A child that recovers on its own inside the unhealthy window is left alone:
// loki and mimir gate /ready on their rings, which go unhealthy while peers
// cycle through a rolling fleet deploy.
func TestChildToleratesUnhealthyShorterThanTheTimeout(t *testing.T) {
	settings := testChildSettings()
	unhealthyUntil := time.Now().Add(100 * time.Millisecond)
	settings.HealthCheck = func(ctx context.Context) error {
		if time.Now().Before(unhealthyUntil) {
			return errors.New("ring has unhealthy instances")
		}
		return nil
	}

	starts := runChild(t, settings, 1500*time.Millisecond)
	if starts != 1 {
		t.Fatalf("a child that recovered on its own was restarted (starts=%d)", starts)
	}
}

// Without a health check the supervisor keeps its original contract: exit is
// the only restart trigger.
func TestChildWithoutHealthCheckOnlyRestartsOnExit(t *testing.T) {
	settings := testChildSettings()
	settings.HealthCheck = nil

	starts := runChild(t, settings, 1000*time.Millisecond)
	if starts != 1 {
		t.Fatalf("child restarted without a health check (starts=%d)", starts)
	}
}
