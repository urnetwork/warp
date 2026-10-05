package main

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Force a pre-cutover ownership failure without canceling the run worker.
// Its first stop fails; its next stop stays at a barrier. The actual native
// service lease must fence a sibling until that exact candidate is retired.
func TestRetirementFailedCandidateKeepsWarmupLeaseUntilRetired(t *testing.T) {
	f := newPromotionLeaseFixture(t, false)
	fixture := `#!/bin/sh
case "$*" in
  "docker ps "*)
    case "$*" in
      *test-connect-g1*) printf 'aaaa11\nbbbb11\n' ;;
      *test-connect-g2*) printf 'aaaa22\nbbbb22\n' ;;
      *) exit 96 ;;
    esac ;;
  "iptables -t nat -L -n")
    printf 'Chain WARP-TEST-OTHER (0 references)\nDNAT tcp -- 0.0.0.0/0 0.0.0.0/0 tcp dpt:41080 to:127.0.0.1:41099\n' ;;
  "iptables "*" -L "*) exit 0 ;;
  *) exit 97 ;;
esac
`
	if err := os.WriteFile(filepath.Join(f.home, "bin", "sudo"), []byte(fixture), 0o700); err != nil {
		t.Fatal(err)
	}
	want := errors.New("failed candidate stop unavailable")
	firstFailure, retryEntered, releaseRetry := make(chan struct{}), make(chan struct{}), make(chan struct{})
	finishRetry := sync.OnceFunc(func() { close(releaseRetry) })
	defer finishRetry()
	var attempts atomic.Int32
	var retired atomic.Bool
	runAndLogFunc = func(cmd *exec.Cmd) error {
		if strings.Contains(strings.Join(cmd.Args, " "), "docker container stop ") && cmd.Args[len(cmd.Args)-1] == "aaaa11" {
			if attempts.Add(1) == 1 {
				close(firstFailure)
				return want
			}
			close(retryEntered)
			<-releaseRetry
			retired.Store(true)
			return nil
		}
		return f.run(cmd)
	}
	outAndLogFunc = func(cmd *exec.Cmd) ([]byte, error) {
		args := strings.Join(cmd.Args, " ")
		if strings.Contains(args, "docker run ") && strings.Contains(args, "WARP_BLOCK=g2") && !retired.Load() {
			t.Error("sibling candidate started before failed candidate retired")
		}
		return f.output(cmd)
	}
	f.start(0)
	promotionLeaseAwait(t, f.started[0], "first candidate did not start")
	f.allowReady[0]()
	promotionLeaseAwait(t, firstFailure, "candidate did not reach failed pre-cutover cleanup")
	f.start(1)
	select {
	case err := <-f.done[0]:
		f.startedRun[0] = false
		t.Fatalf("candidate owner released its warmup lease with cleanup still failed: %v", err)
	case <-retryEntered:
	case <-time.After(8 * time.Second):
		t.Fatal("failed candidate cleanup was not retried by its lease owner")
	}
	probe := newHostDrainLock(f.home, "test", "connect")
	if probe.lock(100 * time.Millisecond) {
		probe.unlock()
		t.Fatal("warmup lease was available while candidate cleanup was still in flight")
	}
	unrelated := newHostDrainLock(f.home, "test", "unrelated")
	if !unrelated.lock(time.Second) {
		t.Fatal("candidate cleanup blocked an unrelated service")
	}
	unrelated.unlock()
	finishRetry()
	select {
	case err := <-f.done[0]:
		f.startedRun[0] = false
		if !errors.Is(err, want) || !strings.Contains(err.Error(), "refusing redirect") {
			t.Fatalf("retirement retry masked the original candidate/cleanup failures: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("retired failed candidate did not release its lease")
	}
	if f.workers[0].pendingCandidateCleanup != "" || len(f.workers[0].retirements.pendingIds()) != 0 {
		t.Fatal("successfully retired candidate retained cleanup ownership")
	}
	promotionLeaseAwait(t, f.started[1], "sibling did not start after failed candidate retired")
	f.allowReady[1]()
	promotionLeaseAwait(t, f.draining[1], "sibling did not promote after failed candidate retired")
}
