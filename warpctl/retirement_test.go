package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

func installRetirementCommands(t *testing.T, run func(*exec.Cmd) error) {
	t.Helper()
	oldRun, oldOut := runAndLogFunc, outAndLogFunc
	runAndLogFunc = run
	outAndLogFunc = func(cmd *exec.Cmd) ([]byte, error) {
		args := strings.Join(cmd.Args, " ")
		if !strings.Contains(args, "docker ps -a --no-trunc --filter id=") {
			return nil, fmt.Errorf("unexpected retirement census: %v", cmd.Args)
		}
		return []byte("aaaaaaaaaaaa\n"), nil
	}
	t.Cleanup(func() { runAndLogFunc, outAndLogFunc = oldRun, oldOut })
}

func TestRetirementPreservesBothCommandFailures(t *testing.T) {
	updateFailure, stopFailure := errors.New("disable failure"), errors.New("stop failure")
	var stopCalls int
	installRetirementCommands(t, func(cmd *exec.Cmd) error {
		if strings.Contains(strings.Join(cmd.Args, " "), "docker update ") {
			return updateFailure
		}
		stopCalls++
		return stopFailure
	})
	err := NewDrainWorker("aaaaaaaaaaaa").Run()
	if !errors.Is(err, updateFailure) || !errors.Is(err, stopFailure) || stopCalls != 1 {
		t.Fatalf("lost a retirement operation/failure: stops=%d err=%v", stopCalls, err)
	}
}

func TestRetirementRetryCannotRenewGrace(t *testing.T) {
	want := errors.New("first stop failed")
	var stops []int
	installRetirementCommands(t, func(cmd *exec.Cmd) error {
		if strings.Contains(strings.Join(cmd.Args, " "), "docker container stop ") {
			seconds, err := strconv.Atoi(cmd.Args[len(cmd.Args)-2])
			if err != nil {
				t.Fatal(err)
			}
			stops = append(stops, seconds)
			if len(stops) == 1 {
				return want
			}
		}
		return nil
	})
	worker := NewDrainWorker("aaaaaaaaaaaa")
	if err := worker.Run(); !errors.Is(err, want) {
		t.Fatal(err)
	}
	// Explicitly advance the owned deadline; no wall-clock sleep controls this
	// transition and no retry is permitted to recreate the original grace.
	worker.stopDeadline = time.Now().Add(-time.Second)
	if err := worker.Run(); err != nil {
		t.Fatal(err)
	}
	if len(stops) != 2 || stops[0] != int(DrainTimeout/time.Second) || stops[1] != 0 {
		t.Fatalf("stop windows=%v", stops)
	}
}

func TestRetirementSuccessNeedsNoAdditionalCensus(t *testing.T) {
	var commands []string
	installRetirementCommands(t, func(cmd *exec.Cmd) error {
		commands = append(commands, strings.Join(cmd.Args, " "))
		return nil
	})
	outAndLogFunc = func(cmd *exec.Cmd) ([]byte, error) {
		t.Errorf("successful Docker retirement unexpectedly depended on another census: %v", cmd.Args)
		return nil, errors.New("census must not run")
	}
	if err := NewDrainWorker("aaaaaaaaaaaa").Run(); err != nil {
		t.Fatal(err)
	}
	if len(commands) != 2 || !strings.Contains(commands[0], "update --restart=no aaaaaaaaaaaa") || !strings.Contains(commands[1], "container stop -t 3600 aaaaaaaaaaaa") {
		t.Fatalf("retirement commands=%v", commands)
	}
}

func TestRetirementAbsenceRequiresSuccessfulCensus(t *testing.T) {
	want := errors.New("Docker operation failed")
	installRetirementCommands(t, func(cmd *exec.Cmd) error { return want })
	outAndLogFunc = func(cmd *exec.Cmd) ([]byte, error) { return nil, want }
	if err := NewDrainWorker("aaaaaaaaaaaa").Run(); !errors.Is(err, want) {
		t.Fatalf("failed census was accepted as absence: %v", err)
	}
	outAndLogFunc = func(cmd *exec.Cmd) ([]byte, error) { return nil, nil }
	if err := NewDrainWorker("aaaaaaaaaaaa").Run(); err != nil {
		t.Fatalf("confirmed absent container could not complete retirement: %v", err)
	}
}

type retirementJoinContext struct {
	context.Context
	joined chan struct{}
	once   sync.Once
}

func (self *retirementJoinContext) Done() <-chan struct{} {
	self.once.Do(func() { close(self.joined) })
	return self.Context.Done()
}

func TestRetirementDuplicateOwnersJoinExactAttempt(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	finish := sync.OnceFunc(func() { close(release) })
	defer finish()
	want := errors.New("shared old stop failed")
	var stops atomic.Int32
	installRetirementCommands(t, func(cmd *exec.Cmd) error {
		if strings.Contains(strings.Join(cmd.Args, " "), "docker container stop ") {
			if stops.Add(1) == 1 {
				close(entered)
			}
			<-release
			return want
		}
		return nil
	})
	owner := &containerRetirements{}
	first := make(chan error, 1)
	go func() { first <- owner.run(context.Background(), "aaaaaaaaaaaa", DrainTimeout) }()
	promotionLeaseAwait(t, entered, "first stop did not start")
	joinCtx := &retirementJoinContext{Context: context.Background(), joined: make(chan struct{})}
	second := make(chan error, 1)
	go func() { second <- owner.run(joinCtx, strings.Repeat("a", 64), DrainTimeout) }()
	promotionLeaseAwait(t, joinCtx.joined, "overlapping cleanup did not join the existing stop")
	finish()
	if firstErr, secondErr := <-first, <-second; !errors.Is(firstErr, want) || !errors.Is(secondErr, want) {
		t.Fatalf("attempt errors changed across join: %v / %v", firstErr, secondErr)
	}
	if stops.Load() != 1 || len(owner.pendingIds()) != 1 {
		t.Fatalf("duplicate stop or lost failed owner: stops=%d pending=%v", stops.Load(), owner.pendingIds())
	}
}

func TestRetirementFailureCannotBeClearedByDifferentWorker(t *testing.T) {
	want := errors.New("first worker retirement failed")
	installRetirementCommands(t, func(cmd *exec.Cmd) error {
		if cmd.Args[len(cmd.Args)-1] == "aaaaaaaaaaaa" {
			return want
		}
		return nil
	})
	first, second := &RunWorker{}, &RunWorker{}
	if err := first.drainContainers([]string{"aaaaaaaaaaaa"}); !errors.Is(err, want) {
		t.Fatal(err)
	}
	if err := second.drainContainers([]string{"bbbbbbbbbbbb"}); err != nil {
		t.Fatal(err)
	}
	if len(first.retirements.pendingIds()) != 1 || len(second.retirements.pendingIds()) != 0 {
		t.Fatal("a different worker changed the failed container's ownership")
	}
}

func TestRetirementAsyncFailureKeepsGenerationAndRetries(t *testing.T) {
	f := newPromotionLeaseFixture(t, false)
	f.workers[0].staggerHostDrain = false
	want := errors.New("first asynchronous stop failed")
	var stops atomic.Int32
	runAndLogFunc = func(cmd *exec.Cmd) error {
		if strings.Contains(strings.Join(cmd.Args, " "), "docker container stop ") && cmd.Args[len(cmd.Args)-1] == "bbbb11" {
			if stops.Add(1) == 1 {
				if err := f.run(cmd); err != nil {
					return err
				}
				return want
			}
			return nil
		}
		return f.run(cmd)
	}
	f.start(0)
	promotionLeaseAwait(t, f.started[0], "candidate did not start")
	f.allowReady[0]()
	promotionLeaseAwait(t, f.draining[0], "old stop did not start")
	err := <-f.done[0]
	f.startedRun[0] = false
	if !errors.Is(err, errRetirementPending) || f.workers[0].pendingDeployment == nil {
		t.Fatalf("async drain was reported as completed: %v", err)
	}
	// The actual deploy entry point must not replace this generation or release
	// a later owner's lease while the old command remains in flight.
	pending := f.workers[0].pendingDeployment
	if err := f.workers[0].deploy(); !errors.Is(err, errRetirementPending) || f.workers[0].pendingDeployment != pending {
		t.Fatalf("pending generation was replaced: %v", err)
	}
	f.finishDrain[0]()
	if err := f.workers[0].completePendingDeployment(true); !errors.Is(err, want) {
		t.Fatalf("async failure disappeared: %v", err)
	}
	if f.workers[0].pendingDeployment != pending || len(f.workers[0].retirements.pendingIds()) != 1 {
		t.Fatal("failed asynchronous retirement lost its owner")
	}
	if err := f.workers[0].completePendingDeployment(true); err != nil {
		t.Fatal(err)
	}
	if f.workers[0].pendingDeployment != nil || len(f.workers[0].retirements.pendingIds()) != 0 || stops.Load() != 2 || f.killed.Load() != 0 {
		t.Fatal("successful retry did not complete exactly the owned retirement")
	}
}

func TestRetirementFailedCandidateDoesNotMaskReadinessFailure(t *testing.T) {
	f := newPromotionLeaseFixture(t, true)
	want := errors.New("candidate stop failed")
	runAndLogFunc = func(cmd *exec.Cmd) error {
		if strings.Contains(strings.Join(cmd.Args, " "), "docker container stop ") && cmd.Args[len(cmd.Args)-1] == "aaaa11" {
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
		if !errors.Is(err, want) || !strings.Contains(err.Error(), "quit") {
			t.Fatalf("cleanup masked the readiness failure or lost its own failure: %v", err)
		}
	case <-time.After(8 * time.Second):
		t.Fatal("failed readiness cleanup did not return")
	}
	if f.workers[0].pendingCandidateCleanup != "aaaa11" || len(f.workers[0].retirements.pendingIds()) != 1 || f.workers[0].pendingDeployment != nil {
		t.Fatal("failed candidate lost cleanup ownership or became a committed generation")
	}
}

// A native child blocks after publishing its PID. It has no Docker, network,
// credentials or production paths; the command deadline must kill and reap it.
func TestRetirementCommandHelper(t *testing.T) {
	if os.Getenv("WARP_RETIREMENT_COMMAND_HELPER") != "1" {
		return
	}
	fmt.Fprintln(os.Stdout, os.Getpid())
	for {
		time.Sleep(time.Hour)
	}
}

func TestRetirementCommandDeadlineKillsAndJoins(t *testing.T) {
	oldRun := runAndLogFunc
	runAndLogFunc = nil
	defer func() { runAndLogFunc = oldRun }()
	readPipe, writePipe, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer readPipe.Close()
	defer writePipe.Close()
	command := exec.Command(os.Args[0], "-test.run=^TestRetirementCommandHelper$")
	command.Env = append(os.Environ(), "WARP_RETIREMENT_COMMAND_HELPER=1")
	command.Stdout = writePipe
	result := make(chan error, 1)
	go func() { result <- runRetirementCommand(context.Background(), 2*time.Second, command) }()
	pidText, err := bufio.NewReader(readPipe).ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(pidText))
	if err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-result:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("native command timeout lost its cause: %v", err)
		}
	case <-time.After(5 * time.Second):
		syscall.Kill(-pid, syscall.SIGKILL)
		t.Fatal("native command owner did not join after its deadline")
	}
	if err := syscall.Kill(pid, 0); !errors.Is(err, syscall.ESRCH) {
		t.Fatalf("native command still exists after join: pid=%d err=%v", pid, err)
	}
}
