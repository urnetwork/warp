package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"
)

const retirementCommandTimeout = 30 * time.Second

var errRetirementPending = errors.New("old-container retirement is still in progress")

// The ready candidate remains the desired generation even when retirement
// fails. Returning an ordinary deployment error would start another candidate
// on every retry instead of finishing the retirement already owned by this one.
type deploymentRetirementError struct {
	err error
}

func (self *deploymentRetirementError) Error() string {
	return fmt.Sprintf("deployment cutover committed; retirement incomplete: %s", self.err)
}

func (self *deploymentRetirementError) Unwrap() error {
	return self.err
}

type deploymentRetirement struct {
	complete func() error
	done     chan error
}

func (self *RunWorker) retirementContext() context.Context {
	if self.quitEvent != nil {
		return self.quitEvent.Ctx
	}
	return context.Background()
}

// Run's watcher owns this slot. Async retirement has one joined completion;
// only that watcher may clear the slot or start another attempt/generation.
func (self *RunWorker) completePendingDeployment(join bool) error {
	pending := self.pendingDeployment
	if pending == nil {
		return nil
	}
	if pending.done == nil {
		pending.done = make(chan error, 1)
		if join {
			pending.done <- pending.complete()
		} else {
			done := pending.done
			go func() { done <- pending.complete() }()
		}
	}
	var err error
	if join {
		err = <-pending.done
	} else {
		select {
		case err = <-pending.done:
		default:
			return &deploymentRetirementError{err: errRetirementPending}
		}
	}
	if err != nil {
		pending.done = nil
		return &deploymentRetirementError{err: err}
	}
	self.pendingDeployment = nil
	return nil
}

// A failed attempt remains owned by its exact container ID, including when
// stop succeeds but disabling restart fails and Docker ps no longer lists it.
// Startup reconciliation and a new cutover can discover the same old ID;
// both join its one active stop and share that attempt's immutable result.
type containerRetirements struct {
	mutex      sync.Mutex
	containers map[string]*containerRetirement
}

type containerRetirement struct {
	worker  *KillWorker
	attempt *containerRetirementAttempt
}

type containerRetirementAttempt struct {
	done chan struct{}
	err  error
}

func (self *containerRetirements) pendingIds() []string {
	self.mutex.Lock()
	defer self.mutex.Unlock()
	ids := []string{}
	for id := range self.containers {
		ids = append(ids, id)
	}
	return ids
}

func (self *containerRetirements) run(ctx context.Context, containerId string, timeout time.Duration) error {
	self.mutex.Lock()
	if self.containers == nil {
		self.containers = map[string]*containerRetirement{}
	}
	// Discovery can return the short or full Docker ID for the same container.
	key := containerId
	for id := range self.containers {
		if containerIdsEqual(id, containerId) {
			key = id
			break
		}
	}
	retirement := self.containers[key]
	if retirement == nil {
		retirement = &containerRetirement{worker: &KillWorker{containerId: containerId, killTimeout: timeout}}
		self.containers[key] = retirement
	}
	if retirement.attempt != nil {
		attempt := retirement.attempt
		select {
		case <-attempt.done:
			// Retry the same owner with its original stop deadline.
		default:
			self.mutex.Unlock()
			select {
			case <-attempt.done:
				return attempt.err
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	}
	attempt := &containerRetirementAttempt{done: make(chan struct{})}
	retirement.attempt = attempt
	self.mutex.Unlock()

	attempt.err = retirement.worker.run(ctx)
	if attempt.err != nil {
		Err.Printf("Container retirement failed container=%s: %s\n", containerId, attempt.err)
	}
	self.mutex.Lock()
	if attempt.err == nil {
		delete(self.containers, key)
	}
	close(attempt.done)
	self.mutex.Unlock()
	return attempt.err
}

// Bounds and joins the actual command process, including sudo's child. The
// stop command gets its entire remaining graceful-stop window plus this RPC
// allowance. No goroutine is abandoned when the command times out.
func retirementCommand(ctx context.Context, command *exec.Cmd) *exec.Cmd {
	cmd := exec.CommandContext(ctx, command.Path, command.Args[1:]...)
	cmd.Args = command.Args
	cmd.Env, cmd.Dir = command.Env, command.Dir
	cmd.Stdin, cmd.Stdout, cmd.Stderr = command.Stdin, command.Stdout, command.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		if errors.Is(err, syscall.ESRCH) {
			return os.ErrProcessDone
		}
		return err
	}
	cmd.WaitDelay = time.Second
	return cmd
}

func runRetirementCommand(ctx context.Context, timeout time.Duration, command *exec.Cmd) error {
	commandCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := retirementCommand(commandCtx, command)
	err := runAndLog(cmd)
	if commandCtx.Err() != nil {
		return errors.Join(commandCtx.Err(), err)
	}
	return err
}

func retirementCommandOutput(ctx context.Context, command *exec.Cmd) ([]byte, error) {
	commandCtx, cancel := context.WithTimeout(ctx, retirementCommandTimeout)
	defer cancel()
	out, err := retirementCommand(commandCtx, command).Output()
	if commandCtx.Err() != nil {
		return nil, errors.Join(commandCtx.Err(), err)
	}
	return out, err
}

// Only a successful Docker census can turn a failed stop into already absent.
// Parsing an error string as absence would hide a daemon/permission failure.
func retiredContainerAbsent(ctx context.Context, containerId string) (bool, error) {
	commandCtx, cancel := context.WithTimeout(ctx, retirementCommandTimeout)
	defer cancel()
	cmd := retirementCommand(commandCtx, docker("ps", "-a", "--no-trunc", "--filter", "id="+containerId, "--format", "{{.ID}}"))
	out, err := outAndLog(cmd)
	if commandCtx.Err() != nil {
		return false, errors.Join(commandCtx.Err(), err)
	}
	if err != nil {
		return false, err
	}
	return strings.TrimSpace(string(out)) == "", nil
}
