package main

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coreos/go-semver/semver"
	"github.com/urnetwork/warp"
)

// Runs the actual deployment orchestrator, native flock and loopback HTTP
// readiness. Every Docker/firewall command terminates in this private fixture;
// PATH contains no real administration tools and unexpected commands fail.
type promotionLeaseFixture struct {
	t           *testing.T
	home        string
	workers     [2]*RunWorker
	started     [2]chan struct{}
	ready       [2]chan struct{}
	draining    [2]chan struct{}
	drain       [2]chan struct{}
	done        [2]chan error
	allowReady  [2]func()
	finishDrain [2]func()
	finishKill  func()
	servers     []*httptest.Server
	warming     atomic.Int32
	maxWarming  atomic.Int32
	startedRun  [2]bool
	killEntered chan struct{}
	killRelease chan struct{}
	killed      atomic.Int32
}

func newPromotionLeaseFixture(t *testing.T, failReadiness bool) *promotionLeaseFixture {
	t.Helper()
	f := &promotionLeaseFixture{t: t, home: t.TempDir(),
		killEntered: make(chan struct{}), killRelease: make(chan struct{})}
	f.finishKill = sync.OnceFunc(func() { close(f.killRelease) })
	bin := filepath.Join(f.home, "bin")
	if err := os.Mkdir(bin, 0o700); err != nil {
		t.Fatal(err)
	}
	// Direct cmd.Output callers also stay inside the fixture.
	script := `#!/bin/sh
case "$*" in
  "docker ps "*)
    case "$*" in
      *test-connect-g1*) printf 'aaaa11\nbbbb11\n' ;;
      *test-connect-g2*) printf 'aaaa22\nbbbb22\n' ;;
      *) exit 96 ;;
    esac ;;
  "iptables "*" -L "*) exit 0 ;;
  *) printf 'unexpected fixture command\n' >&2; exit 97 ;;
esac
`
	if err := os.WriteFile(filepath.Join(bin, "sudo"), []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin)
	t.Setenv("WARP_HOME", f.home)
	oldRun, oldOut, oldQuiet, oldSudo2 := runAndLogFunc, outAndLogFunc, runQuietFunc, sudo2Func
	sudo2Func = nil
	runAndLogFunc = f.run
	outAndLogFunc = f.output
	runQuietFunc = func(cmd *exec.Cmd) (commandOutput, error) {
		name := filepath.Base(cmd.Args[0])
		if name != "netstat" && name != "conntrack" && !(name == "sudo" && len(cmd.Args) > 1 && cmd.Args[1] == "conntrack") {
			return commandOutput{}, fmt.Errorf("unexpected quiet fixture command: %v", cmd.Args)
		}
		return commandOutput{}, nil
	}
	t.Cleanup(func() {
		f.finishKill()
		for i := range f.workers {
			if f.allowReady[i] != nil {
				f.allowReady[i]()
				f.finishDrain[i]()
			}
		}
		for i := range f.workers {
			if f.startedRun[i] {
				select {
				case <-f.done[i]:
				case <-time.After(20 * time.Second):
					t.Error("deployment owner did not join after fixture release")
				}
			}
		}
		for _, server := range f.servers {
			server.Close()
		}
		runAndLogFunc, outAndLogFunc, runQuietFunc, sudo2Func = oldRun, oldOut, oldQuiet, oldSudo2
	})
	for i := range f.workers {
		f.started[i], f.ready[i] = make(chan struct{}), make(chan struct{})
		f.draining[i], f.drain[i] = make(chan struct{}), make(chan struct{})
		f.done[i] = make(chan error, 1)
		f.allowReady[i] = sync.OnceFunc(func() { close(f.ready[i]) })
		f.finishDrain[i] = sync.OnceFunc(func() { close(f.drain[i]) })
		status := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			<-f.ready[i]
			f.warming.Add(-1)
			if failReadiness && i == 0 {
				f.workers[i].quitEvent.Set()
				fmt.Fprint(w, `{"status":"error fixture readiness"}`)
				return
			}
			fmt.Fprint(w, `{"status":"ready"}`)
		}))
		// Close only after deployment/readiness owners have joined.
		f.servers = append(f.servers, status)
		port, err := strconv.Atoi(strings.TrimPrefix(status.URL, "http://127.0.0.1:"))
		if err != nil {
			t.Fatal(err)
		}
		namespace := "fixture"
		f.workers[i] = &RunWorker{
			warpState: &WarpState{warpSettings: &WarpSettings{DockerNamespace: &namespace}},
			env:       "test", service: "connect", block: fmt.Sprintf("g%d", i+1),
			hostNetworking: true, staggerHostDrain: true, statusMode: STATUS_MODE_STANDARD,
			portBlocks:            parsePortBlocks(fmt.Sprintf("80:%d:%d", 41080+i, port)),
			servicesDockerNetwork: &DockerNetwork{networkName: "fixture", ipv4: &NetworkInterface{interfaceIp: "127.0.0.1"}},
			deployedVersion:       semver.New("1.0.0"), quitEvent: warp.NewEvent(),
			vaultMountMode: MOUNT_MODE_NO, configMountMode: MOUNT_MODE_NO, siteMountMode: MOUNT_MODE_NO,
			dataMountMode: MOUNT_MODE_NO, dockerMountMode: MOUNT_MODE_NO,
		}
	}
	return f
}

func (f *promotionLeaseFixture) output(cmd *exec.Cmd) ([]byte, error) {
	args := strings.Join(cmd.Args, " ")
	if strings.Contains(args, "docker image inspect") {
		return []byte("sha256:" + strings.Repeat("1", 64)), nil
	}
	if strings.Contains(args, "docker run ") {
		i := 0
		if strings.Contains(args, "WARP_BLOCK=g2") {
			i = 1
		}
		n := f.warming.Add(1)
		for old := f.maxWarming.Load(); old < n && !f.maxWarming.CompareAndSwap(old, n); old = f.maxWarming.Load() {
		}
		close(f.started[i])
		return []byte([]string{"aaaa11", "aaaa22"}[i]), nil
	}
	return nil, fmt.Errorf("unexpected fixture output command: %v", cmd.Args)
}

func (f *promotionLeaseFixture) run(cmd *exec.Cmd) error {
	args := strings.Join(cmd.Args, " ")
	if strings.Contains(args, "docker pull ") || strings.Contains(args, "docker update ") {
		return nil
	}
	if strings.Contains(args, "docker container stop ") {
		id := cmd.Args[len(cmd.Args)-1]
		if id == "aaaa11" || id == "aaaa22" {
			f.killed.Add(1)
			close(f.killEntered)
			<-f.killRelease
			return nil
		}
		i := 0
		if id == "bbbb22" {
			i = 1
		} else if id != "bbbb11" {
			return fmt.Errorf("unknown fixture drain target %q", id)
		}
		if !strings.Contains(args, "-t "+strconv.Itoa(int(DrainTimeout/time.Second))+" ") {
			f.t.Error("old container lost its full graceful drain timeout")
		}
		close(f.draining[i])
		<-f.drain[i]
		return nil
	}
	if strings.Contains(args, "iptables ") {
		if strings.Contains(args, " -C ") {
			return errors.New("fixture rule absent")
		}
		return nil
	}
	return fmt.Errorf("unexpected fixture mutation command: %v", cmd.Args)
}

func (f *promotionLeaseFixture) start(i int) {
	f.startedRun[i] = true
	go func() { f.done[i] <- f.workers[i].deploy() }()
}

func promotionLeaseAwait(t *testing.T, signal <-chan struct{}, message string) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(8 * time.Second):
		t.Fatal(message)
	}
}

func TestRunWorkerPromotionReleasesSiblingBeforeOldDrain(t *testing.T) {
	f := newPromotionLeaseFixture(t, false)
	f.start(0)
	promotionLeaseAwait(t, f.started[0], "first candidate did not start")
	f.start(1)
	probe := newHostDrainLock(f.home, "test", "connect")
	if probe.lock(100 * time.Millisecond) {
		probe.unlock()
		t.Fatal("host lease was released while readiness was still pending")
	}
	f.allowReady[0]()
	promotionLeaseAwait(t, f.draining[0], "first ready candidate did not reach old-container drain")
	select {
	case <-f.started[1]:
	case <-time.After(time.Second):
		t.Fatal("sibling candidate could not start while first old drain was held")
	}
	if probe.lock(100 * time.Millisecond) {
		probe.unlock()
		t.Fatal("second candidate did not retain the lease through readiness")
	}
	f.allowReady[1]()
	promotionLeaseAwait(t, f.draining[1], "second candidate did not promote while first old drain remained held")
	// A later owner can enter once both candidates are promoted. Completing
	// the first drain must not release that owner's still-active lease.
	if !probe.lock(time.Second) {
		t.Fatal("promoted candidates retained the host lease during old drains")
	}
	defer probe.unlock()
	f.finishDrain[0]()
	select {
	case err := <-f.done[0]:
		f.startedRun[0] = false
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("first deployment did not finish after its drain joined")
	}
	other := newHostDrainLock(f.home, "test", "connect")
	if other.lock(100 * time.Millisecond) {
		other.unlock()
		t.Fatal("first rollout's deferred release unlocked a later owner")
	}
	if got := f.maxWarming.Load(); got != 1 {
		t.Fatalf("simultaneous unready candidates=%d want=1", got)
	}
	if f.killed.Load() != 0 {
		t.Fatal("healthy promoted candidate was killed")
	}
}

func TestRunWorkerPromotionFailureJoinsCleanupBeforeSibling(t *testing.T) {
	f := newPromotionLeaseFixture(t, true)
	f.start(0)
	promotionLeaseAwait(t, f.started[0], "failed candidate did not start")
	f.allowReady[0]()
	promotionLeaseAwait(t, f.killEntered, "readiness failure did not enter candidate rollback")
	f.start(1)
	probe := newHostDrainLock(f.home, "test", "connect")
	if probe.lock(100 * time.Millisecond) {
		probe.unlock()
		t.Fatal("candidate cleanup released host lease before joining")
	}
	f.finishKill()
	select {
	case err := <-f.done[0]:
		f.startedRun[0] = false
		if err == nil {
			t.Fatal("failed readiness was reported as deployment success")
		}
	case <-time.After(time.Second):
		t.Fatal("failed candidate did not join rollback")
	}
	promotionLeaseAwait(t, f.started[1], "sibling did not start after failed candidate cleanup")
	if f.killed.Load() != 1 {
		t.Fatal("failed candidate cleanup did not keep its single close owner")
	}
}

func TestRunWorkerOrphanDrainDoesNotHoldCandidateLease(t *testing.T) {
	f := newPromotionLeaseFixture(t, false)
	// Startup reconciliation already proved these targets do not own live DNAT.
	// Exercise its actual retirement entry point with the old stop still held.
	f.startedRun[0] = true
	go func() {
		f.workers[0].drainContainers([]string{"bbbb11"})
		f.done[0] <- nil
	}()
	promotionLeaseAwait(t, f.draining[0], "inherited old container did not enter full graceful drain")
	f.start(1)
	select {
	case <-f.started[1]:
	case <-time.After(time.Second):
		t.Fatal("startup orphan drain monopolized the candidate lease")
	}
	f.allowReady[1]()
	promotionLeaseAwait(t, f.draining[1], "candidate could not promote while inherited old drain remained held")
	select {
	case <-f.done[0]:
		t.Fatal("old retirement was abandoned before its stop operation joined")
	default:
	}
	if f.killed.Load() != 0 || f.maxWarming.Load() != 1 {
		t.Fatal("orphan retirement disrupted the healthy candidate")
	}
}
