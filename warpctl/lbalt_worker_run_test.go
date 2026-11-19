package main

// Tests of the lb_alt wiring in RunWorker.Run (lbalt_worker.go;
// server/LBALT-IMPL.md §2.2, §2.5; LBALT.md D18): Run itself drives the
// worker, with every command in the command hooks or the PATH fixture, and
// lb_alt operations that are fakes. The fakes end the worker by setting the
// quit event Run creates.

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coreos/go-semver/semver"
)

// Runs the worker's Run until it returns, as `service run` does. Run owns the
// command hooks while it runs, so a Run that outlives the bound panics rather
// than let the test restore the hooks under it.
func lbAltRunWorker(worker *RunWorker, bound time.Duration) {
	done := make(chan struct{})
	go func() {
		defer close(done)
		worker.Run()
	}()
	select {
	case <-done:
	case <-time.After(bound):
		panic("lb_alt fixture Run did not return")
	}
}

// Events recorded from the worker's goroutines.
type lbAltRunEvents struct {
	stateLock sync.Mutex
	events    []string
}

// Appends an event.
func (self *lbAltRunEvents) record(event string) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.events = append(self.events, event)
}

// The events so far.
func (self *lbAltRunEvents) recorded() []string {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.events)
}

// A deployment version client whose every read records a version poll, ends
// the worker and fails, so Run deploys nothing.
func lbAltQuitOnVersionPoll(worker *RunWorker, events *lbAltRunEvents) deploymentVersionClient {
	poll := func(ctx context.Context) (string, error) {
		events.record("poll version")
		worker.quitEvent.Set()
		return "", errors.New("fixture version poll")
	}
	return deploymentVersionFuncs{get: poll, consistent: poll}
}

// Fakes every command an lb worker's Run runs outside its deploys. Routing,
// firewall and docker commands are recorded and succeed, except a firewall
// check, which finds no rule. Routing listings print nothing, and docker ps,
// which Run's startup runs itself, lists no container (the PATH fixture). An
// output or quiet command is recorded and fails.
func lbAltFakeLbRunCommands(t *testing.T, events *lbAltRunEvents) {
	t.Helper()
	bin := filepath.Join(os.Getenv("WARP_HOME"), "bin")
	if err := os.MkdirAll(bin, 0o700); err != nil {
		t.Fatal(err)
	}
	writeSudoFixture(t, bin, `#!/bin/sh
case "$*" in
  "docker ps "*) ;;
  *) printf 'unexpected fixture command\n' >&2; exit 97 ;;
esac
`)
	t.Setenv("PATH", bin)

	previousRun, previousOut, previousQuiet, previousSudo2 := runAndLogFunc, outAndLogFunc, runQuietFunc, sudo2Func
	t.Cleanup(func() {
		runAndLogFunc, outAndLogFunc, runQuietFunc, sudo2Func = previousRun, previousOut, previousQuiet, previousSudo2
	})
	runAndLogFunc = func(cmd *exec.Cmd) error {
		args := strings.Join(cmd.Args, " ")
		events.record(args)
		if strings.Contains(args, "tables ") && strings.Contains(args, " -C ") {
			return errors.New("fixture rule absent")
		}
		return nil
	}
	sudo2Func = func(name []string, args ...string) *exec.Cmd {
		commandArgs := append(slices.Clone(name), args...)
		command := strings.Join(commandArgs, " ")
		if strings.Contains(command, " route show ") || strings.Contains(command, " rule list") {
			return exec.Command("/bin/sh", "-c", "exit 0")
		}
		return exec.Command("sudo", commandArgs...)
	}
	outAndLogFunc = func(cmd *exec.Cmd) ([]byte, error) {
		events.record("output " + strings.Join(cmd.Args, " "))
		return nil, errors.New("unexpected fixture output command")
	}
	runQuietFunc = func(cmd *exec.Cmd) (commandOutput, error) {
		events.record("quiet " + strings.Join(cmd.Args, " "))
		return commandOutput{}, errors.New("unexpected fixture quiet command")
	}
}

// The first command of each routing reconcile of newLbAltSplitWorker's unit.
const lbAltSplitWorkerRoutingReconcile = "sudo ip route replace 192.0.2.128/26 dev warpservices src 192.0.2.129 table 100"

// Run drives an lb_alt interface's unit routing-only (§2.2, §2.5). As its loop
// starts, after the startup's routing reconcile and before the loop's first
// 30 s wait, it reconciles the interface's split and then looks for the
// interface's nginx to retire. It polls no version and starts no container.
// The fake split reconcile ends the worker.
func TestLbAltWorkerRunRoutesAnLbAltInterfaceOnly(t *testing.T) {
	setupTestVault(t, lbAltUnitsYaml(lbAltUnitsSettings{connect: "true"}))
	events := &lbAltRunEvents{}
	lbAltFakeLbRunCommands(t, events)
	ops := defaultLbAltWorkerOps()
	worker := newLbAltSplitWorker(ops)
	ops.reconcileSplit = func(ctx context.Context, config *lbAltSplitConfig) error {
		events.record("reconcile split")
		worker.quitEvent.Set()
		return nil
	}
	ops.listContainers = func(ctx context.Context, containerNamePrefix string, format string) ([]string, error) {
		events.record("list " + containerNamePrefix)
		return nil, nil
	}
	worker.dynamoClient = lbAltQuitOnVersionPoll(worker, events)

	lbAltRunWorker(worker, 2*RoutingTableReconcileTimeout)

	recorded := events.recorded()
	splitIndex := slices.Index(recorded, "reconcile split")
	if splitIndex < 0 {
		t.Fatalf("Run never reconciled the split:\n%s", strings.Join(recorded, "\n"))
	}
	routingReconciles := 0
	for _, event := range recorded[:splitIndex] {
		if event == lbAltSplitWorkerRoutingReconcile {
			routingReconciles += 1
		}
	}
	if routingReconciles != 1 {
		t.Fatalf("%d routing reconciles ran before the split's, want the startup's alone:\n%s", routingReconciles, strings.Join(recorded, "\n"))
	}
	if splitIndex+1 == len(recorded) || recorded[splitIndex+1] != "list test-lb-edge-a.example-eth1-" {
		t.Fatalf("the reconciled split was not followed by the nginx retirement:\n%s", strings.Join(recorded, "\n"))
	}
	for _, event := range recorded {
		if event == "poll version" || strings.Contains(event, "docker run ") || strings.Contains(event, "docker pull ") {
			t.Fatalf("Run of an lb_alt unit ran %q:\n%s", event, strings.Join(recorded, "\n"))
		}
	}
}

// Run's poll loop of an lb unit back on nginx retries a pending removal of
// its interface's split once due, and before it polls versions (D18): a
// removal that failed after the cutover does not wait for the next deploy.
// It removes the split's record with it.
func TestLbAltWorkerRunRetriesAPendingSplitRemoval(t *testing.T) {
	setupTestVault(t, lbAltUnitsYaml(lbAltUnitsSettings{edgeAEth1: "false", connect: "true"}))
	events := &lbAltRunEvents{}
	lbAltFakeLbRunCommands(t, events)
	recordPath := lbAltWriteSplitRecord(t, "test", "eth1")
	ops := defaultLbAltWorkerOps()
	ops.removeSplit = func(ctx context.Context, env string, interfaceName string) error {
		events.record("remove split " + env + " " + interfaceName)
		return nil
	}
	ops.reconcileSplit = func(ctx context.Context, config *lbAltSplitConfig) error {
		t.Error("an nginx unit reconciled a split")
		return nil
	}
	worker := newLbAltSplitWorker(ops)
	worker.lbAlt = false
	worker.lbAltBlocks = nil
	worker.deployedVersion = semver.New("1.0.0")
	worker.dynamoClient = lbAltQuitOnVersionPoll(worker, events)
	// a removal that failed after the nginx cutover, now due
	worker.lbAltState = lbAltWorkerState{splitRemovalPending: true}

	lbAltRunWorker(worker, 2*WarpPollTimeout)

	recorded := events.recorded()
	removeIndex := slices.Index(recorded, "remove split test eth1")
	pollIndex := slices.Index(recorded, "poll version")
	if removeIndex < 0 || pollIndex < removeIndex {
		t.Fatalf("the pending removal was not retried before the version poll:\n%s", strings.Join(recorded, "\n"))
	}
	if _, err := os.Stat(recordPath); !errors.Is(err, fs.ErrNotExist) || worker.lbAltState.splitRemovalPending {
		t.Fatalf("after the removal the record is %v and pending is %t", err, worker.lbAltState.splitRemovalPending)
	}
}

// Makes docker ps list only the containers the fixture's docker run started,
// as on a host where the block ran no container when Run began.
func (self *lbAltWorkerFixture) listStartedContainers(t *testing.T) {
	t.Helper()
	stateFile := filepath.Join(self.home, "started-containers")
	if err := os.WriteFile(stateFile, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("FIXTURE_CID_STATE", stateFile)
	writeSudoFixture(t, filepath.Join(self.home, "bin"), `#!/bin/sh
case "$*" in
  "docker ps "*) while IFS= read -r line; do printf '%s\n' "$line"; done < "$FIXTURE_CID_STATE" ;;
  "iptables "*" -L "*|"ip6tables "*" -L "*) exit 0 ;;
  *) printf 'unexpected fixture command\n' >&2; exit 97 ;;
esac
`)
	previousOut := outAndLogFunc
	outAndLogFunc = func(cmd *exec.Cmd) ([]byte, error) {
		out, err := previousOut(cmd)
		if err == nil && strings.Contains(strings.Join(cmd.Args, " "), "docker run ") {
			err = os.WriteFile(stateFile, []byte(lbAltFixtureContainerId+"\n"), 0o600)
		}
		return out, err
	}
}

// The events of the fixture so far.
func (self *lbAltWorkerFixture) recorded() []string {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.events)
}

// Run keeps a connect candidate whose chains failed after its commit (§2.5)
// as the deployed generation: the next poll retries that candidate's
// promotion and starts no second candidate, which would leave the first
// running with no owner and take another port from the block's pool. The
// fake chain write fails both times and ends the worker at the second, one
// poll after the deploy.
func TestLbAltWorkerRunStartsNoSecondCandidateAfterAChainFailure(t *testing.T) {
	f := newLbAltWorkerFixture(t)
	f.listStartedContainers(t)
	f.worker.deployedVersion = nil
	f.chainsErr = errors.New("fixture chain failure")
	previousChains := f.worker.lbAltOps.writeBlockChains
	f.worker.lbAltOps.writeBlockChains = func(ctx context.Context, env string, block string, splitInterfaces []lbAltSplitInterface, targets []lbAltBlockTarget) error {
		err := previousChains(ctx, env, block, splitInterfaces, targets)
		chainWrites := 0
		for _, event := range f.recorded() {
			if event == "chains" {
				chainWrites += 1
			}
		}
		if 2 <= chainWrites {
			f.worker.quitEvent.Set()
		}
		return err
	}

	lbAltRunWorker(f.worker, 6*WarpPollTimeout)

	counts := map[string]int{}
	for _, event := range f.recorded() {
		counts[event] += 1
	}
	if counts["start"] != 1 || counts["chains"] != 2 || counts["stop"] != 0 || counts["cutover"] != 0 {
		t.Fatalf("events %v: want one start, two chain writes, no stop and no cutover", f.recorded())
	}
	if f.worker.deployedVersion == nil || f.worker.deployedVersion.String() != "1.0.0" {
		t.Fatalf("deployed version %v, want the promoted candidate's", f.worker.deployedVersion)
	}
}

// Between deploys, Run's poll loop of a connect block on an lb_alt host
// writes the block's chains for its deployed generation, before it polls
// versions: a lost chain is back with no connect deploy.
func TestLbAltWorkerRunRefreshesTheChainsBeforePollingVersions(t *testing.T) {
	f := newLbAltWorkerFixture(t)
	f.listStartedContainers(t)
	events := &lbAltRunEvents{}
	f.worker.dynamoClient = lbAltQuitOnVersionPoll(f.worker, events)
	previousChains := f.worker.lbAltOps.writeBlockChains
	f.worker.lbAltOps.writeBlockChains = func(ctx context.Context, env string, block string, splitInterfaces []lbAltSplitInterface, targets []lbAltBlockTarget) error {
		events.record("chains")
		return previousChains(ctx, env, block, splitInterfaces, targets)
	}
	servicePorts := map[int]int{80: f.statusPort, 443: 7301, 4053: 7302}
	f.worker.lbAltState = lbAltWorkerState{chainServicePorts: servicePorts}

	lbAltRunWorker(f.worker, 2*WarpPollTimeout)

	if want := []string{"chains", "poll version"}; !slices.Equal(events.recorded(), want) {
		t.Fatalf("events %v, want %v", events.recorded(), want)
	}
	wantTargets := []lbAltBlockTarget{
		{protocol: "tcp", publicPort: 80, internalPort: f.statusPort},
		{protocol: "tcp", publicPort: 443, internalPort: 7301},
		{protocol: "udp", publicPort: 53, internalPort: 7302},
		{protocol: "udp", publicPort: 443, internalPort: 7301},
		{protocol: "udp", publicPort: 4053, internalPort: 7302},
	}
	if len(f.chainsCalls) != 1 || !slices.Equal(f.chainsCalls[0].targets, wantTargets) {
		t.Fatalf("chains written %v, want the deployed generation's %v", f.chainsCalls, wantTargets)
	}
}
