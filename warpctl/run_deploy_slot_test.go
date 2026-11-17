package main

// The deploy slot (sidecar QD-873): each new process of a block takes a slot none of the block's running processes
// on the host holds, so across deploys the slot alternates and a deploy's new process never holds the slot of the
// old one draining beside it, even when a restart left every slot held. startContainer runs on fake docker
// commands: no Docker, sudo or selector is reached, and nothing sleeps.

import (
	"errors"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"testing"

	"github.com/coreos/go-semver/semver"
	"github.com/urnetwork/warp"
)

func TestSelectDeploySlotTakesASlotNoRunningProcessHolds(t *testing.T) {
	process := func(slot int, slotValid bool, startMillis int64) *deploySlotProcess {
		return &deploySlotProcess{containerId: fmt.Sprintf("c%d", startMillis), slot: slot, slotValid: slotValid, startMillis: startMillis}
	}
	cases := []struct {
		name      string
		processes []*deploySlotProcess
		slot      int
		shared    bool
	}{
		{name: "the block's first process", processes: nil, slot: 0},
		{name: "beside slot 0", processes: []*deploySlotProcess{process(0, true, 1)}, slot: 1},
		{name: "beside slot 1", processes: []*deploySlotProcess{process(1, true, 1)}, slot: 0},
		// a label warp cannot read holds no slot
		{name: "beside a slot past the count", processes: []*deploySlotProcess{process(0, false, 1)}, slot: 0},
		// two processes in one slot, which only an earlier warp could leave, still leave the other free
		{name: "beside two in slot 0", processes: []*deploySlotProcess{process(0, true, 1), process(0, true, 2)}, slot: 1},
		// every slot held: never the newest's, the process this deploy replaces
		{name: "every slot held, the newest in 1", processes: []*deploySlotProcess{process(0, true, 1), process(1, true, 2)}, slot: 0, shared: true},
		{name: "every slot held, the newest in 0", processes: []*deploySlotProcess{process(0, true, 2), process(1, true, 1)}, slot: 1, shared: true},
		{name: "every slot held, the newest listed first", processes: []*deploySlotProcess{process(1, true, 3), process(0, true, 2), process(1, true, 1)}, slot: 0, shared: true},
	}
	for _, c := range cases {
		slot, shared := selectDeploySlot(c.processes, 2)
		if slot != c.slot || shared != c.shared {
			t.Errorf("%s: slot %d shared %t, want %d %t", c.name, slot, shared, c.slot, c.shared)
		}
	}
}

func TestParseDeploySlotProcessesReadsDockerPsLines(t *testing.T) {
	out := "aaaa\ttest-tlsedge-g1-1.0.0-1700000000002\t1\n" +
		// started before warp set a slot: slot 0
		"bbbb\ttest-tlsedge-g1-1.0.0-1700000000001\t\n" +
		// a slot past the count, or not a decimal in one spelling, holds none
		"cccc\ttest-tlsedge-g1-1.0.0-1700000000003\t2\n" +
		"dddd\ttest-tlsedge-g1-1.0.0-1700000000004\t01\n" +
		// a name that does not end in its start time reads as the oldest
		"eeee\tnot-warps-name\t0\n"
	processes, err := parseDeploySlotProcesses([]byte(out), 2)
	if err != nil {
		t.Fatal(err)
	}
	want := []deploySlotProcess{
		{containerId: "aaaa", startMillis: 1700000000002, slot: 1, slotValid: true},
		{containerId: "bbbb", startMillis: 1700000000001, slot: 0, slotValid: true},
		{containerId: "cccc", startMillis: 1700000000003},
		{containerId: "dddd", startMillis: 1700000000004},
		{containerId: "eeee", startMillis: 0, slot: 0, slotValid: true},
	}
	if len(processes) != len(want) {
		t.Fatalf("%d processes, want %d", len(processes), len(want))
	}
	for i, process := range processes {
		if *process != want[i] {
			t.Errorf("line %d: %+v, want %+v", i, *process, want[i])
		}
	}
	if processes, err := parseDeploySlotProcesses([]byte("\n"), 2); err != nil || len(processes) != 0 {
		t.Fatalf("no running container: %v %v", processes, err)
	}
	// the last line's empty label ends in its tab, which the answer's end does not take away
	last, err := parseDeploySlotProcesses([]byte("aaaa\ttest-tlsedge-g1-1.0.0-1\t1\nbbbb\ttest-tlsedge-g1-1.0.0-2\t\n"), 2)
	if err != nil || len(last) != 2 || !last[1].slotValid || last[1].slot != 0 {
		t.Fatalf("a last line with no label: %v", err)
	}
	// a line that is not a container's id, name and slot refuses the listing
	for _, bad := range []string{"aaaa\n", "aaaa test-tlsedge-g1-1.0.0-1 1\n", "aaaa\ttest-tlsedge-g1-1.0.0-1\t1\textra\n", "\ttest-tlsedge-g1-1.0.0-1\t1\n"} {
		if _, err := parseDeploySlotProcesses([]byte(bad), 2); err == nil {
			t.Errorf("%q was read", bad)
		}
	}
}

// One block's containers on a fake host: docker ps lists the running ones, docker run starts one with the slot its
// arguments name, and stop removes one, as a finished drain does.
type deploySlotTestHost struct {
	t            *testing.T
	worker       *RunWorker
	runningSlots []deploySlotTestContainer
	startCount   int
	// the slot each docker run named, in its label and its environment
	startedSlots []int
	// while set, docker ps fails
	psErr error
}

type deploySlotTestContainer struct {
	containerId string
	name        string
	// the warp.slot label as docker ps prints it: "" for a container from before warp set it
	slotLabel string
}

func newDeploySlotTestHost(t *testing.T) *deploySlotTestHost {
	namespace := "fixture"
	vaultHome := t.TempDir()
	self := &deploySlotTestHost{t: t}
	self.worker = &RunWorker{
		warpState:             &WarpState{warpSettings: &WarpSettings{DockerNamespace: &namespace, VaultHome: &vaultHome}},
		dynamoClient:          fixedDeploymentVersionClient{version: "1.0.0"},
		env:                   "test",
		service:               "tlsedge",
		block:                 "g1",
		hostNetworking:        true,
		servicesDockerNetwork: &DockerNetwork{networkName: "fixture", ipv4: &NetworkInterface{interfaceIp: "127.0.0.1"}},
		deployedVersion:       semver.New("1.0.0"),
		quitEvent:             warp.NewEvent(),
		vaultMountMode:        MOUNT_MODE_NO,
		configMountMode:       MOUNT_MODE_NO,
		siteMountMode:         MOUNT_MODE_NO,
		dataMountMode:         MOUNT_MODE_NO,
		dockerMountMode:       MOUNT_MODE_NO,
	}
	previousRun, previousOut := runAndLogFunc, outAndLogFunc
	runAndLogFunc = self.run
	outAndLogFunc = self.output
	t.Cleanup(func() {
		runAndLogFunc, outAndLogFunc = previousRun, previousOut
	})
	return self
}

// The value after flag in args, "" when there is none; with several, the one that starts with prefix.
func deploySlotTestArg(args []string, flag string, prefix string) string {
	for i := 0; i+1 < len(args); i += 1 {
		if args[i] == flag && strings.HasPrefix(args[i+1], prefix) {
			return args[i+1]
		}
	}
	return ""
}

func (self *deploySlotTestHost) output(cmd *exec.Cmd) ([]byte, error) {
	args := strings.Join(cmd.Args, " ")
	switch {
	case strings.Contains(args, "docker image inspect"):
		return []byte("sha256:" + strings.Repeat("2", 64)), nil
	case strings.Contains(args, "docker ps "):
		if self.psErr != nil {
			return nil, self.psErr
		}
		// only this block's containers, anchored, so g1 never reads g10's slots
		if deploySlotTestArg(cmd.Args, "-f", "name=") != "name=^/test-tlsedge-g1-" {
			self.t.Errorf("the slot listing is not the block's own: %v", cmd.Args)
		}
		if deploySlotTestArg(cmd.Args, "--format", "") != "{{.ID}}\t{{.Names}}\t{{.Label \"warp.slot\"}}" {
			self.t.Errorf("the slot listing's format: %v", cmd.Args)
		}
		lines := []string{}
		for _, container := range self.runningSlots {
			lines = append(lines, container.containerId+"\t"+container.name+"\t"+container.slotLabel)
		}
		return []byte(strings.Join(lines, "\n") + "\n"), nil
	case strings.Contains(args, "docker run "):
		label := strings.TrimPrefix(deploySlotTestArg(cmd.Args, "--label", deploySlotLabel+"="), deploySlotLabel+"=")
		env := strings.TrimPrefix(deploySlotTestArg(cmd.Args, "-e", "WARP_SLOT="), "WARP_SLOT=")
		slot, err := strconv.Atoi(label)
		if err != nil || label != env {
			self.t.Fatalf("docker run's slot label %q and WARP_SLOT %q", label, env)
		}
		if deploySlotTestArg(cmd.Args, "-e", "WARP_BLOCK=") != "WARP_BLOCK=g1" {
			self.t.Fatalf("docker run's WARP_BLOCK: %v", cmd.Args)
		}
		self.startCount += 1
		containerId := fmt.Sprintf("c%d", self.startCount)
		self.runningSlots = append(self.runningSlots, deploySlotTestContainer{
			containerId: containerId,
			name:        deploySlotTestArg(cmd.Args, "--name", ""),
			slotLabel:   label,
		})
		self.startedSlots = append(self.startedSlots, slot)
		return []byte(containerId + "\n"), nil
	}
	return nil, fmt.Errorf("unexpected fixture output command: %v", cmd.Args)
}

func (self *deploySlotTestHost) run(cmd *exec.Cmd) error {
	if strings.Contains(strings.Join(cmd.Args, " "), "docker pull ") {
		return nil
	}
	return fmt.Errorf("unexpected fixture command: %v", cmd.Args)
}

// One deploy's candidate start, and the slot it took.
func (self *deploySlotTestHost) deploy() int {
	self.t.Helper()
	containerId, err := self.worker.startContainer(map[int]int{80: 41080})
	if err != nil {
		self.t.Fatal(err)
	}
	if containerId != fmt.Sprintf("c%d", self.startCount) {
		self.t.Fatalf("started %q", containerId)
	}
	return self.startedSlots[len(self.startedSlots)-1]
}

// The old container's drain ends.
func (self *deploySlotTestHost) stop(containerId string) {
	self.t.Helper()
	for i, container := range self.runningSlots {
		if container.containerId == containerId {
			self.runningSlots = append(self.runningSlots[:i], self.runningSlots[i+1:]...)
			return
		}
	}
	self.t.Fatalf("no running %s", containerId)
}

func TestRunWorkerAlternatesTheDeploySlotAcrossDeploys(t *testing.T) {
	host := newDeploySlotTestHost(t)
	// the block's first process
	if slot := host.deploy(); slot != 0 {
		t.Fatalf("first deploy took slot %d", slot)
	}
	// the next deploy starts its candidate beside the old process, which drains only after the cutover
	if slot := host.deploy(); slot != 1 {
		t.Fatalf("second deploy took slot %d beside slot 0", slot)
	}
	host.stop("c1")
	if slot := host.deploy(); slot != 0 {
		t.Fatalf("third deploy took slot %d beside slot 1", slot)
	}
	host.stop("c2")
	if slot := host.deploy(); slot != 1 {
		t.Fatalf("fourth deploy took slot %d beside slot 0", slot)
	}
	if fmt.Sprint(host.startedSlots) != "[0 1 0 1]" {
		t.Fatalf("slots %v", host.startedSlots)
	}
}

func TestRunWorkerDeploySlotPassesOverAProcessFromBeforeTheSlot(t *testing.T) {
	host := newDeploySlotTestHost(t)
	// a container an older warp started holds slot 0, as an edge block reads its missing WARP_SLOT
	host.runningSlots = []deploySlotTestContainer{{containerId: "old", name: "test-tlsedge-g1-0.9.0-1700000000000", slotLabel: ""}}
	if slot := host.deploy(); slot != 1 {
		t.Fatalf("took slot %d beside a process from before the slot", slot)
	}
}

func TestRunWorkerDeploySlotNeverTakesTheReplacedProcesssSlot(t *testing.T) {
	host := newDeploySlotTestHost(t)
	output := captureErrOutput(t)
	// a restart amid a drain: an older process still draining in slot 1 and the live one, newest, in slot 0
	host.runningSlots = []deploySlotTestContainer{
		{containerId: "live", name: "test-tlsedge-g1-1.0.0-1700000000002", slotLabel: "0"},
		{containerId: "draining", name: "test-tlsedge-g1-1.0.0-1700000000001", slotLabel: "1"},
	}
	if slot := host.deploy(); slot != 1 {
		t.Fatalf("took slot %d, the replaced process's", slot)
	}
	if !strings.Contains(output.String(), "Deploy slot 1 is held by an older draining process") {
		t.Fatalf("the shared slot was not logged: %s", output.String())
	}
}

func TestRunWorkerDeploySlotListingFailureStopsTheDeploy(t *testing.T) {
	host := newDeploySlotTestHost(t)
	want := errors.New("fixture docker ps unavailable")
	host.psErr = want
	if _, err := host.worker.startContainer(map[int]int{80: 41080}); !errors.Is(err, want) {
		t.Fatalf("a failed slot listing: %v", err)
	}
	if host.startCount != 0 {
		t.Fatal("a candidate started with no slot")
	}
	// and a slot count that cannot alternate refuses too
	host.psErr = nil
	host.worker.deploySlotSettings = &DeploySlotSettings{SlotCount: 1}
	if _, err := host.worker.startContainer(map[int]int{80: 41080}); err == nil || host.startCount != 0 {
		t.Fatalf("a slot count of 1 started a candidate: %v", err)
	}
}
