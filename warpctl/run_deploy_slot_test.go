package main

// The deploy slot (sidecar QD-873, QD-1011): each new process of an edge service takes the lowest slot none of the
// service's running processes on the host holds, its beta and g1 processes and a deploy's old and new process of
// each among them, listed by the warp.env and warp.service labels so mxedge-platform's containers are never
// counted; a fifth process while four hold every slot is refused before it starts, and the next try takes the
// slot a drain frees; the slot is taken under the service's slot lock, held from the listing through docker run;
// and a service that holds no edge clients takes slot 0 with nothing listed or locked. startContainer runs on fake
// docker commands: no Docker, sudo or selector is reached, and nothing sleeps.

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"github.com/coreos/go-semver/semver"
	"gopkg.in/yaml.v3"

	"github.com/urnetwork/warp"
)

// The services the slot reads as edge services, those whose sidecar block fragment mounts the edge bearer, are
// §13.6's edge blocks that have a fragment: tlsedge, mxedge's router and smtpedge (OPS-M9-01), and never
// mxedge-platform, whose containers share mxedge's name prefix.
func TestDeploySlotEdgeServicesAreTheEdgeBlocks(t *testing.T) {
	paths, err := filepath.Glob(filepath.Join("..", "services", "sidecar-blocks", "*.yml"))
	if err != nil || len(paths) == 0 {
		t.Fatalf("no sidecar block fragments: %v", err)
	}
	edgeServices := []string{}
	services := []string{}
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		fragment := struct {
			Version struct {
				Services map[string]struct {
					SecretFiles []string `yaml:"secret_files"`
				} `yaml:"services"`
			} `yaml:"version"`
		}{}
		if err := yaml.Unmarshal(data, &fragment); err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		for service, serviceConfig := range fragment.Version.Services {
			services = append(services, service)
			if slices.Contains(serviceConfig.SecretFiles, deploySlotEdgeBearerSecretFile) {
				edgeServices = append(edgeServices, service)
			}
		}
	}
	slices.Sort(edgeServices)
	want := []string{"mxedge", "tlsedge"}
	if slices.Contains(services, "smtpedge") {
		want = []string{"mxedge", "smtpedge", "tlsedge"}
	}
	if !slices.Equal(edgeServices, want) {
		t.Fatalf("the services mounting %s are %v, want %v", deploySlotEdgeBearerSecretFile, edgeServices, want)
	}
	if !slices.Contains(services, "mxedge-platform") {
		t.Fatal("no mxedge-platform fragment to hold apart")
	}
}

func TestDeploySlotCountIsFour(t *testing.T) {
	// the beta and g1 processes of an edge service and a deploy's new process beside either (QD-1011); server's
	// EdgeClientKeySettings.SlotCount is the same number, and api refuses a slot at or past it
	if slotCount := DefaultDeploySlotSettings().SlotCount; slotCount != 4 {
		t.Fatalf("slot count %d, want 4", slotCount)
	}
}

func TestSelectDeploySlotTakesTheLowestSlotNoProcessHolds(t *testing.T) {
	process := func(slot int, slotValid bool) *deploySlotProcess {
		return &deploySlotProcess{containerId: fmt.Sprintf("c%d", slot), name: fmt.Sprintf("n%d", slot), slot: slot, slotValid: slotValid}
	}
	cases := []struct {
		name      string
		processes []*deploySlotProcess
		slot      int
		free      bool
	}{
		{name: "the service's first process", processes: nil, slot: 0, free: true},
		{name: "beside slot 0", processes: []*deploySlotProcess{process(0, true)}, slot: 1, free: true},
		{name: "beside slot 1", processes: []*deploySlotProcess{process(1, true)}, slot: 0, free: true},
		// beta and g1 running: a deploy of either takes a slot neither holds
		{name: "beside beta and g1", processes: []*deploySlotProcess{process(0, true), process(1, true)}, slot: 2, free: true},
		{name: "beside three", processes: []*deploySlotProcess{process(1, true), process(2, true), process(0, true)}, slot: 3, free: true},
		{name: "beside a gap", processes: []*deploySlotProcess{process(0, true), process(2, true), process(3, true)}, slot: 1, free: true},
		// a label warp cannot read holds no slot
		{name: "beside a slot past the count", processes: []*deploySlotProcess{process(0, false)}, slot: 0, free: true},
		// two processes in one slot, which only an earlier warp could leave, still leave the others free
		{name: "beside two in slot 0", processes: []*deploySlotProcess{process(0, true), process(0, true)}, slot: 1, free: true},
		// four running: none is free
		{name: "every slot held", processes: []*deploySlotProcess{process(3, true), process(0, true), process(2, true), process(1, true)}, free: false},
	}
	for _, c := range cases {
		slot, free := selectDeploySlot(c.processes, 4)
		if free != c.free || (free && slot != c.slot) {
			t.Errorf("%s: slot %d free %t, want %d %t", c.name, slot, free, c.slot, c.free)
		}
	}
}

func TestParseDeploySlotProcessesReadsDockerPsLines(t *testing.T) {
	out := "aaaa\ttest-tlsedge-g1-1.0.0-1700000000002\t3\n" +
		// started before warp set a slot: slot 0
		"bbbb\ttest-tlsedge-beta-1.0.0-1700000000001\t\n" +
		// a slot past the count, or not a decimal in one spelling, holds none
		"cccc\ttest-tlsedge-g1-1.0.0-1700000000003\t4\n" +
		"dddd\ttest-tlsedge-g1-1.0.0-1700000000004\t01\n" +
		"eeee\ttest-tlsedge-g1-1.0.0-1700000000005\t-1\n"
	processes, err := parseDeploySlotProcesses([]byte(out), 4)
	if err != nil {
		t.Fatal(err)
	}
	want := []deploySlotProcess{
		{containerId: "aaaa", name: "test-tlsedge-g1-1.0.0-1700000000002", slot: 3, slotValid: true},
		{containerId: "bbbb", name: "test-tlsedge-beta-1.0.0-1700000000001", slot: 0, slotValid: true},
		{containerId: "cccc", name: "test-tlsedge-g1-1.0.0-1700000000003"},
		{containerId: "dddd", name: "test-tlsedge-g1-1.0.0-1700000000004"},
		{containerId: "eeee", name: "test-tlsedge-g1-1.0.0-1700000000005"},
	}
	if len(processes) != len(want) {
		t.Fatalf("%d processes, want %d", len(processes), len(want))
	}
	for i, process := range processes {
		if *process != want[i] {
			t.Errorf("line %d: %+v, want %+v", i, *process, want[i])
		}
	}
	if processes, err := parseDeploySlotProcesses([]byte("\n"), 4); err != nil || len(processes) != 0 {
		t.Fatalf("no running container: %v %v", processes, err)
	}
	// the last line's empty label ends in its tab, which the answer's end does not take away
	last, err := parseDeploySlotProcesses([]byte("aaaa\ttest-tlsedge-g1-1.0.0-1\t1\nbbbb\ttest-tlsedge-g1-1.0.0-2\t\n"), 4)
	if err != nil || len(last) != 2 || !last[1].slotValid || last[1].slot != 0 {
		t.Fatalf("a last line with no label: %v", err)
	}
	// a line that is not a container's id, name and slot refuses the listing
	for _, bad := range []string{"aaaa\n", "aaaa test-tlsedge-g1-1.0.0-1 1\n", "aaaa\ttest-tlsedge-g1-1.0.0-1\t1\textra\n", "\ttest-tlsedge-g1-1.0.0-1\t1\n", "aaaa\t\t1\n"} {
		if _, err := parseDeploySlotProcesses([]byte(bad), 4); err == nil {
			t.Errorf("%q was read", bad)
		}
	}
}

// One host's running containers, of every service and environment, on fake docker commands: docker ps answers the
// slot listing by its label filters, each matched exactly and all together, as Docker matches label filters;
// docker run starts a container with the labels its arguments name; and stop ends one, as a finished drain does.
type deploySlotTestHost struct {
	t         *testing.T
	vaultHome string
	warpHome  string

	containers []*deploySlotTestContainer
	startCount int
	// the slot listings docker ps answered
	listingCount int
	// while set, docker ps fails
	psErr error
	// while set, called as docker ps lists and as docker run starts, before either answers
	onList func()
	onRun  func()
}

type deploySlotTestContainer struct {
	containerId string
	name        string
	labels      map[string]string
}

func newDeploySlotTestHost(t *testing.T) *deploySlotTestHost {
	self := &deploySlotTestHost{
		t:         t,
		vaultHome: t.TempDir(),
		warpHome:  t.TempDir(),
	}
	// the edge bearer the edge workers mount: a file, never a bearer
	if err := os.WriteFile(filepath.Join(self.vaultHome, deploySlotEdgeBearerSecretFile), []byte("fixture: not a bearer\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// every run worker on the host shares WARP_HOME, where the slot lock lives
	t.Setenv("WARP_HOME", self.warpHome)
	previousRun, previousOut := runAndLogFunc, outAndLogFunc
	runAndLogFunc = self.run
	outAndLogFunc = self.output
	t.Cleanup(func() {
		runAndLogFunc, outAndLogFunc = previousRun, previousOut
	})
	return self
}

// A run worker of service's block on the host, in the environment "test". edge says whether the service mounts the
// edge bearer.
func (self *deploySlotTestHost) worker(service string, block string, edge bool) *RunWorker {
	namespace := "fixture"
	secretFiles := []string{}
	if edge {
		secretFiles = append(secretFiles, deploySlotEdgeBearerSecretFile)
	}
	return &RunWorker{
		warpState:             &WarpState{warpSettings: &WarpSettings{DockerNamespace: &namespace, VaultHome: &self.vaultHome}},
		dynamoClient:          fixedDeploymentVersionClient{version: "1.0.0"},
		env:                   "test",
		service:               service,
		block:                 block,
		hostNetworking:        true,
		servicesDockerNetwork: &DockerNetwork{networkName: "fixture", ipv4: &NetworkInterface{interfaceIp: "127.0.0.1"}},
		deployedVersion:       semver.New("1.0.0"),
		quitEvent:             warp.NewEvent(),
		vaultMountMode:        MOUNT_MODE_NO,
		configMountMode:       MOUNT_MODE_NO,
		siteMountMode:         MOUNT_MODE_NO,
		dataMountMode:         MOUNT_MODE_NO,
		dockerMountMode:       MOUNT_MODE_NO,
		secretFiles:           secretFiles,
	}
}

// A container already running on the host, as another warp started it: slotLabel "" carries no warp.slot label.
func (self *deploySlotTestHost) add(containerId string, env string, service string, block string, slotLabel string) {
	labels := map[string]string{
		warpEnvLabel:     env,
		warpServiceLabel: service,
		"warp.block":     block,
	}
	if slotLabel != "" {
		labels[deploySlotLabel] = slotLabel
	}
	self.containers = append(self.containers, &deploySlotTestContainer{
		containerId: containerId,
		name:        fmt.Sprintf("%s-%s-%s-0.9.0-%d", env, service, block, 1700000000000+len(self.containers)),
		labels:      labels,
	})
}

// The values of each flag in args.
func deploySlotTestArgs(args []string, flag string) []string {
	values := []string{}
	for i := 0; i+1 < len(args); i += 1 {
		if args[i] == flag {
			values = append(values, args[i+1])
		}
	}
	return values
}

func (self *deploySlotTestHost) output(cmd *exec.Cmd) ([]byte, error) {
	args := strings.Join(cmd.Args, " ")
	switch {
	case strings.Contains(args, "docker image inspect"):
		return []byte("sha256:" + strings.Repeat("2", 64)), nil
	case strings.Contains(args, "docker ps "):
		if self.onList != nil {
			self.onList()
		}
		if self.psErr != nil {
			return nil, self.psErr
		}
		self.listingCount += 1
		if format := deploySlotTestArgs(cmd.Args, "--format"); len(format) != 1 || format[0] != "{{.ID}}\t{{.Names}}\t{{.Label \"warp.slot\"}}" {
			self.t.Errorf("the slot listing's format: %v", cmd.Args)
		}
		// by labels alone, never by a name, whose prefix one service can share with another
		labelFilters := map[string]string{}
		for _, filter := range deploySlotTestArgs(cmd.Args, "-f") {
			key, value, ok := strings.Cut(strings.TrimPrefix(filter, "label="), "=")
			if !strings.HasPrefix(filter, "label=") || !ok {
				self.t.Errorf("the slot listing filters by %q, not by a label's value", filter)
				continue
			}
			labelFilters[key] = value
		}
		if len(labelFilters) != 2 || labelFilters[warpEnvLabel] == "" || labelFilters[warpServiceLabel] == "" {
			self.t.Errorf("the slot listing is not one service's in one environment: %v", cmd.Args)
		}
		lines := []string{}
		for _, container := range self.containers {
			matches := true
			for key, value := range labelFilters {
				if labelValue, ok := container.labels[key]; !ok || labelValue != value {
					matches = false
				}
			}
			if matches {
				lines = append(lines, container.containerId+"\t"+container.name+"\t"+container.labels[deploySlotLabel])
			}
		}
		return []byte(strings.Join(lines, "\n") + "\n"), nil
	case strings.Contains(args, "docker run "):
		if self.onRun != nil {
			self.onRun()
		}
		labels := map[string]string{}
		for _, label := range deploySlotTestArgs(cmd.Args, "--label") {
			key, value, _ := strings.Cut(label, "=")
			labels[key] = value
		}
		envs := map[string]string{}
		for _, env := range deploySlotTestArgs(cmd.Args, "-e") {
			key, value, _ := strings.Cut(env, "=")
			envs[key] = value
		}
		if _, err := strconv.Atoi(labels[deploySlotLabel]); err != nil || labels[deploySlotLabel] != envs["WARP_SLOT"] {
			self.t.Fatalf("docker run's slot label %q and WARP_SLOT %q", labels[deploySlotLabel], envs["WARP_SLOT"])
		}
		if labels["warp.block"] != envs["WARP_BLOCK"] || labels[warpServiceLabel] != envs["WARP_SERVICE"] || labels[warpEnvLabel] != envs["WARP_ENV"] {
			self.t.Fatalf("docker run's labels %v and environment %v", labels, envs)
		}
		self.startCount += 1
		containerId := fmt.Sprintf("c%d", self.startCount)
		names := deploySlotTestArgs(cmd.Args, "--name")
		if len(names) != 1 {
			self.t.Fatalf("docker run's names: %v", names)
		}
		self.containers = append(self.containers, &deploySlotTestContainer{containerId: containerId, name: names[0], labels: labels})
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

// One deploy's candidate start on worker, the container it started and the slot it took.
func (self *deploySlotTestHost) deploy(worker *RunWorker) (string, int) {
	self.t.Helper()
	containerId, err := worker.startContainer(map[int]int{80: 41080})
	if err != nil {
		self.t.Fatalf("%s %s: %v", worker.service, worker.block, err)
	}
	for _, container := range self.containers {
		if container.containerId == containerId {
			slot, err := strconv.Atoi(container.labels[deploySlotLabel])
			if err != nil {
				self.t.Fatal(err)
			}
			return containerId, slot
		}
	}
	self.t.Fatalf("started %q, which is not running", containerId)
	return "", 0
}

// The container's drain ends.
func (self *deploySlotTestHost) stop(containerId string) {
	self.t.Helper()
	for i, container := range self.containers {
		if container.containerId == containerId {
			self.containers = append(self.containers[:i], self.containers[i+1:]...)
			return
		}
	}
	self.t.Fatalf("no running %s", containerId)
}

// tlsedge's beta and g1 blocks run side by side on every lb host and pass the same environment, host and block to
// their client source, so they take different slots, whichever starts first.
func TestRunWorkerGivesAnEdgeServicesBetaAndG1DifferentSlots(t *testing.T) {
	host := newDeploySlotTestHost(t)
	beta, g1 := host.worker("tlsedge", "beta", true), host.worker("tlsedge", "g1", true)
	if _, slot := host.deploy(g1); slot != 0 {
		t.Fatalf("g1 took slot %d on an empty host", slot)
	}
	if _, slot := host.deploy(beta); slot != 1 {
		t.Fatalf("beta took slot %d beside g1's 0", slot)
	}
	if host.listingCount != 2 {
		t.Fatalf("%d listings, want one a start", host.listingCount)
	}
}

// A deploy of either block, beside both blocks' running processes, takes a slot neither holds; with four
// processes running a fifth start is refused before anything starts, and once a drain ends the next try takes the
// slot it freed.
func TestRunWorkerDeploySlotBesideBothBlocksAndTheFifthRefused(t *testing.T) {
	host := newDeploySlotTestHost(t)
	beta, g1 := host.worker("tlsedge", "beta", true), host.worker("tlsedge", "g1", true)
	betaOld, betaOldSlot := host.deploy(beta)
	_, g1OldSlot := host.deploy(g1)
	if betaOldSlot != 0 || g1OldSlot != 1 {
		t.Fatalf("beta %d g1 %d", betaOldSlot, g1OldSlot)
	}
	// beta's deploy starts its candidate beside both, the old one draining only after the cutover
	if _, slot := host.deploy(beta); slot != 2 {
		t.Fatalf("beta's deploy took slot %d beside slots 0 and 1", slot)
	}
	// g1's deploy while beta's old process still drains
	if _, slot := host.deploy(g1); slot != 3 {
		t.Fatalf("g1's deploy took slot %d beside slots 0, 1 and 2", slot)
	}
	// a fifth process, as a restart amid the drains starts: refused, as a full port pool is, with nothing started
	startCount := host.startCount
	_, err := beta.startContainer(map[int]int{80: 41080})
	if !errors.Is(err, errDeploySlotsHeld) {
		t.Fatalf("a fifth process: %v", err)
	}
	if host.startCount != startCount {
		t.Fatal("a fifth process started")
	}
	// the refusal names who holds the slots, never more
	if !strings.Contains(err.Error(), "test-tlsedge-beta-") || !strings.Contains(err.Error(), "in slot 3") {
		t.Fatalf("the refusal: %v", err)
	}
	// beta's old process ends its drain: the next try takes the slot it held
	host.stop(betaOld)
	if _, slot := host.deploy(beta); slot != betaOldSlot {
		t.Fatalf("the next try took slot %d, not the freed %d", slot, betaOldSlot)
	}
}

// mxedge's listing counts mxedge's own processes alone: never mxedge-platform's, whose names share mxedge's prefix
// and which mount no edge bearer, another environment's, or another service's.
func TestRunWorkerDeploySlotCountsOnlyItsOwnService(t *testing.T) {
	host := newDeploySlotTestHost(t)
	host.add("platform-beta", "test", "mxedge-platform", "beta", "0")
	host.add("platform-g1", "test", "mxedge-platform", "g1", "")
	host.add("other-env", "other", "mxedge", "g1", "0")
	host.add("tlsedge-g1", "test", "tlsedge", "g1", "0")
	if !strings.HasPrefix(host.containers[0].name, "test-mxedge-") {
		t.Fatalf("the platform container's name %q does not share mxedge's prefix", host.containers[0].name)
	}
	beta, g1 := host.worker("mxedge", "beta", true), host.worker("mxedge", "g1", true)
	if _, slot := host.deploy(g1); slot != 0 {
		t.Fatalf("mxedge's first process took slot %d", slot)
	}
	if _, slot := host.deploy(beta); slot != 1 {
		t.Fatalf("mxedge's second process took slot %d", slot)
	}
}

// A container an older warp started, with no warp.slot label, holds slot 0, as an edge block reads its missing
// WARP_SLOT.
func TestRunWorkerDeploySlotPassesOverAProcessFromBeforeTheSlot(t *testing.T) {
	host := newDeploySlotTestHost(t)
	host.add("old", "test", "tlsedge", "g1", "")
	if _, slot := host.deploy(host.worker("tlsedge", "beta", true)); slot != 1 {
		t.Fatalf("took slot %d beside a process from before the slot", slot)
	}
}

// A service that mounts no edge bearer ignores its slot: however many of its processes run, its new one takes slot
// 0, with nothing listed, locked or refused.
func TestRunWorkerDeploySlotOfAServiceWithoutEdgeClients(t *testing.T) {
	host := newDeploySlotTestHost(t)
	for i, block := range []string{"beta", "g1", "g2", "g3", "g4"} {
		host.add(fmt.Sprintf("web-%d", i), "test", "web", block, strconv.Itoa(i%4))
	}
	worker := host.worker("web", "g2", false)
	if _, slot := host.deploy(worker); slot != 0 {
		t.Fatalf("took slot %d", slot)
	}
	if host.listingCount != 0 {
		t.Fatalf("listed %d times", host.listingCount)
	}
	if _, err := os.Stat(worker.deploySlotLockPath()); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the slot lock was taken: %v", err)
	}
}

func TestRunWorkerDeploySlotListingFailureStopsTheDeploy(t *testing.T) {
	host := newDeploySlotTestHost(t)
	worker := host.worker("tlsedge", "g1", true)
	want := errors.New("fixture docker ps unavailable")
	host.psErr = want
	if _, err := worker.startContainer(map[int]int{80: 41080}); !errors.Is(err, want) {
		t.Fatalf("a failed slot listing: %v", err)
	}
	if host.startCount != 0 {
		t.Fatal("a candidate started with no slot")
	}
	host.psErr = nil
	// a slot count that cannot hold a deploy's new process beside its old one refuses too, as does a lock wait
	// that would spin
	for _, settings := range []*DeploySlotSettings{
		{SlotCount: 1, LockTimeout: 0, LockRetryInterval: 1},
		{SlotCount: 4, LockTimeout: 0, LockRetryInterval: 0},
	} {
		worker.deploySlotSettings = settings
		if _, err := worker.startContainer(map[int]int{80: 41080}); err == nil || host.startCount != 0 {
			t.Fatalf("%+v started a candidate: %v", *settings, err)
		}
	}
	// and the lock is released after each refusal: the defaults start
	worker.deploySlotSettings = nil
	if _, slot := host.deploy(worker); slot != 0 {
		t.Fatalf("took slot %d", slot)
	}
}

// The slot lock, a file under WARP_HOME every run worker of the service on the host shares, is held from before
// the listing until docker run answers, so another block's worker lists only once the process is listed with its
// slot; a lock another worker holds refuses the start once LockTimeout passes, or at once on quit, with nothing
// listed or started.
func TestRunWorkerDeploySlotLockHoldsFromTheListingThroughDockerRun(t *testing.T) {
	host := newDeploySlotTestHost(t)
	worker := host.worker("tlsedge", "beta", true)
	lockPath := worker.deploySlotLockPath()
	if lockPath != filepath.Join(host.warpHome, "warpctl-deploy-slot-test-tlsedge.lock") {
		t.Fatalf("the slot lock's path %q", lockPath)
	}
	// whether another worker could take the lock now; taken, it is let go at once
	lockFree := func() bool {
		file, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o644)
		if err != nil {
			t.Fatal(err)
		}
		defer file.Close()
		err = syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err != nil && err != syscall.EWOULDBLOCK {
			t.Fatal(err)
		}
		return err == nil
	}

	// another block's worker holds it
	other, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	if err := syscall.Flock(int(other.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	worker.deploySlotSettings = &DeploySlotSettings{SlotCount: 4, LockTimeout: 0, LockRetryInterval: 1}
	if _, err := worker.startContainer(map[int]int{80: 41080}); err == nil || !strings.Contains(err.Error(), "deploy slot lock was not taken") {
		t.Fatalf("a held lock: %v", err)
	}
	// a quit ends the wait at once, however long the timeout (startContainer itself refuses on quit before it
	// reaches the slot, so the wait is asked directly)
	worker.deploySlotSettings = DefaultDeploySlotSettings()
	worker.quitEvent.Set()
	if _, _, err := worker.takeDeploySlot(); err == nil || !strings.Contains(err.Error(), "quit while waiting for the deploy slot lock") {
		t.Fatalf("a held lock on quit: %v", err)
	}
	if host.listingCount != 0 || host.startCount != 0 {
		t.Fatalf("listed %d and started %d without the lock", host.listingCount, host.startCount)
	}
	other.Close()

	// taken: held as the worker lists and as docker run starts, and let go once it answers
	worker.quitEvent = warp.NewEvent()
	listedHeld, ranHeld := false, false
	host.onList = func() {
		listedHeld = !lockFree()
	}
	host.onRun = func() {
		ranHeld = !lockFree()
	}
	host.deploy(worker)
	if !listedHeld || !ranHeld {
		t.Fatalf("the lock was held while listing %t and while running %t", listedHeld, ranHeld)
	}
	if !lockFree() {
		t.Fatal("the lock was kept after the start")
	}
}
