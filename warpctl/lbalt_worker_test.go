package main

// Tests of the lb_alt run worker paths (lbalt_worker.go; server/LBALT-IMPL.md
// §2.2, §2.4-§2.6): the route file of a connect generation, the deploy's
// readiness, chains and cutover order, the routing-only lb unit, the rollback
// removal of a split, route file removal, and the lb version polls.

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coreos/go-semver/semver"

	"github.com/urnetwork/warp"
	"github.com/urnetwork/warp/services"
)

// the container id `docker run` prints in the fixtures
const lbAltFixtureContainerId = "c0ffee000001"

// the revision the fixtures' route file writer reports
const lbAltFixtureRevision = "5d41402abc4b2a76b9719d911017c592ae8f7d3b5d41402abc4b2a76b9719d91"

// What the worker passed pollLbAltReadiness.
type lbAltReadinessCall struct {
	statusUrl  string
	generation string
	revision   string
	expected   []lbAltExpectedSocket
	timeout    time.Duration
}

// What the worker passed writeLbAltBlockChains.
type lbAltChainsCall struct {
	env             string
	block           string
	splitInterfaces []lbAltSplitInterface
	targets         []lbAltBlockTarget
}

// A connect block worker on edge-a of lbAltUnitsServicesYaml, where eth1 is
// lb_alt by its override under connect's declared-off default and eth2 is not,
// deploying through the real startContainer and deployContainerOverlap. Every
// docker, firewall and socket command ends in the command hooks or the PATH
// fixture. The w-route and w-split functions are fakes that record, in
// events, the order the deploy reaches them in, beside the container start,
// the first pool DNAT insert (the cutover) and container stops.
type lbAltWorkerFixture struct {
	t          *testing.T
	home       string
	worker     *RunWorker
	statusPort int
	// guards events and chainsCalls, which a pending promotion's completion
	// appends to from its own goroutine
	stateLock sync.Mutex
	events    []string
	// every firewall change the worker made
	firewallChanges []string
	routeInputs     []*lbAltRouteInputs
	writtenRoutes   []string
	readinessCalls  []lbAltReadinessCall
	chainsCalls     []lbAltChainsCall
	dockerRunArgs   [][]string
	renderErr       error
	readinessErr    error
	chainsErr       error
}

// Appends an event, from whichever goroutine the worker called a fake on.
func (self *lbAltWorkerFixture) record(event string) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.events = append(self.events, event)
}

func newLbAltWorkerFixture(t *testing.T) *lbAltWorkerFixture {
	t.Helper()
	setupTestVault(t, lbAltUnitsYaml(lbAltUnitsSettings{edgeAEth1: "true", connect: "false"}))
	f := &lbAltWorkerFixture{
		t:    t,
		home: os.Getenv("WARP_HOME"),
	}

	bin := filepath.Join(f.home, "bin")
	if err := os.Mkdir(bin, 0o700); err != nil {
		t.Fatal(err)
	}
	writeSudoFixture(t, bin, `#!/bin/sh
case "$*" in
  "docker ps "*) printf '`+lbAltFixtureContainerId+`\n' ;;
  "iptables "*" -L "*) exit 0 ;;
  *) printf 'unexpected fixture command\n' >&2; exit 97 ;;
esac
`)
	t.Setenv("PATH", bin)

	oldRun, oldOut, oldQuiet, oldSudo2 := runAndLogFunc, outAndLogFunc, runQuietFunc, sudo2Func
	t.Cleanup(func() {
		runAndLogFunc, outAndLogFunc, runQuietFunc, sudo2Func = oldRun, oldOut, oldQuiet, oldSudo2
	})
	sudo2Func = nil
	runAndLogFunc = func(cmd *exec.Cmd) error {
		args := strings.Join(cmd.Args, " ")
		switch {
		case strings.Contains(args, "docker pull "), strings.Contains(args, "docker update "), strings.Contains(args, "docker container prune "):
			return nil
		case strings.Contains(args, "docker container stop "):
			f.record("stop")
			return nil
		case strings.Contains(args, "iptables ") && (strings.Contains(args, " -C ") || strings.Contains(args, " -D ")):
			return errors.New("fixture rule absent")
		case strings.Contains(args, "iptables ") && strings.Contains(args, " -I ") && strings.Contains(args, " DNAT "):
			f.stateLock.Lock()
			defer f.stateLock.Unlock()
			f.firewallChanges = append(f.firewallChanges, args)
			if !slices.Contains(f.events, "cutover") {
				f.events = append(f.events, "cutover")
			}
			return nil
		case strings.Contains(args, "iptables "):
			f.stateLock.Lock()
			defer f.stateLock.Unlock()
			f.firewallChanges = append(f.firewallChanges, args)
			return nil
		}
		t.Errorf("unexpected fixture command: %v", cmd.Args)
		return fmt.Errorf("unexpected fixture command: %v", cmd.Args)
	}
	outAndLogFunc = func(cmd *exec.Cmd) ([]byte, error) {
		args := strings.Join(cmd.Args, " ")
		switch {
		case strings.Contains(args, "docker image inspect"):
			return []byte("sha256:" + strings.Repeat("1", 64)), nil
		case strings.Contains(args, "docker run "):
			f.dockerRunArgs = append(f.dockerRunArgs, slices.Clone(cmd.Args))
			f.record("start")
			return []byte(lbAltFixtureContainerId), nil
		}
		t.Errorf("unexpected fixture output command: %v", cmd.Args)
		return nil, fmt.Errorf("unexpected fixture output command: %v", cmd.Args)
	}
	runQuietFunc = func(cmd *exec.Cmd) (commandOutput, error) {
		args := strings.Join(cmd.Args, " ")
		if strings.HasPrefix(args, "ss ") || strings.HasPrefix(args, "netstat ") || strings.Contains(args, "conntrack ") {
			return commandOutput{}, nil
		}
		t.Errorf("unexpected fixture quiet command: %v", cmd.Args)
		return commandOutput{}, fmt.Errorf("unexpected fixture quiet command: %v", cmd.Args)
	}

	status := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"version":"1.0.0","status":"ok"}`)
	}))
	t.Cleanup(status.Close)
	statusPort, err := strconv.Atoi(strings.TrimPrefix(status.URL, "http://127.0.0.1:"))
	if err != nil {
		t.Fatal(err)
	}
	f.statusPort = statusPort

	ops := defaultLbAltWorkerOps()
	ops.renderRouteTable = func(inputs *lbAltRouteInputs) (*LbAltRouteTable, error) {
		f.record("render")
		f.routeInputs = append(f.routeInputs, inputs)
		if f.renderErr != nil {
			return nil, f.renderErr
		}
		return &LbAltRouteTable{
			SchemaVersion: LbAltRouteSchemaVersion,
			Generation:    inputs.generation,
		}, nil
	}
	ops.writeRouteFile = func(warpHome string, containerName string, table *LbAltRouteTable) (string, string, error) {
		if table.Generation != containerName {
			t.Errorf("route file of %s holds the table of %s", containerName, table.Generation)
		}
		f.writtenRoutes = append(f.writtenRoutes, containerName)
		return filepath.Join(warpHome, lbAltRouteHostDirName, containerName, lbAltRouteFileName), lbAltFixtureRevision, nil
	}
	ops.pollReadiness = func(ctx context.Context, statusUrl string, generation string, revision string, expected []lbAltExpectedSocket, timeout time.Duration) error {
		f.record("readiness")
		f.readinessCalls = append(f.readinessCalls, lbAltReadinessCall{
			statusUrl:  statusUrl,
			generation: generation,
			revision:   revision,
			expected:   slices.Clone(expected),
			timeout:    timeout,
		})
		return f.readinessErr
	}
	ops.writeBlockChains = func(ctx context.Context, env string, block string, splitInterfaces []lbAltSplitInterface, targets []lbAltBlockTarget) error {
		f.stateLock.Lock()
		defer f.stateLock.Unlock()
		f.events = append(f.events, "chains")
		f.chainsCalls = append(f.chainsCalls, lbAltChainsCall{
			env:             env,
			block:           block,
			splitInterfaces: slices.Clone(splitInterfaces),
			targets:         slices.Clone(targets),
		})
		return f.chainsErr
	}
	ops.reconcileSplit = func(ctx context.Context, config *lbAltSplitConfig) error {
		t.Error("a connect block reconciled a split")
		return nil
	}
	ops.removeSplit = func(ctx context.Context, env string, interfaceName string) error {
		t.Error("a connect block removed a split")
		return nil
	}
	ops.listContainers = func(ctx context.Context, containerNamePrefix string, format string) ([]string, error) {
		f.record("list " + containerNamePrefix)
		return nil, nil
	}

	namespace := "fixture"
	f.worker = &RunWorker{
		warpState:       &WarpState{warpSettings: &WarpSettings{DockerNamespace: &namespace}},
		dynamoClient:    fixedDeploymentVersionClient{version: "1.0.0"},
		env:             "test",
		service:         "connect",
		block:           "g1",
		hostNetworking:  true,
		statusMode:      STATUS_MODE_STANDARD,
		portBlocks:      parsePortBlocks(fmt.Sprintf("80:7000:%d;443:7001:7301;4053:7002:7302", statusPort)),
		deployedVersion: semver.New("1.0.0"),
		quitEvent:       warp.NewEvent(),
		vaultMountMode:  MOUNT_MODE_NO,
		configMountMode: MOUNT_MODE_NO,
		siteMountMode:   MOUNT_MODE_NO,
		dataMountMode:   MOUNT_MODE_NO,
		dockerMountMode: MOUNT_MODE_NO,
		servicesDockerNetwork: &DockerNetwork{
			networkName: "warpservices",
			ipv4: &NetworkInterface{
				interfaceName: "warpservices",
				interfaceIp:   "127.0.0.1",
			},
		},
		lbAltHost: "edge-a.example",
		lbAltInterfaces: parseLbAltWorkerInterfaces(
			"eth1:warpeth1;eth2:warpeth2",
			lbAltFakeNetworkInterfaces(lbAltFakeEdgeAAddresses),
		),
		lbAltSettings: defaultLbAltWorkerSettings(),
		lbAltOps:      ops,
	}
	return f
}

// The value of a `docker run` flag such as --name, and every value of a
// repeated one such as -e.
func lbAltDockerRunValues(args []string, flag string) []string {
	values := []string{}
	for i, arg := range args {
		if arg == flag && i+1 < len(args) {
			values = append(values, args[i+1])
		}
	}
	return values
}

// A connect generation on an lb_alt host starts with its own route file: the
// renderer gets the services config, the services host, the generation, every
// interface the block binds with its bridge addresses and whether lb_alt is in
// effect on it, the generation's WARP_PORTS and the warpservices address. The
// file is mounted read-only at the contract's path and named by
// WARP_LBALT_ROUTE_FILE and WARP_GENERATION, which no user env var replaces,
// and the worker keeps the generation and revision for readiness.
func TestLbAltWorkerStartContainerMountsItsRouteFile(t *testing.T) {
	f := newLbAltWorkerFixture(t)
	f.worker.envVars = map[string]string{lbAltGenerationEnvName: "user-generation"}
	servicePorts := map[int]int{80: f.statusPort, 443: 7301, 4053: 7302}

	containerId, err := f.worker.startContainer(servicePorts)
	if err != nil {
		t.Fatal(err)
	}
	if containerId != lbAltFixtureContainerId || len(f.dockerRunArgs) != 1 {
		t.Fatalf("started %q with %d docker runs", containerId, len(f.dockerRunArgs))
	}
	runArgs := f.dockerRunArgs[0]
	containerNames := lbAltDockerRunValues(runArgs, "--name")
	if len(containerNames) != 1 || !strings.HasPrefix(containerNames[0], "test-connect-g1-1.0.0-") {
		t.Fatalf("container names %v", containerNames)
	}
	containerName := containerNames[0]

	if len(f.routeInputs) != 1 {
		t.Fatalf("rendered %d route tables", len(f.routeInputs))
	}
	inputs := f.routeInputs[0]
	if inputs.servicesConfig == nil || !services.IsLbAltInterface(inputs.servicesConfig.Latest(), "edge-a.example", "eth1") {
		t.Fatal("the renderer did not get the host's services config")
	}
	wantInterfaces := []lbAltRouteInterfaceInput{
		{name: "eth1", lbAlt: true, ipv4: "192.0.2.1", ipv6: "2001:db8:f1::1"},
		{name: "eth2", lbAlt: false, ipv4: "192.0.2.65", ipv6: "2001:db8:f2::1"},
	}
	if inputs.env != "test" || inputs.host != "edge-a.example" || inputs.generation != containerName ||
		!reflect.DeepEqual(inputs.interfaces, wantInterfaces) || !reflect.DeepEqual(inputs.servicePorts, servicePorts) ||
		inputs.upstreamIpv4 != "127.0.0.1" {
		t.Fatalf("route inputs env %q host %q generation %q interfaces %v ports %v upstream %q", inputs.env, inputs.host, inputs.generation, inputs.interfaces, inputs.servicePorts, inputs.upstreamIpv4)
	}
	if !slices.Equal(f.writtenRoutes, []string{containerName}) {
		t.Fatalf("route files written for %v, want %s", f.writtenRoutes, containerName)
	}

	hostPath := filepath.Join(f.home, lbAltRouteHostDirName, containerName, lbAltRouteFileName)
	wantMount := fmt.Sprintf("type=bind,source=%s,target=/srv/warp/lbalt/route.json,readonly", hostPath)
	if !slices.Contains(lbAltDockerRunValues(runArgs, "--mount"), wantMount) {
		t.Fatalf("docker run mounts %v, want %s", lbAltDockerRunValues(runArgs, "--mount"), wantMount)
	}
	env := lbAltDockerRunValues(runArgs, "-e")
	for _, want := range []string{
		"WARP_LBALT_ROUTE_FILE=/srv/warp/lbalt/route.json",
		"WARP_GENERATION=" + containerName,
		"WARP_HOST_IPV4=127.0.0.1",
	} {
		if !slices.Contains(env, want) {
			t.Fatalf("docker run env %v lacks %s", env, want)
		}
	}
	if slices.Contains(env, "WARP_GENERATION=user-generation") {
		t.Fatal("a user env var replaced the generation")
	}
	if f.worker.lbAltState.candidateGeneration != containerName || f.worker.lbAltState.candidateRevision != lbAltFixtureRevision {
		t.Fatalf("kept candidate %q revision %q", f.worker.lbAltState.candidateGeneration, f.worker.lbAltState.candidateRevision)
	}
}

// A generation whose route file cannot be rendered does not start: connect
// would come up without its front.
func TestLbAltWorkerStartContainerFailsWithoutItsRouteFile(t *testing.T) {
	f := newLbAltWorkerFixture(t)
	f.renderErr = errors.New("fixture render failure")
	if _, err := f.worker.startContainer(map[int]int{80: f.statusPort, 443: 7301, 4053: 7302}); err == nil || !strings.Contains(err.Error(), "fixture render failure") {
		t.Fatalf("start error = %v, want the render failure", err)
	}
	if len(f.dockerRunArgs) != 0 || len(f.writtenRoutes) != 0 {
		t.Fatalf("started %d containers and wrote %v without a route table", len(f.dockerRunArgs), f.writtenRoutes)
	}
	if f.worker.lbAltState.candidateGeneration != "" {
		t.Fatal("a failed generation was kept as the candidate")
	}
}

// The deploy of a connect block on an lb_alt host switches traffic in order:
// the candidate starts, its private status reports lb_alt readiness for its
// own generation, route file and sockets, then the block's chains on every
// bound interface point at it, and only then does the pool cutover start.
// Readiness polls the candidate's own private port with every bridge address
// of every interface times the four listen sockets, and the chains get every
// interface, eth2 too, which is not lb_alt yet, with the §2.3 targets.
func TestLbAltWorkerOverlapGatesTheCutoverOnReadinessThenChains(t *testing.T) {
	f := newLbAltWorkerFixture(t)
	if err := f.worker.deployContainerOverlap(true, nil); err != nil {
		t.Fatal(err)
	}
	if want := []string{"render", "start", "readiness", "chains", "cutover"}; !slices.Equal(f.events, want) {
		t.Fatalf("deploy events %v, want %v", f.events, want)
	}

	containerName := lbAltDockerRunValues(f.dockerRunArgs[0], "--name")[0]
	readinessCall := f.readinessCalls[0]
	if want := fmt.Sprintf("http://127.0.0.1:%d/status", f.statusPort); readinessCall.statusUrl != want {
		t.Fatalf("readiness polled %s, want %s", readinessCall.statusUrl, want)
	}
	if readinessCall.generation != containerName || readinessCall.revision != lbAltFixtureRevision || readinessCall.timeout != defaultLbAltWorkerSettings().readinessTimeout {
		t.Fatalf("readiness of generation %q revision %q timeout %s", readinessCall.generation, readinessCall.revision, readinessCall.timeout)
	}
	wantSockets := []lbAltExpectedSocket{}
	for _, address := range []string{"192.0.2.1", "2001:db8:f1::1", "192.0.2.65", "2001:db8:f2::1"} {
		wantSockets = append(wantSockets,
			lbAltExpectedSocket{protocol: "tcp", address: address, port: f.statusPort},
			lbAltExpectedSocket{protocol: "tcp", address: address, port: 7301},
			lbAltExpectedSocket{protocol: "udp", address: address, port: 7301},
			lbAltExpectedSocket{protocol: "udp", address: address, port: 7302},
		)
	}
	if !reflect.DeepEqual(readinessCall.expected, wantSockets) {
		t.Fatalf("readiness expected\n%v\nwant\n%v", readinessCall.expected, wantSockets)
	}

	chainsCall := f.chainsCalls[0]
	publicPorts := map[string][]int{"tcp": {80, 443}, "udp": {53, 443, 4053}}
	wantSplitInterfaces := []lbAltSplitInterface{
		{name: "eth1", publicIpv4: "198.51.100.1", publicIpv6: "2001:db8:1::1", bridgeIpv4: "192.0.2.1", bridgeIpv6: "2001:db8:f1::1", publicPorts: publicPorts},
		{name: "eth2", publicIpv4: "198.51.100.2", bridgeIpv4: "192.0.2.65", bridgeIpv6: "2001:db8:f2::1", publicPorts: publicPorts},
	}
	wantTargets := []lbAltBlockTarget{
		{protocol: "tcp", publicPort: 80, internalPort: f.statusPort},
		{protocol: "tcp", publicPort: 443, internalPort: 7301},
		{protocol: "udp", publicPort: 53, internalPort: 7302},
		{protocol: "udp", publicPort: 443, internalPort: 7301},
		{protocol: "udp", publicPort: 4053, internalPort: 7302},
	}
	if chainsCall.env != "test" || chainsCall.block != "g1" ||
		!reflect.DeepEqual(chainsCall.splitInterfaces, wantSplitInterfaces) || !reflect.DeepEqual(chainsCall.targets, wantTargets) {
		t.Fatalf("chains of %s %s on\n%v\nwith\n%v", chainsCall.env, chainsCall.block, chainsCall.splitInterfaces, chainsCall.targets)
	}

	// the block has no routing table, so its pool cutover rewrites no source
	// port: a SNAT to its pool ports would give the front's own outbound udp
	// the wrong public port
	if len(f.firewallChanges) == 0 {
		t.Fatal("the cutover changed no firewall rule")
	}
	for _, firewallChange := range f.firewallChanges {
		if strings.Contains(firewallChange, " SNAT ") || strings.Contains(firewallChange, " POSTROUTING ") {
			t.Fatalf("the cutover changed %s", firewallChange)
		}
	}
}

// A candidate that never reports lb_alt ready gets no chain and no cutover,
// and is stopped: no flow ever reached it. The chains never belong to it, so
// no later refresh points them at it either.
func TestLbAltWorkerOverlapStopsAnUnreadyCandidateBeforeItsChains(t *testing.T) {
	f := newLbAltWorkerFixture(t)
	f.readinessErr = errors.New("fixture sockets 3/4")
	err := f.worker.deployContainerOverlap(true, nil)
	if err == nil || !strings.Contains(err.Error(), "fixture sockets 3/4") {
		t.Fatalf("deploy error = %v, want the readiness failure", err)
	}
	if want := []string{"render", "start", "readiness", "stop"}; !slices.Equal(f.events, want) {
		t.Fatalf("deploy events %v, want %v", f.events, want)
	}
	f.worker.refreshLbAltWorkerChainsIfDue(time.Now().Add(time.Hour))
	if len(f.chainsCalls) != 0 {
		t.Fatalf("a refresh pointed the chains at a candidate that was never ready: %v", f.chainsCalls)
	}
}

// A non-positive readiness timeout fails the deploy before its first poll, so
// no candidate is promoted unchecked: the candidate is stopped with no
// readiness poll, chain or cutover.
func TestLbAltWorkerOverlapRefusesANonPositiveReadinessTimeout(t *testing.T) {
	for _, readinessTimeout := range []time.Duration{0, -time.Second} {
		f := newLbAltWorkerFixture(t)
		f.worker.lbAltSettings.readinessTimeout = readinessTimeout
		err := f.worker.deployContainerOverlap(true, nil)
		if err == nil || !strings.Contains(err.Error(), "is not positive") {
			t.Fatalf("readiness timeout %s: deploy error = %v, want a refusal", readinessTimeout, err)
		}
		if want := []string{"render", "start", "stop"}; !slices.Equal(f.events, want) {
			t.Fatalf("readiness timeout %s: deploy events %v, want %v", readinessTimeout, f.events, want)
		}
	}
}

// When the chains fail after the commit, the pool cutover does not run, and
// the candidate, which some chain may already point at, keeps running as the
// deployed generation: the deploy reports a promoted generation, which Run
// keeps, with its promotion pending. Each completion retries the chains for
// that same candidate, and once they are written it runs the cutover and the
// old generations' retirement. No other candidate starts and none stops.
func TestLbAltWorkerOverlapKeepsTheCandidateWhenItsChainsFail(t *testing.T) {
	f := newLbAltWorkerFixture(t)
	f.chainsErr = errors.New("fixture chain failure")
	err := f.worker.deployContainerOverlap(true, nil)
	var retirementErr *deploymentRetirementError
	if !errors.As(err, &retirementErr) || !strings.Contains(err.Error(), "fixture chain failure") {
		t.Fatalf("deploy error = %v, want a promoted deploy with the chain failure", err)
	}
	if want := []string{"render", "start", "readiness", "chains"}; !slices.Equal(f.events, want) {
		t.Fatalf("deploy events %v, want %v", f.events, want)
	}
	if f.worker.pendingDeployment == nil {
		t.Fatal("the committed candidate's promotion is not pending")
	}

	if err := f.worker.completePendingDeployment(true); !errors.As(err, &retirementErr) || !strings.Contains(err.Error(), "fixture chain failure") {
		t.Fatalf("completion error = %v, want the chain failure again", err)
	}
	f.chainsErr = nil
	if err := f.worker.completePendingDeployment(true); err != nil {
		t.Fatalf("completion error = %v", err)
	}
	if want := []string{"render", "start", "readiness", "chains", "chains", "chains", "cutover"}; !slices.Equal(f.events, want) {
		t.Fatalf("deploy events %v, want %v", f.events, want)
	}
	if f.worker.pendingDeployment != nil {
		t.Fatal("the promotion is still pending after it completed")
	}
	for _, chainsCall := range f.chainsCalls[1:] {
		if !reflect.DeepEqual(chainsCall, f.chainsCalls[0]) {
			t.Fatalf("a retry wrote\n%v\nnot the candidate's\n%v", chainsCall, f.chainsCalls[0])
		}
	}
}

// Between deploys a connect block on an lb_alt host writes its chains for the
// candidate its latest deploy committed, once every chainRefreshTimeout, which
// heals a chain lost other than by a rollback with no connect deploy. A failed
// write waits for the next refresh, and a non-positive interval leaves the
// chains to the deploys.
func TestLbAltWorkerRefreshesItsChainsBetweenDeploys(t *testing.T) {
	f := newLbAltWorkerFixture(t)
	deployed := time.Now()
	if err := f.worker.deployContainerOverlap(true, nil); err != nil {
		t.Fatal(err)
	}
	if len(f.chainsCalls) != 1 {
		t.Fatalf("the deploy wrote the chains %d times", len(f.chainsCalls))
	}
	chainRefreshTimeout := defaultLbAltWorkerSettings().chainRefreshTimeout

	f.worker.refreshLbAltWorkerChainsIfDue(deployed)
	if len(f.chainsCalls) != 1 {
		t.Fatal("the chains were rewritten before the refresh was due")
	}
	due := time.Now().Add(chainRefreshTimeout)
	f.chainsErr = errors.New("fixture xtables lock")
	f.worker.refreshLbAltWorkerChainsIfDue(due)
	if len(f.chainsCalls) != 2 || !reflect.DeepEqual(f.chainsCalls[1], f.chainsCalls[0]) {
		t.Fatalf("the refresh wrote %v, want the deployed generation's chains again", f.chainsCalls[1:])
	}
	f.chainsErr = nil
	f.worker.refreshLbAltWorkerChainsIfDue(due)
	if len(f.chainsCalls) != 2 {
		t.Fatal("a failed refresh was retried before the next refresh")
	}
	f.worker.refreshLbAltWorkerChainsIfDue(due.Add(chainRefreshTimeout))
	if len(f.chainsCalls) != 3 || !reflect.DeepEqual(f.chainsCalls[2], f.chainsCalls[0]) {
		t.Fatalf("the next refresh wrote %v", f.chainsCalls[2:])
	}

	f.worker.lbAltSettings.chainRefreshTimeout = 0
	f.worker.refreshLbAltWorkerChainsIfDue(due.Add(time.Hour))
	if len(f.chainsCalls) != 3 {
		t.Fatal("a non-positive refresh interval rewrote the chains")
	}
}

// A block that binds no lb interface deploys as before: no route file, mount
// or lb_alt env, no lb_alt readiness and no chains.
func TestLbAltWorkerOverlapWithoutLbAltInterfacesIsUnchanged(t *testing.T) {
	f := newLbAltWorkerFixture(t)
	f.worker.lbAltInterfaces = nil
	if err := f.worker.deployContainerOverlap(true, nil); err != nil {
		t.Fatal(err)
	}
	if want := []string{"start", "cutover"}; !slices.Equal(f.events, want) {
		t.Fatalf("deploy events %v, want %v", f.events, want)
	}
	runArgs := f.dockerRunArgs[0]
	for _, value := range append(lbAltDockerRunValues(runArgs, "--mount"), lbAltDockerRunValues(runArgs, "-e")...) {
		if strings.Contains(value, "lbalt") || strings.HasPrefix(value, "WARP_GENERATION=") {
			t.Fatalf("docker run carries %s", value)
		}
	}
}

// An lb worker with every command in hooks and the PATH fixture, deploying an
// nginx lb on edge-a eth1 of lbAltUnitsServicesYaml. Its docker network is
// loopback so the status poll reaches a local server. events records the
// first public DNAT insert ("public dnat") and the split removals.
type lbAltLbFixture struct {
	worker      *RunWorker
	events      []string
	removeCalls []string
	removeErr   error
}

func newLbAltLbFixture(t *testing.T, lbAlt bool) *lbAltLbFixture {
	t.Helper()
	f := newLbAltWorkerFixture(t)
	lbFixture := &lbAltLbFixture{}
	previousRun := runAndLogFunc
	runAndLogFunc = func(cmd *exec.Cmd) error {
		args := strings.Join(cmd.Args, " ")
		if strings.Contains(args, " -I ") && strings.Contains(args, " -d 198.51.100.1 ") && !slices.Contains(lbFixture.events, "public dnat") {
			lbFixture.events = append(lbFixture.events, "public dnat")
		}
		return previousRun(cmd)
	}
	ops := f.worker.lbAltOps
	ops.removeSplit = func(ctx context.Context, env string, interfaceName string) error {
		lbFixture.events = append(lbFixture.events, "remove split")
		lbFixture.removeCalls = append(lbFixture.removeCalls, env+" "+interfaceName)
		return lbFixture.removeErr
	}
	namespace := "fixture"
	lbFixture.worker = &RunWorker{
		warpState:       &WarpState{warpSettings: &WarpSettings{DockerNamespace: &namespace}},
		dynamoClient:    fixedDeploymentVersionClient{version: "1.0.0"},
		env:             "test",
		service:         "lb",
		block:           "edge-a.example-eth1",
		hostNetworking:  true,
		statusMode:      STATUS_MODE_STANDARD,
		portBlocks:      parsePortBlocks(fmt.Sprintf("80:7000:%d;443:7001:7301", f.statusPort)),
		deployedVersion: semver.New("1.0.0"),
		quitEvent:       warp.NewEvent(),
		vaultMountMode:  MOUNT_MODE_NO,
		configMountMode: MOUNT_MODE_NO,
		siteMountMode:   MOUNT_MODE_NO,
		dataMountMode:   MOUNT_MODE_NO,
		dockerMountMode: MOUNT_MODE_NO,
		servicesDockerNetwork: &DockerNetwork{
			networkName: "warpservices",
			ipv4: &NetworkInterface{
				interfaceName: "warpservices",
				interfaceIp:   "127.0.0.1",
			},
		},
		dockerNetwork: &DockerNetwork{
			networkName: "warpeth1",
			ipv4: &NetworkInterface{
				interfaceName:   "warpeth1",
				interfaceIp:     "127.0.0.1",
				interfaceSubnet: "127.0.0.0/8",
			},
		},
		routingTable: &RoutingTable{
			interfaceName: "eth1",
			tableNumber:   100,
			tableName:     "warp100",
			ipv4: &NetworkInterface{
				interfaceName:    "eth1",
				interfaceIp:      "198.51.100.1",
				interfaceSubnet:  "198.51.100.0/24",
				interfaceGateway: "198.51.100.254",
			},
		},
		fwMark:        100,
		lbAlt:         lbAlt,
		lbAltSettings: defaultLbAltWorkerSettings(),
		lbAltOps:      ops,
	}
	return lbFixture
}

// Writes the record an lb_alt unit of the interface leaves
// (lbAltWorkerSplitRecordPath) and returns its path.
func lbAltWriteSplitRecord(t *testing.T, env string, interfaceName string) string {
	t.Helper()
	recordPath := lbAltWorkerSplitRecordPath(os.Getenv("WARP_HOME"), env, interfaceName)
	if err := os.MkdirAll(filepath.Dir(recordPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(recordPath, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	return recordPath
}

// Rolling an interface back to nginx (D18): the nginx lb's cutover puts its
// public DNAT back first, and only then is the split the interface's lb_alt
// unit recorded removed. A failed removal stays pending and is retried from
// the poll loop once due, not before, until it succeeds; then the record
// goes, and the split is not removed again.
func TestLbAltWorkerNginxCutoverRemovesTheSplitAfterItsDnat(t *testing.T) {
	f := newLbAltLbFixture(t, false)
	recordPath := lbAltWriteSplitRecord(t, "test", "eth1")
	f.removeErr = errors.New("fixture xtables lock")
	if err := f.worker.deployContainerOverlap(true, nil); err != nil {
		t.Fatal(err)
	}
	if want := []string{"public dnat", "remove split"}; !slices.Equal(f.events, want) {
		t.Fatalf("cutover events %v, want %v", f.events, want)
	}
	if !slices.Equal(f.removeCalls, []string{"test eth1"}) || !f.worker.lbAltState.splitRemovalPending {
		t.Fatalf("removals %v, pending %t", f.removeCalls, f.worker.lbAltState.splitRemovalPending)
	}

	attempted := time.Now()
	f.worker.retryLbAltWorkerSplitRemovalIfDue(attempted)
	if len(f.removeCalls) != 1 {
		t.Fatalf("a removal retried before it was due: %v", f.removeCalls)
	}
	if _, err := os.Stat(recordPath); err != nil {
		t.Fatalf("the record of a split not yet removed is gone: %v", err)
	}
	f.removeErr = nil
	f.worker.retryLbAltWorkerSplitRemovalIfDue(attempted.Add(defaultLbAltWorkerSettings().splitRemovalRetryTimeout + time.Second))
	if len(f.removeCalls) != 2 || f.worker.lbAltState.splitRemovalPending {
		t.Fatalf("removals %v, pending %t after the due retry", f.removeCalls, f.worker.lbAltState.splitRemovalPending)
	}
	if _, err := os.Stat(recordPath); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("the record of a removed split stayed: %v", err)
	}
	f.worker.retryLbAltWorkerSplitRemovalIfDue(attempted.Add(time.Hour))
	f.worker.removeLbAltWorkerSplitAfterCutover()
	if len(f.removeCalls) != 2 {
		t.Fatalf("a removed split was removed again: %v", f.removeCalls)
	}
}

// The cutover of an nginx interface that has no split record, because it was
// never lb_alt or its split was already removed, removes no split, so an nginx
// deploy where lb_alt never ran depends on no lb_alt rule.
func TestLbAltWorkerNginxCutoverLeavesAnUnrecordedInterfaceAlone(t *testing.T) {
	f := newLbAltLbFixture(t, false)
	if err := f.worker.deployContainerOverlap(true, nil); err != nil {
		t.Fatal(err)
	}
	if want := []string{"public dnat"}; !slices.Equal(f.events, want) {
		t.Fatalf("cutover events %v, want %v", f.events, want)
	}
	f.worker.retryLbAltWorkerSplitRemovalIfDue(time.Now().Add(time.Hour))
	if len(f.removeCalls) != 0 || f.worker.lbAltState.splitRemovalPending {
		t.Fatalf("removals %v, pending %t", f.removeCalls, f.worker.lbAltState.splitRemovalPending)
	}
	// another env's record is not this interface's
	lbAltWriteSplitRecord(t, "other", "eth1")
	f.worker.removeLbAltWorkerSplitAfterCutover()
	if len(f.removeCalls) != 0 {
		t.Fatalf("another env's record removed a split: %v", f.removeCalls)
	}
}

// The lb unit of an lb_alt interface starts no nginx: a deploy reached by
// mistake refuses before any command runs, so no container starts and
// nginx's public port map (publicPortServiceTargets), which would publish udp
// 80 and keep 4053 private, never reaches an interface whose public ports are
// connect's. A transparent interface's unit deploys nothing either.
func TestLbAltWorkerLbAltLbUnitDeploysNoNginx(t *testing.T) {
	for _, transparent := range []bool{false, true} {
		f := newLbAltLbFixture(t, !transparent)
		f.worker.transparent = transparent
		commands := []string{}
		previousRun, previousOut, previousSudo2 := runAndLogFunc, outAndLogFunc, sudo2Func
		runAndLogFunc = func(cmd *exec.Cmd) error {
			commands = append(commands, strings.Join(cmd.Args, " "))
			return previousRun(cmd)
		}
		outAndLogFunc = func(cmd *exec.Cmd) ([]byte, error) {
			commands = append(commands, strings.Join(cmd.Args, " "))
			return previousOut(cmd)
		}
		sudo2Func = func(name []string, args ...string) *exec.Cmd {
			commands = append(commands, strings.Join(append(slices.Clone(name), args...), " "))
			return exec.Command("sudo", append(slices.Clone(name), args...)...)
		}

		err := f.worker.deployContainerOverlap(true, nil)
		runAndLogFunc, outAndLogFunc, sudo2Func = previousRun, previousOut, previousSudo2
		if err == nil || !strings.Contains(err.Error(), "routing-only lb unit deploys no container") {
			t.Fatalf("transparent %t: deploy error = %v, want a refusal", transparent, err)
		}
		if len(commands) != 0 || len(f.events) != 0 {
			t.Fatalf("transparent %t: the refused deploy ran %v with events %v", transparent, commands, f.events)
		}
	}
}

// The lb units that run routing-only: a transparent interface's and an lb_alt
// interface's. A plain lb and a service block poll versions and deploy.
func TestLbAltWorkerRoutingOnlyLbUnits(t *testing.T) {
	for _, routingOnly := range []struct {
		worker *RunWorker
		want   bool
	}{
		{worker: &RunWorker{service: "lb", transparent: true}, want: true},
		{worker: &RunWorker{service: "lb", lbAlt: true}, want: true},
		{worker: &RunWorker{service: "lb"}, want: false},
		{worker: &RunWorker{service: "connect", lbAltInterfaces: []*lbAltWorkerInterface{{interfaceName: "eth1"}}}, want: false},
	} {
		if got := routingOnly.worker.isRoutingOnlyLb(); got != routingOnly.want {
			t.Errorf("service %s transparent %t lb_alt %t: routing-only %t, want %t", routingOnly.worker.service, routingOnly.worker.transparent, routingOnly.worker.lbAlt, got, routingOnly.want)
		}
	}
}

// Fakes the routing commands of initRoutingTable and records them: listings
// print nothing, and every other command is recorded instead of run.
func lbAltFakeRoutingCommands(t *testing.T) *[]string {
	t.Helper()
	previousRun, previousSudo2 := runAndLogFunc, sudo2Func
	t.Cleanup(func() {
		runAndLogFunc, sudo2Func = previousRun, previousSudo2
	})
	commands := []string{}
	runAndLogFunc = func(cmd *exec.Cmd) error {
		commands = append(commands, strings.Join(cmd.Args, " "))
		return nil
	}
	sudo2Func = func(name []string, args ...string) *exec.Cmd {
		commandArgs := append(slices.Clone(name), args...)
		command := strings.Join(commandArgs, " ")
		if strings.Contains(command, " route show ") || strings.Contains(command, " rule list") {
			return exec.Command("printf", "%s", "")
		}
		return exec.Command("sudo", commandArgs...)
	}
	return &commands
}

// The routing-only unit of an lb_alt interface reconciles the interface's
// routing and then its split, with the public addresses of the interface,
// the bridge addresses of its docker network, the public ports from the host's
// services config, read once, and the blocks of --lbaltblocks. A transparent
// interface's unit reconciles only its routing.
func TestLbAltWorkerRoutingOnlyLoopReconcilesTheSplit(t *testing.T) {
	setupTestVault(t, lbAltUnitsYaml(lbAltUnitsSettings{connect: "true"}))
	commands := lbAltFakeRoutingCommands(t)
	splitConfigs := []*lbAltSplitConfig{}
	loads := 0
	ops := defaultLbAltWorkerOps()
	ops.loadServicesConfig = func(vaultHome string, env string) (*services.ServicesConfig, error) {
		loads += 1
		return services.LoadServicesConfigFrom(vaultHome, env)
	}
	ops.reconcileSplit = func(ctx context.Context, config *lbAltSplitConfig) error {
		splitConfigs = append(splitConfigs, config)
		*commands = append(*commands, "reconcile split")
		return nil
	}
	// no nginx container is left to retire
	ops.listContainers = func(ctx context.Context, containerNamePrefix string, format string) ([]string, error) {
		return nil, nil
	}
	blockWeights := parseLbAltWorkerBlocks("beta:1;g1:24;g2:25;g3:25;g4:25")
	worker := &RunWorker{
		warpState: &WarpState{warpSettings: &WarpSettings{}},
		env:       "test",
		service:   "lb",
		block:     "edge-a.example-eth1",
		servicesDockerNetwork: &DockerNetwork{
			networkName: "warpservices",
			ipv4: &NetworkInterface{
				interfaceName:   "warpservices",
				interfaceIp:     "192.0.2.129",
				interfaceSubnet: "192.0.2.128/26",
			},
		},
		dockerNetwork: &DockerNetwork{
			networkName: "warpeth1",
			ipv4: &NetworkInterface{
				interfaceName:   "warpeth1",
				interfaceIp:     "192.0.2.1",
				interfaceSubnet: "192.0.2.0/26",
			},
			ipv6: &NetworkInterface{
				interfaceName:   "warpeth1",
				interfaceIp:     "2001:db8:f1::1",
				interfaceSubnet: "2001:db8:f1::/64",
			},
		},
		routingTable: &RoutingTable{
			interfaceName: "eth1",
			tableNumber:   100,
			tableName:     "warp100",
			ipv4: &NetworkInterface{
				interfaceName:    "eth1",
				interfaceIp:      "198.51.100.1",
				interfaceSubnet:  "198.51.100.0/24",
				interfaceGateway: "198.51.100.254",
			},
			ipv6: &NetworkInterface{
				interfaceName:    "eth1",
				interfaceIp:      "2001:db8:1::1",
				interfaceSubnet:  "2001:db8:1::/64",
				interfaceGateway: "2001:db8:1::fffe",
			},
		},
		fwMark:        100,
		lbAlt:         true,
		lbAltBlocks:   blockWeights,
		lbAltSettings: defaultLbAltWorkerSettings(),
		lbAltOps:      ops,
	}

	// the loop's start, then two reconciles
	worker.reconcileLbAltWorkerInterface()
	reconcile := worker.routingOnlyReconcile()
	reconcile()
	worker.nextRoutingTableReconcile = time.Time{}
	reconcile()

	if len(splitConfigs) != 3 || loads != 1 {
		t.Fatalf("%d split reconciles with %d services config loads, want 3 with 1", len(splitConfigs), loads)
	}
	wantConfig := &lbAltSplitConfig{
		env: "test",
		splitInterface: lbAltSplitInterface{
			name:        "eth1",
			publicIpv4:  "198.51.100.1",
			publicIpv6:  "2001:db8:1::1",
			bridgeIpv4:  "192.0.2.1",
			bridgeIpv6:  "2001:db8:f1::1",
			publicPorts: map[string][]int{"tcp": {80, 443}, "udp": {53, 443, 4053}},
		},
		blockWeights: blockWeights,
	}
	for _, splitConfig := range splitConfigs {
		if !reflect.DeepEqual(splitConfig, wantConfig) {
			t.Fatalf("split config\n%+v\nwant\n%+v", splitConfig, wantConfig)
		}
	}
	// each reconcile restores the routing before it reconciles the split
	routeIndex := slices.Index(*commands, "sudo ip route replace 198.51.100.0/24 dev eth1 src 198.51.100.1 table 100")
	splitIndexes := []int{}
	for i, command := range *commands {
		if command == "reconcile split" {
			splitIndexes = append(splitIndexes, i)
		}
	}
	if routeIndex < 0 || len(splitIndexes) != 3 || !(splitIndexes[0] < routeIndex && routeIndex < splitIndexes[1]) {
		t.Fatalf("routing and split order:\n%s", strings.Join(*commands, "\n"))
	}

	worker.lbAlt = false
	worker.transparent = true
	worker.nextRoutingTableReconcile = time.Time{}
	worker.routingOnlyReconcile()()
	if len(splitConfigs) != 3 {
		t.Fatal("a transparent interface's unit reconciled a split")
	}
}

// When the host's services config does not have lb_alt in effect on the
// interface, as when the vault already rolled it back but the unit was not
// regenerated, the unit leaves the split as it is, rather than reconcile it to
// no ports, and tries again at the next reconcile. It places no split rule,
// so it records none either.
func TestLbAltWorkerSplitWaitsForTheServicesConfig(t *testing.T) {
	setupTestVault(t, lbAltUnitsYaml(lbAltUnitsSettings{edgeAEth1: "false", connect: "true"}))
	errOutput := captureErrOutput(t)
	reconciles := 0
	ops := defaultLbAltWorkerOps()
	ops.reconcileSplit = func(ctx context.Context, config *lbAltSplitConfig) error {
		reconciles += 1
		return nil
	}
	worker := &RunWorker{
		warpState:     &WarpState{warpSettings: &WarpSettings{}},
		env:           "test",
		service:       "lb",
		block:         "edge-a.example-eth1",
		routingTable:  &RoutingTable{interfaceName: "eth1", ipv4: &NetworkInterface{interfaceIp: "198.51.100.1"}},
		lbAlt:         true,
		lbAltBlocks:   parseLbAltWorkerBlocks("beta:1"),
		lbAltSettings: defaultLbAltWorkerSettings(),
		lbAltOps:      ops,
	}
	worker.reconcileLbAltWorkerInterface()
	worker.reconcileLbAltWorkerInterface()
	if reconciles != 0 || worker.lbAltState.splitPublicPorts != nil {
		t.Fatalf("reconciled %d times with public ports %v", reconciles, worker.lbAltState.splitPublicPorts)
	}
	if strings.Count(errOutput.String(), "lb_alt is not in effect on it there") != 2 {
		t.Fatalf("the skew was not logged on each reconcile:\n%s", errOutput.String())
	}
	if _, err := os.Stat(lbAltWorkerSplitRecordPath(os.Getenv("WARP_HOME"), "test", "eth1")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("a unit that placed no split recorded one: %v", err)
	}
}

// An lb_alt interface's unit with its routing table, docker network and
// blocks, on edge-a eth1 of lbAltUnitsServicesYaml, with lb port blocks for
// the conntrack cleanup and every lb_alt operation from ops.
func newLbAltSplitWorker(ops *lbAltWorkerOps) *RunWorker {
	return &RunWorker{
		warpState:      &WarpState{warpSettings: &WarpSettings{}},
		env:            "test",
		service:        "lb",
		block:          "edge-a.example-eth1",
		hostNetworking: true,
		portBlocks:     parsePortBlocks("80:7000:7201;443:7001:7231"),
		servicesDockerNetwork: &DockerNetwork{
			networkName: "warpservices",
			ipv4: &NetworkInterface{
				interfaceName:   "warpservices",
				interfaceIp:     "192.0.2.129",
				interfaceSubnet: "192.0.2.128/26",
			},
		},
		dockerNetwork: &DockerNetwork{
			networkName: "warpeth1",
			ipv4: &NetworkInterface{
				interfaceName:   "warpeth1",
				interfaceIp:     "192.0.2.1",
				interfaceSubnet: "192.0.2.0/26",
			},
		},
		routingTable: &RoutingTable{
			interfaceName: "eth1",
			tableNumber:   100,
			tableName:     "warp100",
			ipv4: &NetworkInterface{
				interfaceName:    "eth1",
				interfaceIp:      "198.51.100.1",
				interfaceSubnet:  "198.51.100.0/24",
				interfaceGateway: "198.51.100.254",
			},
			ipv6: &NetworkInterface{
				interfaceName:    "eth1",
				interfaceIp:      "2001:db8:1::1",
				interfaceSubnet:  "2001:db8:1::/64",
				interfaceGateway: "2001:db8:1::fffe",
			},
		},
		fwMark:        100,
		lbAlt:         true,
		lbAltBlocks:   parseLbAltWorkerBlocks("beta:1;g1:24;g2:25;g3:25;g4:25"),
		lbAltSettings: defaultLbAltWorkerSettings(),
		lbAltOps:      ops,
	}
}

// Before an lb_alt interface's unit reconciles its split, which may place the
// split's first rule, the split record is there under WARP_HOME, for the
// interface in the unit's env, so a rollback to nginx finds the split to
// remove even after an interrupted reconcile. A record removed meanwhile is
// written again before the next reconcile.
func TestLbAltWorkerRecordsTheSplitBeforeReconcilingIt(t *testing.T) {
	setupTestVault(t, lbAltUnitsYaml(lbAltUnitsSettings{connect: "true"}))
	recordPath := filepath.Join(os.Getenv("WARP_HOME"), "lbalt-split", "test", "eth1")
	recordedAtReconcile := []bool{}
	ops := defaultLbAltWorkerOps()
	ops.reconcileSplit = func(ctx context.Context, config *lbAltSplitConfig) error {
		_, err := os.Stat(recordPath)
		recordedAtReconcile = append(recordedAtReconcile, err == nil)
		return errors.New("fixture no ready block")
	}
	ops.listContainers = func(ctx context.Context, containerNamePrefix string, format string) ([]string, error) {
		t.Error("a unit whose split failed to reconcile listed its nginx")
		return nil, nil
	}
	worker := newLbAltSplitWorker(ops)

	worker.reconcileLbAltWorkerInterface()
	if err := os.Remove(recordPath); err != nil {
		t.Fatal(err)
	}
	worker.reconcileLbAltWorkerInterface()
	if !slices.Equal(recordedAtReconcile, []bool{true, true}) {
		t.Fatalf("recorded at each reconcile: %v", recordedAtReconcile)
	}
}

// An lb_alt interface's nginx retires only once the interface's split is in
// place (D1; §4.6 step 3). While the split reconcile fails, nginx keeps
// serving and is not even listed. The first reconcile that succeeds drains
// every nginx container of the block, with an nginx deploy's grace, on a
// goroutine of its own, while the reconciles go on and start no second
// retirement. Once the drain ends, the next reconcile cleans the stale
// conntrack entries of the retired ports and prunes the stopped containers,
// and with none left it retires nothing more.
func TestLbAltWorkerRetiresNginxOnlyAfterTheSplitIsInPlace(t *testing.T) {
	setupTestVault(t, lbAltUnitsYaml(lbAltUnitsSettings{connect: "true"}))
	const nginxContainerId = "0ea7c0000001"
	var stateLock sync.Mutex
	events := []string{}
	record := func(event string) {
		stateLock.Lock()
		defer stateLock.Unlock()
		events = append(events, event)
	}
	recorded := func() []string {
		stateLock.Lock()
		defer stateLock.Unlock()
		return slices.Clone(events)
	}
	stopping := make(chan struct{})
	releaseStop := make(chan struct{})

	previousRun, previousOut, previousQuiet := runAndLogFunc, outAndLogFunc, runQuietFunc
	t.Cleanup(func() {
		runAndLogFunc, outAndLogFunc, runQuietFunc = previousRun, previousOut, previousQuiet
	})
	runAndLogFunc = func(cmd *exec.Cmd) error {
		args := strings.Join(cmd.Args, " ")
		switch {
		case strings.Contains(args, "docker update --restart=no "+nginxContainerId):
			record("update")
		case strings.Contains(args, "docker container stop "):
			record(strings.TrimSpace(args[strings.Index(args, "docker container stop "):]))
			close(stopping)
			<-releaseStop
		case strings.Contains(args, "docker container prune "):
			record("prune")
		default:
			t.Errorf("unexpected fixture command: %v", cmd.Args)
			return errors.New("unexpected fixture command")
		}
		return nil
	}
	outAndLogFunc = func(cmd *exec.Cmd) ([]byte, error) {
		t.Errorf("unexpected fixture output command: %v", cmd.Args)
		return nil, errors.New("unexpected fixture output command")
	}
	runQuietFunc = func(cmd *exec.Cmd) (commandOutput, error) {
		args := strings.Join(cmd.Args, " ")
		switch {
		case strings.HasPrefix(args, "ss ") || strings.HasPrefix(args, "netstat "):
			record("sockets")
		case strings.Contains(args, "conntrack -L ") && strings.Contains(args, "--reply-src 192.0.2.1 "):
			record("conntrack")
		default:
			t.Errorf("unexpected fixture quiet command: %v", cmd.Args)
			return commandOutput{}, errors.New("unexpected fixture quiet command")
		}
		return commandOutput{}, nil
	}

	splitErr := errors.New("fixture no ready block")
	ops := defaultLbAltWorkerOps()
	ops.reconcileSplit = func(ctx context.Context, config *lbAltSplitConfig) error {
		if splitErr != nil {
			record("split failed")
		} else {
			record("split")
		}
		return splitErr
	}
	ops.listContainers = func(ctx context.Context, containerNamePrefix string, format string) ([]string, error) {
		record("list " + containerNamePrefix + " " + format)
		if slices.Contains(recorded(), "prune") {
			return nil, nil
		}
		return []string{nginxContainerId}, nil
	}
	worker := newLbAltSplitWorker(ops)
	// the routing reconcile is not due in this test
	worker.nextRoutingTableReconcile = time.Now().Add(time.Hour)
	reconcile := worker.routingOnlyReconcile()

	reconcile()
	if want := []string{"split failed"}; !slices.Equal(recorded(), want) {
		t.Fatalf("events %v, want %v", recorded(), want)
	}

	splitErr = nil
	reconcile()
	if want := []string{"split failed", "split", "list test-lb-edge-a.example-eth1- {{.ID}}"}; !slices.Equal(recorded(), want) {
		t.Fatalf("events %v, want %v", recorded(), want)
	}
	select {
	case <-stopping:
	case <-time.After(10 * time.Second):
		t.Fatal("the listed nginx was not stopped")
	}
	reconcile()
	if want := []string{
		"split failed", "split", "list test-lb-edge-a.example-eth1- {{.ID}}",
		"update", "docker container stop -t 3600 " + nginxContainerId,
		"split",
	}; !slices.Equal(recorded(), want) {
		t.Fatalf("events while nginx drains %v, want %v", recorded(), want)
	}

	close(releaseStop)
	// join the retirement, and hand its result back for the worker to observe
	retirementErr := <-worker.orphanDrain
	if retirementErr != nil {
		t.Fatalf("retirement error = %v", retirementErr)
	}
	worker.orphanDrain <- retirementErr
	reconcile()
	if want := []string{
		"split failed", "split", "list test-lb-edge-a.example-eth1- {{.ID}}",
		"update", "docker container stop -t 3600 " + nginxContainerId,
		"split",
		"split", "sockets", "conntrack", "prune", "list test-lb-edge-a.example-eth1- {{.ID}}",
	}; !slices.Equal(recorded(), want) {
		t.Fatalf("events after the drain %v, want %v", recorded(), want)
	}
	if worker.orphanDrain != nil {
		t.Fatal("a retirement started with no nginx left")
	}
}

// A block's route files go with their containers: after prune, every
// generation directory of the block whose container docker no longer lists
// is removed, and the directories of live containers, other blocks and other
// services stay. A block with no route files asks docker nothing.
func TestLbAltWorkerPruneRemovesTheRouteFilesOfRemovedContainers(t *testing.T) {
	f := newLbAltWorkerFixture(t)
	routeHome := filepath.Join(f.home, lbAltRouteHostDirName)
	generations := []string{
		"test-connect-g1-1.0.0-1000",
		"test-connect-g1-1.0.0-2000",
		"test-connect-g10-1.0.0-3000",
		"test-api-g1-1.0.0-4000",
	}
	for _, generation := range generations {
		if err := os.MkdirAll(filepath.Join(routeHome, generation), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	listedPrefixes := []string{}
	removed := []string{}
	previousRun := runAndLogFunc
	runAndLogFunc = func(cmd *exec.Cmd) error {
		if strings.Contains(strings.Join(cmd.Args, " "), "docker container prune ") {
			f.record("prune")
		}
		return previousRun(cmd)
	}
	f.worker.lbAltOps.listContainers = func(ctx context.Context, containerNamePrefix string, format string) ([]string, error) {
		f.record("list")
		listedPrefixes = append(listedPrefixes, containerNamePrefix+" "+format)
		return []string{"test-connect-g1-1.0.0-2000"}, nil
	}
	f.worker.lbAltOps.removeRouteFile = func(warpHome string, containerName string) error {
		f.record("remove " + containerName)
		removed = append(removed, containerName)
		return os.RemoveAll(filepath.Join(warpHome, lbAltRouteHostDirName, containerName))
	}

	f.worker.prune()
	if want := []string{"prune", "list", "remove test-connect-g1-1.0.0-1000"}; !slices.Equal(f.events, want) {
		t.Fatalf("prune events %v, want %v", f.events, want)
	}
	if !slices.Equal(listedPrefixes, []string{"test-connect-g1- {{.Names}}"}) {
		t.Fatalf("listed containers by %v", listedPrefixes)
	}
	if got, want := readDirNames(t, routeHome), []string{"test-api-g1-1.0.0-4000", "test-connect-g1-1.0.0-2000", "test-connect-g10-1.0.0-3000"}; !slices.Equal(got, want) {
		t.Fatalf("route files left %v, want %v", got, want)
	}

	f.events = nil
	f.worker.block = "g2"
	f.worker.prune()
	if want := []string{"prune"}; !slices.Equal(f.events, want) {
		t.Fatalf("a block without route files: events %v, want %v", f.events, want)
	}
}

// The route file is rendered for the host the unit names (--lbalthost), which
// is the host's key in services.yml, never one guessed from the machine's
// host name. A worker without one starts no generation.
func TestLbAltWorkerRendersForTheHostItsUnitNames(t *testing.T) {
	f := newLbAltWorkerFixture(t)
	f.worker.lbAltHost = "edge-b.example"
	f.worker.lbAltInterfaces = parseLbAltWorkerInterfaces("eth1:warpeth1", lbAltFakeNetworkInterfaces(lbAltFakeEdgeAAddresses))
	if _, err := f.worker.startContainer(map[int]int{80: f.statusPort, 443: 7301, 4053: 7302}); err != nil {
		t.Fatal(err)
	}
	if len(f.routeInputs) != 1 || f.routeInputs[0].host != "edge-b.example" {
		t.Fatalf("rendered for %v, want edge-b.example", f.routeInputs)
	}

	f = newLbAltWorkerFixture(t)
	f.worker.lbAltHost = ""
	if _, err := f.worker.startContainer(map[int]int{80: f.statusPort, 443: 7301, 4053: 7302}); err == nil || !strings.Contains(err.Error(), "--lbalthost") {
		t.Fatalf("start error = %v, want the missing host", err)
	}
	if len(f.dockerRunArgs) != 0 || len(f.routeInputs) != 0 {
		t.Fatalf("a worker without a host started %d containers and rendered %d tables", len(f.dockerRunArgs), len(f.routeInputs))
	}
}

// With every lb interface of the env lb_alt, the lb version poll of `deploy
// lb` does not run: only connect's front answers the lb status route, with
// its own version, so the poll could only run to its timeout. It says why.
func TestLbAltLbVersionPollIsSkippedWithNoInterfaceOnNginx(t *testing.T) {
	env := setupTestVault(t, lbAltUnitsYaml(lbAltUnitsSettings{connect: "true"}))
	if nginxInterfaces := services.NginxLbInterfaces(getServicesConfig(env).Latest()); len(nginxInterfaces) != 0 {
		t.Fatalf("the fixture leaves %v on nginx, so this case checks nothing", nginxInterfaces)
	}
	output := &strings.Builder{}
	previousOut := Out.Writer()
	Out.SetOutput(output)
	t.Cleanup(func() { Out.SetOutput(previousOut) })

	if recovered := lbAltRecoverPanic(func() {
		pollLbServiceStatusUntil(env, "lb", "2.0.0", 0)
	}); recovered != nil {
		t.Fatalf("the lb version poll ran: %v", recovered)
	}
	if !strings.Contains(output.String(), "Will not poll the lb version: no lb interface of test is left on nginx") {
		t.Fatalf("the skip was not said:\n%s", output.String())
	}
}

// The lb version polls of `deploy lb` and `ls versions` leave out the samples
// connect's lb_alt front answers on an lb_alt interface, which carry connect's
// version: an lb deploy converges on the nginx samples alone. Samples that are
// all the front's are no evidence, so the poll does not converge on them.
func TestLbAltFrontSamplesAreLeftOutOfLbVersionPolls(t *testing.T) {
	nginx := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"version":"2.0.0","status":"ok"}`)
	}))
	t.Cleanup(nginx.Close)
	front := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"version":"9.9.9","status":"ok","front":"lbalt"}`+"\n")
	}))
	t.Cleanup(front.Close)

	statusVersions := sampleStatusVersions(2, []string{nginx.URL, front.URL})
	if want := map[semver.Version]int{*semver.New("2.0.0"): 2}; !reflect.DeepEqual(statusVersions.versions, want) {
		t.Fatalf("sampled versions %v, want %v", statusVersions.versions, want)
	}
	if len(statusVersions.errors) != 0 || statusVersions.lbAltFrontCount != 2 {
		t.Fatalf("errors %v, front samples %d", statusVersions.errors, statusVersions.lbAltFrontCount)
	}

	previousOut := Out.Writer()
	Out.SetOutput(&strings.Builder{})
	t.Cleanup(func() { Out.SetOutput(previousOut) })
	if err := pollStatusUntil("test", "lb", 2, []string{nginx.URL, front.URL}, "2.0.0", 0); err != nil {
		t.Fatalf("lb poll with front samples: %s", err)
	}
	if err := pollStatusUntil("test", "lb", 2, []string{front.URL}, "2.0.0", 0); err == nil {
		t.Fatal("an lb poll converged on front samples alone")
	}
}
