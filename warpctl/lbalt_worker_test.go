package main

// Tests of the lb_alt run worker paths (lbalt_worker.go; server/LBALT-IMPL.md
// §2.2, §2.4-§2.6): the route file of a connect generation, the deploy's
// readiness, chains and cutover order, the routing-only lb unit, the rollback
// removal of a split, route file removal, and the lb version polls.

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
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
	t              *testing.T
	home           string
	worker         *RunWorker
	statusPort     int
	events         []string
	routeInputs    []*lbAltRouteInputs
	writtenRoutes  []string
	readinessCalls []lbAltReadinessCall
	chainsCalls    []lbAltChainsCall
	dockerRunArgs  [][]string
	renderErr      error
	readinessErr   error
	chainsErr      error
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
			f.events = append(f.events, "stop")
			return nil
		case strings.Contains(args, "iptables ") && (strings.Contains(args, " -C ") || strings.Contains(args, " -D ")):
			return errors.New("fixture rule absent")
		case strings.Contains(args, "iptables ") && strings.Contains(args, " -I ") && strings.Contains(args, " DNAT "):
			if !slices.Contains(f.events, "cutover") {
				f.events = append(f.events, "cutover")
			}
			return nil
		case strings.Contains(args, "iptables "):
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
			f.events = append(f.events, "start")
			return []byte(lbAltFixtureContainerId), nil
		}
		t.Errorf("unexpected fixture output command: %v", cmd.Args)
		return nil, fmt.Errorf("unexpected fixture output command: %v", cmd.Args)
	}
	runQuietFunc = func(cmd *exec.Cmd) (commandOutput, error) {
		args := strings.Join(cmd.Args, " ")
		if strings.HasPrefix(args, "netstat ") || strings.Contains(args, "conntrack ") {
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
	ops.hostname = func() (string, error) {
		return "edge-a", nil
	}
	ops.renderRouteTable = func(inputs *lbAltRouteInputs) (*LbAltRouteTable, error) {
		f.events = append(f.events, "render")
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
		f.events = append(f.events, "readiness")
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
		{protocol: "udp", publicPort: 443, internalPort: 7301},
		{protocol: "udp", publicPort: 4053, internalPort: 7302},
		{protocol: "udp", publicPort: 53, internalPort: 7302},
	}
	if chainsCall.env != "test" || chainsCall.block != "g1" ||
		!reflect.DeepEqual(chainsCall.splitInterfaces, wantSplitInterfaces) || !reflect.DeepEqual(chainsCall.targets, wantTargets) {
		t.Fatalf("chains of %s %s on\n%v\nwith\n%v", chainsCall.env, chainsCall.block, chainsCall.splitInterfaces, chainsCall.targets)
	}
}

// A candidate that never reports lb_alt ready gets no chain and no cutover,
// and is stopped: no flow ever reached it.
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
}

// When the chains fail, the pool cutover does not run, and the candidate,
// which some chain may already point at, keeps running.
func TestLbAltWorkerOverlapKeepsTheCandidateWhenItsChainsFail(t *testing.T) {
	f := newLbAltWorkerFixture(t)
	f.chainsErr = errors.New("fixture chain failure")
	err := f.worker.deployContainerOverlap(true, nil)
	if err == nil || !strings.Contains(err.Error(), "fixture chain failure") {
		t.Fatalf("deploy error = %v, want the chain failure", err)
	}
	if want := []string{"render", "start", "readiness", "chains"}; !slices.Equal(f.events, want) {
		t.Fatalf("deploy events %v, want %v", f.events, want)
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

// Rolling an interface back to nginx (D18): the nginx lb's cutover puts its
// public DNAT back first, and only then is the interface's split removed. A
// failed removal stays pending and is retried from the poll loop once due,
// not before, until it succeeds.
func TestLbAltWorkerNginxCutoverRemovesTheSplitAfterItsDnat(t *testing.T) {
	f := newLbAltLbFixture(t, false)
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
	f.removeErr = nil
	f.worker.retryLbAltWorkerSplitRemovalIfDue(attempted.Add(defaultLbAltWorkerSettings().splitRemovalRetryTimeout + time.Second))
	if len(f.removeCalls) != 2 || f.worker.lbAltState.splitRemovalPending {
		t.Fatalf("removals %v, pending %t after the due retry", f.removeCalls, f.worker.lbAltState.splitRemovalPending)
	}
	f.worker.retryLbAltWorkerSplitRemovalIfDue(attempted.Add(time.Hour))
	if len(f.removeCalls) != 2 {
		t.Fatalf("a removed split was removed again: %v", f.removeCalls)
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
	worker.reconcileLbAltWorkerSplit()
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
// no ports, and tries again at the next reconcile.
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
	worker.reconcileLbAltWorkerSplit()
	worker.reconcileLbAltWorkerSplit()
	if reconciles != 0 || worker.lbAltState.splitPublicPorts != nil {
		t.Fatalf("reconciled %d times with public ports %v", reconciles, worker.lbAltState.splitPublicPorts)
	}
	if strings.Count(errOutput.String(), "lb_alt is not in effect on it there") != 2 {
		t.Fatalf("the skew was not logged on each reconcile:\n%s", errOutput.String())
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
			f.events = append(f.events, "prune")
		}
		return previousRun(cmd)
	}
	f.worker.lbAltOps.containerNames = func(ctx context.Context, containerNamePrefix string) ([]string, error) {
		f.events = append(f.events, "list")
		listedPrefixes = append(listedPrefixes, containerNamePrefix)
		return []string{"test-connect-g1-1.0.0-2000"}, nil
	}
	f.worker.lbAltOps.removeRouteFile = func(warpHome string, containerName string) error {
		f.events = append(f.events, "remove "+containerName)
		removed = append(removed, containerName)
		return os.RemoveAll(filepath.Join(warpHome, lbAltRouteHostDirName, containerName))
	}

	f.worker.prune()
	if want := []string{"prune", "list", "remove test-connect-g1-1.0.0-1000"}; !slices.Equal(f.events, want) {
		t.Fatalf("prune events %v, want %v", f.events, want)
	}
	if !slices.Equal(listedPrefixes, []string{"test-connect-g1-"}) {
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

// The services config host of a block is the lb host named like the machine,
// exactly or by first label, and otherwise the one lb host whose lb interfaces
// and docker networks are exactly the block's. Anything else is an error, not
// a guess.
func TestLbAltWorkerFindsItsServicesHost(t *testing.T) {
	env := setupTestVault(t, lbAltUnitsYaml(lbAltUnitsSettings{connect: "true"}))
	version := getServicesConfig(env).Latest()
	interfaces := func(interfaceNetworks string) []*lbAltWorkerInterface {
		lbAltInterfaces := []*lbAltWorkerInterface{}
		for _, interfaceNetwork := range strings.Split(interfaceNetworks, ";") {
			interfaceName, dockerNetworkName, _ := strings.Cut(interfaceNetwork, ":")
			lbAltInterfaces = append(lbAltInterfaces, &lbAltWorkerInterface{
				interfaceName: interfaceName,
				dockerNetwork: &DockerNetwork{networkName: dockerNetworkName},
			})
		}
		return lbAltInterfaces
	}
	for _, find := range []struct {
		hostname   string
		interfaces string
		want       string
	}{
		{hostname: "edge-a.example", interfaces: "eth1:warpeth1", want: "edge-a.example"},
		{hostname: "edge-a", interfaces: "eth1:warpeth1", want: "edge-a.example"},
		{hostname: "edge-b.example.net", interfaces: "eth1:warpeth1;eth2:warpeth2", want: "edge-b.example"},
		{hostname: "machine-7", interfaces: "eth2:warpeth2;eth1:warpeth1", want: "edge-a.example"},
		{hostname: "machine-7", interfaces: "eth1:warpeth1", want: "edge-b.example"},
		{hostname: "machine-7", interfaces: "eth9:warpeth9", want: ""},
	} {
		host, err := lbAltWorkerHost(version, find.hostname, interfaces(find.interfaces))
		if host != find.want || (err == nil) != (find.want != "") {
			t.Errorf("%s with %s: host %q, error %v, want %q", find.hostname, find.interfaces, host, err, find.want)
		}
	}

	twins := &services.ServicesConfigVersion{
		Lb: &services.LbConfig{
			Interfaces: map[string]map[string]*services.LbBlock{
				"edge-a.one.example": {"eth1": {DockerNetwork: "warpeth1"}},
				"edge-a.two.example": {"eth1": {DockerNetwork: "warpeth1"}},
			},
		},
	}
	if host, err := lbAltWorkerHost(twins, "edge-a", interfaces("eth1:warpeth1")); err == nil {
		t.Fatalf("two identical hosts named like the machine resolved to %s", host)
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
