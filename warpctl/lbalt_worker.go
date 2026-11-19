package main

// The lb_alt side of warpctl's units and run workers (server/LBALT-IMPL.md
// §2.2-§2.6; LBALT.md D2, D5, D11, D13, D18): connect fronts an lb interface
// itself, in place of an nginx lb.
//
//   - Units. The lb unit of an interface lb_alt is in effect on gets
//     --lbalt=true and the lb_alt service's blocks (--lbaltblocks). It stays a
//     non-transparent lb unit, so the host keeps its plain service units and
//     gets no per-interface ones. The lb_alt service's units on an lb_alt host
//     get every non-transparent lb interface of the host (--lbaltnets),
//     whatever each interface's override, so flipping one interface changes
//     only that interface's lb unit and never redeploys connect.
//   - The lb unit of an lb_alt interface is routing-only, like a transparent
//     one, and also reconciles the interface's split across the blocks
//     (w-split's reconcileLbAltSplit) at its start and on every 30 s routing
//     reconcile. An lb unit back on nginx removes the split its interface left,
//     once nginx's public DNAT is back (D18).
//   - A connect block on an lb_alt host starts each generation with its own
//     route file (w-route), mounted read-only and named by
//     WARP_LBALT_ROUTE_FILE and WARP_GENERATION. Its deploy switches traffic to
//     a candidate only after the candidate's private status reports that
//     generation, that file and every public socket ready (§2.4). It then
//     points the block's own chain on every bound interface at the candidate
//     (§2.5), and only then runs the ordinary cutover.
//   - A route file goes when its container does: the block's prune removes the
//     files of containers that are gone.
//
// The worker reaches the services config, the route renderer, the split and
// docker's container names through lbAltWorkerOps, which tests replace. Like
// the rest of RunWorker, these methods run on the worker's Run goroutine.

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/docopt/docopt-go"

	"github.com/urnetwork/warp/services"
)

// The service ports connect's lb_alt front listens on (server/LBALT-IMPL.md
// §2.1 listen, §2.3): its port-80 handler on service port 80, tls on tcp and
// quic on udp of service port 443, and whodis on service port 4053. These are
// values of the route file contract.
const (
	lbAltWorkerHttpServicePort   = 80
	lbAltWorkerHttpsServicePort  = 443
	lbAltWorkerQuicServicePort   = 443
	lbAltWorkerWhodisServicePort = 4053
)

// The lb type of the lb_alt service's tcp 443 port block (§2.3). It is
// neither "http" nor "stream", so the nginx http and stream generators leave
// the port alone.
const lbAltWorkerTcpLbType = "tcp"

// Tunables of the lb_alt worker paths.
type lbAltWorkerSettings struct {
	// How long a deploy polls a candidate connect generation's private status
	// for lb_alt readiness (§2.4) before the deploy fails and the candidate is
	// stopped. Connect binds every public socket before its private status
	// first answers, so a healthy generation is ready at the first poll; this
	// bounds one that never gets there, as long as the candidate status poll
	// that runs before it.
	readinessTimeout time.Duration
	// How long an lb unit back on nginx waits before it retries removing its
	// interface's split after a failed removal. Until a removal succeeds, the
	// split still sends udp 4053 to connect. Non-positive retries on every
	// poll.
	splitRemovalRetryTimeout time.Duration
}

// The defaults, a new instance on every call.
func defaultLbAltWorkerSettings() *lbAltWorkerSettings {
	return &lbAltWorkerSettings{
		readinessTimeout:         120 * time.Second,
		splitRemovalRetryTimeout: 30 * time.Second,
	}
}

// What the lb_alt worker paths call outside the worker: the services config,
// the machine's host name, the route file (w-route), the split (w-split) and
// docker's container names. defaultLbAltWorkerOps calls the real ones; tests
// replace single functions.
type lbAltWorkerOps struct {
	loadServicesConfig func(vaultHome string, env string) (*services.ServicesConfig, error)
	hostname           func() (string, error)
	renderRouteTable   func(inputs *lbAltRouteInputs) (*LbAltRouteTable, error)
	writeRouteFile     func(warpHome string, containerName string, table *LbAltRouteTable) (hostPath string, revision string, err error)
	removeRouteFile    func(warpHome string, containerName string) error
	reconcileSplit     func(ctx context.Context, config *lbAltSplitConfig) error
	removeSplit        func(ctx context.Context, env string, interfaceName string) error
	writeBlockChains   func(ctx context.Context, env string, block string, splitInterfaces []lbAltSplitInterface, targets []lbAltBlockTarget) error
	pollReadiness      func(ctx context.Context, statusUrl string, generation string, revision string, expected []lbAltExpectedSocket, timeout time.Duration) error
	// the names of the containers, running or not, whose names start with the
	// prefix
	containerNames func(ctx context.Context, containerNamePrefix string) ([]string, error)
}

// The real operations, a new instance on every call.
func defaultLbAltWorkerOps() *lbAltWorkerOps {
	return &lbAltWorkerOps{
		loadServicesConfig: services.LoadServicesConfigFrom,
		hostname:           os.Hostname,
		renderRouteTable:   renderLbAltRouteTable,
		writeRouteFile:     writeLbAltRouteFile,
		removeRouteFile:    removeLbAltRouteFile,
		reconcileSplit:     reconcileLbAltSplit,
		removeSplit:        removeLbAltSplit,
		writeBlockChains:   writeLbAltBlockChains,
		pollReadiness:      pollLbAltReadiness,
		containerNames:     lbAltWorkerContainerNames,
	}
}

// Docker's names of the containers, running or not, whose names start with
// the prefix.
func lbAltWorkerContainerNames(ctx context.Context, containerNamePrefix string) ([]string, error) {
	out, err := retirementCommandOutput(ctx, docker(
		"ps", "-a",
		"-f", containerNamePrefixFilter(containerNamePrefix),
		"--format", "{{.Names}}",
	))
	if err != nil {
		return nil, err
	}
	containerNames := []string{}
	for _, line := range strings.Split(string(out), "\n") {
		if containerName := strings.TrimSpace(line); containerName != "" {
			containerNames = append(containerNames, containerName)
		}
	}
	return containerNames, nil
}

// What a worker's lb_alt paths keep between calls.
type lbAltWorkerState struct {
	// the generation startContainer last wrote a route file for, and the
	// file's revision, which the candidate's readiness must report
	candidateGeneration string
	candidateRevision   string
	// the public ports of an lb_alt lb unit's interface, once read from the
	// services config
	splitPublicPorts map[string][]int
	// an lb unit back on nginx still has to remove its interface's split, at
	// or after nextSplitRemoval
	splitRemovalPending bool
	nextSplitRemoval    time.Time
}

// The worker's lb_alt settings, the defaults when it was built without them.
func (self *RunWorker) getLbAltSettings() *lbAltWorkerSettings {
	if self.lbAltSettings != nil {
		return self.lbAltSettings
	}
	return defaultLbAltWorkerSettings()
}

// The worker's lb_alt operations, the real ones when it was built without
// them.
func (self *RunWorker) getLbAltOps() *lbAltWorkerOps {
	if self.lbAltOps != nil {
		return self.lbAltOps
	}
	return defaultLbAltWorkerOps()
}

// The worker's lifetime: the lb_alt calls end when the worker quits.
func (self *RunWorker) lbAltWorkerContext() context.Context {
	if self.quitEvent != nil {
		return self.quitEvent.Ctx
	}
	return context.Background()
}

// One lb interface a block of the lb_alt service binds on an lb_alt host
// (--lbaltnets).
type lbAltWorkerInterface struct {
	interfaceName string
	// the interface's own addresses, the public ones; ipv6 is nil when the
	// interface has none
	publicIpv4 *NetworkInterface
	publicIpv6 *NetworkInterface
	// the interface's docker network, whose bridge addresses the front's
	// public sockets bind
	dockerNetwork *DockerNetwork
}

// The interface as the split's block chains take it: its addresses in
// canonical form, and the public ports of the §2.3 table.
func (self *lbAltWorkerInterface) splitInterface() lbAltSplitInterface {
	splitInterface := lbAltSplitInterface{
		name:        self.interfaceName,
		publicPorts: lbAltWorkerPublicPorts(),
	}
	if self.publicIpv4 != nil {
		splitInterface.publicIpv4 = canonicalLbAltWorkerAddress(self.publicIpv4.interfaceIp)
	}
	if self.publicIpv6 != nil {
		splitInterface.publicIpv6 = canonicalLbAltWorkerAddress(self.publicIpv6.interfaceIp)
	}
	if self.dockerNetwork != nil && self.dockerNetwork.ipv4 != nil {
		splitInterface.bridgeIpv4 = canonicalLbAltWorkerAddress(self.dockerNetwork.ipv4.interfaceIp)
	}
	if self.dockerNetwork != nil && self.dockerNetwork.ipv6 != nil {
		splitInterface.bridgeIpv6 = canonicalLbAltWorkerAddress(self.dockerNetwork.ipv6.interfaceIp)
	}
	return splitInterface
}

// An address in canonical netip text, the form connect reports its sockets in
// (§2.4); text that does not parse as it is.
func canonicalLbAltWorkerAddress(address string) string {
	addr, err := netip.ParseAddr(address)
	if err != nil {
		return address
	}
	return addr.Unmap().String()
}

// One row of the §2.3 table: a public (protocol, port) of an lb_alt interface,
// and the service port whose internal port the front's socket for it listens
// on.
type lbAltWorkerPublicTarget struct {
	protocol    string
	publicPort  int
	servicePort int
}

// The §2.3 table, in its order. Public udp 53 is whodis aliased to 4053.
func lbAltWorkerPublicTargets() []lbAltWorkerPublicTarget {
	return []lbAltWorkerPublicTarget{
		{protocol: "tcp", publicPort: 80, servicePort: lbAltWorkerHttpServicePort},
		{protocol: "tcp", publicPort: 443, servicePort: lbAltWorkerHttpsServicePort},
		{protocol: "udp", publicPort: 443, servicePort: lbAltWorkerQuicServicePort},
		{protocol: "udp", publicPort: 4053, servicePort: lbAltWorkerWhodisServicePort},
		{protocol: "udp", publicPort: 53, servicePort: lbAltWorkerWhodisServicePort},
	}
}

// The public ports of the §2.3 table by protocol, each sorted.
func lbAltWorkerPublicPorts() map[string][]int {
	publicPorts := map[string][]int{
		"tcp": {},
		"udp": {},
	}
	for _, publicTarget := range lbAltWorkerPublicTargets() {
		publicPorts[publicTarget.protocol] = append(publicPorts[publicTarget.protocol], publicTarget.publicPort)
	}
	for _, ports := range publicPorts {
		slices.Sort(ports)
	}
	return publicPorts
}

// One socket the front binds on each bridge address: a protocol, and the
// service port whose internal port it listens on.
type lbAltWorkerListenSocket struct {
	protocol    string
	servicePort int
}

// The front's sockets on each bridge address: every (protocol, service port)
// of the §2.3 table once, in its order. That is tcp on the http and https
// listen ports, and udp on the quic and whodis listen ports.
func lbAltWorkerListenSockets() []lbAltWorkerListenSocket {
	listenSockets := []lbAltWorkerListenSocket{}
	for _, publicTarget := range lbAltWorkerPublicTargets() {
		listenSocket := lbAltWorkerListenSocket{
			protocol:    publicTarget.protocol,
			servicePort: publicTarget.servicePort,
		}
		if !slices.Contains(listenSockets, listenSocket) {
			listenSockets = append(listenSockets, listenSocket)
		}
	}
	return listenSockets
}

// The DNATs of the block's chain (§2.5): every row of the §2.3 table, to the
// generation's internal port for the row's service port. An error when
// WARP_PORTS lacks one of them.
func lbAltWorkerBlockTargets(servicePortsToInternalPort map[int]int) ([]lbAltBlockTarget, error) {
	blockTargets := []lbAltBlockTarget{}
	for _, publicTarget := range lbAltWorkerPublicTargets() {
		internalPort, ok := servicePortsToInternalPort[publicTarget.servicePort]
		if !ok {
			return nil, fmt.Errorf("WARP_PORTS has no service port %d, which the lb_alt front listens on", publicTarget.servicePort)
		}
		blockTargets = append(blockTargets, lbAltBlockTarget{
			protocol:     publicTarget.protocol,
			publicPort:   publicTarget.publicPort,
			internalPort: internalPort,
		})
	}
	return blockTargets, nil
}

// --lbaltblocks: the blocks and weights in the given order (the lb_alt
// service's, in services.ServiceBlockWeights order), block:weight joined by
// semicolons.
func formatLbAltWorkerBlocks(blockWeights []services.BlockWeight) string {
	blockWeightStrs := []string{}
	for _, blockWeight := range blockWeights {
		blockWeightStrs = append(blockWeightStrs, fmt.Sprintf("%s:%d", blockWeight.Block, blockWeight.Weight))
	}
	return strings.Join(blockWeightStrs, ";")
}

// Parses --lbaltblocks. Panics on a malformed entry, a negative weight or a
// block listed twice, as the other flags do.
func parseLbAltWorkerBlocks(blockWeightsStr string) []services.BlockWeight {
	blockWeights := []services.BlockWeight{}
	listedBlocks := map[string]bool{}
	for _, blockWeightStr := range strings.Split(blockWeightsStr, ";") {
		block, weightStr, ok := strings.Cut(blockWeightStr, ":")
		if !ok || block == "" {
			panic(fmt.Sprintf("lb_alt block must be block:weight (%s)", blockWeightStr))
		}
		weight, err := strconv.Atoi(weightStr)
		if err != nil || weight < 0 {
			panic(fmt.Sprintf("lb_alt block weight must be a non-negative int (%s)", blockWeightStr))
		}
		if listedBlocks[block] {
			panic(fmt.Sprintf("lb_alt block repeats %s", block))
		}
		listedBlocks[block] = true
		blockWeights = append(blockWeights, services.BlockWeight{
			Block:  block,
			Weight: weight,
		})
	}
	return blockWeights
}

// --lbaltnets: every non-transparent lb interface of the host and its docker
// network, iface:docker_network joined by semicolons, sorted by interface
// (services.LbInterfaceNames).
func formatLbAltWorkerNetworks(version *services.ServicesConfigVersion, host string) string {
	interfaceNetworkStrs := []string{}
	for _, interfaceName := range services.LbInterfaceNames(version, host) {
		dockerNetworkName := ""
		if lbBlock := version.Lb.Interfaces[host][interfaceName]; lbBlock != nil {
			dockerNetworkName = lbBlock.DockerNetwork
		}
		interfaceNetworkStrs = append(interfaceNetworkStrs, fmt.Sprintf("%s:%s", interfaceName, dockerNetworkName))
	}
	return strings.Join(interfaceNetworkStrs, ";")
}

// Parses --lbaltnets. Each interface and its docker network is looked up the
// way --rttable and --dockernet are: each needs exactly one IPv4 address, and
// a failed lookup panics. More than one global IPv6 address does not panic:
// chooseLbAltWorkerAddress picks one. Panics on a malformed entry, or an
// interface or docker network listed twice.
func parseLbAltWorkerInterfaces(
	interfaceNetworksStr string,
	loadNetworkInterfaces func(string) ([]*NetworkInterface, []*NetworkInterface, error),
) []*lbAltWorkerInterface {
	lbAltInterfaces := []*lbAltWorkerInterface{}
	listedInterfaceNames := map[string]bool{}
	listedDockerNetworkNames := map[string]bool{}
	for _, interfaceNetworkStr := range strings.Split(interfaceNetworksStr, ";") {
		interfaceName, dockerNetworkName, ok := strings.Cut(interfaceNetworkStr, ":")
		if !ok || interfaceName == "" || dockerNetworkName == "" {
			panic(fmt.Sprintf("lb_alt network must be interface:docker_network (%s)", interfaceNetworkStr))
		}
		if listedInterfaceNames[interfaceName] {
			panic(fmt.Sprintf("lb_alt network repeats the interface %s", interfaceName))
		}
		listedInterfaceNames[interfaceName] = true
		// two interfaces on one bridge would bind its addresses twice
		if listedDockerNetworkNames[dockerNetworkName] {
			panic(fmt.Sprintf("lb_alt network repeats the docker network %s", dockerNetworkName))
		}
		listedDockerNetworkNames[dockerNetworkName] = true
		publicIpv4, publicIpv6 := lbAltWorkerInterfaceAddresses(interfaceName, loadNetworkInterfaces)
		bridgeIpv4, bridgeIpv6 := lbAltWorkerInterfaceAddresses(dockerNetworkName, loadNetworkInterfaces)
		lbAltInterfaces = append(lbAltInterfaces, &lbAltWorkerInterface{
			interfaceName: interfaceName,
			publicIpv4:    publicIpv4,
			publicIpv6:    publicIpv6,
			dockerNetwork: &DockerNetwork{
				networkName: dockerNetworkName,
				ipv4:        bridgeIpv4,
				ipv6:        bridgeIpv6,
			},
		})
	}
	return lbAltInterfaces
}

// An interface's IPv4 address, which it must have exactly one of, as
// requireNetworkInterfaceIpv4OptionalIpv6 requires, and its IPv6 address, nil
// when it has none. Unlike requireNetworkInterfaceIpv4OptionalIpv6, several
// global IPv6 addresses pick one rather than panic: a block binds every
// interface of its host, so one interface's extra address must not stop
// every block on the host.
func lbAltWorkerInterfaceAddresses(
	interfaceName string,
	loadNetworkInterfaces func(string) ([]*NetworkInterface, []*NetworkInterface, error),
) (*NetworkInterface, *NetworkInterface) {
	ipv4NetworkInterfaces, ipv6NetworkInterfaces, err := loadNetworkInterfaces(interfaceName)
	if err != nil {
		panic(err)
	}
	switch len(ipv4NetworkInterfaces) {
	case 0:
		panic(fmt.Errorf("Could not map docker interface %s to interface", interfaceName))
	case 1:
	default:
		panic(fmt.Errorf("More than one v4 network attached to interface %s", interfaceName))
	}
	return ipv4NetworkInterfaces[0], chooseLbAltWorkerAddress(interfaceName, ipv6NetworkInterfaces)
}

// One address of an interface's addresses of one family: the only one, or,
// when there are several, the lowest in address order, which a restart picks
// again. Several are logged, since only the one is used. Nil when there are
// none.
func chooseLbAltWorkerAddress(interfaceName string, networkInterfaces []*NetworkInterface) *NetworkInterface {
	switch len(networkInterfaces) {
	case 0:
		return nil
	case 1:
		return networkInterfaces[0]
	}
	chosen := slices.MinFunc(networkInterfaces, func(a *NetworkInterface, b *NetworkInterface) int {
		aAddr, aErr := netip.ParseAddr(a.interfaceIp)
		bAddr, bErr := netip.ParseAddr(b.interfaceIp)
		if aErr == nil && bErr == nil {
			return aAddr.Compare(bAddr)
		}
		return strings.Compare(a.interfaceIp, b.interfaceIp)
	})
	Err.Printf(
		"lb_alt: interface %s has %d addresses of one family; using the lowest, %s\n",
		interfaceName,
		len(networkInterfaces),
		chosen.interfaceIp,
	)
	return chosen
}

// The lb_alt flags of `service run` (§2.2), as serviceRun reads them:
//   - --lbalt=true on the lb unit of an lb_alt interface, which needs the
//     unit's routing table and --lbaltblocks;
//   - --lbaltblocks, block:weight;..., only with --lbalt=true;
//   - --lbaltnets on a block of the lb_alt service, never on an lb
//     (parseLbAltWorkerInterfaces).
//
// Panics on a malformed or misplaced flag, as the other flags do.
func parseLbAltWorkerFlags(
	opts docopt.Opts,
	service string,
	routingTable *RoutingTable,
	loadNetworkInterfaces func(string) ([]*NetworkInterface, []*NetworkInterface, error),
) (lbAlt bool, lbAltInterfaces []*lbAltWorkerInterface, lbAltBlocks []services.BlockWeight) {
	if lbAltStr, err := opts.String("--lbalt"); err == nil {
		lbAlt, err = strconv.ParseBool(lbAltStr)
		if err != nil {
			panic(fmt.Sprintf("--lbalt must be true or false (%s)", lbAltStr))
		}
	}
	if blockWeightsStr, err := opts.String("--lbaltblocks"); err == nil {
		if !lbAlt {
			panic("--lbaltblocks needs --lbalt=true")
		}
		lbAltBlocks = parseLbAltWorkerBlocks(blockWeightsStr)
	}
	if lbAlt {
		if service != "lb" {
			panic(fmt.Sprintf("--lbalt is for an lb unit, not %s", service))
		}
		if routingTable == nil {
			panic("--lbalt needs the interface's routing table (--rttable)")
		}
		if len(lbAltBlocks) == 0 {
			panic("--lbalt needs the blocks to split across (--lbaltblocks)")
		}
	}
	if interfaceNetworksStr, err := opts.String("--lbaltnets"); err == nil {
		if service == "lb" {
			panic("--lbaltnets is for the blocks of the lb_alt service, not an lb")
		}
		lbAltInterfaces = parseLbAltWorkerInterfaces(interfaceNetworksStr, loadNetworkInterfaces)
	}
	return
}

// The lb_alt flags of an lb interface's unit: when lb_alt is in effect on the
// interface, --lbalt=true and the lb_alt service's blocks (§2.2); otherwise
// none, so an nginx interface's unit is what it was. The unit keeps
// --transparent=false, its routing table and mark, and its lb port blocks,
// which a rollback to nginx needs.
func (self *SystemdUnits) lbAltLbUnitArgs(host string, interfaceName string) []string {
	version := self.servicesConfig.Versions[0]
	if !services.IsLbAltInterface(version, host, interfaceName) {
		return nil
	}
	lbAltService, ok := services.LbAltService(version)
	if !ok {
		// validation refuses an lb_alt override with no lb_alt service
		panic(fmt.Errorf("%s %s is lb_alt, but no service declares lb_alt", host, interfaceName))
	}
	return []string{
		"--lbalt=true",
		fmt.Sprintf(`--lbaltblocks="%s"`, formatLbAltWorkerBlocks(services.ServiceBlockWeights(version.Services[lbAltService]))),
	}
}

// The lb_alt flag of a block unit: on an lb_alt host, the blocks of the
// lb_alt service get --lbaltnets, every non-transparent lb interface of the
// host, whatever each interface's override (§2.2). Other services get none.
func (self *SystemdUnits) lbAltServiceUnitArgs(host string, service string) []string {
	version := self.servicesConfig.Versions[0]
	lbAltService, ok := services.LbAltService(version)
	if !ok || service != lbAltService || !services.IsLbAltHost(version, host) {
		return nil
	}
	return []string{
		fmt.Sprintf(`--lbaltnets="%s"`, formatLbAltWorkerNetworks(version, host)),
	}
}

// Whether the worker is an lb unit that runs routing-only: on a transparent
// interface, where no lb runs, and on an lb_alt interface, where connect owns
// the public ports. Either way it polls no version and deploys no container.
func (self *RunWorker) isRoutingOnlyLb() bool {
	return self.service == "lb" && (self.transparent || self.lbAlt)
}

// The routing-only loop's reconcile: the interface's routing table, policy
// rules and masquerade, and on an lb_alt interface its split. Nil, as before,
// for a unit without a routing table.
func (self *RunWorker) routingOnlyReconcile() func() {
	if self.routingTable == nil {
		return nil
	}
	return func() {
		self.reconcileRoutingTableIfDue(time.Now())
		self.reconcileLbAltWorkerSplit()
	}
}

// Reconciles an lb_alt interface's split (w-split), at the routing-only
// loop's start and on each of its reconciles. A failure is logged and left to
// the next reconcile; the rules in place keep serving meanwhile. Nothing on
// an interface that is not lb_alt.
func (self *RunWorker) reconcileLbAltWorkerSplit() {
	if !self.lbAlt {
		return
	}
	splitConfig, err := self.lbAltWorkerSplitConfig()
	if err != nil {
		Err.Printf("lb_alt split of %s not reconciled: %s\n", self.block, err)
		return
	}
	if err := self.getLbAltOps().reconcileSplit(self.lbAltWorkerContext(), splitConfig); err != nil {
		Err.Printf("lb_alt split of %s failed to reconcile: %s\n", self.block, err)
	}
}

// The lb_alt interface's split as its lb unit reconciles it: the public
// addresses from the interface (the routing table's, which picks up a late
// IPv6), the bridge addresses from its docker network, the public ports from
// the host's services config, and the blocks from --lbaltblocks.
func (self *RunWorker) lbAltWorkerSplitConfig() (*lbAltSplitConfig, error) {
	if self.routingTable == nil {
		return nil, errors.New("the lb unit has no routing table")
	}
	publicPorts, err := self.lbAltWorkerSplitPublicPorts()
	if err != nil {
		return nil, err
	}
	splitInterface := lbAltSplitInterface{
		name:        self.routingTable.interfaceName,
		publicPorts: publicPorts,
	}
	if self.routingTable.ipv4 != nil {
		splitInterface.publicIpv4 = canonicalLbAltWorkerAddress(self.routingTable.ipv4.interfaceIp)
	}
	if self.routingTable.ipv6 != nil {
		splitInterface.publicIpv6 = canonicalLbAltWorkerAddress(self.routingTable.ipv6.interfaceIp)
	}
	if self.dockerNetwork != nil && self.dockerNetwork.ipv4 != nil {
		splitInterface.bridgeIpv4 = canonicalLbAltWorkerAddress(self.dockerNetwork.ipv4.interfaceIp)
	}
	if self.dockerNetwork != nil && self.dockerNetwork.ipv6 != nil {
		splitInterface.bridgeIpv6 = canonicalLbAltWorkerAddress(self.dockerNetwork.ipv6.interfaceIp)
	}
	return &lbAltSplitConfig{
		env:            self.env,
		splitInterface: splitInterface,
		blockWeights:   slices.Clone(self.lbAltBlocks),
	}, nil
}

// The public ports of the lb unit's interface (services.LbAltPublicPorts),
// read from the host's services config once: every input to them is also an
// input to the lb unit, whose change restarts the worker. Until the config
// loads, and has ports for the interface, which it has only while lb_alt is in
// effect on the interface there, an error, and nothing is kept.
func (self *RunWorker) lbAltWorkerSplitPublicPorts() (map[string][]int, error) {
	if self.lbAltState.splitPublicPorts != nil {
		return self.lbAltState.splitPublicPorts, nil
	}
	interfaceName := self.routingTable.interfaceName
	host, ok := strings.CutSuffix(self.block, "-"+interfaceName)
	if !ok || host == "" {
		return nil, fmt.Errorf("lb block %s does not end with its interface %s", self.block, interfaceName)
	}
	servicesConfig, err := self.getLbAltOps().loadServicesConfig(self.warpState.warpSettings.RequireVaultHome(), self.env)
	if err != nil {
		return nil, err
	}
	publicPorts := services.LbAltPublicPorts(servicesConfig.Latest(), host, interfaceName)
	if len(publicPorts["tcp"]) == 0 && len(publicPorts["udp"]) == 0 {
		return nil, fmt.Errorf("the services config has no lb_alt public ports for %s %s: lb_alt is not in effect on it there", host, interfaceName)
	}
	self.lbAltState.splitPublicPorts = publicPorts
	return publicPorts, nil
}

// Called once an lb unit on nginx has put its interface's public DNAT back on
// nginx (redirect). Removes the split the interface's lb_alt mode left, which
// until then still sends udp 4053, and anything else nginx does not take
// first, to connect (D18). Most cutovers find no split, which w-split treats
// as removed. A failure is retried from the poll loop
// (retryLbAltWorkerSplitRemovalIfDue).
func (self *RunWorker) removeLbAltWorkerSplitAfterCutover() {
	if self.service != "lb" || self.lbAlt || self.routingTable == nil || !self.hostNetworking {
		return
	}
	self.lbAltState.splitRemovalPending = true
	self.lbAltState.nextSplitRemoval = time.Time{}
	self.retryLbAltWorkerSplitRemovalIfDue(time.Now())
}

// Removes the interface's split when a removal is pending and due.
func (self *RunWorker) retryLbAltWorkerSplitRemovalIfDue(now time.Time) {
	if !self.lbAltState.splitRemovalPending || now.Before(self.lbAltState.nextSplitRemoval) {
		return
	}
	if err := self.getLbAltOps().removeSplit(self.lbAltWorkerContext(), self.env, self.routingTable.interfaceName); err != nil {
		Err.Printf("lb_alt split of %s not removed yet: %s\n", self.block, err)
		self.lbAltState.nextSplitRemoval = now.Add(self.getLbAltSettings().splitRemovalRetryTimeout)
		return
	}
	self.lbAltState.splitRemovalPending = false
}

// Whether the worker is a block of the lb_alt service on an lb_alt host, which
// binds the host's lb interfaces (--lbaltnets).
func (self *RunWorker) bindsLbAltInterfaces() bool {
	return 0 < len(self.lbAltInterfaces)
}

// Renders and writes the route file of a connect generation on an lb_alt host
// (§2.1, §2.2; D5), and returns the docker args that mount it read-only at
// lbAltRouteContainerPath and the env that names it and the generation. The
// generation, which is the container name, and the file's revision are kept
// for the candidate's readiness poll. Nothing for a worker that binds no lb
// interfaces.
func (self *RunWorker) prepareLbAltWorkerGeneration(containerName string, servicePortsToInternalPort map[int]int) ([]string, map[string]string, error) {
	self.lbAltState.candidateGeneration = ""
	self.lbAltState.candidateRevision = ""
	if !self.bindsLbAltInterfaces() {
		return nil, nil, nil
	}
	ops := self.getLbAltOps()
	servicesConfig, err := ops.loadServicesConfig(self.warpState.warpSettings.RequireVaultHome(), self.env)
	if err != nil {
		return nil, nil, fmt.Errorf("lb_alt route file of %s: %w", containerName, err)
	}
	routeInputs, err := self.lbAltWorkerRouteInputs(servicesConfig, containerName, servicePortsToInternalPort)
	if err != nil {
		return nil, nil, fmt.Errorf("lb_alt route file of %s: %w", containerName, err)
	}
	routeTable, err := ops.renderRouteTable(routeInputs)
	if err != nil {
		return nil, nil, fmt.Errorf("lb_alt route file of %s: %w", containerName, err)
	}
	hostPath, revision, err := ops.writeRouteFile(self.warpState.warpSettings.RequireWarpHome(), containerName, routeTable)
	if err != nil {
		return nil, nil, fmt.Errorf("lb_alt route file of %s: %w", containerName, err)
	}
	self.lbAltState.candidateGeneration = containerName
	self.lbAltState.candidateRevision = revision

	mountArgs := []string{
		"--mount",
		fmt.Sprintf("type=bind,source=%s,target=%s,readonly", hostPath, lbAltRouteContainerPath),
	}
	env := map[string]string{
		lbAltRouteFileEnvName:  lbAltRouteContainerPath,
		lbAltGenerationEnvName: containerName,
	}
	return mountArgs, env, nil
}

// What w-route renders a generation's table from: the services config, the
// services config host this worker runs on, every lb interface the worker
// binds with its docker network's bridge addresses and whether lb_alt is in
// effect on it, the generation's WARP_PORTS, and the warpservices bridge
// address the upstream blocks listen on.
func (self *RunWorker) lbAltWorkerRouteInputs(
	servicesConfig *services.ServicesConfig,
	containerName string,
	servicePortsToInternalPort map[int]int,
) (*lbAltRouteInputs, error) {
	version := servicesConfig.Latest()
	hostname, err := self.getLbAltOps().hostname()
	if err != nil {
		return nil, err
	}
	host, err := lbAltWorkerHost(version, hostname, self.lbAltInterfaces)
	if err != nil {
		return nil, err
	}
	if self.servicesDockerNetwork == nil || self.servicesDockerNetwork.ipv4 == nil {
		return nil, errors.New("the upstream needs the services network's IPv4 address")
	}
	interfaceInputs := []lbAltRouteInterfaceInput{}
	for _, lbAltInterface := range self.lbAltInterfaces {
		interfaceInput := lbAltRouteInterfaceInput{
			name:  lbAltInterface.interfaceName,
			lbAlt: services.IsLbAltInterface(version, host, lbAltInterface.interfaceName),
		}
		if lbAltInterface.dockerNetwork != nil && lbAltInterface.dockerNetwork.ipv4 != nil {
			interfaceInput.ipv4 = canonicalLbAltWorkerAddress(lbAltInterface.dockerNetwork.ipv4.interfaceIp)
		}
		if lbAltInterface.dockerNetwork != nil && lbAltInterface.dockerNetwork.ipv6 != nil {
			interfaceInput.ipv6 = canonicalLbAltWorkerAddress(lbAltInterface.dockerNetwork.ipv6.interfaceIp)
		}
		interfaceInputs = append(interfaceInputs, interfaceInput)
	}
	return &lbAltRouteInputs{
		servicesConfig: servicesConfig,
		env:            self.env,
		host:           host,
		generation:     containerName,
		interfaces:     interfaceInputs,
		servicePorts:   maps.Clone(servicePortsToInternalPort),
		upstreamIpv4:   canonicalLbAltWorkerAddress(self.servicesDockerNetwork.ipv4.interfaceIp),
	}, nil
}

// The services config host a block runs on, which names its lb interfaces
// there. The worker knows only the machine's host name and its own interfaces,
// so: the lb host named exactly the host name; else the one lb host whose
// first label is the host name's first label (a short host name against a
// qualified one, or the reverse); else the one lb host whose non-transparent
// lb interfaces and docker networks are exactly the worker's. An error when
// none or several match.
func lbAltWorkerHost(version *services.ServicesConfigVersion, hostname string, lbAltInterfaces []*lbAltWorkerInterface) (string, error) {
	if version == nil || version.Lb == nil {
		return "", errors.New("the services config has no lb interfaces")
	}
	hosts := slices.Sorted(maps.Keys(version.Lb.Interfaces))
	if slices.Contains(hosts, hostname) {
		return hostname, nil
	}

	firstLabel := func(name string) string {
		label, _, _ := strings.Cut(name, ".")
		return label
	}
	labelHosts := []string{}
	for _, host := range hosts {
		if firstLabel(host) == firstLabel(hostname) {
			labelHosts = append(labelHosts, host)
		}
	}
	if len(labelHosts) == 1 {
		return labelHosts[0], nil
	}

	workerNetworks := slices.Clone(lbAltInterfaces)
	slices.SortFunc(workerNetworks, func(a *lbAltWorkerInterface, b *lbAltWorkerInterface) int {
		return strings.Compare(a.interfaceName, b.interfaceName)
	})
	workerNetworkStrs := []string{}
	for _, lbAltInterface := range workerNetworks {
		dockerNetworkName := ""
		if lbAltInterface.dockerNetwork != nil {
			dockerNetworkName = lbAltInterface.dockerNetwork.networkName
		}
		workerNetworkStrs = append(workerNetworkStrs, fmt.Sprintf("%s:%s", lbAltInterface.interfaceName, dockerNetworkName))
	}
	workerNetworksStr := strings.Join(workerNetworkStrs, ";")
	networkHosts := []string{}
	for _, host := range hosts {
		if formatLbAltWorkerNetworks(version, host) == workerNetworksStr {
			networkHosts = append(networkHosts, host)
		}
	}
	if len(networkHosts) == 1 {
		return networkHosts[0], nil
	}
	return "", fmt.Errorf(
		"no one lb host of the services config is this machine (%s): %d match its name and %d its lb interfaces",
		hostname,
		len(labelHosts),
		len(networkHosts),
	)
}

// The sockets a ready generation reports (§2.4): on each bridge address of
// every interface it binds, each of lbAltWorkerListenSockets at the
// generation's internal port. In interface order, IPv4 before IPv6.
func (self *RunWorker) lbAltWorkerExpectedSockets(servicePortsToInternalPort map[int]int) ([]lbAltExpectedSocket, error) {
	expectedSockets := []lbAltExpectedSocket{}
	for _, lbAltInterface := range self.lbAltInterfaces {
		if lbAltInterface.dockerNetwork == nil {
			return nil, fmt.Errorf("lb interface %s has no docker network", lbAltInterface.interfaceName)
		}
		for _, bridgeInterface := range []*NetworkInterface{lbAltInterface.dockerNetwork.ipv4, lbAltInterface.dockerNetwork.ipv6} {
			if bridgeInterface == nil {
				continue
			}
			for _, listenSocket := range lbAltWorkerListenSockets() {
				internalPort, ok := servicePortsToInternalPort[listenSocket.servicePort]
				if !ok {
					return nil, fmt.Errorf("WARP_PORTS has no service port %d, which the lb_alt front listens on", listenSocket.servicePort)
				}
				expectedSockets = append(expectedSockets, lbAltExpectedSocket{
					protocol: listenSocket.protocol,
					address:  canonicalLbAltWorkerAddress(bridgeInterface.interfaceIp),
					port:     internalPort,
				})
			}
		}
	}
	return expectedSockets, nil
}

// Polls the candidate generation's private status until it reports lb_alt
// ready (§2.4; w-split's pollLbAltReadiness): status ok, the generation and
// route file revision startContainer kept, and every socket of
// lbAltWorkerExpectedSockets up. The deploy runs it after the ordinary status
// poll and before any rule points at the candidate, so a candidate that never
// gets ready is stopped without having carried a flow. Nothing for a worker
// that binds no lb interfaces.
func (self *RunWorker) pollLbAltWorkerCandidate(servicePortsToInternalPort map[int]int) error {
	if !self.bindsLbAltInterfaces() {
		return nil
	}
	generation := self.lbAltState.candidateGeneration
	if generation == "" {
		return errors.New("the lb_alt candidate has no route file")
	}
	httpPort, ok := servicePortsToInternalPort[lbAltWorkerHttpServicePort]
	if !ok {
		return fmt.Errorf("WARP_PORTS has no service port %d for the lb_alt candidate's private status", lbAltWorkerHttpServicePort)
	}
	if self.servicesDockerNetwork == nil || self.servicesDockerNetwork.ipv4 == nil {
		return errors.New("the lb_alt candidate's private status needs the services network's IPv4 address")
	}
	expectedSockets, err := self.lbAltWorkerExpectedSockets(servicePortsToInternalPort)
	if err != nil {
		return err
	}
	statusUrl := fmt.Sprintf(
		"http://%s/status",
		net.JoinHostPort(self.servicesDockerNetwork.ipv4.interfaceIp, strconv.Itoa(httpPort)),
	)
	Err.Printf("Poll lb_alt readiness of %s (%d sockets)\n", generation, len(expectedSockets))
	if err := self.getLbAltOps().pollReadiness(
		self.lbAltWorkerContext(),
		statusUrl,
		generation,
		self.lbAltState.candidateRevision,
		expectedSockets,
		self.getLbAltSettings().readinessTimeout,
	); err != nil {
		return fmt.Errorf("lb_alt candidate %s not ready: %w", generation, err)
	}
	return nil
}

// Points the block's own chain on every interface it binds at the candidate's
// listen ports (§2.5), once pollLbAltWorkerCandidate accepted the candidate
// and before the ordinary cutover. Every bound interface gets the chain,
// lb_alt or not yet, so an interface whose override later turns lb_alt on
// finds every block's chain in place: that flip changes only the lb unit and
// redeploys no block (§2.2). Nothing for a worker that binds no lb
// interfaces.
func (self *RunWorker) writeLbAltWorkerBlockChains(servicePortsToInternalPort map[int]int) error {
	if !self.bindsLbAltInterfaces() {
		return nil
	}
	blockTargets, err := lbAltWorkerBlockTargets(servicePortsToInternalPort)
	if err != nil {
		return err
	}
	splitInterfaces := []lbAltSplitInterface{}
	for _, lbAltInterface := range self.lbAltInterfaces {
		splitInterfaces = append(splitInterfaces, lbAltInterface.splitInterface())
	}
	if err := self.getLbAltOps().writeBlockChains(
		self.lbAltWorkerContext(),
		self.env,
		self.block,
		splitInterfaces,
		blockTargets,
	); err != nil {
		return fmt.Errorf("lb_alt chains of block %s: %w", self.block, err)
	}
	return nil
}

// Removes the route files of this block's generations whose containers are
// gone: the removal half of §2.2, run once prune has removed the block's
// stopped containers. A generation whose container still exists, running or
// stopped, keeps its file, which its mount needs. A worker without a warp
// home wrote no route files.
func (self *RunWorker) removeLbAltWorkerRouteFiles() {
	// the warp home RequireWarpHome reads, without its panic
	warpHome := os.Getenv("WARP_HOME")
	if warpHome == "" {
		return
	}
	entries, err := os.ReadDir(filepath.Join(warpHome, lbAltRouteHostDirName))
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			Err.Printf("lb_alt route files not listed: %s\n", err)
		}
		return
	}
	containerNamePrefix := fmt.Sprintf("%s-%s-%s-", self.env, self.service, self.block)
	generationNames := []string{}
	for _, entry := range entries {
		if entry.IsDir() && strings.HasPrefix(entry.Name(), containerNamePrefix) {
			generationNames = append(generationNames, entry.Name())
		}
	}
	if len(generationNames) == 0 {
		return
	}
	ops := self.getLbAltOps()
	containerNames, err := ops.containerNames(self.lbAltWorkerContext(), containerNamePrefix)
	if err != nil {
		Err.Printf("lb_alt route files kept, containers not listed: %s\n", err)
		return
	}
	for _, generationName := range generationNames {
		if slices.Contains(containerNames, generationName) {
			continue
		}
		if err := ops.removeRouteFile(warpHome, generationName); err != nil {
			Err.Printf("lb_alt route file of %s not removed: %s\n", generationName, err)
		}
	}
}
