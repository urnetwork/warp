package main

// The lb_alt side of warpctl's units and run workers (server/LBALT-IMPL.md
// §2.2-§2.6; LBALT.md D1, D2, D5, D11, D13, D18): connect fronts an lb
// interface itself, in place of an nginx lb.
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
//     reconcile. Before its first split rule it records under WARP_HOME that
//     the interface may have a split (lbAltWorkerSplitRecordPath). Once a
//     reconcile succeeds, the interface's nginx containers drain with an nginx
//     deploy's grace and are pruned (D1; §4.6 step 3).
//   - An lb unit back on nginx removes the split its interface left, once
//     nginx's public DNAT is back (D18), and only when the record is there.
//     removeLbAltSplit takes the interface's block chains with it, so an
//     interface that was never lb_alt keeps the chains connect wrote on it.
//   - A connect block on an lb_alt host starts each generation with its own
//     route file (w-route), mounted read-only and named by
//     WARP_LBALT_ROUTE_FILE and WARP_GENERATION. Its deploy switches traffic to
//     a candidate only after the candidate's private status reports that
//     generation, that file and every public socket ready (§2.4). It then
//     points the block's own chain on every bound interface at the candidate
//     (§2.5), and only then runs the ordinary cutover. When the chains or the
//     cutover fail after the commit, the candidate stays the deployed
//     generation and the poll loop finishes its promotion, with no other
//     candidate started. Between deploys the poll loop rewrites the chains, so
//     the chains a rollback removed are back before the interface is lb_alt
//     again.
//   - A route file goes when its container does: the block's prune removes the
//     files of containers that are gone.
//
// The worker reaches the services config, the route renderer, the split and
// docker's container listings through lbAltWorkerOps, which tests replace.
// Like the rest of RunWorker, these methods run on the worker's Run goroutine.
// The exceptions are an incomplete promotion's chain writes, which run in the
// pending deployment's completion and write no lb_alt state, and the nginx
// retirement's goroutine, which touches only the worker's retirements.

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

// The lb type of the lb_alt service's tcp 443 port block (§2.3). It is
// neither "http" nor "stream", so the nginx http and stream generators leave
// the port alone.
const lbAltWorkerTcpLbType = "tcp"

// The directory under the warp home that holds the split records
// (lbAltWorkerSplitRecordPath). It sits beside the route files' directory, not
// in it.
const lbAltWorkerSplitRecordDirName = "lbalt-split"

// Tunables of the lb_alt worker paths.
type lbAltWorkerSettings struct {
	// How long a deploy polls a candidate connect generation's private status
	// for lb_alt readiness (§2.4) before the deploy fails and the candidate is
	// stopped. Connect binds every public socket before its private status
	// first answers, so a healthy generation is ready at the first poll; this
	// bounds one that never gets there, as long as the candidate status poll
	// that runs before it. Non-positive fails every lb_alt deploy before its
	// first poll, so no candidate is promoted unchecked.
	readinessTimeout time.Duration
	// How long an lb unit back on nginx waits before it retries removing its
	// interface's split after a failed removal. Until a removal succeeds, the
	// split still sends udp 4053 to connect. Non-positive retries on every
	// poll.
	splitRemovalRetryTimeout time.Duration
	// How often a connect block on an lb_alt host rewrites its chains between
	// deploys, for the generation its latest deploy committed. A rollback's
	// removeLbAltSplit takes the interface's block chains with its split, so
	// this bounds how long an interface turned lb_alt again waits for them,
	// with no connect deploy. 30 s, the lb units' split reconcile interval.
	// Non-positive leaves the chains to the deploys.
	chainRefreshTimeout time.Duration
	// How long a retired nginx container of an lb_alt interface drains before
	// docker kills it: the grace an nginx deploy gives the container it
	// replaces (DrainTimeout). Non-positive kills it at once.
	nginxDrainTimeout time.Duration
}

// The defaults, a new instance on every call.
func defaultLbAltWorkerSettings() *lbAltWorkerSettings {
	return &lbAltWorkerSettings{
		readinessTimeout:         120 * time.Second,
		splitRemovalRetryTimeout: 30 * time.Second,
		chainRefreshTimeout:      30 * time.Second,
		nginxDrainTimeout:        DrainTimeout,
	}
}

// What the lb_alt worker paths call outside the worker: the services config,
// the machine's host name, the route file (w-route), the split (w-split) and
// docker's container listings. defaultLbAltWorkerOps calls the real ones;
// tests replace single functions.
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
	// the containers, running or not, whose names start with the prefix: one
	// line each in a docker --format template, such as {{.ID}}
	listContainers func(ctx context.Context, containerNamePrefix string, format string) ([]string, error)
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
		listContainers: func(ctx context.Context, containerNamePrefix string, format string) ([]string, error) {
			out, err := retirementCommandOutput(ctx, docker(
				"ps", "-a",
				"-f", containerNamePrefixFilter(containerNamePrefix),
				"--format", format,
			))
			if err != nil {
				return nil, err
			}
			lines := []string{}
			for _, line := range strings.Split(string(out), "\n") {
				if line := strings.TrimSpace(line); line != "" {
					lines = append(lines, line)
				}
			}
			return lines, nil
		},
	}
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
	// the WARP_PORTS of the generation a connect block's chains point at, the
	// candidate its latest deploy committed; the poll loop rewrites the chains
	// at or after nextChainRefresh
	chainServicePorts map[int]int
	nextChainRefresh  time.Time
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

// The record that an lb_alt lb unit may have left a split on its interface:
// <warp home>/lbalt-split/<env>/<interface>, an empty file. The lb_alt unit
// writes it before any split rule can exist, and the unit back on nginx
// removes the split only when the record is there, and then the record.
func lbAltWorkerSplitRecordPath(warpHome string, env string, interfaceName string) string {
	return filepath.Join(warpHome, lbAltWorkerSplitRecordDirName, env, interfaceName)
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
// canonical form, and every public port of the §2.3 table
// (lbAltTablePublicPorts), whether lb_alt is in effect on the interface yet
// or not.
func (self *lbAltWorkerInterface) splitInterface() lbAltSplitInterface {
	splitInterface := lbAltSplitInterface{
		name:        self.interfaceName,
		publicPorts: lbAltTablePublicPorts(),
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
// lbAltWorkerInterfaceAddresses picks one. Panics on a malformed entry, or an
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
// every block on the host. The one picked is the lowest in address order,
// which a restart picks again, and the choice is logged, since only it is
// used.
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
	switch len(ipv6NetworkInterfaces) {
	case 0:
		return ipv4NetworkInterfaces[0], nil
	case 1:
		return ipv4NetworkInterfaces[0], ipv6NetworkInterfaces[0]
	}
	chosen := slices.MinFunc(ipv6NetworkInterfaces, func(a *NetworkInterface, b *NetworkInterface) int {
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
		len(ipv6NetworkInterfaces),
		chosen.interfaceIp,
	)
	return ipv4NetworkInterfaces[0], chosen
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
// interface, --lbalt=true and the lb_alt service's blocks (§2.2), block:weight
// joined by semicolons in services.ServiceBlockWeights order; otherwise none,
// so an nginx interface's unit is what it was. The unit keeps
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
	blockWeightStrs := []string{}
	for _, blockWeight := range services.ServiceBlockWeights(version.Services[lbAltService]) {
		blockWeightStrs = append(blockWeightStrs, fmt.Sprintf("%s:%d", blockWeight.Block, blockWeight.Weight))
	}
	return []string{
		"--lbalt=true",
		fmt.Sprintf(`--lbaltblocks="%s"`, strings.Join(blockWeightStrs, ";")),
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
// rules and masquerade, and on an lb_alt interface its split and its nginx's
// retirement. Nil, as before, for a unit without a routing table.
func (self *RunWorker) routingOnlyReconcile() func() {
	if self.routingTable == nil {
		return nil
	}
	return func() {
		self.reconcileRoutingTableIfDue(time.Now())
		self.reconcileLbAltWorkerInterface()
	}
}

// An lb_alt interface's reconcile, at the routing-only loop's start and on
// each of its reconciles: the interface's split (w-split), and once the split
// is in place, the retirement of the interface's nginx. The split record is
// written before the split reconcile, so a rollback finds the split even after
// a reconcile that was interrupted. A failure is logged and left to the next
// reconcile; the rules and containers in place keep serving meanwhile.
// Nothing on an interface that is not lb_alt.
func (self *RunWorker) reconcileLbAltWorkerInterface() {
	if !self.lbAlt {
		return
	}
	ops := self.getLbAltOps()

	// The split as the lb unit reconciles it: the public addresses from the
	// interface (the routing table's, which picks up a late IPv6), the bridge
	// addresses from its docker network, the public ports from the host's
	// services config, and the blocks from --lbaltblocks. The public ports
	// (services.LbAltPublicPorts) are read once: every input to them is also
	// an input to the lb unit, whose change restarts the worker. Until the
	// config loads, and has ports for the interface, which it has only while
	// lb_alt is in effect on the interface there, an error, and nothing is
	// kept.
	splitConfig := func() (*lbAltSplitConfig, error) {
		if self.routingTable == nil {
			return nil, errors.New("the lb unit has no routing table")
		}
		interfaceName := self.routingTable.interfaceName
		if self.lbAltState.splitPublicPorts == nil {
			host, ok := strings.CutSuffix(self.block, "-"+interfaceName)
			if !ok || host == "" {
				return nil, fmt.Errorf("lb block %s does not end with its interface %s", self.block, interfaceName)
			}
			servicesConfig, err := ops.loadServicesConfig(self.warpState.warpSettings.RequireVaultHome(), self.env)
			if err != nil {
				return nil, err
			}
			publicPorts := services.LbAltPublicPorts(servicesConfig.Latest(), host, interfaceName)
			if len(publicPorts["tcp"]) == 0 && len(publicPorts["udp"]) == 0 {
				return nil, fmt.Errorf("the services config has no lb_alt public ports for %s %s: lb_alt is not in effect on it there", host, interfaceName)
			}
			self.lbAltState.splitPublicPorts = publicPorts
		}
		splitInterface := lbAltSplitInterface{
			name:        interfaceName,
			publicPorts: self.lbAltState.splitPublicPorts,
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

	// Writes the split record when it is missing (lbAltWorkerSplitRecordPath).
	recordSplit := func(interfaceName string) error {
		recordPath := lbAltWorkerSplitRecordPath(self.warpState.warpSettings.RequireWarpHome(), self.env, interfaceName)
		if _, err := os.Stat(recordPath); err == nil {
			return nil
		} else if !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		if err := os.MkdirAll(filepath.Dir(recordPath), 0o755); err != nil {
			return err
		}
		return os.WriteFile(recordPath, nil, 0o644)
	}

	// Retires the interface's nginx once the split carries the interface's new
	// flows (D1; §4.6 step 3). Every container of the block drains with
	// nginxDrainTimeout's grace, on a goroutine of its own, while the loop
	// keeps reconciling. It runs in the worker's orphan drain, which Run joins
	// at exit, so one retirement runs at a time, after the startup one. When
	// one ends, the stale udp conntrack entries of the retired ports go, so
	// their flows re-resolve against the split, and the stopped containers are
	// pruned. Containers that are still there are retired again.
	retireNginx := func() {
		if self.orphanDrain != nil {
			select {
			case err := <-self.orphanDrain:
				self.orphanDrain = nil
				if err != nil {
					Err.Printf("lb_alt nginx of %s not retired yet: %s\n", self.block, err)
				}
				self.cleanupStaleConntrack()
				self.prune()
			default:
				return
			}
		}
		containerIds, err := ops.listContainers(
			self.retirementContext(),
			fmt.Sprintf("%s-%s-%s-", self.env, self.service, self.block),
			"{{.ID}}",
		)
		if err != nil {
			Err.Printf("lb_alt nginx of %s not listed: %s\n", self.block, err)
			return
		}
		// retain failed exact ids even when docker no longer lists them, as
		// drainContainers does
		for _, pendingId := range self.retirements.pendingIds() {
			if !slices.ContainsFunc(containerIds, func(containerId string) bool { return containerIdsEqual(containerId, pendingId) }) {
				containerIds = append(containerIds, pendingId)
			}
		}
		if len(containerIds) == 0 {
			return
		}
		Err.Printf("lb_alt split of %s is in place; retiring %d nginx container(s)\n", self.block, len(containerIds))
		ctx := self.retirementContext()
		nginxDrainTimeout := self.getLbAltSettings().nginxDrainTimeout
		done := make(chan error, 1)
		self.orphanDrain = done
		go func() {
			retirementErrors := []error{}
			for _, containerId := range containerIds {
				if err := self.retirements.run(ctx, containerId, nginxDrainTimeout); err != nil {
					retirementErrors = append(retirementErrors, err)
				}
			}
			done <- errors.Join(retirementErrors...)
		}()
	}

	config, err := splitConfig()
	if err != nil {
		Err.Printf("lb_alt split of %s not reconciled: %s\n", self.block, err)
		return
	}
	if err := recordSplit(config.splitInterface.name); err != nil {
		Err.Printf("lb_alt split of %s not reconciled, since it could not be recorded: %s\n", self.block, err)
		return
	}
	if err := ops.reconcileSplit(self.retirementContext(), config); err != nil {
		Err.Printf("lb_alt split of %s failed to reconcile: %s\n", self.block, err)
		return
	}
	retireNginx()
}

// Called once an lb unit on nginx has put its interface's public DNAT back on
// nginx (redirect). Removes the split the interface's lb_alt mode left, which
// until then still sends udp 4053, and anything else nginx does not take
// first, to connect (D18). Only an interface with a split record has one
// (lbAltWorkerSplitRecordPath): the cutovers of every other interface leave
// every chain alone, the connect blocks' chains on it among them. A failure is
// retried from the poll loop (retryLbAltWorkerSplitRemovalIfDue).
func (self *RunWorker) removeLbAltWorkerSplitAfterCutover() {
	if self.service != "lb" || self.lbAlt || self.routingTable == nil || !self.hostNetworking {
		return
	}
	self.lbAltState.splitRemovalPending = true
	self.lbAltState.nextSplitRemoval = time.Time{}
	self.retryLbAltWorkerSplitRemovalIfDue(time.Now())
}

// Removes the interface's split when a removal is pending and due, and then
// its record. With no record, there is nothing to remove. A record that
// outlives its split only makes the next cutover remove the split again.
func (self *RunWorker) retryLbAltWorkerSplitRemovalIfDue(now time.Time) {
	if !self.lbAltState.splitRemovalPending || now.Before(self.lbAltState.nextSplitRemoval) {
		return
	}
	recordPath := lbAltWorkerSplitRecordPath(self.warpState.warpSettings.RequireWarpHome(), self.env, self.routingTable.interfaceName)
	if _, err := os.Stat(recordPath); errors.Is(err, fs.ErrNotExist) {
		self.lbAltState.splitRemovalPending = false
		return
	} else if err != nil {
		Err.Printf("lb_alt split record of %s not read: %s\n", self.block, err)
		self.lbAltState.nextSplitRemoval = now.Add(self.getLbAltSettings().splitRemovalRetryTimeout)
		return
	}
	if err := self.getLbAltOps().removeSplit(self.retirementContext(), self.env, self.routingTable.interfaceName); err != nil {
		Err.Printf("lb_alt split of %s not removed yet: %s\n", self.block, err)
		self.lbAltState.nextSplitRemoval = now.Add(self.getLbAltSettings().splitRemovalRetryTimeout)
		return
	}
	if err := os.Remove(recordPath); err != nil && !errors.Is(err, fs.ErrNotExist) {
		Err.Printf("lb_alt split of %s removed, but not its record: %s\n", self.block, err)
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
//
// w-route renders the table from the services config, the services config
// host this worker runs on (lbAltWorkerHost), every lb interface the worker
// binds with its docker network's bridge addresses and whether lb_alt is in
// effect on it, the generation's WARP_PORTS, and the warpservices bridge
// address the upstream blocks listen on.
func (self *RunWorker) prepareLbAltWorkerGeneration(containerName string, servicePortsToInternalPort map[int]int) ([]string, map[string]string, error) {
	self.lbAltState.candidateGeneration = ""
	self.lbAltState.candidateRevision = ""
	if !self.bindsLbAltInterfaces() {
		return nil, nil, nil
	}
	ops := self.getLbAltOps()

	routeInputs := func() (*lbAltRouteInputs, error) {
		servicesConfig, err := ops.loadServicesConfig(self.warpState.warpSettings.RequireVaultHome(), self.env)
		if err != nil {
			return nil, err
		}
		version := servicesConfig.Latest()
		hostname, err := ops.hostname()
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

	inputs, err := routeInputs()
	if err != nil {
		return nil, nil, fmt.Errorf("lb_alt route file of %s: %w", containerName, err)
	}
	routeTable, err := ops.renderRouteTable(inputs)
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

// Polls the candidate generation's private status until it reports lb_alt
// ready (§2.4; w-split's pollLbAltReadiness): status ok, the generation and
// route file revision startContainer kept, and every expected socket up. A
// ready generation reports, on each bridge address of every interface it
// binds, the front's socket for each (protocol, service port) of the §2.3
// table at the generation's internal port, in interface order, IPv4 before
// IPv6. The deploy runs it after the ordinary status poll and before any rule
// points at the candidate, so a candidate that never gets ready is stopped
// without having carried a flow. Nothing for a worker that binds no lb
// interfaces.
func (self *RunWorker) pollLbAltWorkerCandidate(servicePortsToInternalPort map[int]int) error {
	if !self.bindsLbAltInterfaces() {
		return nil
	}
	generation := self.lbAltState.candidateGeneration
	if generation == "" {
		return errors.New("the lb_alt candidate has no route file")
	}
	readinessTimeout := self.getLbAltSettings().readinessTimeout
	if readinessTimeout <= 0 {
		return fmt.Errorf("lb_alt candidate %s not polled: its readiness timeout %s is not positive", generation, readinessTimeout)
	}
	httpPort, ok := servicePortsToInternalPort[services.LbAltHttpServicePort]
	if !ok {
		return fmt.Errorf("WARP_PORTS has no service port %d for the lb_alt candidate's private status", services.LbAltHttpServicePort)
	}
	if self.servicesDockerNetwork == nil || self.servicesDockerNetwork.ipv4 == nil {
		return errors.New("the lb_alt candidate's private status needs the services network's IPv4 address")
	}
	expectedSockets := []lbAltExpectedSocket{}
	for _, lbAltInterface := range self.lbAltInterfaces {
		if lbAltInterface.dockerNetwork == nil {
			return fmt.Errorf("lb interface %s has no docker network", lbAltInterface.interfaceName)
		}
		for _, bridgeInterface := range []*NetworkInterface{lbAltInterface.dockerNetwork.ipv4, lbAltInterface.dockerNetwork.ipv6} {
			if bridgeInterface == nil {
				continue
			}
			for _, publicPortRow := range services.LbAltPublicPortTable() {
				internalPort, ok := servicePortsToInternalPort[publicPortRow.ServicePort]
				if !ok {
					return fmt.Errorf("WARP_PORTS has no service port %d, which the lb_alt front listens on", publicPortRow.ServicePort)
				}
				// public udp 53 and 4053 share the whodis socket
				expectedSocket := lbAltExpectedSocket{
					protocol: publicPortRow.Protocol,
					address:  canonicalLbAltWorkerAddress(bridgeInterface.interfaceIp),
					port:     internalPort,
				}
				if !slices.Contains(expectedSockets, expectedSocket) {
					expectedSockets = append(expectedSockets, expectedSocket)
				}
			}
		}
	}
	statusUrl := fmt.Sprintf(
		"http://%s/status",
		net.JoinHostPort(self.servicesDockerNetwork.ipv4.interfaceIp, strconv.Itoa(httpPort)),
	)
	Err.Printf("Poll lb_alt readiness of %s (%d sockets)\n", generation, len(expectedSockets))
	if err := self.getLbAltOps().pollReadiness(
		self.retirementContext(),
		statusUrl,
		generation,
		self.lbAltState.candidateRevision,
		expectedSockets,
		readinessTimeout,
	); err != nil {
		return fmt.Errorf("lb_alt candidate %s not ready: %w", generation, err)
	}
	return nil
}

// Makes the committed candidate the generation the block's chains point at:
// the deploy writes them next, and the poll loop rewrites them for it between
// deploys (refreshLbAltWorkerChainsIfDue). A candidate that was never
// committed never gets the chains. Nothing for a worker that binds no lb
// interfaces.
func (self *RunWorker) assignLbAltWorkerChains(servicePortsToInternalPort map[int]int) {
	if !self.bindsLbAltInterfaces() {
		return
	}
	self.lbAltState.chainServicePorts = maps.Clone(servicePortsToInternalPort)
	self.lbAltState.nextChainRefresh = time.Now().Add(self.getLbAltSettings().chainRefreshTimeout)
}

// Points the block's own chain on every interface it binds at the
// generation's listen ports (§2.5): every row of the §2.3 table, to the
// generation's internal port for the row's service port (lbAltBlockTargets).
// A deploy writes them once pollLbAltWorkerCandidate accepted the candidate
// and before the ordinary cutover. Every bound interface gets the chain,
// lb_alt or not yet, so an interface whose override later turns lb_alt on
// finds every block's chain in place: that flip changes only the lb unit and
// redeploys no block (§2.2). Nothing for a worker that binds no lb
// interfaces.
func (self *RunWorker) writeLbAltWorkerBlockChains(servicePortsToInternalPort map[int]int) error {
	if !self.bindsLbAltInterfaces() {
		return nil
	}
	blockTargets, err := lbAltBlockTargets(lbAltTablePublicPorts(), servicePortsToInternalPort)
	if err != nil {
		return fmt.Errorf("lb_alt chains of block %s: %w", self.block, err)
	}
	splitInterfaces := []lbAltSplitInterface{}
	for _, lbAltInterface := range self.lbAltInterfaces {
		splitInterfaces = append(splitInterfaces, lbAltInterface.splitInterface())
	}
	if err := self.getLbAltOps().writeBlockChains(
		self.retirementContext(),
		self.env,
		self.block,
		splitInterfaces,
		blockTargets,
	); err != nil {
		return fmt.Errorf("lb_alt chains of block %s: %w", self.block, err)
	}
	return nil
}

// Rewrites the block's chains for the generation they point at
// (assignLbAltWorkerChains), once due. A rollback's removeLbAltSplit removes
// the interface's block chains with its split, and the interface finds them
// again when it turns lb_alt once more, with no connect deploy. Run calls it
// only while no deployment is pending, so it never races a promotion's own
// chain write. A failure is logged and left to the next refresh.
func (self *RunWorker) refreshLbAltWorkerChainsIfDue(now time.Time) {
	chainRefreshTimeout := self.getLbAltSettings().chainRefreshTimeout
	if self.lbAltState.chainServicePorts == nil || chainRefreshTimeout <= 0 || now.Before(self.lbAltState.nextChainRefresh) {
		return
	}
	self.lbAltState.nextChainRefresh = now.Add(chainRefreshTimeout)
	if err := self.writeLbAltWorkerBlockChains(self.lbAltState.chainServicePorts); err != nil {
		Err.Printf("lb_alt chains of %s not refreshed: %s\n", self.block, err)
	}
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
	containerNames, err := ops.listContainers(self.retirementContext(), containerNamePrefix, "{{.Names}}")
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
