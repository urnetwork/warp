package services

// The lb_alt mode (server/LBALT.md): the lb_alt service, which only connect
// may be, fronts an lb interface itself in place of an nginx lb. Its blocks
// bind the interface's bridge addresses and own its public ports, and warpctl
// splits the interface's new flows across the blocks by a hash of the client
// source address (server/LBALT-IMPL.md §2.2-§2.5). The setting is a service
// default (ServiceConfig.LbAlt) with a per-interface override (LbBlock.LbAlt),
// whose false is the single-interface rollback switch.
//
// An lb_alt interface is routing-only like a transparent one, but it stays an
// lb interface: in DNS, in the edge inventory and in the lb set. Nothing here
// treats it as transparent.
//
// Every consumer reads the setting through these functions, so the effective
// value has one definition. They are pure and safe for concurrent use. A nil
// version, lb, service or interface reads as no lb_alt, a nil interface entry
// (`eth1:` with no settings) is an interface with every setting unset, and
// maps are walked in sorted order, so results and the first validation error
// are deterministic.

import (
	"errors"
	"fmt"
	"math"
	"slices"
	"sort"

	"golang.org/x/exp/maps"
)

// The only service that may declare lb_alt: the lb_alt front is connect's
// (server/LBALT.md D2).
const lbAltConnectService = "connect"

// The buckets the lb_alt split hashes client source addresses into, one per
// percent of addresses: the HMARK modulus of server/LBALT-IMPL.md §2.5. This
// is a protocol value, since changing it moves most addresses to another
// bucket and so to another block.
const LbAltBucketCount = 100

// The service's own lb_alt default, before any interface override: false
// when it is unset or declared false.
func (self *ServiceConfig) IsLbAlt() bool {
	return self != nil && self.LbAlt != nil && *self.LbAlt
}

// The services that declare lb_alt, true or false, sorted.
func lbAltDeclaringServices(version *ServicesConfigVersion) []string {
	declaringServices := []string{}
	if version == nil {
		return declaringServices
	}
	for service, serviceConfig := range version.Services {
		if serviceConfig != nil && serviceConfig.LbAlt != nil {
			declaringServices = append(declaringServices, service)
		}
	}
	sort.Strings(declaringServices)
	return declaringServices
}

// The single service that declares lb_alt. Its default may be true or false:
// a declared false still names the service, so an interface override can
// turn single interfaces on under it (D2). False when no service declares
// lb_alt, or more than one does, which validation refuses.
func LbAltService(version *ServicesConfigVersion) (string, bool) {
	declaringServices := lbAltDeclaringServices(version)
	if len(declaringServices) != 1 {
		return "", false
	}
	return declaringServices[0], true
}

// The interface's effective lb_alt setting (D2): its own override when it
// sets one, else the lb_alt service's default, which reaches only the
// non-transparent interfaces of the hosts the service is placed on
// (HostsForService). An unknown host or interface, or a version with no lb,
// is not lb_alt.
func IsLbAltInterface(version *ServicesConfigVersion, host string, interfaceName string) bool {
	if version == nil || version.Lb == nil {
		return false
	}
	lbBlock, ok := version.Lb.Interfaces[host][interfaceName]
	if !ok {
		return false
	}
	if lbBlock != nil && lbBlock.LbAlt != nil {
		return *lbBlock.LbAlt
	}
	if lbBlock != nil && lbBlock.Transparent {
		return false
	}
	service, ok := LbAltService(version)
	if !ok || !version.Services[service].IsLbAlt() {
		return false
	}
	return slices.Contains(HostsForService(version, service), host)
}

// Whether connect on the host binds the host's lb interfaces for lb_alt
// (server/LBALT-IMPL.md §2.2): the lb_alt service is connect, it is placed on
// the host, and either its default is on or one of the host's interfaces
// overrides lb_alt to true. Under a default that is on, rolling interfaces
// back to false leaves the host on, so the rollback switch never changes
// connect's units.
func IsLbAltHost(version *ServicesConfigVersion, host string) bool {
	service, ok := LbAltService(version)
	if !ok || service != lbAltConnectService {
		return false
	}
	if !slices.Contains(HostsForService(version, service), host) {
		return false
	}
	if version.Services[service].IsLbAlt() {
		return true
	}
	for _, lbBlock := range version.Lb.Interfaces[host] {
		if lbBlock != nil && lbBlock.LbAlt != nil && *lbBlock.LbAlt {
			return true
		}
	}
	return false
}

// The host's non-transparent lb interfaces, sorted: the interfaces connect
// binds on an lb_alt host (warpctl's --lbaltnets), whether lb_alt is on for
// each or not, so flipping one interface's override never changes connect's
// units.
func LbInterfaceNames(version *ServicesConfigVersion, host string) []string {
	interfaceNames := []string{}
	if version == nil || version.Lb == nil {
		return interfaceNames
	}
	for interfaceName, lbBlock := range version.Lb.Interfaces[host] {
		if lbBlock != nil && lbBlock.Transparent {
			continue
		}
		interfaceNames = append(interfaceNames, interfaceName)
	}
	sort.Strings(interfaceNames)
	return interfaceNames
}

// The interfaces lb_alt is in effect on (IsLbAltInterface), sorted, by host.
// A host with none is left out.
func LbAltInterfaces(version *ServicesConfigVersion) map[string][]string {
	hostInterfaceNames := map[string][]string{}
	if version == nil || version.Lb == nil {
		return hostInterfaceNames
	}
	hosts := maps.Keys(version.Lb.Interfaces)
	sort.Strings(hosts)
	for _, host := range hosts {
		interfaceNames := maps.Keys(version.Lb.Interfaces[host])
		sort.Strings(interfaceNames)
		for _, interfaceName := range interfaceNames {
			if IsLbAltInterface(version, host, interfaceName) {
				hostInterfaceNames[host] = append(hostInterfaceNames[host], interfaceName)
			}
		}
	}
	return hostInterfaceNames
}

// The stream port services in effect on an interface, by protocol: the
// interface's own entry for a port wins and the lb's entries fill the rest,
// as SetDefaultStreamPortServices merges them, but into new maps, so the
// answer is the same whether or not warpctl has already merged in place.
// Both protocols are always present. A nil lb or interface contributes
// nothing.
func EffectivePortServices(lb *LbConfig, lbBlock *LbBlock) map[string]map[int]string {
	effectivePortServices := map[string]map[int]string{
		"tcp": {},
		"udp": {},
	}
	merge := func(allPortServices map[string]map[int]string) {
		for protocol, portServices := range allPortServices {
			for port, service := range portServices {
				effectivePortServices[protocol][port] = service
			}
		}
	}
	if lb != nil {
		merge(lb.AllPortServices())
	}
	if lbBlock != nil {
		merge(lbBlock.AllPortServices())
	}
	return effectivePortServices
}

// The public ports of an lb_alt interface by protocol, each sorted
// (server/LBALT-IMPL.md §2.3), the one list the host rules and the VyOS
// generator both open there:
//   - tcp: the lb's http ports (lb.ports);
//   - udp: the stream ports in effect on the interface that map to the lb_alt
//     service, and the udp forward ports whose target maps to it.
//
// On main's shape that is tcp 80 and 443, and udp 443, 4053 and 53 (to 4053).
// Unlike on an nginx interface, the forward target 4053 is public too. The
// map is empty when the interface is not lb_alt.
func LbAltPublicPorts(version *ServicesConfigVersion, host string, interfaceName string) map[string][]int {
	if !IsLbAltInterface(version, host, interfaceName) {
		return map[string][]int{}
	}
	lb := version.Lb
	tcpPorts := lb.HttpTcpPorts()
	udpPorts := []int{}
	if service, ok := LbAltService(version); ok {
		udpPortServices := EffectivePortServices(lb, lb.Interfaces[host][interfaceName])["udp"]
		for port, portService := range udpPortServices {
			if portService == service {
				udpPorts = append(udpPorts, port)
			}
		}
		for publicPort, targetPort := range lb.UdpForwardPorts {
			if udpPortServices[targetPort] == service {
				udpPorts = append(udpPorts, publicPort)
			}
		}
	}
	slices.Sort(tcpPorts)
	slices.Sort(udpPorts)
	return map[string][]int{
		"tcp": slices.Compact(tcpPorts),
		"udp": slices.Compact(udpPorts),
	}
}

// One block of a service and its weight, as the service's `blocks` list
// declares them.
type BlockWeight struct {
	Block  string
	Weight int
}

// The service's blocks in a stable order: the order of the `blocks` list,
// with the blocks of one list entry sorted by name, which is how warpctl
// orders blocks when it allocates their ports. The lb_alt split hands out
// buckets in this order (LbAltBucketBlocks). A block listed twice is kept
// twice.
func ServiceBlockWeights(serviceConfig *ServiceConfig) []BlockWeight {
	blockWeights := []BlockWeight{}
	if serviceConfig == nil {
		return blockWeights
	}
	for _, entryBlockWeights := range serviceConfig.Blocks {
		blocks := maps.Keys(entryBlockWeights)
		sort.Strings(blocks)
		for _, block := range blocks {
			blockWeights = append(blockWeights, BlockWeight{
				Block:  block,
				Weight: entryBlockWeights[block],
			})
		}
	}
	return blockWeights
}

// The block of each bucket of the lb_alt split, indexed by bucket. Each block
// takes one contiguous range of buckets, in the order of blockWeights
// (ServiceBlockWeights), and a block of weight 0 takes none.
//
// The counts are the largest-remainder rounding of weight × buckets / total.
// Each block first gets the floor of its share, and the buckets left over go
// one each to the largest remainders, ties to the earlier block. Then each
// positive-weight block left with no bucket takes one from the block furthest
// over its share among those holding at least two, ties to the later block,
// so every positive weight gets a bucket. When every share is at least one
// bucket, no block moves, and each count is its share rounded down or up.
// Main's connect weights (beta 1, g1 24, g2-g4 25) over 100 buckets are
// exact.
//
// An error when no block has a positive weight, when more blocks have one
// than there are buckets, or when a weight is negative, a block is listed
// twice, or the weights are too large to split.
func LbAltBucketBlocks(blockWeights []BlockWeight, buckets int) ([]string, error) {
	positiveCount := 0
	total := 0
	listedBlocks := map[string]bool{}
	for _, blockWeight := range blockWeights {
		if listedBlocks[blockWeight.Block] {
			return nil, fmt.Errorf("block %q is listed more than once", blockWeight.Block)
		}
		listedBlocks[blockWeight.Block] = true
		if blockWeight.Weight < 0 {
			return nil, fmt.Errorf("block %q has the negative weight %d", blockWeight.Block, blockWeight.Weight)
		}
		if blockWeight.Weight == 0 {
			continue
		}
		if math.MaxInt-total < blockWeight.Weight {
			return nil, fmt.Errorf("the block weights overflow at block %q", blockWeight.Block)
		}
		total += blockWeight.Weight
		positiveCount += 1
	}
	if positiveCount == 0 {
		return nil, errors.New("no block has a positive weight")
	}
	if buckets < positiveCount {
		return nil, fmt.Errorf("more blocks have a positive weight (%d) than there are buckets (%d)", positiveCount, buckets)
	}
	if math.MaxInt/buckets < total {
		return nil, fmt.Errorf("the block weights total %d, too large to split into %d buckets", total, buckets)
	}

	// each block's share is weight × buckets / total; remainders are scaled
	// by total, so the comparisons stay exact
	bucketCounts := make([]int, len(blockWeights))
	remainders := make([]int, len(blockWeights))
	positiveIndexes := []int{}
	assignedCount := 0
	for i, blockWeight := range blockWeights {
		bucketCounts[i] = blockWeight.Weight * buckets / total
		remainders[i] = blockWeight.Weight * buckets % total
		assignedCount += bucketCounts[i]
		if 0 < blockWeight.Weight {
			positiveIndexes = append(positiveIndexes, i)
		}
	}
	// fewer buckets are left over than there are positive blocks, since the
	// remainders are each under one bucket
	sort.SliceStable(positiveIndexes, func(a int, b int) bool {
		return remainders[positiveIndexes[b]] < remainders[positiveIndexes[a]]
	})
	for _, i := range positiveIndexes[:buckets-assignedCount] {
		bucketCounts[i] += 1
	}

	// how far a block is over its share, scaled by total
	overShare := func(i int) int {
		return bucketCounts[i]*total - blockWeights[i].Weight*buckets
	}
	for i, blockWeight := range blockWeights {
		if blockWeight.Weight == 0 || 0 < bucketCounts[i] {
			continue
		}
		// a donor holding two exists: the other positive blocks hold all the
		// buckets, and there are at least as many buckets as positive blocks
		donor := -1
		for j := range blockWeights {
			if 2 <= bucketCounts[j] && (donor < 0 || overShare(donor) <= overShare(j)) {
				donor = j
			}
		}
		bucketCounts[donor] -= 1
		bucketCounts[i] = 1
	}

	bucketBlocks := make([]string, 0, buckets)
	for i, blockWeight := range blockWeights {
		for range bucketCounts[i] {
			bucketBlocks = append(bucketBlocks, blockWeight.Block)
		}
	}
	return bucketBlocks, nil
}
