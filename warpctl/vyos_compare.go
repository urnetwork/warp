package main

import (
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/docopt/docopt-go"
	"github.com/urnetwork/warp/vyos"
)

const vyosCompareInputBytes = 4 * 1024 * 1024
const vyosCompareMaxNeighbors = 1024

// This is a private, versioned JSON interface. Comparison counts contain no
// paths, command text or values. Topology contains addresses and must remain
// private at its caller. Each completion bit describes its own authority,
// not equality, capture atomicity, neighbor liveness or a complete host census.
type vyosComparisonSummary struct {
	SchemaVersion int                    `json:"schema_version"`
	Complete      bool                   `json:"complete"`
	Reason        string                 `json:"reason"`
	Running       vyosComparisonLayer    `json:"running"`
	Saved         vyosComparisonLayer    `json:"saved"`
	Topology      vyosComparisonTopology `json:"topology"`
}

type vyosComparisonLayer struct {
	Complete        bool   `json:"complete"`
	Changes         int    `json:"changes"`
	Deletes         int    `json:"deletes"`
	Sets            int    `json:"sets"`
	Unverified      int    `json:"unverified"`
	ProtectedDelete bool   `json:"protected_delete"`
	Reason          string `json:"reason"`
}

type vyosComparisonTopology struct {
	Complete  bool                     `json:"complete"`
	Reason    string                   `json:"reason"`
	Neighbors []vyosComparisonNeighbor `json:"neighbors"`
	Conntrack vyosComparisonConntrack  `json:"conntrack"`
}

type vyosComparisonNeighbor struct {
	Interface string `json:"interface"`
	Family    string `json:"family"`
	Address   string `json:"address"`
	Role      string `json:"role"`
}

type vyosComparisonConntrack struct {
	// Explicit means at least one independently valid explicit field. Zero is
	// unknown/unset for that field, not a default or a fully known capacity.
	Explicit  bool   `json:"explicit"`
	TableSize uint64 `json:"table_size"`
	HashSize  uint64 `json:"hash_size"`
}

func vyosSavedFileName(router string) string {
	return router + "-saved.config"
}

// No generator, environment, settings, vault or router is read here. A missing
// live/saved file does not erase independent desired-topology authority; an
// empty input directory is the supported topology-only request.
func vyosCompareConfig(opts docopt.Opts) {
	router, _ := opts.String("<router>")
	desiredDir, _ := opts.String("--desired")
	inDir, _ := opts.String("--in")
	summary := vyosCompareSnapshots(router, desiredDir, inDir)
	if err := json.NewEncoder(Out.Writer()).Encode(summary); err != nil {
		panic(errors.New("cannot encode configuration comparison"))
	}
}

func vyosCompareSnapshots(router string, desiredDir string, inDir string) vyosComparisonSummary {
	summary := vyosComparisonSummary{
		SchemaVersion: 1,
		Reason:        "desired-unavailable",
		Running:       vyosComparisonLayer{Reason: "desired-unavailable"},
		Saved:         vyosComparisonLayer{Reason: "desired-unavailable"},
		Topology:      vyosComparisonTopology{Reason: "desired-unavailable", Neighbors: []vyosComparisonNeighbor{}},
	}
	if router == "" || len(router) > 63 || strings.Trim(router, "abcdefghijklmnopqrstuvwxyz0123456789-") != "" || desiredDir == "" || inDir == "" {
		summary.Reason = "request-invalid"
		return summary
	}
	// One open/read/parse establishes the immutable in-memory desired tree for
	// both comparisons and all expected topology. Never reload settings here.
	desired, reason := vyosReadComparisonInput(filepath.Join(desiredDir, vyosConfigFileName(router)), router)
	if reason != "" {
		summary.Reason = reason
		return summary
	}
	summary.Running = vyosCompareLayer(filepath.Join(inDir, vyosLiveFileName(router)), router, desired)
	summary.Saved = vyosCompareLayer(filepath.Join(inDir, vyosSavedFileName(router)), router, desired)
	summary.Topology = vyosCompareTopology(desired.Root)
	summary.Complete = summary.Running.Complete && summary.Saved.Complete && summary.Topology.Complete
	summary.Reason = "complete"
	if !summary.Complete {
		summary.Reason = "incomplete"
	}
	return summary
}

func vyosReadComparisonInput(path string, router string) (*vyos.Config, string) {
	file, err := os.Open(path)
	if err != nil {
		return nil, "input-unavailable"
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > vyosCompareInputBytes {
		return nil, "input-invalid"
	}
	data, err := io.ReadAll(io.LimitReader(file, vyosCompareInputBytes+1))
	if err != nil || len(data) > vyosCompareInputBytes {
		return nil, "input-invalid"
	}
	config, err := vyos.Parse(string(data))
	if err != nil {
		return nil, "input-invalid"
	}
	if names := config.Root.LeafValues("system", "host-name"); len(names) != 1 || names[0] != router {
		return nil, "hostname-mismatch"
	}
	// These are essential containers in generated edge/lan/gateway snapshots.
	// Their presence catches partial shape; it does not attest capture atomicity.
	for _, name := range []string{"firewall", "interfaces", "protocols", "service", "system"} {
		if config.Root.Lookup(name) == nil {
			return nil, "input-shape-incomplete"
		}
	}
	if config.Root.Lookup("interfaces").Empty() || config.Root.Lookup("service", "ssh") == nil {
		return nil, "input-shape-incomplete"
	}
	return config, ""
}

func vyosCompareLayer(path string, router string, desired *vyos.Config) vyosComparisonLayer {
	live, reason := vyosReadComparisonInput(path, router)
	if reason != "" {
		return vyosComparisonLayer{Reason: reason}
	}
	// Count drift without destructive admission. Refusing a protected deletion
	// must not hide known drift or turn it into an apparent empty comparison.
	migration, err := vyos.Migrate(live.Root, desired.Root, vyos.MigrateOptions{})
	if err != nil {
		return vyosComparisonLayer{Reason: "comparison-unavailable"}
	}
	layer := vyosComparisonLayer{
		Complete:   migration.UnverifiedComparisons == 0,
		Changes:    len(migration.Deletes) + len(migration.Sets),
		Deletes:    len(migration.Deletes),
		Sets:       len(migration.Sets),
		Unverified: migration.UnverifiedComparisons,
		Reason:     "compared",
	}
	protected, err := vyosSnapshotProtectedPaths(desired.Root)
	if err != nil {
		layer.Complete = false
		layer.Reason = "protection-unavailable"
		return layer
	}
	liveUplinks := vyosSnapshotUplinks(live.Root)
	protected = append(protected, liveUplinks...)
	_, err = vyos.Migrate(live.Root, desired.Root, vyos.MigrateOptions{Protected: protected})
	var protectedErr *vyos.ProtectedPathError
	if errors.As(err, &protectedErr) {
		layer.ProtectedDelete = true
	} else if err != nil {
		layer.Complete = false
		layer.Reason = "comparison-unavailable"
	}
	if len(liveUplinks) == 0 {
		layer.Complete = false
		layer.Reason = "protection-unavailable"
	}
	if layer.Unverified != 0 {
		layer.Reason = "concealed-values"
	}
	return layer
}

type vyosComparisonInterface struct {
	prefixes   []netip.Prefix
	addresses  []netip.Addr
	advertised []netip.Prefix
	uplink     bool
	member     bool
}

func vyosCompareTopology(root *vyos.Node) vyosComparisonTopology {
	topology := vyosComparisonTopology{Reason: "topology-unavailable", Neighbors: []vyosComparisonNeighbor{}}
	// Explicit capacity is independent of neighbor extraction. Missing or
	// malformed capacity never substitutes a platform/kernel default.
	capacity := func(name string) uint64 {
		values := root.LeafValues("system", "conntrack", name)
		if len(values) != 1 {
			return 0
		}
		value, err := strconv.ParseUint(values[0], 10, 32)
		if err != nil {
			return 0
		}
		return value
	}
	tableSize, hashSize := capacity("table-size"), capacity("hash-size")
	topology.Conntrack = vyosComparisonConntrack{Explicit: tableSize != 0 || hashSize != 0, TableSize: tableSize, HashSize: hashSize}
	interfaces := map[string]vyosComparisonInterface{}
	interfaceRoot := root.Lookup("interfaces")
	if interfaceRoot == nil {
		return topology
	}
	for _, key := range interfaceRoot.ContainerKeys() {
		if key.Name != "ethernet" && key.Name != "bridge" {
			continue
		}
		if key.Tag == "" || len(key.Tag) > 32 || strings.Trim(key.Tag, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-") != "" {
			topology.Reason = "interface-unsupported"
			return topology
		}
		if _, ok := interfaces[key.Tag]; ok {
			topology.Reason = "interface-ambiguous"
			return topology
		}
		node := interfaceRoot.Container(key)
		iface := vyosComparisonInterface{
			uplink: slices.Contains(node.LeafValues("firewall", "local", "name"), "WAN_LOCAL") || slices.Contains(node.LeafValues("firewall", "local", "ipv6-name"), "WANv6_LOCAL"),
			member: node.HasLeaf("bridge-group", "bridge"),
		}
		for _, text := range node.LeafValues("address") {
			prefix, err := netip.ParsePrefix(text)
			if err != nil || prefix.Addr().Is4In6() || prefix.Addr().Zone() != "" {
				topology.Reason = "interface-address-unsupported"
				return topology
			}
			iface.prefixes = append(iface.prefixes, prefix)
			iface.addresses = append(iface.addresses, prefix.Addr())
		}
		if advert := node.Lookup("ipv6", "router-advert"); advert != nil {
			for _, prefixKey := range advert.ContainerKeys() {
				if prefixKey.Name != "prefix" {
					continue
				}
				prefix, err := netip.ParsePrefix(prefixKey.Tag)
				flags := advert.Container(prefixKey).LeafValues("on-link-flag")
				if err != nil || !prefix.Addr().Is6() || prefix.Addr().Is4In6() || prefix.Bits() != 64 || len(flags) != 1 || flags[0] != "true" {
					topology.Reason = "advertised-prefix-unsupported"
					return topology
				}
				iface.prefixes = append(iface.prefixes, prefix)
				iface.advertised = append(iface.advertised, prefix)
			}
		}
		interfaces[key.Tag] = iface
	}
	neighbors := map[vyosComparisonNeighbor]bool{}
	add := func(ifaceName string, address netip.Addr, role string) bool {
		iface, ok := interfaces[ifaceName]
		if !ok || iface.member || (role == "upstream") != iface.uplink || !address.IsValid() || address.Is4In6() || address.IsUnspecified() || address.IsMulticast() || address.Zone() != "" {
			return false
		}
		for _, candidate := range interfaces {
			if slices.Contains(candidate.addresses, address) {
				return false
			}
		}
		family := "ipv6"
		if address.Is4() {
			family = "ipv4"
		}
		neighbors[vyosComparisonNeighbor{Interface: ifaceName, Family: family, Address: address.String(), Role: role}] = true
		return len(neighbors) <= vyosCompareMaxNeighbors
	}
	gateways := root.LeafValues("system", "gateway-address")
	if len(gateways) != 1 {
		topology.Reason = "ipv4-upstream-unavailable"
		return topology
	}
	gateway, err := netip.ParseAddr(gateways[0])
	if err != nil || !gateway.Is4() {
		topology.Reason = "ipv4-upstream-unavailable"
		return topology
	}
	gatewayInterface := ""
	for name, iface := range interfaces {
		if !iface.uplink || iface.member {
			continue
		}
		for _, prefix := range iface.prefixes {
			if prefix.Contains(gateway) {
				if gatewayInterface != "" && gatewayInterface != name {
					topology.Reason = "ipv4-upstream-ambiguous"
					return topology
				}
				gatewayInterface = name
			}
		}
	}
	if !add(gatewayInterface, gateway, "upstream") {
		topology.Reason = "ipv4-upstream-unavailable"
		return topology
	}
	static := root.Lookup("protocols", "static")
	if static == nil {
		topology.Reason = "static-routes-unavailable"
		return topology
	}
	for _, key := range root.Lookup("protocols").ContainerKeys() {
		if key.Name != "static" || key.Tag != "" {
			topology.Reason = "routing-protocol-unsupported"
			return topology
		}
	}
	hasUpstream6 := false
	for _, key := range static.ContainerKeys() {
		route := static.Container(key)
		prefix, parseErr := netip.ParsePrefix(key.Tag)
		if parseErr != nil {
			topology.Reason = "static-route-unsupported"
			return topology
		}
		switch key.Name {
		case "interface-route":
			keys := route.ContainerKeys()
			if !prefix.Addr().Is4() || prefix.Bits() != 32 || len(keys) != 1 || keys[0].Name != "next-hop-interface" || !add(keys[0].Tag, prefix.Addr(), "port") {
				topology.Reason = "port-route-unsupported"
				return topology
			}
		case "route6":
			if !prefix.Addr().Is6() || prefix.Addr().Is4In6() {
				topology.Reason = "static-route-unsupported"
				return topology
			}
			keys := route.ContainerKeys()
			if len(keys) == 1 && keys[0].Name == "blackhole" && keys[0].Tag == "" {
				continue
			}
			if len(keys) != 1 || keys[0].Name != "next-hop" {
				topology.Reason = "ipv6-next-hop-ambiguous"
				return topology
			}
			address, parseErr := netip.ParseAddr(keys[0].Tag)
			ifaces := route.Container(keys[0]).LeafValues("interface")
			role := "port"
			if prefix.Bits() == 0 {
				role = "upstream"
				hasUpstream6 = true
			}
			if parseErr != nil || !address.Is6() || len(ifaces) != 1 || !add(ifaces[0], address, role) {
				topology.Reason = "ipv6-next-hop-unavailable"
				return topology
			}
		default:
			topology.Reason = "static-route-unsupported"
			return topology
		}
	}
	if !hasUpstream6 {
		topology.Reason = "ipv6-upstream-unavailable"
		return topology
	}
	// A prefix advertises a network, not a host. Only an exact destination in
	// the generated host-rule range supplies downstream IPv6 host authority.
	chain := root.Lookup("firewall", "ipv6-name", "WANv6_IN")
	if chain == nil {
		topology.Reason = "ipv6-host-authority-unavailable"
		return topology
	}
	for _, key := range chain.ContainerKeys() {
		if key.Name != "rule" {
			continue
		}
		number, parseErr := strconv.Atoi(key.Tag)
		if parseErr != nil {
			topology.Reason = "ipv6-host-rule-unsupported"
			return topology
		}
		if number < vyosHostRuleStart || vyosFirewallReservedRuleStart <= number {
			continue
		}
		values := chain.Container(key).LeafValues("destination", "address")
		if len(values) != 1 {
			topology.Reason = "ipv6-host-address-unavailable"
			return topology
		}
		address, parseErr := netip.ParseAddr(values[0])
		if parseErr != nil || !address.Is6() || address.Is4In6() {
			topology.Reason = "ipv6-host-address-unsupported"
			return topology
		}
		match := ""
		for name, iface := range interfaces {
			if iface.uplink || iface.member {
				continue
			}
			for _, prefix := range iface.prefixes {
				if prefix.Bits() == 64 && prefix.Contains(address) {
					if match != "" && match != name {
						topology.Reason = "ipv6-host-interface-ambiguous"
						return topology
					}
					match = name
				}
			}
		}
		if !add(match, address, "port") {
			topology.Reason = "ipv6-host-interface-unavailable"
			return topology
		}
	}
	explicitNeighborsOnly := false
	for name, iface := range interfaces {
		if iface.uplink || iface.member {
			continue
		}
		for _, prefix := range iface.advertised {
			hasHost := false
			for neighbor := range neighbors {
				address, _ := netip.ParseAddr(neighbor.Address)
				if neighbor.Interface == name && neighbor.Role == "port" && prefix.Contains(address) {
					hasHost = true
				}
			}
			if !hasHost {
				// Generated configs advertise spare ports too. This limits host
				// census authority, not the exact upstream/static expectations.
				explicitNeighborsOnly = true
			}
		}
	}
	for neighbor := range neighbors {
		topology.Neighbors = append(topology.Neighbors, neighbor)
	}
	sort.Slice(topology.Neighbors, func(i int, j int) bool {
		a, b := topology.Neighbors[i], topology.Neighbors[j]
		return strings.Join([]string{a.Interface, a.Family, a.Address, a.Role}, "\x00") < strings.Join([]string{b.Interface, b.Family, b.Address, b.Role}, "\x00")
	})
	topology.Complete = true
	topology.Reason = "derived"
	if explicitNeighborsOnly {
		topology.Reason = "derived-explicit-neighbors-only"
	}
	return topology
}
