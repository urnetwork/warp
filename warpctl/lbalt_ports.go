package main

// Socket occupancy and conntrack cleanup for generations that bind several
// bridges (server/LBALT.md §4.7; server/LBALT-IMPL.md §3, unit w-split).
//
// A connect generation on an lb_alt host binds the services bridge and every
// lb interface bridge, in both families, at the same internal ports, with
// several SO_REUSEPORT sockets on the public ones. A successful bind then no
// longer proves a port is free, and one bridge's listeners no longer show
// which generation holds a port. So sockets are read from `ss -Htuln`, which
// prints every address in full (netstat -tuln cut long IPv6 addresses to its
// column; its wide listing, -W, is the fallback where ss cannot run), and
// recorded as (address, protocol, port) for every listener on the host.
//
// Ports. Port blocks give every service block its own internal ports on a host
// (getPortBlocks, rule 1), so a listener on one of a block's pool ports, on any
// address and either protocol, means the port is held: by one of the block's
// generations, or by a stray socket a new generation must not share under
// SO_REUSEPORT. The allocator treats a pool port as occupied when any address
// holds it, which covers every bridge a generation binds (the services bridge
// and each lb_alt bridge, both families) without the worker naming them.
//
// Conntrack. A generation is retired once none of its sockets is left on any
// address. A live generation, current or draining, keeps its trusted
// services-bridge listeners for its whole lifetime (LBALT.md §4.6), so its
// ports stay held even while one of its public sockets is being re-created
// (D22). Cleanup deletes udp tuples only for pool ports no socket holds, on
// the block's own bridge and on every other bridge the block's generations
// listen on (a connect block's lb_alt bridges). It never interrupts a live
// drain, and it never leaves a repeat dial pinned to a retired generation's
// public socket. A bridge where none of the block's generations listens any
// more is not found, so its last tuples wait for conntrack's own timeout.

import (
	"errors"
	"fmt"
	"net/netip"
	"os/exec"
	"slices"
	"strconv"
	"strings"
)

// One listening socket: tcp or udp, the bound address (its family's
// unspecified address for a wildcard bind) and the port.
type listenSocket struct {
	protocol string
	address  netip.Addr
	port     int
}

// The host's listening sockets at one moment.
type listenSockets struct {
	heldSockets map[listenSocket]bool
	// every port any socket listens on, either protocol and any address
	heldPorts map[int]bool
	// the socket rows the listing held
	rowCount int
}

// Parses `ss -Htuln` into the host's listening sockets. A row is
// "<netid> <state> <recv-q> <send-q> <local address:port> <peer address:port>",
// and the local address is the first field after the netid that holds a port.
// Rows in netstat -tuln's layout ("<proto> <recv-q> <send-q> <local> <foreign>
// [state]", with tcp6 and udp6 and unbracketed IPv6) are found the same way.
// Rows whose first field is not tcp or udp, such as netstat's headers, are
// skipped. A tcp or udp row without a readable local address fails the whole
// parse: a socket the allocator cannot see is a port it might hand out again.
// Errors name the row, never its addresses.
func parseListenSockets(out []byte) (*listenSockets, error) {
	sockets := &listenSockets{
		heldSockets: map[listenSocket]bool{},
		heldPorts:   map[int]bool{},
		rowCount:    0,
	}
	for lineIndex, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		var protocol string
		switch fields[0] {
		case "tcp", "tcp6":
			protocol = "tcp"
		case "udp", "udp6":
			protocol = "udp"
		default:
			continue
		}
		sockets.rowCount += 1

		localField := ""
		for _, field := range fields[1:] {
			if strings.Contains(field, ":") {
				localField = field
				break
			}
		}
		if localField == "" {
			return nil, fmt.Errorf("socket row %d has no local address", lineIndex+1)
		}
		addresses, port, err := parseListenAddress(localField)
		if err != nil {
			return nil, fmt.Errorf("socket row %d: %w", lineIndex+1, err)
		}
		for _, address := range addresses {
			sockets.heldSockets[listenSocket{
				protocol: protocol,
				address:  address,
				port:     port,
			}] = true
		}
		sockets.heldPorts[port] = true
	}
	return sockets, nil
}

// Parses a local address field: 198.51.100.1:443, [2001:db8::1]:443, *:443,
// 127.0.0.53%lo:53, [fe80::1%eth0]:546, or netstat's ::1:443. ss's * is a
// dual-stack wildcard and yields both unspecified addresses. A device or zone
// suffix is dropped, and an IPv4-mapped address is read as IPv4, the traffic
// it accepts.
func parseListenAddress(field string) ([]netip.Addr, int, error) {
	var hostPart string
	var portPart string
	if strings.HasPrefix(field, "[") {
		end := strings.LastIndex(field, "]:")
		if end < 0 {
			return nil, 0, errors.New("unreadable bracketed address")
		}
		hostPart = field[1:end]
		portPart = field[end+2:]
	} else {
		end := strings.LastIndex(field, ":")
		if end < 0 {
			return nil, 0, errors.New("address has no port")
		}
		hostPart = field[:end]
		portPart = field[end+1:]
	}
	port, err := strconv.Atoi(portPart)
	if err != nil || port < 1 || 65535 < port {
		return nil, 0, errors.New("unreadable port")
	}
	if hostPart == "*" {
		return []netip.Addr{netip.IPv4Unspecified(), netip.IPv6Unspecified()}, port, nil
	}
	if zoneIndex := strings.Index(hostPart, "%"); 0 <= zoneIndex {
		hostPart = hostPart[:zoneIndex]
	}
	address, err := netip.ParseAddr(hostPart)
	if err != nil {
		return nil, 0, errors.New("unreadable address")
	}
	return []netip.Addr{address.Unmap()}, port, nil
}

// Whether a socket of the protocol listens on the address and port, bound to
// the address itself or to its family's unspecified address.
func (self *listenSockets) holds(protocol string, address netip.Addr, port int) bool {
	address = address.Unmap().WithZone("")
	if self.heldSockets[listenSocket{protocol: protocol, address: address, port: port}] {
		return true
	}
	unspecifiedAddress := netip.IPv4Unspecified()
	if address.Is6() {
		unspecifiedAddress = netip.IPv6Unspecified()
	}
	return self.heldSockets[listenSocket{protocol: protocol, address: unspecifiedAddress, port: port}]
}

// Whether any socket, of either protocol and on any address, listens on the
// port.
func (self *listenSockets) holdsPort(port int) bool {
	return self.heldPorts[port]
}

// The specific addresses, neither unspecified nor loopback, that hold any of
// the ports, sorted: the bridges a block's generations bind.
func (self *listenSockets) addressesHolding(ports map[int]bool) []netip.Addr {
	addressSet := map[netip.Addr]bool{}
	for socket := range self.heldSockets {
		if !ports[socket.port] || socket.address.IsUnspecified() || socket.address.IsLoopback() {
			continue
		}
		addressSet[socket.address] = true
	}
	addresses := make([]netip.Addr, 0, len(addressSet))
	for address := range addressSet {
		addresses = append(addresses, address)
	}
	slices.SortFunc(addresses, func(a netip.Addr, b netip.Addr) int {
		return a.Compare(b)
	})
	return addresses
}

// The commands that list the host's listening sockets, in order of preference.
// Both print every address in full: ss, and netstat's wide listing where ss
// cannot run (no iproute2, or one too old for -H). Neither needs privileges.
func listenSocketCommands() [][]string {
	return [][]string{
		{"ss", "-Htuln"},
		{"netstat", "-tulnW"},
	}
}

// Lists the host's listening sockets with the first listing command that runs.
// A listing that runs but cannot be read fails, with no fallback, so the
// snapshot fails closed.
func readListenSockets(run func(name string, args []string) (commandOutput, error)) (*listenSockets, error) {
	commandErrors := []string{}
	for _, command := range listenSocketCommands() {
		output, err := run(command[0], command[1:])
		if err != nil {
			commandErrors = append(commandErrors, fmt.Sprintf("%s: %s", command[0], quietCommandError(err)))
			continue
		}
		return parseListenSockets(output.stdout)
	}
	return nil, fmt.Errorf("socket discovery: %s", strings.Join(commandErrors, "; "))
}

// Lists every listening socket on the host. The output, tens of thousands of
// udp sockets on a busy edge, is parsed without being copied into the journal.
func scanListenSockets() (*listenSockets, error) {
	return readListenSockets(func(name string, args []string) (commandOutput, error) {
		return runQuiet(exec.Command(name, args...))
	})
}

// The pool ports no socket holds on any address: the ports of retired
// generations, whose conntrack tuples are stale on every bridge.
func (self *RunWorker) staleConntrackCandidatePorts(occupiedPorts map[int]bool) map[int]bool {
	candidatePorts := map[int]bool{}
	for _, internalPorts := range self.portBlocks.externalsToInternals {
		for _, internalPort := range internalPorts {
			if !occupiedPorts[internalPort] {
				candidatePorts[internalPort] = true
			}
		}
	}
	return candidatePorts
}

// Removes the udp conntrack tuples that pin flows to a retired generation of
// this block on the bridges its generations bind besides its own network: a
// connect block's lb_alt interface bridges, in both families. The bridges are
// the addresses the block's pool ports listen on, so a worker needs no list of
// them, and only tuples of ports no socket holds anywhere are deleted.
func (self *RunWorker) cleanupStaleLbAltBridgeConntrack(occupiedPorts map[int]bool, sockets *listenSockets) []conntrackCleanupStats {
	poolPorts, err := self.configuredInternalPorts()
	if err != nil {
		Err.Printf("Conntrack cleanup skipped for lb_alt bridges: %s\n", err)
		return nil
	}
	ownAddresses := map[netip.Addr]bool{}
	for _, networkConfig := range self.getNetworkConfigs() {
		if address, err := netip.ParseAddr(networkConfig.dockerNetwork.interfaceIp); err == nil {
			ownAddresses[address.Unmap()] = true
		}
	}
	candidatePorts := self.staleConntrackCandidatePorts(occupiedPorts)

	allStats := []conntrackCleanupStats{}
	for _, bridgeAddress := range sockets.addressesHolding(poolPorts) {
		if ownAddresses[bridgeAddress] {
			continue
		}
		family := "ipv4"
		if bridgeAddress.Is6() {
			family = "ipv6"
		}
		stats := cleanupStaleConntrackOnBridge(family, bridgeAddress.String(), candidatePorts)
		stats.bridge = bridgeAddress.String()
		self.logConntrackCleanup(stats)
		allStats = append(allStats, stats)
	}
	return allStats
}
