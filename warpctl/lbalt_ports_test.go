package main

import (
	"fmt"
	"maps"
	"net/netip"
	"os/exec"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/urnetwork/warp"
)

// The listening sockets as "<protocol> <address> <port>", sorted.
func lbAltTestSocketNames(sockets *listenSockets) []string {
	names := []string{}
	for socket := range sockets.heldSockets {
		names = append(names, fmt.Sprintf("%s %s %d", socket.protocol, socket.address, socket.port))
	}
	slices.Sort(names)
	return names
}

func TestLbAltListenSocketsParseSsRows(t *testing.T) {
	out := strings.Join([]string{
		"tcp   LISTEN 0      4096           192.0.2.1:7201        0.0.0.0:*",
		"udp   UNCONN 0      0           198.51.100.4:7231        0.0.0.0:*",
		"tcp   LISTEN 0      4096   [2001:db8:4:0:a:b:c:d]:7231         [::]:*",
		"tcp   LISTEN 0      4096                   *:9100              *:*",
		"udp   UNCONN 0      0                0.0.0.0:68          0.0.0.0:*",
		"tcp   LISTEN 0      128                 [::]:22             [::]:*",
		"tcp   LISTEN 0      4096   [::ffff:198.51.100.9]:7261           *:*",
		// sockets bound to a device, as ss prints them: the device follows
		// the address, after the bracket of an IPv6 one
		"udp   UNCONN 0      0          127.0.0.53%lo:53          0.0.0.0:*",
		"udp   UNCONN 0      0         [2001:db8:fe::1]%eth0:546      [::]:*",
		"udp   UNCONN 0      0                 [::]%eth1:547      [::]:*",
		"udp   UNCONN 0      0                  *%eth0:67              *:*",
		"udp   UNCONN 0      0           0.0.0.0%eth0:69          0.0.0.0:*",
		"",
	}, "\n")
	sockets, err := parseListenSockets([]byte(out))
	if err != nil {
		t.Fatal(err)
	}
	requireLbAltRules(t, "sockets", lbAltTestSocketNames(sockets), []string{
		"tcp 0.0.0.0 9100",
		"tcp 192.0.2.1 7201",
		"tcp 198.51.100.9 7261",
		"tcp 2001:db8:4:0:a:b:c:d 7231",
		"tcp :: 22",
		"tcp :: 9100",
		"udp 0.0.0.0 67",
		"udp 0.0.0.0 68",
		"udp 0.0.0.0 69",
		"udp 127.0.0.53 53",
		"udp 198.51.100.4 7231",
		"udp 2001:db8:fe::1 546",
		"udp :: 547",
		"udp :: 67",
	})
	if sockets.rowCount != 12 {
		t.Fatalf("%d rows", sockets.rowCount)
	}
	for _, port := range []int{7201, 7231, 9100, 68, 22, 53, 546, 547, 67, 69, 7261} {
		if !sockets.holdsPort(port) {
			t.Errorf("port %d not held", port)
		}
	}
	if sockets.holdsPort(7202) {
		t.Error("port 7202 held")
	}
}

// ss prints a long IPv6 address in full. netstat cut the same socket's address
// to its 23-character column, leaving no address to match a bridge against,
// so its row is refused rather than read as some other address.
func TestLbAltListenSocketsKeepLongIpv6Addresses(t *testing.T) {
	longAddress := netip.MustParseAddr("2001:db8:1234:5678:9abc:def0:1234:5678")
	sockets, err := parseListenSockets([]byte("tcp   LISTEN 0      4096   [2001:db8:1234:5678:9abc:def0:1234:5678]:7443   [::]:*\n"))
	if err != nil {
		t.Fatal(err)
	}
	if !sockets.holds("tcp", longAddress, 7443) {
		t.Fatalf("sockets %v", lbAltTestSocketNames(sockets))
	}
	if _, err := parseListenSockets([]byte("tcp6       0      0 2001:db8:1234:5678:7443 :::*                    LISTEN\n")); err == nil {
		t.Fatal("netstat's cut address was read as an address")
	}
}

// Rows in netstat -tuln's layout read the same way.
func TestLbAltListenSocketsParseNetstatRows(t *testing.T) {
	out := `Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State
tcp        0      0 192.0.2.1:7201          0.0.0.0:*               LISTEN
tcp6       0      0 ::1:7231                :::*                    LISTEN
udp        0      0 0.0.0.0:68              0.0.0.0:*
udp6       0      0 :::5353                 :::*
`
	sockets, err := parseListenSockets([]byte(out))
	if err != nil {
		t.Fatal(err)
	}
	requireLbAltRules(t, "sockets", lbAltTestSocketNames(sockets), []string{
		"tcp 192.0.2.1 7201",
		"tcp ::1 7231",
		"udp 0.0.0.0 68",
		"udp :: 5353",
	})
	if sockets.rowCount != 4 {
		t.Fatalf("%d rows", sockets.rowCount)
	}
}

// A socket the allocator cannot read is a port it might hand out again, so the
// snapshot fails, and the error names the row, not its addresses.
func TestLbAltListenSocketsFailClosedOnAnUnreadableRow(t *testing.T) {
	for _, row := range []string{
		"tcp   LISTEN 0      4096   unreadable.example:7201   0.0.0.0:*",
		"udp   UNCONN 0      0      198.51.100.4:dns          0.0.0.0:*",
		"tcp   LISTEN 0      4096",
		// only a device may follow an IPv6 address's bracket
		"udp   UNCONN 0      0      [2001:db8:fe::1]eth0:546  [::]:*",
		"udp   UNCONN 0      0      [2001:db8:fe::1:546       [::]:*",
	} {
		_, err := parseListenSockets([]byte("udp   UNCONN 0      0      192.0.2.1:7231   0.0.0.0:*\n" + row + "\n"))
		if err == nil || !strings.Contains(err.Error(), "row 2") {
			t.Errorf("row %q: %v", row, err)
			continue
		}
		if strings.Contains(err.Error(), "example") || strings.Contains(err.Error(), "198.51.100.4") {
			t.Errorf("error %q repeats the row", err)
		}
	}
}

func TestLbAltListenSocketsHoldByAddressFamilyAndProtocol(t *testing.T) {
	sockets, err := parseListenSockets([]byte(strings.Join([]string{
		"tcp   LISTEN 0      4096       192.0.2.1:7201        0.0.0.0:*",
		"tcp   LISTEN 0      4096               *:9100              *:*",
		"udp   UNCONN 0      0            0.0.0.0:68          0.0.0.0:*",
		"tcp   LISTEN 0      128             [::]:22             [::]:*",
	}, "\n")))
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		protocol string
		address  string
		port     int
		holds    bool
	}{
		{protocol: "tcp", address: "192.0.2.1", port: 7201, holds: true},
		// another protocol, another address
		{protocol: "udp", address: "192.0.2.1", port: 7201, holds: false},
		{protocol: "tcp", address: "192.0.2.2", port: 7201, holds: false},
		// ss's * holds both families
		{protocol: "tcp", address: "198.51.100.7", port: 9100, holds: true},
		{protocol: "tcp", address: "2001:db8::7", port: 9100, holds: true},
		// a wildcard holds only its own family
		{protocol: "udp", address: "198.51.100.7", port: 68, holds: true},
		{protocol: "udp", address: "2001:db8::7", port: 68, holds: false},
		{protocol: "tcp", address: "2001:db8::7", port: 22, holds: true},
		{protocol: "tcp", address: "198.51.100.7", port: 22, holds: false},
	}
	for _, c := range cases {
		if holds := sockets.holds(c.protocol, netip.MustParseAddr(c.address), c.port); holds != c.holds {
			t.Errorf("%s %s %d: holds %t, want %t", c.protocol, c.address, c.port, holds, c.holds)
		}
	}
	addresses := sockets.addressesHolding(map[int]bool{7201: true, 9100: true, 68: true})
	if len(addresses) != 1 || addresses[0] != netip.MustParseAddr("192.0.2.1") {
		t.Fatalf("addresses holding the ports %v, want only the specific one", addresses)
	}
}

// Answers the quiet commands a worker runs: ss with the listening rows, or,
// when ss is missing, netstat's wide listing with its own rows; and conntrack
// from a responder. It records the listing and conntrack commands.
type lbAltTestQuietCommands struct {
	stateLock  sync.Mutex
	listenRows string
	// ss fails as a host without iproute2's ss does
	ssMissing bool
	// what netstat -tulnW prints
	wideNetstatRows    string
	listingCommands    [][]string
	conntrackCommands  [][]string
	conntrackResponder func(args []string) (commandOutput, error)
}

func installLbAltTestQuietCommands(t *testing.T, quietCommands *lbAltTestQuietCommands) {
	t.Helper()
	origRunQuiet := runQuietFunc
	runQuietFunc = func(cmd *exec.Cmd) (commandOutput, error) {
		args := cmd.Args
		if 0 < len(args) && args[0] == "sudo" {
			args = args[1:]
		}
		if len(args) == 0 {
			return commandOutput{}, fmt.Errorf("empty command")
		}
		switch args[0] {
		case "ss", "netstat":
			func() {
				quietCommands.stateLock.Lock()
				defer quietCommands.stateLock.Unlock()
				quietCommands.listingCommands = append(quietCommands.listingCommands, slices.Clone(args))
			}()
			switch {
			case slices.Equal(args, []string{"ss", "-Htuln"}) && quietCommands.ssMissing:
				return commandOutput{}, &exec.Error{Name: "ss", Err: exec.ErrNotFound}
			case slices.Equal(args, []string{"ss", "-Htuln"}):
				return commandOutput{stdout: []byte(quietCommands.listenRows)}, nil
			case slices.Equal(args, []string{"netstat", "-tulnW"}):
				return commandOutput{stdout: []byte(quietCommands.wideNetstatRows)}, nil
			}
			return commandOutput{}, fmt.Errorf("unexpected listing %v", args)
		case "conntrack":
			var responder func(args []string) (commandOutput, error)
			func() {
				quietCommands.stateLock.Lock()
				defer quietCommands.stateLock.Unlock()
				quietCommands.conntrackCommands = append(quietCommands.conntrackCommands, slices.Clone(args))
				responder = quietCommands.conntrackResponder
			}()
			if responder == nil {
				return commandOutput{}, nil
			}
			return responder(args)
		}
		return commandOutput{}, fmt.Errorf("unexpected command %v", args)
	}
	t.Cleanup(func() {
		runQuietFunc = origRunQuiet
	})
}

// A connect generation binds the services bridge and its lb_alt interface
// bridges at the same internal ports, the public ones with SO_REUSEPORT, so a
// port held on any of them is not free: a bind there would succeed and share
// the port with a draining generation.
func TestFindOccupiedPortsSeesEveryBridgeTheGenerationBinds(t *testing.T) {
	logOutput := captureErrOutput(t)
	installLbAltTestQuietCommands(t, &lbAltTestQuietCommands{
		listenRows: strings.Join([]string{
			// the current generation's trusted sockets on the services bridge
			"tcp   LISTEN 0      4096        192.0.2.1:14000        0.0.0.0:*",
			"udp   UNCONN 0      0           192.0.2.1:14010        0.0.0.0:*",
			// a draining generation's public tcp 443 socket, held only on an
			// lb_alt bridge
			"tcp   LISTEN 0      4096     198.51.100.4:14011        0.0.0.0:*",
			// another's, only on an lb_alt bridge's long IPv6 address
			"udp   UNCONN 0      0      [2001:db8:1234:5678:9abc:def0:1234:5678]:14012   [::]:*",
		}, "\n") + "\n",
	})
	worker := &RunWorker{
		env:            "main",
		service:        "connect",
		block:          "g1",
		hostNetworking: true,
		quitEvent:      warp.NewEvent(),
		servicesDockerNetwork: &DockerNetwork{
			networkName: "warpservices",
			ipv4: &NetworkInterface{
				interfaceName: "warpservices",
				interfaceIp:   "192.0.2.1",
			},
		},
		portBlocks: parsePortBlocks("80:7123:14000-14001;443:7124:14010-14013"),
	}

	occupiedPorts, err := worker.findOccupiedPorts()
	if err != nil {
		t.Fatal(err)
	}
	occupiedList := slices.Sorted(func(yield func(int) bool) {
		for port := range occupiedPorts {
			if !yield(port) {
				return
			}
		}
	})
	if !slices.Equal(occupiedList, []int{14000, 14010, 14011, 14012}) {
		t.Fatalf("occupied ports %v", occupiedList)
	}
	externalPorts, servicePorts := worker.assignDeployPorts()
	if externalPorts[7123] != 14001 || externalPorts[7124] != 14013 || servicePorts[80] != 14001 || servicePorts[443] != 14013 {
		t.Fatalf("assigned %v %v", externalPorts, servicePorts)
	}
	if !strings.Contains(logOutput.String(), "scanned=4") || !strings.Contains(logOutput.String(), "occupied_pool_ports=4") {
		t.Fatalf("log %q", logOutput.String())
	}
	// the snapshot is never copied into the journal
	if strings.Contains(logOutput.String(), "198.51.100.4") {
		t.Fatal("socket discovery logged an address")
	}
}

// A host whose ss cannot run, missing or too old for -H, is read with netstat's
// wide listing, which keeps long IPv6 addresses whole, never with the cut
// -tuln listing.
func TestFindOccupiedPortsFallsBackToTheWideNetstatListing(t *testing.T) {
	captureErrOutput(t)
	quietCommands := &lbAltTestQuietCommands{
		ssMissing: true,
		wideNetstatRows: `Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State
tcp        0      0 192.0.2.1:14000         0.0.0.0:*               LISTEN
udp6       0      0 2001:db8:1234:5678:9abc:def0:1234:5678:14011 :::*
`,
	}
	installLbAltTestQuietCommands(t, quietCommands)
	worker := &RunWorker{
		env:            "main",
		service:        "connect",
		block:          "g1",
		hostNetworking: true,
		servicesDockerNetwork: &DockerNetwork{
			networkName: "warpservices",
			ipv4: &NetworkInterface{
				interfaceName: "warpservices",
				interfaceIp:   "192.0.2.1",
			},
		},
		portBlocks: parsePortBlocks("80:7123:14000-14001;443:7124:14010-14013"),
	}
	occupiedPorts, err := worker.findOccupiedPorts()
	if err != nil {
		t.Fatal(err)
	}
	if len(occupiedPorts) != 2 || !occupiedPorts[14000] || !occupiedPorts[14011] {
		t.Fatalf("occupied ports %v", occupiedPorts)
	}
	listings := []string{}
	for _, args := range quietCommands.listingCommands {
		listings = append(listings, strings.Join(args, " "))
	}
	requireLbAltRules(t, "listings", listings, []string{"ss -Htuln", "netstat -tulnW"})
}

// A listing that ran but cannot be read fails the snapshot: falling back would
// hide a socket the allocator could hand out again.
func TestFindOccupiedPortsFailsClosedOnAnUnreadableListing(t *testing.T) {
	captureErrOutput(t)
	quietCommands := &lbAltTestQuietCommands{
		listenRows:      "tcp   LISTEN 0      4096   unreadable.example:14000   0.0.0.0:*\n",
		wideNetstatRows: "",
	}
	installLbAltTestQuietCommands(t, quietCommands)
	worker := &RunWorker{
		env:            "main",
		service:        "connect",
		block:          "g1",
		hostNetworking: true,
		portBlocks:     parsePortBlocks("80:7123:14000-14001"),
	}
	if _, err := worker.findOccupiedPorts(); err == nil {
		t.Fatal("an unreadable listing was accepted")
	}
	if len(quietCommands.listingCommands) != 1 {
		t.Fatalf("listings %v, want ss alone", quietCommands.listingCommands)
	}
}

// A host's DHCP clients bind sockets to a device, which ss prints with the
// device after the address. Those rows are read, so the deploy goes on, and a
// device-bound socket on a pool port still holds it.
func TestFindOccupiedPortsReadsDeviceBoundSockets(t *testing.T) {
	captureErrOutput(t)
	installLbAltTestQuietCommands(t, &lbAltTestQuietCommands{
		listenRows: strings.Join([]string{
			"udp   UNCONN 0      0      [2001:db8:fe::1]%eth0:546      [::]:*",
			"udp   UNCONN 0      0                  *%eth0:68            *:*",
			// a stray socket on the block's first pool port
			"tcp   LISTEN 0      4096           [::]%eth0:14000       [::]:*",
		}, "\n") + "\n",
	})
	worker := &RunWorker{
		env:            "main",
		service:        "connect",
		block:          "g1",
		hostNetworking: true,
		quitEvent:      warp.NewEvent(),
		servicesDockerNetwork: &DockerNetwork{
			networkName: "warpservices",
			ipv4: &NetworkInterface{
				interfaceName: "warpservices",
				interfaceIp:   "192.0.2.1",
			},
		},
		portBlocks: parsePortBlocks("80:7123:14000-14001"),
	}

	occupiedPorts, err := worker.findOccupiedPorts()
	if err != nil {
		t.Fatal(err)
	}
	if len(occupiedPorts) != 1 || !occupiedPorts[14000] {
		t.Fatalf("occupied ports %v", occupiedPorts)
	}
	externalPorts, servicePorts := worker.assignDeployPorts()
	if externalPorts[7123] != 14001 || servicePorts[80] != 14001 {
		t.Fatalf("assigned %v %v", externalPorts, servicePorts)
	}
}

// A connect block's public flows are DNATed to its lb_alt bridges, so their
// tuples pin to those bridges' addresses. Only a retired generation's, whose
// port no socket holds on any address, are deleted, on every bridge the
// block binds; a draining generation keeps its tuples even while one of its
// public sockets is being re-created.
func TestCleanupStaleConntrackDeletesOnlyRetiredGenerationsOnLbAltBridges(t *testing.T) {
	logOutput := captureErrOutput(t)
	const rawFlowMarker = "RAW_CONNTRACK_FLOW_MUST_NOT_BE_LOGGED"
	quietCommands := &lbAltTestQuietCommands{
		listenRows: strings.Join([]string{
			// the current generation on 14100: trusted on the services bridge,
			// public on both addresses of the lb_alt bridge
			"udp   UNCONN 0      0           192.0.2.1:14100        0.0.0.0:*",
			"udp   UNCONN 0      0        198.51.100.4:14100        0.0.0.0:*",
			"tcp   LISTEN 0      4096     198.51.100.4:14100        0.0.0.0:*",
			"udp   UNCONN 0      0     [2001:db8:4::1]:14100           [::]:*",
			// the draining generation on 14099: its trusted socket is up, its
			// public sockets are being re-created
			"udp   UNCONN 0      0           192.0.2.1:14099        0.0.0.0:*",
			// another block's port on the same bridge
			"udp   UNCONN 0      0        198.51.100.4:15000        0.0.0.0:*",
			// the retired generation on 14098 holds nothing
		}, "\n") + "\n",
		conntrackResponder: func(args []string) (commandOutput, error) {
			replySource := flagValue(args, "--reply-src")
			switch args[1] {
			case "-L":
				out := ""
				for _, port := range []int{14098, 14099, 14100, 15000} {
					out += conntrackSaveEntry(replySource, port, rawFlowMarker)
				}
				return commandOutput{stdout: []byte(out)}, nil
			case "-D":
				return commandOutput{stdout: []byte(conntrackSaveEntry(replySource, 14098, rawFlowMarker))}, nil
			}
			return commandOutput{}, nil
		},
	}
	installLbAltTestQuietCommands(t, quietCommands)
	worker := &RunWorker{
		env:            "main",
		service:        "connect",
		block:          "g1",
		hostNetworking: true,
		servicesDockerNetwork: &DockerNetwork{
			networkName: "warpservices",
			ipv4: &NetworkInterface{
				interfaceName: "warpservices",
				interfaceIp:   "192.0.2.1",
			},
		},
		portBlocks: parsePortBlocks("443:7124:14098-14101"),
	}

	worker.cleanupStaleConntrack()

	listed := []string{}
	deleted := []string{}
	for _, args := range quietCommands.conntrackCommands {
		command := fmt.Sprintf("%s %s", flagValue(args, "-f"), flagValue(args, "--reply-src"))
		switch args[1] {
		case "-L":
			listed = append(listed, command)
		case "-D":
			deleted = append(deleted, command+" "+flagValue(args, "--reply-port-src"))
		}
	}
	requireLbAltRules(t, "listed bridges", listed, []string{
		"ipv4 192.0.2.1",
		"ipv4 198.51.100.4",
		"ipv6 2001:db8:4::1",
	})
	requireLbAltRules(t, "deleted tuples", deleted, []string{
		"ipv4 192.0.2.1 14098",
		"ipv4 198.51.100.4 14098",
		"ipv6 2001:db8:4::1 14098",
	})
	if strings.Count(logOutput.String(), "Conntrack cleanup") != 3 || !strings.Contains(logOutput.String(), "family=ipv6 bridge=2001:db8:4::1 scanned=4") {
		t.Fatalf("log %q", logOutput.String())
	}
	if strings.Contains(logOutput.String(), rawFlowMarker) {
		t.Fatal("conntrack rows were logged")
	}
}

// Another block's lb_alt chain still claims a port; the worker's own, which
// hold its own targets, do not. A block of another service is never the owner
// of connect's chains, though it may share their block name. Pools never hold
// a public port on main, so a port that is both is synthetic here.
func TestValidateRedirectPortOwnershipCountsTheWorkersOwnLbAltChains(t *testing.T) {
	rec := newIptablesRecorder()
	installRecorder(t, rec)
	listing := func(chains ...string) string {
		return "Chain PREROUTING (policy ACCEPT)\ntarget     prot opt source               destination\n\n" + strings.Join(chains, "\n\n")
	}
	lbAltChain := func(chain string, internalPort int) string {
		return fmt.Sprintf("Chain %s (1 references)\ntarget     prot opt source               destination\nDNAT       udp  --  0.0.0.0/0            0.0.0.0/0            udp dpt:4053 to:198.51.100.4:%d", chain, internalPort)
	}
	connectWorker := &RunWorker{
		env:            "main",
		service:        "connect",
		block:          "g1",
		hostNetworking: true,
		servicesDockerNetwork: &DockerNetwork{
			networkName: "warpservices",
			ipv4: &NetworkInterface{
				interfaceName: "warpservices",
				interfaceIp:   "192.0.2.1",
			},
		},
	}
	desiredPorts := map[int]int{7178: 4053}

	rec.listings["-n"] = listing(lbAltChain("WARP-MAIN-LBA-ENO4NP3-G1", 7262), lbAltChain("WARP-MAIN-LBA-ENO4NP3-G2", 7263))
	err := connectWorker.validateRedirectPortOwnership(desiredPorts)
	if err == nil || !strings.Contains(err.Error(), "WARP-MAIN-LBA-ENO4NP3-G2") {
		t.Fatalf("another block's lb_alt chain: %v", err)
	}
	rec.listings["-n"] = listing(lbAltChain("WARP-MAIN-LBA-ENO4NP3-G1", 7262), lbAltChain("WARP-MAIN-LBA-ENO2NP1-G1", 7262))
	if err := connectWorker.validateRedirectPortOwnership(desiredPorts); err != nil {
		t.Fatalf("the block's own lb_alt chains: %v", err)
	}
	apiWorker := &RunWorker{
		env:            "main",
		service:        "api",
		block:          "g1",
		hostNetworking: true,
		servicesDockerNetwork: &DockerNetwork{
			networkName: "warpservices",
			ipv4: &NetworkInterface{
				interfaceName: "warpservices",
				interfaceIp:   "192.0.2.1",
			},
		},
	}
	rec.listings["-n"] = listing(lbAltChain("WARP-MAIN-LBA-ENO4NP3-G1", 7262))
	err = apiWorker.validateRedirectPortOwnership(desiredPorts)
	if err == nil || !strings.Contains(err.Error(), "WARP-MAIN-LBA-ENO4NP3-G1") {
		t.Fatalf("connect's lb_alt chain for an api block of the same name: %v", err)
	}

	// an lb unit owns its interface's split and block chains, not another
	// interface's
	lbWorker := &RunWorker{
		env:            "main",
		service:        "lb",
		block:          "edge-a.example-eno4np3",
		hostNetworking: true,
		dockerNetwork: &DockerNetwork{
			networkName: "warpeno4np3",
			ipv4: &NetworkInterface{
				interfaceName: "warpeno4np3",
				interfaceIp:   "198.51.100.4",
			},
		},
	}
	rec.listings["-n"] = listing(lbAltChain("WARP-MAIN-LBA-ENO4NP3-G2", 7263), lbAltChain("WARP-MAIN-LBT-ENO4NP3", 7263))
	if err := lbWorker.validateRedirectPortOwnership(desiredPorts); err != nil {
		t.Fatalf("the interface's own lb_alt chains: %v", err)
	}
	rec.listings["-n"] = listing(lbAltChain("WARP-MAIN-LBA-ENO2NP1-G2", 7263))
	if err := lbWorker.validateRedirectPortOwnership(desiredPorts); err == nil || !strings.Contains(err.Error(), "WARP-MAIN-LBA-ENO2NP1-G2") {
		t.Fatalf("another interface's lb_alt chain: %v", err)
	}
	if len(rec.getRules()) != 0 {
		t.Fatalf("ownership validation wrote rules: %v", rec.getRules())
	}
}

// At a restart, a container the block's lb_alt chains still DNAT to is a live
// owner, in either family, even when the pool chain already moved on: the
// worker stopped between switching the two.
func TestActiveRedirectInternalPortsProtectsTheBlocksLbAltTargets(t *testing.T) {
	rec := newIptablesRecorder()
	installRecorder(t, rec)
	worker := &RunWorker{
		env:            "main",
		service:        "connect",
		block:          "g1",
		hostNetworking: true,
		servicesDockerNetwork: &DockerNetwork{
			networkName: "warpservices",
			ipv4: &NetworkInterface{
				interfaceName: "warpservices",
				interfaceIp:   "192.0.2.1",
			},
		},
		portBlocks: parsePortBlocks("443:7124:14010-14013"),
	}
	chainName := worker.iptablesChainName()
	rec.listings[chainName] = fmt.Sprintf(`Chain %s (2 references)
target     prot opt source               destination
DNAT       udp  --  0.0.0.0/0            0.0.0.0/0            udp dpt:7124 to:192.0.2.1:14011`, chainName)
	rec.listings["iptables:L:-n"] = fmt.Sprintf(`Chain %s (2 references)
target     prot opt source               destination
DNAT       udp  --  0.0.0.0/0            0.0.0.0/0            udp dpt:7124 to:192.0.2.1:14011

Chain WARP-MAIN-LBA-ENO4NP3-G1 (1 references)
target     prot opt source               destination
DNAT       udp  --  0.0.0.0/0            0.0.0.0/0            udp dpt:443 to:198.51.100.4:14010

Chain WARP-MAIN-LBA-ENO4NP3-G2 (1 references)
target     prot opt source               destination
DNAT       udp  --  0.0.0.0/0            0.0.0.0/0            udp dpt:443 to:198.51.100.4:14013`, chainName)
	// the IPv6 chain is one generation behind
	rec.listings["ip6tables:L:-n"] = `Chain WARP-MAIN-LBA-ENO4NP3-G1 (1 references)
target     prot opt source               destination
DNAT       udp      ::/0                 ::/0                 udp dpt:443 to:[2001:db8:4::1]:14012`

	activePorts, err := worker.activeRedirectInternalPorts()
	if err != nil {
		t.Fatal(err)
	}
	activeList := []int{}
	for port := range activePorts {
		activeList = append(activeList, port)
	}
	slices.Sort(activeList)
	if !slices.Equal(activeList, []int{14010, 14011, 14012}) {
		t.Fatalf("active ports %v", activeList)
	}
	container := func(containerId string, internalPort int) *Container {
		return &Container{
			ContainerId: containerId,
			Config: &ContainerConfig{
				Env: []string{fmt.Sprintf("WARP_PORTS=443:%d", internalPort)},
			},
		}
	}
	orphanedContainerIds, err := selectOrphanedServiceBlockContainers(ContainerList{
		container("lb-alt-ipv4-owner", 14010),
		container("pool-owner", 14011),
		container("lb-alt-ipv6-owner", 14012),
		container("unreferenced", 14013),
	}, activePorts)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(orphanedContainerIds, []string{"unreferenced"}) {
		t.Fatalf("orphaned %v", orphanedContainerIds)
	}
}

// connect g1 on an lb_alt host, binding eno4np3, with its pool chain listed in
// IPv4 and its eno4np3 block chain in IPv6 alone, as a first chain write
// leaves them when its IPv4 transaction failed and its IPv6 one committed.
// Counts the worker's ip6tables listings.
func newLbAltIpv6OnlyChainWorker(t *testing.T, bindsLbAltInterfaces bool) (*RunWorker, *int) {
	t.Helper()
	rec := newIptablesRecorder()
	installRecorder(t, rec)
	ip6tablesListings := 0
	recordedSudo2 := sudo2Func
	sudo2Func = func(name []string, args ...string) *exec.Cmd {
		if name[len(name)-1] == "ip6tables" {
			ip6tablesListings += 1
		}
		return recordedSudo2(name, args...)
	}
	t.Cleanup(func() {
		sudo2Func = recordedSudo2
	})
	worker := &RunWorker{
		env:            "main",
		service:        "connect",
		block:          "g1",
		hostNetworking: true,
		servicesDockerNetwork: &DockerNetwork{
			networkName: "warpservices",
			ipv4: &NetworkInterface{
				interfaceName: "warpservices",
				interfaceIp:   "192.0.2.1",
			},
		},
		portBlocks: parsePortBlocks("443:7124:14010-14013"),
	}
	if bindsLbAltInterfaces {
		worker.lbAltInterfaces = []*lbAltWorkerInterface{
			&lbAltWorkerInterface{
				interfaceName: "eno4np3",
				dockerNetwork: nil,
			},
		}
	}
	chainName := worker.iptablesChainName()
	poolListing := fmt.Sprintf(`Chain %s (2 references)
target     prot opt source               destination
DNAT       udp  --  0.0.0.0/0            0.0.0.0/0            udp dpt:7124 to:192.0.2.1:14011`, chainName)
	rec.listings[chainName] = poolListing
	rec.listings["iptables:L:-n"] = poolListing
	rec.listings["ip6tables:L:-n"] = `Chain WARP-MAIN-LBA-ENO4NP3-G1 (1 references)
target     prot opt source               destination
DNAT       udp      ::/0                 ::/0                 udp dpt:443 to:[2001:db8:4::1]:14012`
	return worker, &ip6tablesListings
}

// A block that binds lb interfaces reads its chains in IPv6 whatever IPv4
// shows, so a port only its IPv6 chain targets is the committed generation's:
// its container is kept from the startup orphan drain, and the next candidate
// does not get the port, which the lb unit's reconcile would give the block's
// buckets as soon as the candidate bound it.
func TestLbAltWorkerChainPortsReadABlockChainInIpv6Alone(t *testing.T) {
	worker, _ := newLbAltIpv6OnlyChainWorker(t, true)
	activePorts, err := worker.activeRedirectInternalPorts()
	if err != nil {
		t.Fatal(err)
	}
	if got := slices.Sorted(maps.Keys(activePorts)); !slices.Equal(got, []int{14011, 14012}) {
		t.Fatalf("active ports %v, want the pool's 14011 and the IPv6 chain's 14012", got)
	}
	chainPorts, err := worker.lbAltWorkerChainPorts()
	if err != nil {
		t.Fatal(err)
	}
	if got := slices.Sorted(maps.Keys(chainPorts)); !slices.Equal(got, []int{14012}) {
		t.Fatalf("chain ports %v, want the IPv6 chain's 14012", got)
	}
	orphanedContainerIds, err := selectOrphanedServiceBlockContainers(ContainerList{
		&Container{ContainerId: "pool-owner", Config: &ContainerConfig{Env: []string{"WARP_PORTS=443:14011"}}},
		&Container{ContainerId: "ipv6-chain-owner", Config: &ContainerConfig{Env: []string{"WARP_PORTS=443:14012"}}},
		&Container{ContainerId: "unreferenced", Config: &ContainerConfig{Env: []string{"WARP_PORTS=443:14013"}}},
	}, activePorts)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(orphanedContainerIds, []string{"unreferenced"}) {
		t.Fatalf("orphaned %v, want only the unreferenced container", orphanedContainerIds)
	}
}

// A worker that binds no lb interfaces reads IPv6 only once IPv4 shows it an
// lb_alt chain, so on a host without lb_alt it never runs ip6tables here.
func TestLbAltChainTargetPortsSkipIpv6WithoutABoundInterface(t *testing.T) {
	worker, ip6tablesListings := newLbAltIpv6OnlyChainWorker(t, false)
	activePorts, err := worker.activeRedirectInternalPorts()
	if err != nil {
		t.Fatal(err)
	}
	if got := slices.Sorted(maps.Keys(activePorts)); !slices.Equal(got, []int{14011}) {
		t.Fatalf("active ports %v, want the pool's 14011", got)
	}
	if *ip6tablesListings != 0 {
		t.Fatalf("ip6tables listed %d times", *ip6tablesListings)
	}
}

// The lb unit's chain carries the entry jumps to its split; pruning removes
// only DNATs to dead pool targets and leaves them.
func TestPruneUnownedRedirectRulesKeepsTheLbAltEntryJumps(t *testing.T) {
	rec := newIptablesRecorder()
	installRecorder(t, rec)
	worker := &RunWorker{
		env:            "main",
		service:        "lb",
		block:          "edge-a.example-eno4np3",
		hostNetworking: true,
		portBlocks:     parsePortBlocks("443:7443:7301-7302"),
		dockerNetwork: &DockerNetwork{
			networkName: "warpeno4np3",
			ipv4: &NetworkInterface{
				interfaceName: "warpeno4np3",
				interfaceIp:   "198.51.100.4",
			},
		},
	}
	chainName := worker.iptablesChainName()
	rec.listings["iptables:S:"+chainName] = strings.Join([]string{
		fmt.Sprintf("-A %s -d 203.0.113.4/32 -p tcp -m multiport --dports 80,443 -m comment --comment warp-main-lba-eno4np3 -j WARP-MAIN-LBA-ENO4NP3", chainName),
		fmt.Sprintf("-A %s -d 203.0.113.4/32 -p udp -m multiport --dports 53,443,4053 -m comment --comment warp-main-lba-eno4np3 -j WARP-MAIN-LBA-ENO4NP3", chainName),
		fmt.Sprintf("-A %s -d 203.0.113.4/32 -p tcp -m tcp --dport 443 -j DNAT --to-destination 198.51.100.4:7302", chainName),
		fmt.Sprintf("-A %s -p tcp --dport 7443 -j DNAT --to-destination 198.51.100.4:7302", chainName),
	}, "\n")

	if err := worker.pruneUnownedRedirectRules(map[int]bool{7301: true}); err != nil {
		t.Fatal(err)
	}
	deleted := []string{}
	for _, rule := range rec.findRules("-D") {
		deleted = append(deleted, strings.Join(rule.args, " "))
	}
	requireLbAltRules(t, "pruned rules", deleted, []string{
		fmt.Sprintf("-t nat -D %s -d 203.0.113.4/32 -p tcp -m tcp --dport 443 -j DNAT --to-destination 198.51.100.4:7302", chainName),
		fmt.Sprintf("-t nat -D %s -p tcp --dport 7443 -j DNAT --to-destination 198.51.100.4:7302", chainName),
	})
}
