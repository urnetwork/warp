package main

// Tests of the routing table a routed unit parses from --rttable
// (parseRoutingTableWith).

import (
	"strings"
	"testing"
)

// An interface with several global IPv6 addresses, as during a renumbering or
// with a stable and a SLAAC address, has none the routing table can choose,
// so the table starts without IPv6 and the unit runs, as the routing
// reconcile's refresh leaves such an interface; that refresh adopts the
// address once the interface has exactly one. One address is taken as it is,
// and none leaves the table without IPv6. Several addresses used to panic,
// which stopped the unit, IPv4 and all, on every restart.
func TestParseRoutingTableStartsWithoutIpv6WhenTheInterfaceHasSeveral(t *testing.T) {
	logOutput := captureErrOutput(t)
	publicIpv4 := &NetworkInterface{
		interfaceName:    "eth1",
		interfaceIp:      "198.51.100.1",
		interfaceSubnet:  "198.51.100.0/24",
		interfaceGateway: "198.51.100.254",
	}
	publicIpv6s := []*NetworkInterface{
		{
			interfaceName:    "eth1",
			interfaceIp:      "2001:db8:1::1",
			interfaceSubnet:  "2001:db8:1::/64",
			interfaceGateway: "2001:db8:1::fffe",
		},
		{
			interfaceName:    "eth1",
			interfaceIp:      "2001:db8:1::2",
			interfaceSubnet:  "2001:db8:1::/64",
			interfaceGateway: "2001:db8:1::fffe",
		},
	}
	rtTables := []byte("255\tlocal\n254\tmain\n100\twarp100\n101\twarp101\n")
	cases := []struct {
		ipv6s    []*NetworkInterface
		wantIpv6 *NetworkInterface
	}{
		{ipv6s: nil, wantIpv6: nil},
		{ipv6s: publicIpv6s[:1], wantIpv6: publicIpv6s[0]},
		{ipv6s: publicIpv6s, wantIpv6: nil},
	}
	for _, c := range cases {
		routingTable := parseRoutingTableWith("eth1:101", rtTables, func(interfaceName string) ([]*NetworkInterface, []*NetworkInterface, error) {
			if interfaceName != "eth1" {
				t.Fatalf("looked up %s", interfaceName)
			}
			return []*NetworkInterface{publicIpv4}, c.ipv6s, nil
		})
		if routingTable.interfaceName != "eth1" || routingTable.tableNumber != 101 || routingTable.tableName != "warp101" || routingTable.ipv4 != publicIpv4 {
			t.Fatalf("%d IPv6 addresses: table %s %d %s with %v", len(c.ipv6s), routingTable.interfaceName, routingTable.tableNumber, routingTable.tableName, routingTable.ipv4)
		}
		if ipv6 := routingTable.getIpv6(); ipv6 != c.wantIpv6 {
			t.Fatalf("%d IPv6 addresses: the table took %v, want %v", len(c.ipv6s), ipv6, c.wantIpv6)
		}
	}
	if !strings.Contains(logOutput.String(), "Routing interface eth1 has 2 global IPv6 addresses") {
		t.Fatalf("the parse did not log the addresses it could not choose between:\n%s", logOutput.String())
	}

	// the routing reconcile's refresh adopts the address once it is the only one
	ipv6s := publicIpv6s
	worker := &RunWorker{
		routingTable: parseRoutingTableWith("eth1:101", rtTables, func(string) ([]*NetworkInterface, []*NetworkInterface, error) {
			return []*NetworkInterface{publicIpv4}, ipv6s, nil
		}),
		networkInterfaces: func(string) ([]*NetworkInterface, []*NetworkInterface, error) {
			return []*NetworkInterface{publicIpv4}, ipv6s, nil
		},
	}
	worker.refreshMissingRoutingTableIpv6()
	if ipv6 := worker.routingTable.getIpv6(); ipv6 != nil {
		t.Fatalf("the refresh took %v from two addresses", ipv6)
	}
	ipv6s = publicIpv6s[1:]
	worker.refreshMissingRoutingTableIpv6()
	if ipv6 := worker.routingTable.getIpv6(); ipv6 != publicIpv6s[1] {
		t.Fatalf("the refresh took %v, want the one address left", ipv6)
	}
}
