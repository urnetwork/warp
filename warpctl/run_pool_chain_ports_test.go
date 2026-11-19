package main

// Tests of the ports a deploy never hands a candidate because the block's own
// chain still DNATs to them, though no socket holds them (assignDeployPorts,
// poolChainTargetPorts).

import (
	"reflect"
	"strings"
	"testing"

	"github.com/urnetwork/warp"
)

// A service block g1 of env test whose committed generation died: no socket
// holds any pool port, and the block's chain still DNATs its external ports,
// and the internal ports themselves, to that generation's ports. The
// candidate gets the next ports of the pool, so it takes no public traffic
// before its readiness poll and cutover.
func TestAllocationSkipsThePortsTheBlocksChainStillTargets(t *testing.T) {
	captureErrOutput(t)
	installLbAltTestQuietCommands(t, &lbAltTestQuietCommands{listenRows: ""})
	rec := newIptablesRecorder()
	installRecorder(t, rec)
	worker := &RunWorker{
		env:            "test",
		service:        "api",
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
		portBlocks: parsePortBlocks("80:7080:8001-8003;8080:7081:8011-8013"),
	}
	rec.listings["iptables:L:WARP-TEST-API-G1"] = strings.Join([]string{
		"Chain WARP-TEST-API-G1 (2 references)",
		"target     prot opt source               destination",
		"DNAT       tcp  --  0.0.0.0/0            0.0.0.0/0            tcp dpt:8001 to:192.0.2.1:8001",
		"DNAT       tcp  --  0.0.0.0/0            0.0.0.0/0            tcp dpt:7080 to:192.0.2.1:8001",
		"DNAT       tcp  --  0.0.0.0/0            0.0.0.0/0            tcp dpt:8011 to:192.0.2.1:8011",
		"DNAT       tcp  --  0.0.0.0/0            0.0.0.0/0            tcp dpt:7081 to:192.0.2.1:8011",
	}, "\n")

	externalPorts, servicePorts := worker.assignDeployPorts()
	if want := map[int]int{7080: 8002, 7081: 8012}; !reflect.DeepEqual(externalPorts, want) {
		t.Fatalf("assigned external ports %v, want %v, around the chain's targets", externalPorts, want)
	}
	if want := map[int]int{80: 8002, 8080: 8012}; !reflect.DeepEqual(servicePorts, want) {
		t.Fatalf("assigned service ports %v, want %v", servicePorts, want)
	}
}

// An nginx lb unit's chain also holds the public rules scoped to its
// interface, and a cutover moves each family on its own, so a port that only
// the IPv6 chain still targets is kept too.
func TestAllocationSkipsAnLbChainsPublicTargetsInEitherFamily(t *testing.T) {
	captureErrOutput(t)
	installLbAltTestQuietCommands(t, &lbAltTestQuietCommands{listenRows: ""})
	rec := newIptablesRecorder()
	installRecorder(t, rec)
	worker := &RunWorker{
		env:            "test",
		service:        "lb",
		block:          "edge-a.example-eth1",
		hostNetworking: true,
		quitEvent:      warp.NewEvent(),
		routingTable: &RoutingTable{
			interfaceName: "eth1",
			tableNumber:   100,
			tableName:     "warp100",
			ipv4: &NetworkInterface{
				interfaceName: "eth1",
				interfaceIp:   "198.51.100.1",
			},
			ipv6: &NetworkInterface{
				interfaceName: "eth1",
				interfaceIp:   "2001:db8:1::1",
			},
		},
		dockerNetwork: &DockerNetwork{
			networkName: "warpeth1",
			ipv4: &NetworkInterface{
				interfaceName: "warpeth1",
				interfaceIp:   "192.0.2.1",
			},
			ipv6: &NetworkInterface{
				interfaceName: "warpeth1",
				interfaceIp:   "2001:db8:2::1",
			},
		},
		portBlocks: parsePortBlocks("80:7080:8001-8003;443:7443:8011-8013"),
	}
	rec.listings["iptables:L:WARP-TEST-LB-ETH1"] = strings.Join([]string{
		"Chain WARP-TEST-LB-ETH1 (2 references)",
		"target     prot opt source               destination",
		"DNAT       tcp  --  0.0.0.0/0            198.51.100.1         tcp dpt:80 to:192.0.2.1:8001",
		"DNAT       tcp  --  0.0.0.0/0            198.51.100.1         tcp dpt:443 to:192.0.2.1:8011",
		"DNAT       tcp  --  0.0.0.0/0            0.0.0.0/0            tcp dpt:7080 to:192.0.2.1:8001",
		"DNAT       tcp  --  0.0.0.0/0            0.0.0.0/0            tcp dpt:7443 to:192.0.2.1:8011",
	}, "\n")
	// the IPv6 chain's public 443 rule still points at an older generation
	rec.listings["ip6tables:L:WARP-TEST-LB-ETH1"] = strings.Join([]string{
		"Chain WARP-TEST-LB-ETH1 (2 references)",
		"target     prot opt source               destination",
		"DNAT       tcp      ::/0                 2001:db8:1::1        tcp dpt:80 to:[2001:db8:2::1]:8001",
		"DNAT       tcp      ::/0                 2001:db8:1::1        tcp dpt:443 to:[2001:db8:2::1]:8012",
	}, "\n")

	_, servicePorts := worker.assignDeployPorts()
	if want := map[int]int{80: 8002, 443: 8013}; !reflect.DeepEqual(servicePorts, want) {
		t.Fatalf("assigned service ports %v, want %v, around both families' targets", servicePorts, want)
	}
}

// A pool whose only port no socket holds is one the chain targets allocates
// nothing, so the deploy waits for a port, as for the lb_alt chains, rather
// than put the candidate behind the chain.
func TestAllocationWaitsWhenOnlyPoolChainTargetsAreFree(t *testing.T) {
	captureErrOutput(t)
	installLbAltTestQuietCommands(t, &lbAltTestQuietCommands{
		// a draining generation still holds 8002
		listenRows: "tcp   LISTEN 0      4096        192.0.2.1:8002        0.0.0.0:*\n",
	})
	rec := newIptablesRecorder()
	installRecorder(t, rec)
	worker := &RunWorker{
		env:            "test",
		service:        "api",
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
		portBlocks: parsePortBlocks("80:7080:8001-8002"),
	}
	rec.listings["iptables:L:WARP-TEST-API-G1"] = strings.Join([]string{
		"Chain WARP-TEST-API-G1 (2 references)",
		"target     prot opt source               destination",
		"DNAT       tcp  --  0.0.0.0/0            0.0.0.0/0            tcp dpt:7080 to:192.0.2.1:8001",
	}, "\n")

	if externalPorts, servicePorts := worker.assignDeployPorts(); externalPorts != nil || servicePorts != nil {
		t.Fatalf("assigned %v %v from a pool whose only free port is the chain's target", externalPorts, servicePorts)
	}
}
