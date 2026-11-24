package main

// Tests of the ports a connect block's deploy never hands a candidate on an
// lb_alt host: those its lb_alt chains send public flows to (lbalt_worker.go,
// lbAltWorkerChainPorts; server/LBALT.md D13, §4.7).

import (
	"reflect"
	"strings"
	"testing"

	"github.com/urnetwork/warp"
)

// A connect block g1 of env main that binds the lb interface ens4np3, whose
// bridge is 198.51.100.4, with two to four pool ports per service port.
// Nothing listens on any pool port: the generation its chains point at died.
func newLbAltChainPortsWorker(t *testing.T) *RunWorker {
	t.Helper()
	captureErrOutput(t)
	installLbAltTestQuietCommands(t, &lbAltTestQuietCommands{
		listenRows: "",
	})
	return &RunWorker{
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
		portBlocks: parsePortBlocks("80:7123:14000-14001;443:7124:14010-14013;4053:7125:14020-14023;5080:7126:14030-14031"),
		lbAltInterfaces: []*lbAltWorkerInterface{
			{
				interfaceName: "ens4np3",
				dockerNetwork: &DockerNetwork{
					networkName: "warpens4np3",
					ipv4: &NetworkInterface{
						interfaceName: "warpens4np3",
						interfaceIp:   "198.51.100.4",
					},
				},
			},
		},
	}
}

// A restarted worker knows nothing of its chains but what iptables lists:
// the ports the block's own chains DNAT to, in either family, are not handed
// out, though no socket holds them, and the chains of another block, which
// target ports outside this block's pool by rule, take nothing from it.
func TestLbAltWorkerAllocationSkipsTheTargetsOfTheBlocksChains(t *testing.T) {
	worker := newLbAltChainPortsWorker(t)
	rec := newIptablesRecorder()
	installRecorder(t, rec)
	rec.listings["iptables:L:-n"] = strings.Join([]string{
		"Chain WARP-MAIN-LBA-ENS4NP3-G1 (1 references)",
		"target     prot opt source               destination",
		"DNAT       tcp  --  0.0.0.0/0            0.0.0.0/0            tcp dpt:80 to:198.51.100.4:14000",
		"DNAT       tcp  --  0.0.0.0/0            0.0.0.0/0            tcp dpt:443 to:198.51.100.4:14010",
		"DNAT       udp  --  0.0.0.0/0            0.0.0.0/0            udp dpt:53 to:198.51.100.4:14020",
		"DNAT       udp  --  0.0.0.0/0            0.0.0.0/0            udp dpt:443 to:198.51.100.4:14010",
		"DNAT       udp  --  0.0.0.0/0            0.0.0.0/0            udp dpt:4053 to:198.51.100.4:14020",
		"",
		"Chain WARP-MAIN-LBA-ENS4NP3-G2 (1 references)",
		"target     prot opt source               destination",
		"DNAT       tcp  --  0.0.0.0/0            0.0.0.0/0            tcp dpt:80 to:198.51.100.4:14001",
	}, "\n")
	// the IPv6 chain is one generation behind
	rec.listings["ip6tables:L:-n"] = strings.Join([]string{
		"Chain WARP-MAIN-LBA-ENS4NP3-G1 (1 references)",
		"target     prot opt source               destination",
		"DNAT       udp      ::/0                 ::/0                 udp dpt:443 to:[2001:db8:4::1]:14011",
	}, "\n")

	externalPorts, servicePorts := worker.assignDeployPorts()
	wantServicePorts := map[int]int{80: 14001, 443: 14012, 4053: 14021, 5080: 14030}
	if !reflect.DeepEqual(servicePorts, wantServicePorts) {
		t.Fatalf("assigned service ports %v, want %v, around the chains' targets", servicePorts, wantServicePorts)
	}
	if externalPorts[7123] != 14001 || externalPorts[7124] != 14012 || externalPorts[7125] != 14021 || externalPorts[7126] != 14030 {
		t.Fatalf("assigned external ports %v", externalPorts)
	}
}

// The generation the block's latest deploy committed keeps its ports while
// its chains are lost, since the chain refresh writes them back to those
// ports. Only the ports its chains target are kept: its other service ports
// go to the candidate as before.
func TestLbAltWorkerAllocationSkipsTheCommittedGenerationsChainPorts(t *testing.T) {
	worker := newLbAltChainPortsWorker(t)
	rec := newIptablesRecorder()
	installRecorder(t, rec)
	worker.lbAltState.chainServicePorts = map[int]int{80: 14000, 443: 14010, 4053: 14020, 5080: 14030}

	_, servicePorts := worker.assignDeployPorts()
	wantServicePorts := map[int]int{80: 14001, 443: 14011, 4053: 14021, 5080: 14030}
	if !reflect.DeepEqual(servicePorts, wantServicePorts) {
		t.Fatalf("assigned service ports %v, want %v, around the committed generation's chain ports", servicePorts, wantServicePorts)
	}
}

// A pool whose every free port is a chain target allocates nothing, so the
// deploy waits for a port rather than put the candidate behind a chain.
func TestLbAltWorkerAllocationWaitsWhenOnlyChainTargetsAreFree(t *testing.T) {
	worker := newLbAltChainPortsWorker(t)
	rec := newIptablesRecorder()
	installRecorder(t, rec)
	worker.portBlocks = parsePortBlocks("80:7123:14000;443:7124:14010-14011;4053:7125:14020-14021")
	worker.lbAltState.chainServicePorts = map[int]int{80: 14000, 443: 14010, 4053: 14020}

	if externalPorts, servicePorts := worker.assignDeployPorts(); externalPorts != nil || servicePorts != nil {
		t.Fatalf("assigned %v %v from a pool whose only free port 80 is a chain target", externalPorts, servicePorts)
	}
}
