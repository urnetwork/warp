package main

// The public port table of the lb_alt network-namespace harness
// (lbalt_netns_test.go): an lb_alt interface's public ports, and the connect
// service port behind each (server/LBALT-IMPL.md §2.3). It is the harness's
// own copy of that contract: the edge tests probe these ports, give them to
// the split, and point the block chains at the service ports' internal ports.
// warpctl's own table moves while the integration goes on (lbalt/int-warp
// moves it into services), and a harness that named it would stop building
// on one side of the move, in linux files a darwin build never compiles.
// TestLbAltNetnsPublicPortTableIsTheWorkersTable checks the copy against the
// table a connect block's worker writes its chains from, through the worker's
// own chain write.

import (
	"cmp"
	"context"
	"slices"
	"testing"
)

// The service ports behind the public ports, the keys of WARP_PORTS (§2.1
// listen): the front's port-80 handler on 80, tls on tcp and quic on udp of
// 443, and whodis on 4053.
const (
	lbAltNetnsHttpServicePort   = 80
	lbAltNetnsHttpsServicePort  = 443
	lbAltNetnsWhodisServicePort = 4053
)

// One row of the table: a public (protocol, port) of an lb_alt interface, and
// the service port whose internal port the front's socket for it listens on.
type lbAltNetnsPublicPortRow struct {
	protocol    string
	publicPort  int
	servicePort int
}

// The §2.3 table, in its order. Public udp 53 reaches whodis, as 4053 does.
func lbAltNetnsPublicPortTable() []lbAltNetnsPublicPortRow {
	return []lbAltNetnsPublicPortRow{
		lbAltNetnsPublicPortRow{protocol: "tcp", publicPort: 80, servicePort: lbAltNetnsHttpServicePort},
		lbAltNetnsPublicPortRow{protocol: "tcp", publicPort: 443, servicePort: lbAltNetnsHttpsServicePort},
		lbAltNetnsPublicPortRow{protocol: "udp", publicPort: 443, servicePort: lbAltNetnsHttpsServicePort},
		lbAltNetnsPublicPortRow{protocol: "udp", publicPort: 4053, servicePort: lbAltNetnsWhodisServicePort},
		lbAltNetnsPublicPortRow{protocol: "udp", publicPort: 53, servicePort: lbAltNetnsWhodisServicePort},
	}
}

// The table's public ports by protocol, each sorted, as the split takes an
// interface's public ports.
func lbAltNetnsSplitPublicPorts() map[string][]int {
	publicPorts := map[string][]int{}
	for _, row := range lbAltNetnsPublicPortTable() {
		publicPorts[row.protocol] = append(publicPorts[row.protocol], row.publicPort)
	}
	for _, ports := range publicPorts {
		slices.Sort(ports)
	}
	return publicPorts
}

// The block chain targets of a generation: each row of the table to the
// internal port of its service port in the generation's WARP_PORTS.
func lbAltNetnsBlockTargets(servicePortsToInternalPort map[int]int) []lbAltBlockTarget {
	blockTargets := []lbAltBlockTarget{}
	for _, row := range lbAltNetnsPublicPortTable() {
		blockTargets = append(blockTargets, lbAltBlockTarget{
			protocol:     row.protocol,
			publicPort:   row.publicPort,
			internalPort: servicePortsToInternalPort[row.servicePort],
		})
	}
	return blockTargets
}

// The harness's copy of the table is the one a connect block's worker writes
// its chains from (writeLbAltWorkerBlockChains): for a generation's
// WARP_PORTS, the worker gives the interface exactly the copy's public ports,
// and points each at the internal port of the copy's service port.
func TestLbAltNetnsPublicPortTableIsTheWorkersTable(t *testing.T) {
	servicePortsToInternalPort := map[int]int{
		lbAltNetnsHttpServicePort:   15010,
		lbAltNetnsHttpsServicePort:  15011,
		lbAltNetnsWhodisServicePort: 15012,
	}
	writeCount := 0
	writtenSplitInterfaces := []lbAltSplitInterface{}
	writtenTargets := []lbAltBlockTarget{}
	ops := defaultLbAltWorkerOps()
	ops.writeBlockChains = func(ctx context.Context, env string, block string, splitInterfaces []lbAltSplitInterface, targets []lbAltBlockTarget) error {
		writeCount += 1
		writtenSplitInterfaces = splitInterfaces
		writtenTargets = targets
		return nil
	}
	worker := &RunWorker{
		env:     "test",
		service: lbAltBlockService,
		block:   "g1",
		lbAltInterfaces: []*lbAltWorkerInterface{
			&lbAltWorkerInterface{
				interfaceName: "eth0",
				dockerNetwork: nil,
			},
		},
		lbAltOps: ops,
	}
	if err := worker.writeLbAltWorkerBlockChains(servicePortsToInternalPort); err != nil {
		t.Fatal(err)
	}
	if writeCount != 1 || len(writtenSplitInterfaces) != 1 {
		t.Fatalf("the worker wrote %d times for %d interfaces, want once for its one interface", writeCount, len(writtenSplitInterfaces))
	}

	// a protocol with no ports means none, as the split takes it
	publicPorts := map[string][]int{}
	for protocol, ports := range writtenSplitInterfaces[0].publicPorts {
		if 0 < len(ports) {
			publicPorts[protocol] = slices.Sorted(slices.Values(ports))
		}
	}
	wantPublicPorts := lbAltNetnsSplitPublicPorts()
	if len(publicPorts) != len(wantPublicPorts) {
		t.Fatalf("the worker's public ports are %v, the harness's %v", publicPorts, wantPublicPorts)
	}
	for protocol, wantPorts := range wantPublicPorts {
		if !slices.Equal(publicPorts[protocol], wantPorts) {
			t.Fatalf("the worker's public ports are %v, the harness's %v", publicPorts, wantPublicPorts)
		}
	}

	// the order of the targets is the worker's; the chain is written per
	// protocol and port
	compareTargets := func(a lbAltBlockTarget, b lbAltBlockTarget) int {
		return cmp.Or(
			cmp.Compare(a.protocol, b.protocol),
			cmp.Compare(a.publicPort, b.publicPort),
			cmp.Compare(a.internalPort, b.internalPort),
		)
	}
	targets := slices.SortedFunc(slices.Values(writtenTargets), compareTargets)
	wantTargets := slices.SortedFunc(slices.Values(lbAltNetnsBlockTargets(servicePortsToInternalPort)), compareTargets)
	if !slices.Equal(targets, wantTargets) {
		t.Fatalf("the worker's block chain targets are %v, the harness's %v", targets, wantTargets)
	}
}
