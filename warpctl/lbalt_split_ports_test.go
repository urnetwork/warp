package main

// Tests of the ports the lb_alt split marks and jumps (lbalt_split.go): only
// ports a front socket serves (lbAltCheckPublicPorts), on the in-memory host
// of lbalt_split_test.go.

import (
	"context"
	"strings"
	"testing"
)

// A public port no front socket serves never enters the split: a reconcile
// whose public ports name one (a wider lb `ports` list, or udp 80) writes no
// HMARK rule and no entry jump, and the interface keeps nginx's DNAT alone.
func TestLbAltSplitMarksAndJumpsOnlyPortsAFrontSocketServes(t *testing.T) {
	for _, publicPorts := range []map[string][]int{
		{"tcp": {80, 443, 8443}, "udp": {53, 443, 4053}},
		{"tcp": {80, 443}, "udp": {53, 80, 443, 4053}},
	} {
		// every block is ready on the table's ports
		splitInterface := lbAltTestDualStackInterface()
		names := lbAltTestNames(t, splitInterface)
		host := newLbAltTestHost(t, splitInterface)
		writer := newLbAltTestWriter(t, host, t.TempDir())
		generations := lbAltTestGenerations()
		writeLbAltTestBlockChains(t, writer, generations, splitInterface)
		host.setListenRows(lbAltTestListenRows(generations, splitInterface))
		host.clearCommands()

		splitInterface.publicPorts = publicPorts
		err := writer.reconcile(context.Background(), lbAltTestConfig(splitInterface))
		if err == nil || !strings.Contains(err.Error(), "has no front socket") {
			t.Fatalf("%v: reconcile err = %v, want the port refused", publicPorts, err)
		}
		if restores := host.commandsNamed("iptables-restore", "ip6tables-restore"); len(restores) != 0 {
			t.Fatalf("%v: the reconcile wrote %d transactions", publicPorts, len(restores))
		}
		for _, family := range []string{"ipv4", "ipv6"} {
			for _, table := range []string{"mangle", "nat"} {
				requireLbAltRules(t, family+" "+table+" split rules", host.rulesMentioning(family, table, names.ruleComment), []string{})
			}
		}
	}
}
