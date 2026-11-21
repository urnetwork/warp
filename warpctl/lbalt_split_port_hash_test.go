package main

// Tests of the lb_alt split's port-hash sources (server LBALTOPT2 R16;
// lbalt_split.go's hmarkRules, services.LbAltPortHashSources): the rules of
// each source come after the address-only rules of their chain, are spelled
// and listed back in iptables' own form, change and go with the config and on
// rollback, and reach the lb unit through --lbaltporthash.

import (
	"context"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/docopt/docopt-go"
)

// An interface's test config with port-hash sources, given as prefixes in
// any order.
func lbAltTestPortHashConfig(splitInterface lbAltSplitInterface, sources ...string) *lbAltSplitConfig {
	config := lbAltTestConfig(splitInterface)
	for _, source := range sources {
		config.portHashSources = append(config.portHashSources, netip.MustParsePrefix(source))
	}
	return config
}

// The family's public address and its prefix length on the dual-stack test
// interface.
func lbAltTestPortHashDestination(family string) (string, string) {
	if family == "ipv6" {
		return "2001:db8:ff04::1/128", "128"
	}
	return "203.0.113.4/32", "32"
}

// One chain's HMARK rules on the dual-stack test interface, as iptables -S
// lists them: the address-only rules of tcp and udp, then each port-hash
// source's, in the order given.
func lbAltTestListedHmarkRules(family string, sources ...string) []string {
	destination, addressBits := lbAltTestPortHashDestination(family)
	match := "-m conntrack --ctstate NEW -m comment --comment warp-main-lba-ens4np3 -j HMARK --hmark-src-prefix " + addressBits
	hash := "--hmark-rnd 0x4c42414c --hmark-mod 100 --hmark-offset 65536"
	rules := []string{
		"-d " + destination + " -p tcp -m multiport --dports 80,443 " + match + " " + hash,
		"-d " + destination + " -p udp -m multiport --dports 53,443,4053 " + match + " " + hash,
	}
	for _, source := range sources {
		rules = append(rules,
			"-s "+source+" -d "+destination+" -p tcp -m multiport --dports 80,443 "+match+" --hmark-sport-mask 0xffff "+hash,
			"-s "+source+" -d "+destination+" -p udp -m multiport --dports 53,443,4053 "+match+" --hmark-sport-mask 0xffff "+hash,
		)
	}
	return rules
}

// The family's HMARK rules on the dual-stack test interface as the split
// spells them, "<chain> <arguments>": in each chain the address-only rules,
// byte for byte those of the split before port-hash sources, then each
// source's.
func lbAltTestSpelledHmarkRules(family string, sources ...string) []string {
	destination, addressBits := lbAltTestPortHashDestination(family)
	match := "-m conntrack --ctstate NEW -m comment --comment warp-main-lba-ens4np3 -j HMARK --hmark-src-prefix " + addressBits
	hash := "--hmark-mod 100 --hmark-offset 0x10000 --hmark-rnd 0x4c42414c"
	rules := []string{}
	for _, chain := range []string{"PREROUTING", "OUTPUT"} {
		rules = append(rules,
			chain+" -d "+destination+" -p tcp -m multiport --dports 80,443 "+match+" "+hash,
			chain+" -d "+destination+" -p udp -m multiport --dports 53,443,4053 "+match+" "+hash,
		)
		for _, source := range sources {
			rules = append(rules,
				chain+" -s "+source+" -d "+destination+" -p tcp -m multiport --dports 80,443 "+match+" --hmark-sport-mask 0xffff "+hash,
				chain+" -s "+source+" -d "+destination+" -p udp -m multiport --dports 53,443,4053 "+match+" --hmark-sport-mask 0xffff "+hash,
			)
		}
	}
	return rules
}

// The dual-stack test interface's host with every block ready and the
// interface's split reconciled from the config.
func newLbAltTestPortHashHost(t *testing.T, config *lbAltSplitConfig) (*fakeLbAltHost, *lbAltSplitWriter) {
	t.Helper()
	host := newLbAltTestHost(t, config.splitInterface)
	writer := newLbAltTestWriter(t, host, t.TempDir())
	generations := lbAltTestGenerations()
	writeLbAltTestBlockChains(t, writer, generations, config.splitInterface)
	host.setListenRows(lbAltTestListenRows(generations, config.splitInterface))
	host.clearCommands()
	if err := writer.reconcile(context.Background(), config); err != nil {
		t.Fatal(err)
	}
	return host, writer
}

// The restore inputs of the family's commands, by table.
func lbAltTestRestoreInputs(host *fakeLbAltHost, family string) map[string][]string {
	restoreName := "iptables-restore"
	if family == "ipv6" {
		restoreName = "ip6tables-restore"
	}
	inputs := map[string][]string{}
	for _, restore := range host.commandsNamed(restoreName) {
		table, _, _ := strings.Cut(strings.TrimPrefix(restore.stdin, "*"), "\n")
		inputs[table] = append(inputs[table], restore.stdin)
	}
	return inputs
}

// The split plans the address-only rules of each chain first and then each
// port-hash source's, for no, one and two sources in each family, sorted
// whatever order the config gives them in. With none the rules are byte for
// byte the split's before port-hash sources, and so is the one transaction
// that writes them. Each source's rules list back as written, in order, so
// a flow from a source takes the address-only mark and then its own.
func TestLbAltSplitPortHashRulesFollowTheAddressRules(t *testing.T) {
	for _, c := range []struct {
		name        string
		sources     []string
		ipv4Sources []string
		ipv6Sources []string
	}{
		{
			name:        "none",
			sources:     nil,
			ipv4Sources: nil,
			ipv6Sources: nil,
		},
		{
			name:        "one in each family",
			sources:     []string{"2001:db8:c0::/48", "192.0.2.0/27"},
			ipv4Sources: []string{"192.0.2.0/27"},
			ipv6Sources: []string{"2001:db8:c0::/48"},
		},
		{
			name:        "two in each family",
			sources:     []string{"198.51.100.128/25", "2001:db8:c1::/64", "192.0.2.0/27", "2001:db8:c0::/48"},
			ipv4Sources: []string{"192.0.2.0/27", "198.51.100.128/25"},
			ipv6Sources: []string{"2001:db8:c0::/48", "2001:db8:c1::/64"},
		},
		{
			name:        "ipv4 alone",
			sources:     []string{"192.0.2.0/27"},
			ipv4Sources: []string{"192.0.2.0/27"},
			ipv6Sources: nil,
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			config := lbAltTestPortHashConfig(lbAltTestDualStackInterface(), c.sources...)
			plan, err := newLbAltInterfacePlan(config)
			if err != nil {
				t.Fatal(err)
			}
			host, _ := newLbAltTestPortHashHost(t, config)
			for _, family := range plan.families {
				familySources := c.ipv4Sources
				if family.name == "ipv6" {
					familySources = c.ipv6Sources
				}
				spelled := []string{}
				for _, rule := range plan.hmarkRules(family) {
					spelled = append(spelled, rule.chain+" "+strings.Join(rule.spec, " "))
				}
				requireLbAltRules(t, family.name+" planned HMARK rules", spelled, lbAltTestSpelledHmarkRules(family.name, familySources...))

				listed := lbAltTestListedHmarkRules(family.name, familySources...)
				requireLbAltRules(t, family.name+" mangle PREROUTING", host.chainRules(family.name, "mangle", "PREROUTING"), listed)
				requireLbAltRules(t, family.name+" mangle OUTPUT", host.chainRules(family.name, "mangle", "OUTPUT"), listed)

				// one transaction inserts the rules at the head of each chain,
				// in order
				mangleInputs := lbAltTestRestoreInputs(host, family.name)["mangle"]
				wantLines := []string{"*mangle"}
				positions := map[string]int{}
				for _, rule := range lbAltTestSpelledHmarkRules(family.name, familySources...) {
					chain, spec, _ := strings.Cut(rule, " ")
					positions[chain] += 1
					wantLines = append(wantLines, fmt.Sprintf("-I %s %d %s", chain, positions[chain], spec))
				}
				wantLines = append(wantLines, "COMMIT", "")
				if len(mangleInputs) != 1 || mangleInputs[0] != strings.Join(wantLines, "\n") {
					t.Fatalf("%s mangle transactions:\n%s\nwant one:\n%s", family.name, strings.Join(mangleInputs, "\n"), strings.Join(wantLines, "\n"))
				}
			}
		})
	}
}

// The port-hash rules list back in the form the reconcile compares with, so
// another reconcile writes nothing, on a dual-stack interface and on one
// with no public IPv6, which gets no IPv6 rules of either kind.
func TestLbAltSplitReconcileWritesNothingWithPortHashSources(t *testing.T) {
	sources := []string{"192.0.2.0/27", "198.51.100.128/25", "2001:db8:c0::/48", "2001:db8:c1::/64"}
	dualStackInterface := lbAltTestDualStackInterface()
	ipv4OnlyInterface := lbAltTestIpv4OnlyInterface()
	host := newLbAltTestHost(t, dualStackInterface, ipv4OnlyInterface)
	writer := newLbAltTestWriter(t, host, t.TempDir())
	generations := lbAltTestGenerations()
	writeLbAltTestBlockChains(t, writer, generations, dualStackInterface, ipv4OnlyInterface)
	host.setListenRows(lbAltTestListenRows(generations, dualStackInterface, ipv4OnlyInterface))
	for _, splitInterface := range []lbAltSplitInterface{dualStackInterface, ipv4OnlyInterface} {
		if err := writer.reconcile(context.Background(), lbAltTestPortHashConfig(splitInterface, sources...)); err != nil {
			t.Fatal(err)
		}
	}
	ipv4OnlyNames := lbAltTestNames(t, ipv4OnlyInterface)
	if got := len(host.rulesMentioning("ipv4", "mangle", ipv4OnlyNames.ruleComment+" ")); got != 2*(2+2*2) {
		t.Fatalf("ens4 has %d ipv4 HMARK rules, want %d", got, 2*(2+2*2))
	}
	requireLbAltRules(t, "ens4 ipv6 HMARK rules", host.rulesMentioning("ipv6", "mangle", ipv4OnlyNames.ruleComment+" "), []string{})
	before := host.listing("ipv4", "nat") + host.listing("ipv4", "mangle") + host.listing("ipv6", "nat") + host.listing("ipv6", "mangle")
	host.clearCommands()

	for range 2 {
		for _, splitInterface := range []lbAltSplitInterface{dualStackInterface, ipv4OnlyInterface} {
			// the config in another order is the same config
			reversedSources := slices.Clone(sources)
			slices.Reverse(reversedSources)
			if err := writer.reconcile(context.Background(), lbAltTestPortHashConfig(splitInterface, reversedSources...)); err != nil {
				t.Fatal(err)
			}
		}
	}
	if restores := host.commandsNamed("iptables-restore", "ip6tables-restore"); len(restores) != 0 {
		t.Fatalf("an unchanged host was written:\n%v", restores)
	}
	after := host.listing("ipv4", "nat") + host.listing("ipv4", "mangle") + host.listing("ipv6", "nat") + host.listing("ipv6", "mangle")
	if before != after {
		t.Fatal("an unchanged reconcile changed the tables")
	}
}

// Adding or removing a port-hash source rewrites only the HMARK rules, of the
// family it is in, in one transaction: a source's rules go when it leaves the
// config, and with none left the tables are those of a host that never had
// any. The split chain, the entry jumps and the other family are not written.
func TestLbAltSplitPortHashSourceChangesRewriteOnlyTheHmarkRules(t *testing.T) {
	splitInterface := lbAltTestDualStackInterface()
	host, writer := newLbAltTestPortHashHost(t, lbAltTestPortHashConfig(splitInterface, "192.0.2.0/27", "2001:db8:c0::/48"))

	for _, step := range []struct {
		name            string
		sources         []string
		ipv4Sources     []string
		ipv6Sources     []string
		writtenFamilies []string
	}{
		{
			name:            "a second ipv4 source",
			sources:         []string{"192.0.2.0/27", "198.51.100.128/25", "2001:db8:c0::/48"},
			ipv4Sources:     []string{"192.0.2.0/27", "198.51.100.128/25"},
			ipv6Sources:     []string{"2001:db8:c0::/48"},
			writtenFamilies: []string{"ipv4"},
		},
		{
			name:            "the first ipv4 source removed",
			sources:         []string{"198.51.100.128/25", "2001:db8:c0::/48"},
			ipv4Sources:     []string{"198.51.100.128/25"},
			ipv6Sources:     []string{"2001:db8:c0::/48"},
			writtenFamilies: []string{"ipv4"},
		},
		{
			name:            "the ipv6 source replaced",
			sources:         []string{"198.51.100.128/25", "2001:db8:c1::/64"},
			ipv4Sources:     []string{"198.51.100.128/25"},
			ipv6Sources:     []string{"2001:db8:c1::/64"},
			writtenFamilies: []string{"ipv6"},
		},
		{
			name:            "every source removed",
			sources:         nil,
			ipv4Sources:     nil,
			ipv6Sources:     nil,
			writtenFamilies: []string{"ipv4", "ipv6"},
		},
	} {
		host.clearCommands()
		config := lbAltTestPortHashConfig(splitInterface, step.sources...)
		if err := writer.reconcile(context.Background(), config); err != nil {
			t.Fatalf("%s: %s", step.name, err)
		}
		for _, family := range []string{"ipv4", "ipv6"} {
			familySources := step.ipv4Sources
			if family == "ipv6" {
				familySources = step.ipv6Sources
			}
			listed := lbAltTestListedHmarkRules(family, familySources...)
			requireLbAltRules(t, step.name+": "+family+" mangle PREROUTING", host.chainRules(family, "mangle", "PREROUTING"), listed)
			requireLbAltRules(t, step.name+": "+family+" mangle OUTPUT", host.chainRules(family, "mangle", "OUTPUT"), listed)

			inputs := lbAltTestRestoreInputs(host, family)
			wantMangleCount := 0
			if slices.Contains(step.writtenFamilies, family) {
				wantMangleCount = 1
			}
			if len(inputs["nat"]) != 0 || len(inputs["mangle"]) != wantMangleCount {
				t.Fatalf("%s: %s wrote %d nat and %d mangle transactions, want none and %d:\n%v", step.name, family, len(inputs["nat"]), len(inputs["mangle"]), wantMangleCount, inputs)
			}
		}

		host.clearCommands()
		if err := writer.reconcile(context.Background(), config); err != nil {
			t.Fatal(err)
		}
		if restores := host.commandsNamed("iptables-restore", "ip6tables-restore"); len(restores) != 0 {
			t.Fatalf("%s: the changed rules were written again: %v", step.name, restores)
		}
	}

	neverHost, _ := newLbAltTestPortHashHost(t, lbAltTestConfig(splitInterface))
	for _, family := range []string{"ipv4", "ipv6"} {
		for _, table := range []string{"mangle", "nat"} {
			if got, want := host.listing(family, table), neverHost.listing(family, table); got != want {
				t.Fatalf("%s %s with every source removed:\n%s\nwant, as on a host that never had one:\n%s", family, table, got, want)
			}
		}
	}
}

// The rollback (removeLbAltSplit) takes the port-hash rules with the other
// rules of the interface's comment, in both families, and leaves the block
// chains; a second removal writes nothing.
func TestLbAltSplitRemovalTakesThePortHashRules(t *testing.T) {
	splitInterface := lbAltTestDualStackInterface()
	names := lbAltTestNames(t, splitInterface)
	host, writer := newLbAltTestPortHashHost(t, lbAltTestPortHashConfig(splitInterface, "192.0.2.0/27", "198.51.100.128/25", "2001:db8:c0::/48"))
	if got := len(host.rulesMentioning("ipv4", "mangle", "-s 192.0.2.0/27 ")); got != 4 {
		t.Fatalf("%d ipv4 rules of 192.0.2.0/27 before the removal, want 4", got)
	}
	blockChainsBefore := map[string][]string{}
	for _, family := range []string{"ipv4", "ipv6"} {
		blockChainsBefore[family] = host.chainsWithPrefix(family, "nat", names.blockChainPrefix)
	}

	if err := writer.remove(context.Background(), lbAltTestEnv, splitInterface.name); err != nil {
		t.Fatal(err)
	}
	for _, family := range []string{"ipv4", "ipv6"} {
		for _, table := range []string{"mangle", "nat"} {
			requireLbAltRules(t, family+" "+table+" rules of the interface", host.rulesMentioning(family, table, names.ruleComment+" "), []string{})
		}
		requireLbAltRules(t, family+" mangle PREROUTING", host.chainRules(family, "mangle", "PREROUTING"), []string{})
		requireLbAltRules(t, family+" mangle OUTPUT", host.chainRules(family, "mangle", "OUTPUT"), []string{})
		requireLbAltRules(t, family+" block chains", host.chainsWithPrefix(family, "nat", names.blockChainPrefix), blockChainsBefore[family])
	}

	host.clearCommands()
	if err := writer.remove(context.Background(), lbAltTestEnv, splitInterface.name); err != nil {
		t.Fatal(err)
	}
	if restores := host.commandsNamed("iptables-restore", "ip6tables-restore"); len(restores) != 0 {
		t.Fatalf("a second removal wrote: %v", restores)
	}
}

// A port-hash source the rules could not match or list back stops the
// reconcile before it lists or writes anything, as any other bad config does.
func TestLbAltSplitRefusesPortHashSourcesItCannotList(t *testing.T) {
	for _, c := range []struct {
		source netip.Prefix
		other  string
		want   string
	}{
		{source: netip.MustParsePrefix("::ffff:192.0.2.0/123"), want: "IPv4-mapped IPv6 prefix"},
		{source: netip.MustParsePrefix("192.0.2.5/27"), want: "has host bits set; the prefix is 192.0.2.0/27"},
		{source: netip.MustParsePrefix("2001:db8:c0::1/48"), want: "has host bits set; the prefix is 2001:db8:c0::/48"},
		{source: netip.MustParsePrefix("0.0.0.0/0"), want: "is every source of its family"},
		{source: netip.MustParsePrefix("::/0"), want: "is every source of its family"},
		{source: netip.MustParsePrefix("192.0.2.0/28"), other: "192.0.2.0/27", want: "overlaps"},
		{source: netip.Prefix{}, want: "is not a prefix"},
	} {
		splitInterface := lbAltTestDualStackInterface()
		host := newLbAltTestHost(t, splitInterface)
		writer := newLbAltTestWriter(t, host, t.TempDir())
		config := lbAltTestConfig(splitInterface)
		config.portHashSources = []netip.Prefix{c.source}
		if c.other != "" {
			config.portHashSources = append(config.portHashSources, netip.MustParsePrefix(c.other))
		}
		host.clearCommands()
		err := writer.reconcile(context.Background(), config)
		if err == nil || !strings.Contains(err.Error(), c.want) || !strings.Contains(err.Error(), "interface ens4np3") {
			t.Errorf("%s: reconcile returned %v, want an error with %q", c.source, err, c.want)
		}
		if commands := host.commandsNamed("iptables", "ip6tables", "iptables-restore", "ip6tables-restore", "ss"); len(commands) != 0 {
			t.Errorf("%s: a refused config ran %v", c.source, commands)
		}
	}
}

// The port-hash rule as iptables 1.8.10 (nf_tables) lists it, read in a
// container on Linux 7.0: -s first, masked, and the source port mask after the
// source prefix. Its key is the key of the arguments that add it. A rule that
// differs in its source, its port mask or its spelling of the tuple is
// another rule.
func TestLbAltSplitPortHashRuleKeysMatchTheListedForms(t *testing.T) {
	for _, c := range []struct {
		added  string
		listed string
	}{
		{
			added:  "-s 192.0.2.0/27 -d 203.0.113.4/32 -p tcp -m multiport --dports 80,443 -m conntrack --ctstate NEW -m comment --comment warp-main-lba-ens4np3 -j HMARK --hmark-src-prefix 32 --hmark-sport-mask 0xffff --hmark-mod 100 --hmark-offset 0x10000 --hmark-rnd 0x4c42414c",
			listed: "-s 192.0.2.0/27 -d 203.0.113.4/32 -p tcp -m multiport --dports 80,443 -m conntrack --ctstate NEW -m comment --comment warp-main-lba-ens4np3 -j HMARK --hmark-src-prefix 32 --hmark-sport-mask 0xffff --hmark-rnd 0x4c42414c --hmark-mod 100 --hmark-offset 65536",
		},
		{
			added:  "-s 2001:db8:c0::/48 -d 2001:db8:ff04::1/128 -p udp -m multiport --dports 53,443,4053 -m conntrack --ctstate NEW -m comment --comment warp-main-lba-ens4np3 -j HMARK --hmark-src-prefix 128 --hmark-sport-mask 0xffff --hmark-mod 100 --hmark-offset 0x10000 --hmark-rnd 0x4c42414c",
			listed: "-s 2001:db8:c0::/48 -d 2001:db8:ff04::1/128 -p udp -m multiport --dports 53,443,4053 -m conntrack --ctstate NEW -m comment --comment warp-main-lba-ens4np3 -j HMARK --hmark-src-prefix 128 --hmark-sport-mask 0xffff --hmark-rnd 0x4c42414c --hmark-mod 100 --hmark-offset 65536",
		},
		// a source compares as a prefix, whatever its spelling
		{added: "-s 192.0.2.7 -j X", listed: "-s 192.0.2.7/32 -j X"},
		{added: "--source 2001:DB8:C0::/48 -j X", listed: "-s 2001:db8:c0::/48 -j X"},
	} {
		added, err := splitIptablesArgs(c.added)
		if err != nil {
			t.Fatal(err)
		}
		listed, err := splitIptablesArgs(c.listed)
		if err != nil {
			t.Fatal(err)
		}
		if parseIptablesRuleKey(added) != parseIptablesRuleKey(listed) {
			t.Errorf("keys differ:\n%+v\n%+v", parseIptablesRuleKey(added), parseIptablesRuleKey(listed))
		}
	}
	portHashRule := "-s 192.0.2.0/27 -d 203.0.113.4/32 -p tcp -j HMARK --hmark-src-prefix 32 --hmark-sport-mask 0xffff --hmark-mod 100 --hmark-offset 0x10000 --hmark-rnd 0x4c42414c"
	for _, other := range []string{
		// the address-only rule
		"-d 203.0.113.4/32 -p tcp -j HMARK --hmark-src-prefix 32 --hmark-mod 100 --hmark-offset 0x10000 --hmark-rnd 0x4c42414c",
		"-s 192.0.2.0/27 -d 203.0.113.4/32 -p tcp -j HMARK --hmark-src-prefix 32 --hmark-mod 100 --hmark-offset 0x10000 --hmark-rnd 0x4c42414c",
		"-s 192.0.2.0/28 -d 203.0.113.4/32 -p tcp -j HMARK --hmark-src-prefix 32 --hmark-sport-mask 0xffff --hmark-mod 100 --hmark-offset 0x10000 --hmark-rnd 0x4c42414c",
		"! -s 192.0.2.0/27 -d 203.0.113.4/32 -p tcp -j HMARK --hmark-src-prefix 32 --hmark-sport-mask 0xffff --hmark-mod 100 --hmark-offset 0x10000 --hmark-rnd 0x4c42414c",
		"-s 192.0.2.0/27 -d 203.0.113.4/32 -p tcp -j HMARK --hmark-src-prefix 32 --hmark-sport-mask 0xff00 --hmark-mod 100 --hmark-offset 0x10000 --hmark-rnd 0x4c42414c",
		"-s 192.0.2.0/27 -d 203.0.113.4/32 -p tcp -j HMARK --hmark-src-prefix 32 --hmark-sport-mask 0xffff --hmark-dport-mask 0xffff --hmark-mod 100 --hmark-offset 0x10000 --hmark-rnd 0x4c42414c",
		// iptables never lists the tuple, which in IPv4 stores another mask
		"-s 192.0.2.0/27 -d 203.0.113.4/32 -p tcp -j HMARK --hmark-tuple src,sport --hmark-mod 100 --hmark-offset 0x10000 --hmark-rnd 0x4c42414c",
	} {
		a, _ := splitIptablesArgs(portHashRule)
		b, _ := splitIptablesArgs(other)
		if parseIptablesRuleKey(a) == parseIptablesRuleKey(b) {
			t.Errorf("keys equal: %q and %q", portHashRule, other)
		}
	}
}

// The fake iptables lists and stores a port-hash rule as iptables 1.8.10 did
// in the container: added with the prefix and the mask, its listed form
// deletes it; added with the tuple, an IPv4 rule lists the same but its
// listed form deletes nothing, while an IPv6 one, whose tuple mask is the
// full prefix, is deleted.
func TestLbAltFakeIptablesStoresThePortHashRuleAsIptablesDoes(t *testing.T) {
	for _, c := range []struct {
		family    string
		added     string
		listed    string
		deletable bool
	}{
		{
			family:    "ipv4",
			added:     "-s 192.0.2.0/27 -d 203.0.113.4/32 -p tcp -j HMARK --hmark-src-prefix 32 --hmark-sport-mask 0xffff --hmark-mod 100 --hmark-offset 0x10000 --hmark-rnd 0x4c42414c",
			listed:    "-s 192.0.2.0/27 -d 203.0.113.4/32 -p tcp -j HMARK --hmark-src-prefix 32 --hmark-sport-mask 0xffff --hmark-rnd 0x4c42414c --hmark-mod 100 --hmark-offset 65536",
			deletable: true,
		},
		{
			family:    "ipv4",
			added:     "-d 203.0.113.4/32 -s 192.0.2.0/27 -p tcp -j HMARK --hmark-tuple src,sport --hmark-mod 100 --hmark-offset 0x10000 --hmark-rnd 0x4c42414c",
			listed:    "-s 192.0.2.0/27 -d 203.0.113.4/32 -p tcp -j HMARK --hmark-src-prefix 32 --hmark-sport-mask 0xffff --hmark-rnd 0x4c42414c --hmark-mod 100 --hmark-offset 65536",
			deletable: false,
		},
		{
			family:    "ipv6",
			added:     "-s 2001:db8:c0::/48 -d 2001:db8:ff04::1/128 -p udp -j HMARK --hmark-tuple src,sport --hmark-mod 100 --hmark-offset 0x10000 --hmark-rnd 0x4c42414c",
			listed:    "-s 2001:db8:c0::/48 -d 2001:db8:ff04::1/128 -p udp -j HMARK --hmark-src-prefix 128 --hmark-sport-mask 0xffff --hmark-rnd 0x4c42414c --hmark-mod 100 --hmark-offset 65536",
			deletable: true,
		},
	} {
		host := newFakeLbAltHost()
		host.addRule(t, c.family, "mangle", "PREROUTING", c.added)
		requireLbAltRules(t, c.added, host.chainRules(c.family, "mangle", "PREROUTING"), []string{c.listed})
		restore := newIptablesRestore("mangle")
		listedArgs, err := splitIptablesArgs(c.listed)
		if err != nil {
			t.Fatal(err)
		}
		restore.deleteRule("PREROUTING", listedArgs)
		restoreName := "iptables-restore"
		if c.family == "ipv6" {
			restoreName = "ip6tables-restore"
		}
		_, err = host.run(context.Background(), lbAltCommand{
			name:       restoreName,
			args:       []string{"-w", "--noflush"},
			stdin:      restore.input(),
			privileged: true,
		})
		if (err == nil) != c.deletable {
			t.Fatalf("%s: deleting by the listed form returned %v, want deletable %t", c.added, err, c.deletable)
		}
	}
}

// The lb unit flag carries the sources in the order services.yml's list is
// sorted in, and parses back to them. Malformed and misplaced values stop the
// worker at start, as the other flags do.
func TestLbAltWorkerParsesThePortHashFlag(t *testing.T) {
	loadNetworkInterfaces := lbAltFakeNetworkInterfaces(lbAltFakeEdgeAAddresses)
	routingTable := &RoutingTable{interfaceName: "eth1", tableNumber: 100}
	_, _, _, _, sources := parseLbAltWorkerFlags(
		docopt.Opts{"--lbalt": "true", "--lbaltblocks": "beta:1", "--lbaltporthash": "192.0.2.0/27;2001:db8:c0::/48"},
		"lb",
		routingTable,
		loadNetworkInterfaces,
	)
	if want := []netip.Prefix{netip.MustParsePrefix("192.0.2.0/27"), netip.MustParsePrefix("2001:db8:c0::/48")}; !slices.Equal(sources, want) {
		t.Fatalf("parsed the port-hash sources %v, want %v", sources, want)
	}

	for _, refused := range []struct {
		opts docopt.Opts
		want string
	}{
		{opts: docopt.Opts{"--lbaltporthash": "192.0.2.0/27"}, want: "--lbaltporthash needs --lbalt=true"},
		{opts: docopt.Opts{"--lbalt": "false", "--lbaltporthash": "192.0.2.0/27"}, want: "--lbaltporthash needs --lbalt=true"},
		{opts: docopt.Opts{"--lbalt": "true", "--lbaltblocks": "beta:1", "--lbaltporthash": ""}, want: "is not an IPv4 or IPv6 prefix"},
		{opts: docopt.Opts{"--lbalt": "true", "--lbaltblocks": "beta:1", "--lbaltporthash": "192.0.2.7"}, want: "is not an IPv4 or IPv6 prefix"},
		{opts: docopt.Opts{"--lbalt": "true", "--lbaltblocks": "beta:1", "--lbaltporthash": "192.0.2.7/27"}, want: "has host bits set"},
		{opts: docopt.Opts{"--lbalt": "true", "--lbaltblocks": "beta:1", "--lbaltporthash": "::ffff:192.0.2.0/123"}, want: "IPv4-mapped IPv6 prefix"},
		{opts: docopt.Opts{"--lbalt": "true", "--lbaltblocks": "beta:1", "--lbaltporthash": "0.0.0.0/0"}, want: "is every source of its family"},
		{opts: docopt.Opts{"--lbalt": "true", "--lbaltblocks": "beta:1", "--lbaltporthash": "192.0.2.0/27;192.0.2.16/28"}, want: "overlaps"},
		{opts: docopt.Opts{"--lbalt": "true", "--lbaltblocks": "beta:1", "--lbaltporthash": "192.0.2.0/27;"}, want: "is not an IPv4 or IPv6 prefix"},
	} {
		recovered := lbAltRecoverPanic(func() {
			parseLbAltWorkerFlags(refused.opts, "lb", routingTable, loadNetworkInterfaces)
		})
		if recovered == nil || !strings.Contains(fmt.Sprint(recovered), refused.want) {
			t.Errorf("%v: recovered %v, want a panic with %q", refused.opts, recovered, refused.want)
		}
	}
}

// lb.lb_alt_port_hash_sources reaches the lb unit of every interface lb_alt
// is in effect on, as --lbaltporthash with the prefixes sorted, and no other
// unit, so applying it restarts only those lb units, one interface at a time
// with run-lb-unit.sh. An empty list, or none, renders every unit byte for
// byte as before, and the flag the unit carries parses back to the list.
func TestLbAltPortHashSourcesChangeOnlyTheLbAltLbUnits(t *testing.T) {
	const yamlSources = `["2001:db8:c0::/48", 198.51.100.0/27]`
	const wantFlag = `--lbaltporthash="198.51.100.0/27;2001:db8:c0::/48"`
	for _, c := range []struct {
		name     string
		settings lbAltUnitsSettings
		// the lb blocks lb_alt is in effect on
		lbAltBlocks []string
	}{
		{
			name:        "every interface lb_alt",
			settings:    lbAltUnitsSettings{connect: "true"},
			lbAltBlocks: []string{"edge-a.example-eth1", "edge-a.example-eth2", "edge-b.example-eth1"},
		},
		{
			name:        "one interface lb_alt",
			settings:    lbAltUnitsSettings{edgeAEth1: "true", connect: "false"},
			lbAltBlocks: []string{"edge-a.example-eth1"},
		},
		{
			name:        "no interface lb_alt",
			settings:    lbAltUnitsSettings{connect: "false"},
			lbAltBlocks: []string{},
		},
	} {
		with := c.settings
		with.portHashSources = yamlSources
		changed, afterUnits := lbAltChangedUnits(t, c.settings, with)
		want := []string{}
		for _, block := range c.lbAltBlocks {
			host, _, _ := strings.Cut(block, "-eth")
			want = append(want, fmt.Sprintf("%s lb %s", host, block))
		}
		slices.Sort(want)
		if !slices.Equal(changed, want) {
			t.Fatalf("%s: the port-hash sources changed the units %v, want only %v", c.name, changed, want)
		}
		for _, block := range c.lbAltBlocks {
			host, _, _ := strings.Cut(block, "-eth")
			unit := afterUnits[host]["lb"][block].serviceUnit
			if got := lbAltUnitArgsWithPrefix(t, unit, "--lbalt"); !slices.Equal(got, []string{"--lbalt=true", lbAltUnitsBlocksArg, wantFlag}) {
				t.Fatalf("%s: %s lb unit carries %v:\n%s", c.name, block, got, unit)
			}
			_, _, _, _, sources := parseLbAltWorkerFlags(
				lbAltParseUnitOpts(t, unit),
				"lb",
				&RoutingTable{interfaceName: "eth1", tableNumber: 100},
				lbAltFakeNetworkInterfaces(lbAltFakeEdgeAAddresses),
			)
			if want := []netip.Prefix{netip.MustParsePrefix("198.51.100.0/27"), netip.MustParsePrefix("2001:db8:c0::/48")}; !slices.Equal(sources, want) {
				t.Fatalf("%s: %s lb unit parsed to the port-hash sources %v, want %v", c.name, block, sources, want)
			}
		}

		empty := c.settings
		empty.portHashSources = "[]"
		if changed, _ := lbAltChangedUnits(t, c.settings, empty); len(changed) != 0 {
			t.Fatalf("%s: an empty list changed the units %v", c.name, changed)
		}
	}
}

// The lb unit's routing-only loop hands the sources of --lbaltporthash to the
// split, on every reconcile.
func TestLbAltWorkerReconcilesTheSplitWithItsPortHashSources(t *testing.T) {
	setupTestVault(t, lbAltUnitsYaml(lbAltUnitsSettings{connect: "true"}))
	splitConfigs := []*lbAltSplitConfig{}
	ops := defaultLbAltWorkerOps()
	ops.reconcileSplit = func(ctx context.Context, config *lbAltSplitConfig) error {
		splitConfigs = append(splitConfigs, config)
		return nil
	}
	ops.listContainers = func(ctx context.Context, containerNamePrefix string, format string) ([]string, error) {
		return nil, nil
	}
	worker := newLbAltSplitWorker(ops)
	sources := []netip.Prefix{netip.MustParsePrefix("198.51.100.0/27"), netip.MustParsePrefix("2001:db8:c0::/48")}
	worker.lbAltPortHashSources = slices.Clone(sources)

	worker.reconcileLbAltWorkerInterface()
	worker.reconcileLbAltWorkerInterface()
	if len(splitConfigs) != 2 {
		t.Fatalf("%d split reconciles, want 2", len(splitConfigs))
	}
	for _, config := range splitConfigs {
		if !slices.Equal(config.portHashSources, sources) {
			t.Fatalf("the split got the port-hash sources %v, want %v", config.portHashSources, sources)
		}
	}
	// the worker's list is the unit's: the split gets a copy
	splitConfigs[0].portHashSources[0] = netip.MustParsePrefix("192.0.2.0/27")
	if !slices.Equal(worker.lbAltPortHashSources, sources) {
		t.Fatalf("the split config shares the worker's list, now %v", worker.lbAltPortHashSources)
	}
}
