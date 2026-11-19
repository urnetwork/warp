package main

// Tests of the dns side of lb_alt (dns.go, dns_route53.go): lb_alt interfaces
// stay lb set members, the lb_alt service's dns aliases (the alt.* names of
// server/LBALT.md D14) resolve to the lb_alt interfaces with one owner per
// name, and records the derivation leaves behind are reported, not deleted.

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/route53/types"
	"gopkg.in/yaml.v3"

	"github.com/urnetwork/warp/services"
)

// the alt service's dns aliases in dnsFixtureWithDns
const lbAltDnsAltAliasesYaml = "            dns_aliases:\n                - alt.example.com\n                - alt-v4.example.com\n                - alt-v6.example.com\n"

// The dns fixture (dnsFixtureWithDns) in the lb_alt shape of
// lbAltVyosServicesYaml, with the alt.* names moved from the alt service to
// connect, the lb_alt service: the dns handover of server/LBALT.md §8 step 6,
// while alt still runs on fireside with its public udp ports.
func lbAltDnsServicesYaml(t *testing.T, servicesYaml string, interfaces lbAltVyosInterfaces) string {
	t.Helper()
	servicesYaml = lbAltVyosServicesYaml(t, dnsFixtureWithDns(servicesYaml), interfaces)
	servicesYaml = lbAltEdgeReplace(t, servicesYaml, lbAltDnsAltAliasesYaml, "")
	return lbAltEdgeReplace(t, servicesYaml, "        connect:\n", "        connect:\n"+lbAltDnsAltAliasesYaml)
}

// lbAltDnsServicesYaml once the alt service is removed (server/LBALT.md §8
// step 8), which leaves its <env>-alt records behind
func lbAltDnsServicesYamlWithoutAlt(t *testing.T, servicesYaml string, interfaces lbAltVyosInterfaces) string {
	t.Helper()
	servicesYaml = lbAltDnsServicesYaml(t, servicesYaml, interfaces)
	servicesYaml = lbAltEdgeReplace(t, servicesYaml,
		"        alt:\n            exposed: false\n            hosts:\n                - fireside.example.com\n            ports:\n                - 80\n                - 5080+10\n            external_udp_ports:\n                - 443\n                - 4053\n            # the block's own dnat aliases public udp 53 to whodis; the router\n            # in front of fireside only admits 53\n            external_udp_forward_ports:\n                53: 4053\n            blocks:\n                - g1: 1\n",
		"",
	)
	return lbAltEdgeReplace(t, servicesYaml, "            - alt\n            - proxy\n", "            - proxy\n")
}

// Loads a services yaml as warpctl does, returning the load error.
func loadLbAltEdgeServicesYaml(t *testing.T, servicesYaml string) error {
	t.Helper()
	vaultDir := t.TempDir()
	env := "lbaltedge"
	if err := os.MkdirAll(filepath.Join(vaultDir, env), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(vaultDir, env, "services.yml"), []byte(servicesYaml), 0644); err != nil {
		t.Fatal(err)
	}
	_, err := services.LoadServicesConfigFrom(vaultDir, env)
	return err
}

// The lb set of lbAltDnsServicesYaml with lb_alt off for every interface, in
// the address shape interfaces gives (its lb_alt flags are ignored). lb_alt
// never changes the lb set, so a test with lb_alt on compares its lb set with
// this one. Call it before the test's own vault: it sets up one of its own.
func lbAltDnsPlainLbMembers(t *testing.T, interfaces lbAltVyosInterfaces) []dnsMember {
	t.Helper()
	plainInterfaces := lbAltVyosInterfaces{eno2np1Ipv4Only: interfaces.eno2np1Ipv4Only}
	input := newDnsTestInput(t, func(servicesYaml string) string {
		return lbAltDnsServicesYaml(t, servicesYaml, plainInterfaces)
	})
	domains, err := dnsDerive(input)
	if err != nil {
		t.Fatal(err)
	}
	lb := findDnsName(t, domains[0], input.Env+"-lb.example.com")
	memberIds := []string{}
	for _, member := range lb.Members {
		memberIds = append(memberIds, member.Id)
	}
	// every front interface of the fixture: the transparent proxy host is none
	wantMemberIds := []string{"edge-0-eno2", "edge-3-eno1np0", "edge-3-eno2np1", "edge-5-enp33s0f1np1", "legacy-0-eno2"}
	if lb.Kind != dnsLbSet || !reflect.DeepEqual(memberIds, wantMemberIds) {
		t.Fatalf("plain lb = %+v, want the members %v", lb, wantMemberIds)
	}
	return lb.Members
}

// The member of members with id.
func lbAltDnsMember(t *testing.T, members []dnsMember, id string) dnsMember {
	t.Helper()
	for _, member := range members {
		if member.Id == id {
			return member
		}
	}
	t.Fatalf("no lb member %s in %+v", id, members)
	return dnsMember{}
}

// The records the alt service left in the zone at name and its -v4 and -v6
// names: the proxy host's addresses, one family on each narrow name.
func lbAltDnsAltRecords(name string, ipv4 string, ipv6 string) []types.ResourceRecordSet {
	label, domain, _ := strings.Cut(name, ".")
	record := func(recordName string, recordType types.RRType, value string) types.ResourceRecordSet {
		return types.ResourceRecordSet{Name: aws.String(recordName + "."), Type: recordType, TTL: aws.Int64(120), ResourceRecords: []types.ResourceRecord{{Value: aws.String(value)}}}
	}
	return []types.ResourceRecordSet{
		record(name, types.RRTypeA, ipv4),
		record(name, types.RRTypeAaaa, ipv6),
		record(label+"-v4."+domain, types.RRTypeA, ipv4),
		record(label+"-v6."+domain, types.RRTypeAaaa, ipv6),
	}
}

// the route53 record sets of a domain by key
func lbAltRoute53Desired(t *testing.T, domain *dnsDomain, input dnsPlanInput) map[string]*route53Rrset {
	t.Helper()
	rrsets, err := route53Desired(domain, input)
	if err != nil {
		t.Fatal(err)
	}
	byKey := map[string]*route53Rrset{}
	for _, rrset := range rrsets {
		byKey[rrset.key()] = rrset
	}
	return byKey
}

// A host with one lb_alt interface among plain ones (edge-3 eno1np0): every
// interface stays in the lb set with its weight and health check, and the
// alt.* names, now connect's dns aliases, are a weighted set over the lb_alt
// member alone, with alt-v4 and alt-v6 aliasing it with one family each. The
// set reuses the member's lb health check, so no new check is needed.
func TestDnsLbAltMixedHostGetsAWeightedSet(t *testing.T) {
	plainMembers := lbAltDnsPlainLbMembers(t, lbAltVyosInterfaces{})
	input := newDnsTestInput(t, func(servicesYaml string) string {
		return lbAltDnsServicesYaml(t, servicesYaml, lbAltVyosInterfaces{eno1np0: true})
	})
	domains, err := dnsDerive(input)
	if err != nil {
		t.Fatal(err)
	}
	com := domains[0]
	env := input.Env
	firesideIpv6 := lbAltEdgeInterfaceIpv6(t, input.ServicesConfig, "fireside.example.com", "eno1np0")

	lb := findDnsName(t, com, env+"-lb.example.com")
	if lb.Kind != dnsLbSet || !reflect.DeepEqual(lb.Members, plainMembers) {
		t.Fatalf("lb = %+v, want every front interface, lb_alt or not", lb)
	}
	member := lbAltDnsMember(t, plainMembers, "edge-3-eno1np0")
	if member.Ipv4 != "203.0.113.84" || member.Ipv6 == "" || member.Weight != 100 {
		t.Fatalf("edge-3 eno1np0 = %+v, want a dual-stack member of weight 100", member)
	}
	alt := findDnsName(t, com, "alt.example.com")
	if alt.Kind != dnsLbSet || !alt.HasIpv4 || !alt.HasIpv6 || !reflect.DeepEqual(alt.Members, []dnsMember{member}) {
		t.Fatalf("alt = %+v, want the weighted set of the lb_alt member", alt)
	}
	altV4 := findDnsName(t, com, "alt-v4.example.com")
	if altV4.Kind != dnsAliasTo || altV4.Target != "alt.example.com" || !altV4.HasIpv4 || altV4.HasIpv6 || !reflect.DeepEqual(altV4.Ipv4, []string{member.Ipv4}) || len(altV4.Ipv6) != 0 {
		t.Fatalf("alt-v4 = %+v", altV4)
	}
	altV6 := findDnsName(t, com, "alt-v6.example.com")
	if altV6.Kind != dnsAliasTo || altV6.Target != "alt.example.com" || altV6.HasIpv4 || !altV6.HasIpv6 || !reflect.DeepEqual(altV6.Ipv6, []string{member.Ipv6}) {
		t.Fatalf("alt-v6 = %+v", altV6)
	}
	// alt itself still runs: its own names keep the proxy host's addresses
	if altService := findDnsName(t, com, env+"-alt.example.com"); altService.Kind != dnsAddresses || !reflect.DeepEqual(altService.Ipv4, []string{"203.0.113.92"}) || !reflect.DeepEqual(altService.Ipv6, []string{firesideIpv6}) {
		t.Fatalf("%s-alt = %+v", env, altService)
	}

	byKey := lbAltRoute53Desired(t, com, input)
	lbMember := byKey[env+"-lb.example.com|A|edge-3-eno1np0"]
	altMember := byKey["alt.example.com|A|edge-3-eno1np0"]
	if lbMember == nil || altMember == nil || altMember.Weight != 100 || !reflect.DeepEqual(altMember.Values, []string{"203.0.113.84"}) || altMember.HealthCheck == nil || altMember.HealthCheck.key() != lbMember.HealthCheck.key() {
		t.Fatalf("alt member = %+v, lb member = %+v, want one weighted member on the lb's health check", altMember, lbMember)
	}
	if byKey["alt.example.com|AAAA|edge-3-eno1np0"] == nil || byKey["alt.example.com|A|edge-3-eno2np1"] != nil || byKey["alt.example.com|A|"] != nil {
		t.Fatal("alt must be the weighted set of eno1np0 alone")
	}
	if byKey["alt-v4.example.com|A|"] == nil || byKey["alt-v4.example.com|A|"].AliasTarget != "alt.example.com" || byKey["alt-v4.example.com|AAAA|"] != nil {
		t.Fatal("alt-v4 must alias the set with A only")
	}
	if byKey["alt-v6.example.com|AAAA|"] == nil || byKey["alt-v6.example.com|AAAA|"].AliasTarget != "alt.example.com" || byKey["alt-v6.example.com|A|"] != nil {
		t.Fatal("alt-v6 must alias the set with AAAA only")
	}

	// the plan against the zone as alt left it: the alt.* records move from
	// the proxy host to the edge, and the lb member's check is reused. The
	// check's path holds the lb hidden prefix, so it is derived, never written
	statusPath, err := dnsStatusPath(input.ServicesConfig)
	if err != nil {
		t.Fatal(err)
	}
	lbHost := env + "-lb.example.com"
	fake := &fakeRoute53{
		zone:   "Z1",
		rrsets: lbAltDnsAltRecords("alt.example.com", "203.0.113.92", firesideIpv6),
		healthChecks: []types.HealthCheck{
			route53HealthCheckFixture("hc-a", types.HealthCheckTypeHttp, member.Ipv4, statusPath, lbHost),
			route53HealthCheckFixture("hc-aaaa", types.HealthCheckTypeHttp, member.Ipv6, statusPath, lbHost),
		},
	}
	provider := &route53Provider{api: fake, ctx: context.Background()}
	planned, err := provider.Plan(com, input)
	if err != nil {
		t.Fatal(err)
	}
	plan := []string{}
	for _, change := range planned {
		plan = append(plan, change.String())
	}
	planText := strings.Join(plan, "\n")
	for _, want := range []string{
		"- A alt.example.com 203.0.113.92 ttl=120",
		"+ A alt.example.com " + member.Ipv4 + " ttl=120 set=edge-3-eno1np0 weight=100 health-check",
		"- AAAA alt.example.com " + firesideIpv6 + " ttl=120",
		"+ AAAA alt.example.com " + member.Ipv6 + " ttl=120 set=edge-3-eno1np0 weight=100 health-check",
		"~ A alt-v4.example.com -> alt.example.com (was A alt-v4.example.com 203.0.113.92 ttl=120)",
		"~ AAAA alt-v6.example.com -> alt.example.com (was AAAA alt-v6.example.com " + firesideIpv6 + " ttl=120)",
	} {
		if !strings.Contains(planText, want) {
			t.Errorf("plan lacks %q:\n%s", want, planText)
		}
	}
	for _, absent := range []string{"+ health check A-edge-3-eno1np0", "+ health check AAAA-edge-3-eno1np0", "- health check hc-a", "- health check hc-aaaa"} {
		if strings.Contains(planText, absent) {
			t.Errorf("plan must reuse the lb member's checks, but has %q:\n%s", absent, planText)
		}
	}
}

// A mixed host whose only lb_alt interface has no IPv6 address (edge-3
// eno2np1, IPv4 only) while other lb set members have one: alt is the
// weighted set of that member with A records alone, alt-v4 aliases it, and
// alt-v6 derives nothing, noted. An AAAA alias of alt would name a record
// that does not exist, which route53 refuses, failing the domain's whole
// change batch.
func TestDnsLbAltMixedHostWithAnIpv4OnlyLbAltMember(t *testing.T) {
	interfaces := lbAltVyosInterfaces{eno2np1: true, eno2np1Ipv4Only: true}
	plainMembers := lbAltDnsPlainLbMembers(t, interfaces)
	input := newDnsTestInput(t, func(servicesYaml string) string {
		return lbAltDnsServicesYaml(t, servicesYaml, interfaces)
	})
	domains, err := dnsDerive(input)
	if err != nil {
		t.Fatal(err)
	}
	com := domains[0]

	// the other members keep the lb set dual-stack
	lb := findDnsName(t, com, input.Env+"-lb.example.com")
	if lb.Kind != dnsLbSet || !lb.HasIpv6 || !reflect.DeepEqual(lb.Members, plainMembers) {
		t.Fatalf("lb = %+v, want every front interface, with IPv6", lb)
	}
	member := lbAltDnsMember(t, plainMembers, "edge-3-eno2np1")
	if member.Ipv4 != "203.0.113.85" || member.Ipv6 != "" {
		t.Fatalf("edge-3 eno2np1 = %+v, want an IPv4-only member", member)
	}
	alt := findDnsName(t, com, "alt.example.com")
	if alt.Kind != dnsLbSet || !alt.HasIpv4 || alt.HasIpv6 || !reflect.DeepEqual(alt.Members, []dnsMember{member}) {
		t.Fatalf("alt = %+v, want the IPv4 set of the lb_alt member", alt)
	}
	altV4 := findDnsName(t, com, "alt-v4.example.com")
	if altV4.Kind != dnsAliasTo || altV4.Target != "alt.example.com" || !altV4.HasIpv4 || altV4.HasIpv6 || !reflect.DeepEqual(altV4.Ipv4, []string{member.Ipv4}) {
		t.Fatalf("alt-v4 = %+v", altV4)
	}
	if slices.Contains(dnsNameList(com), "alt-v6.example.com") {
		t.Fatalf("alt-v6 = %+v, derived though no lb_alt member has an IPv6 address", findDnsName(t, com, "alt-v6.example.com"))
	}
	if want := "alt-v6.example.com: no lb_alt member has an ipv6 address (service connect dns alias (lb_alt))"; !slices.Contains(com.Notes, want) {
		t.Fatalf("notes lack %q:\n%s", want, strings.Join(com.Notes, "\n"))
	}

	byKey := lbAltRoute53Desired(t, com, input)
	for key, rrset := range byKey {
		if strings.HasPrefix(key, "alt.example.com|AAAA|") || strings.HasPrefix(key, "alt-v4.example.com|AAAA|") || strings.HasPrefix(key, "alt-v6.example.com|") {
			t.Errorf("%s = %s, want no AAAA record of the alt names", key, rrset)
		}
	}
	if byKey["alt.example.com|A|edge-3-eno2np1"] == nil || byKey["alt-v4.example.com|A|"] == nil || byKey["alt-v4.example.com|A|"].AliasTarget != "alt.example.com" {
		t.Fatal("alt must be the A set of eno2np1, with alt-v4 aliasing it")
	}
}

// With lb_alt on for every front interface (connect's default), the lb_alt
// set is the lb set, so the alt.* names alias it, one family per -v4 and -v6
// name, and no second weighted set is derived.
func TestDnsLbAltAllMembersAliasTheLbSet(t *testing.T) {
	plainMembers := lbAltDnsPlainLbMembers(t, lbAltVyosInterfaces{})
	input := newDnsTestInput(t, func(servicesYaml string) string {
		return lbAltDnsServicesYaml(t, servicesYaml, lbAltVyosInterfaces{connectDefault: true})
	})
	domains, err := dnsDerive(input)
	if err != nil {
		t.Fatal(err)
	}
	com := domains[0]
	firesideIpv6 := lbAltEdgeInterfaceIpv6(t, input.ServicesConfig, "fireside.example.com", "eno1np0")
	lbName := input.Env + "-lb.example.com"
	if lb := findDnsName(t, com, lbName); lb.Kind != dnsLbSet || !reflect.DeepEqual(lb.Members, plainMembers) {
		t.Fatalf("lb = %+v", lb)
	}
	for name, families := range map[string][2]bool{
		"alt.example.com":    {true, true},
		"alt-v4.example.com": {true, false},
		"alt-v6.example.com": {false, true},
	} {
		derived := findDnsName(t, com, name)
		if derived.Kind != dnsAliasTo || derived.Target != lbName || derived.HasIpv4 != families[0] || derived.HasIpv6 != families[1] {
			t.Errorf("%s = %+v, want an alias of %s with families %v", name, derived, lbName, families)
		}
	}
	if got := findDnsName(t, com, "alt-v6.example.com").Ipv6; len(got) != 5 {
		t.Errorf("alt-v6 resolves to %v, want the 5 lb ipv6 addresses", got)
	}
	byKey := lbAltRoute53Desired(t, com, input)
	for key, rrset := range byKey {
		if strings.HasPrefix(key, "alt") && (rrset.SetId != "" || rrset.AliasTarget != lbName) {
			t.Errorf("%s = %s, want an alias of %s", key, rrset, lbName)
		}
	}
	if byKey["alt.example.com|A|"] == nil || byKey["alt.example.com|AAAA|"] == nil || byKey["alt-v4.example.com|AAAA|"] != nil || byKey["alt-v6.example.com|A|"] != nil {
		t.Fatal("the alt aliases have the wrong families")
	}

	// the plan against the zone as alt left it: each alt.* record becomes an
	// alias of the lb set in place, with no weighted member and no new check
	fake := &fakeRoute53{
		zone:   "Z1",
		rrsets: lbAltDnsAltRecords("alt.example.com", "203.0.113.92", firesideIpv6),
	}
	planned, err := (&route53Provider{api: fake, ctx: context.Background()}).Plan(com, input)
	if err != nil {
		t.Fatal(err)
	}
	altChanges := []string{}
	for _, change := range planned {
		if strings.Contains(change.What, " alt") {
			altChanges = append(altChanges, change.String())
		}
	}
	// in the order of the derived names
	wantAltChanges := []string{
		"~ A alt-v4.example.com -> " + lbName + " (was A alt-v4.example.com 203.0.113.92 ttl=120)",
		"~ AAAA alt-v6.example.com -> " + lbName + " (was AAAA alt-v6.example.com " + firesideIpv6 + " ttl=120)",
		"~ A alt.example.com -> " + lbName + " (was A alt.example.com 203.0.113.92 ttl=120)",
		"~ AAAA alt.example.com -> " + lbName + " (was AAAA alt.example.com " + firesideIpv6 + " ttl=120)",
	}
	if !reflect.DeepEqual(altChanges, wantAltChanges) {
		t.Fatalf("alt changes =\n%s\nwant\n%s", strings.Join(altChanges, "\n"), strings.Join(wantAltChanges, "\n"))
	}
}

// With no lb_alt member the alt.* names derive nothing, noted, and the lb set
// is as before.
func TestDnsLbAltNamesWithNoLbAltMember(t *testing.T) {
	input := newDnsTestInput(t, func(servicesYaml string) string {
		return lbAltDnsServicesYaml(t, servicesYaml, lbAltVyosInterfaces{})
	})
	domains, err := dnsDerive(input)
	if err != nil {
		t.Fatal(err)
	}
	com := domains[0]
	for _, derived := range com.Names {
		if strings.HasPrefix(derived.Name, "alt") {
			t.Errorf("%s derived with no lb_alt member: %+v", derived.Name, derived)
		}
	}
	notes := strings.Join(com.Notes, "\n")
	for _, name := range []string{"alt.example.com", "alt-v4.example.com", "alt-v6.example.com"} {
		if want := name + ": no lb set member is lb_alt, no records (service connect dns alias (lb_alt))"; !strings.Contains(notes, want) {
			t.Errorf("notes lack %q:\n%s", want, notes)
		}
	}
}

// A dns-only name has exactly one owner at derivation, in either order: it is
// refused when another derivation already produced it (alt's own names while
// alt still runs), when a later one produces it (a host-pinned service sorted
// after connect), and when the lb serves it (a top level expose alias).
func TestDnsLbAltRefusesASecondOwner(t *testing.T) {
	derive := func(mutate func(string) string) error {
		t.Helper()
		input := newDnsTestInput(t, func(servicesYaml string) string {
			return mutate(lbAltDnsServicesYaml(t, servicesYaml, lbAltVyosInterfaces{eno1np0: true}))
		})
		_, err := dnsDerive(input)
		return err
	}
	// connect's dns aliases with one more name
	addConnectAlias := func(servicesYaml string, name string) string {
		return lbAltEdgeReplace(t, servicesYaml, "        connect:\n"+lbAltDnsAltAliasesYaml, "        connect:\n"+lbAltDnsAltAliasesYaml+"                - "+name+"\n")
	}

	err := derive(func(servicesYaml string) string {
		return addConnectAlias(servicesYaml, "test-alt.example.com")
	})
	if err == nil || !strings.Contains(err.Error(), "test-alt.example.com is derived both as service alt (direct) and as service connect dns alias (lb_alt), and a dns-only name has one owner") {
		t.Errorf("err = %v, want alt's own name refused", err)
	}

	err = derive(func(servicesYaml string) string {
		servicesYaml = addConnectAlias(servicesYaml, "test-relay.example.com")
		servicesYaml = lbAltEdgeReplace(t, servicesYaml, "            - alt\n            - proxy\n", "            - alt\n            - proxy\n            - relay\n")
		return lbAltEdgeReplace(t, servicesYaml,
			"                - g1: 1\n        proxy:\n",
			"                - g1: 1\n        relay:\n            exposed: false\n            hosts:\n                - fireside.example.com\n            ports:\n                - 80\n            external_udp_ports:\n                - 5000\n            blocks:\n                - g1: 1\n        proxy:\n",
		)
	})
	if err == nil || !strings.Contains(err.Error(), "test-relay.example.com is derived both as service connect dns alias (lb_alt) and as service relay (direct), and a dns-only name has one owner") {
		t.Errorf("err = %v, want a later owner refused", err)
	}

	err = derive(func(servicesYaml string) string {
		return addConnectAlias(servicesYaml, "fireside.example.com")
	})
	if err == nil || !strings.Contains(err.Error(), "fireside.example.com is a dns-only name (service connect dns alias (lb_alt)), but the lb also serves it") {
		t.Errorf("err = %v, want a served name refused", err)
	}

	// and the handover itself derives
	if err := derive(func(servicesYaml string) string { return servicesYaml }); err != nil {
		t.Fatal(err)
	}
}

// A name both alt and connect list is refused when the config loads, before
// any derivation: the handover moves each alt.* name in one version. The
// derivation refuses it on its own too, for a config built without the load
// checks.
func TestDnsLbAltRefusesANameAltAndConnectBothList(t *testing.T) {
	servicesYaml, err := os.ReadFile(filepath.Join("testdata", "services-vyos.yml"))
	if err != nil {
		t.Fatal(err)
	}
	mutated := lbAltVyosServicesYaml(t, dnsFixtureWithDns(string(servicesYaml)), lbAltVyosInterfaces{eno1np0: true})
	// alt keeps its names, and connect lists alt.example.com too
	mutated = lbAltEdgeReplace(t, mutated, "        connect:\n", "        connect:\n            dns_aliases:\n                - alt.example.com\n")
	if err := loadLbAltEdgeServicesYaml(t, mutated); err == nil || !strings.Contains(err.Error(), `services "alt" and "connect" both declare the dns alias "alt.example.com"`) {
		t.Fatalf("err = %v, want the second owner refused at load", err)
	}

	var unchecked services.ServicesConfig
	if err := yaml.Unmarshal([]byte(mutated), &unchecked); err != nil {
		t.Fatal(err)
	}
	_, err = dnsDerive(dnsPlanInput{Env: "test", ServicesConfig: &unchecked})
	if err == nil || !strings.Contains(err.Error(), "alt.example.com is derived both as service alt dns alias and as service connect dns alias (lb_alt), and a dns-only name has one owner") {
		t.Fatalf("err = %v, want the second owner refused at derivation", err)
	}
}

// After the alt service is gone, its <env>-alt records are no longer derived.
// The route53 plan and sync report each one as stale, for explicit removal,
// and never delete it; records outside the env's namespace and the dns
// aliases, unmanaged names, and every name of another domain are not
// reported.
func TestDnsLbAltRoute53ReportsStaleAltRecords(t *testing.T) {
	input := newDnsTestInput(t, func(servicesYaml string) string {
		servicesYaml = lbAltDnsServicesYamlWithoutAlt(t, servicesYaml, lbAltVyosInterfaces{eno1np0: true})
		return lbAltEdgeReplace(t, servicesYaml, "        - www.example.com\n    other_domain_services:\n", "        - www.example.com\n        - test-keep.example.com\n    other_domain_services:\n")
	})
	env := input.Env
	if env != "test" {
		t.Fatalf("env = %s, the fixture names assume test", env)
	}
	// the proxy host keeps its interface after alt is gone
	firesideIpv6 := lbAltEdgeInterfaceIpv6(t, input.ServicesConfig, "fireside.example.com", "eno1np0")
	newFake := func() *fakeRoute53 {
		return &fakeRoute53{
			zone: "Z1",
			rrsets: append(lbAltDnsAltRecords("test-alt.example.com", "203.0.113.92", firesideIpv6),
				// unmanaged, and outside every namespace the derivation owns
				types.ResourceRecordSet{Name: aws.String("test-keep.example.com."), Type: types.RRTypeA, TTL: aws.Int64(120), ResourceRecords: []types.ResourceRecord{{Value: aws.String("192.0.2.10")}}},
				types.ResourceRecordSet{Name: aws.String("vpn-0.example.com."), Type: types.RRTypeA, TTL: aws.Int64(300), ResourceRecords: []types.ResourceRecord{{Value: aws.String("192.0.2.1")}}},
			),
		}
	}
	wantNotes := []string{
		"stale A test-alt.example.com 203.0.113.92 ttl=120: the derivation no longer produces this record; remove it explicitly, or list the name in dns unmanaged",
		"stale AAAA test-alt.example.com " + firesideIpv6 + " ttl=120: the derivation no longer produces this record; remove it explicitly, or list the name in dns unmanaged",
		"stale A test-alt-v4.example.com 203.0.113.92 ttl=120: the derivation no longer produces this record; remove it explicitly, or list the name in dns unmanaged",
		"stale AAAA test-alt-v6.example.com " + firesideIpv6 + " ttl=120: the derivation no longer produces this record; remove it explicitly, or list the name in dns unmanaged",
	}
	checkNotes := func(domain *dnsDomain) {
		t.Helper()
		notes := strings.Join(domain.Notes, "\n")
		for _, want := range wantNotes {
			if !strings.Contains(notes, want) {
				t.Errorf("notes lack %q:\n%s", want, notes)
			}
		}
		for _, absent := range []string{"test-keep", "vpn-0"} {
			if strings.Contains(notes, absent) {
				t.Errorf("notes report %s:\n%s", absent, notes)
			}
		}
	}

	domains, err := dnsDerive(input)
	if err != nil {
		t.Fatal(err)
	}
	for _, derived := range domains[0].Names {
		if strings.HasPrefix(derived.Name, env+"-alt") {
			t.Fatalf("%s is still derived without the alt service", derived.Name)
		}
	}
	// another domain carries <env>-<service> names the lb serves but the
	// derivation never produces, so none of them is stale there
	if domains[1].Primary || domains[1].isStaleCandidate(env+"-alt.example.net") || domains[1].isStaleCandidate(env+"-web.example.net") {
		t.Fatal("a name of another domain is a stale candidate")
	}
	if !domains[0].isStaleCandidate(env+"-alt.example.com") || !domains[0].isStaleCandidate("alt-v6.example.com") || domains[0].isStaleCandidate("vpn-0.example.com") {
		t.Fatal("the primary domain's stale candidates are wrong")
	}
	plannedFake := newFake()
	planned, err := (&route53Provider{api: plannedFake, ctx: context.Background()}).Plan(domains[0], input)
	if err != nil {
		t.Fatal(err)
	}
	for _, change := range planned {
		if strings.Contains(change.What, "test-alt") || strings.Contains(change.What, "test-keep") || strings.Contains(change.What, "vpn-0") {
			t.Errorf("the plan changes a record it does not own: %s", change)
		}
	}
	checkNotes(domains[0])

	// sync: the stale records survive, reported again
	domains, err = dnsDerive(input)
	if err != nil {
		t.Fatal(err)
	}
	appliedFake := newFake()
	if _, err := (&route53Provider{api: appliedFake, ctx: context.Background()}).Apply(domains[0], input); err != nil {
		t.Fatal(err)
	}
	for _, change := range appliedFake.changes {
		name := aws.ToString(change.ResourceRecordSet.Name)
		if strings.HasPrefix(name, "test-alt") || strings.HasPrefix(name, "test-keep") || strings.HasPrefix(name, "vpn-0") {
			t.Errorf("sync %s %s", change.Action, name)
		}
	}
	checkNotes(domains[0])
}

// The dns-only names are no input of TLS or HTTP routing: neither the lb's
// served names (Hostnames, the certificates nginx and the route file look
// up), nor the service and lb hosts the nginx config and the lb_alt route file
// are generated from, nor any generated nginx config holds them.
func TestDnsLbAltNamesStayOutOfTlsAndRoutes(t *testing.T) {
	servicesYaml, err := os.ReadFile(filepath.Join("testdata", "services-vyos.yml"))
	if err != nil {
		t.Fatal(err)
	}
	mutated := lbAltVyosServicesYaml(t, string(servicesYaml), lbAltVyosInterfaces{eno1np0: true})
	mutated = lbAltEdgeReplace(t, mutated, "        connect:\n", "        connect:\n"+lbAltDnsAltAliasesYaml)
	env, _ := setupTestVaultWithTLS(t, []byte(mutated))
	dnsOnlyNames := []string{"alt.example.com", "alt-v4.example.com", "alt-v6.example.com"}
	holdsDnsOnlyName := func(values []string) string {
		for _, value := range values {
			for _, dnsOnlyName := range dnsOnlyNames {
				if strings.Contains(value, dnsOnlyName) {
					return value
				}
			}
		}
		return ""
	}

	servicesConfig := getServicesConfig(env)
	if got := servicesConfig.Latest().Services["connect"].DnsAliases; !reflect.DeepEqual(got, dnsOnlyNames) {
		t.Fatalf("connect dns aliases = %v", got)
	}
	if found := holdsDnsOnlyName(servicesConfig.Hostnames(env, nil)); found != "" {
		t.Fatalf("Hostnames serves %s", found)
	}
	nginxConfig, err := NewNginxConfig(env, nil)
	if err != nil {
		t.Fatal(err)
	}
	if found := holdsDnsOnlyName(nginxConfig.serviceHosts("connect")); found != "" {
		t.Fatalf("connect is served on %s", found)
	}
	if found := holdsDnsOnlyName(nginxConfig.lbHosts()); found != "" {
		t.Fatalf("the lb is served on %s", found)
	}
	tlsNames := []string{}
	for name := range nginxConfig.domainTlsKeys {
		tlsNames = append(tlsNames, name)
	}
	if found := holdsDnsOnlyName(tlsNames); found != "" {
		t.Fatalf("a certificate is looked up for %s", found)
	}
	blockConfigs := nginxConfig.Generate()
	if len(blockConfigs) == 0 {
		t.Fatal("no lb config generated")
	}
	// the control: connect's served name is found where the dns-only names
	// are not
	connectHost := env + "-connect.example.com"
	if !slices.Contains(nginxConfig.serviceHosts("connect"), connectHost) || nginxConfig.domainTlsKeys[connectHost] == nil {
		t.Fatalf("%s is not served", connectHost)
	}
	for block, config := range blockConfigs {
		if !strings.Contains(config, connectHost) {
			t.Errorf("lb block %s config does not serve %s", block, connectHost)
		}
		if found := holdsDnsOnlyName(strings.Split(config, "\n")); found != "" {
			t.Errorf("lb block %s config holds %q", block, found)
		}
	}
}
