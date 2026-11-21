package services

// Tests of lb.lb_alt_port_hash_sources (server LBALTOPT2 R16): the source
// prefixes whose new flows the lb_alt split hashes by source address and
// port.

import (
	"net/netip"
	"slices"
	"strings"
	"testing"
)

// lbAltServicesYaml with lb.lb_alt_port_hash_sources set to the yaml value.
func lbAltPortHashYaml(t *testing.T, settings lbAltSettings, value string) string {
	t.Helper()
	return lbAltInsertAfter(t, lbAltYaml(settings), "      ports: [80, 443]", "      lb_alt_port_hash_sources: "+value)
}

// Prefixes of either family load in any order and come back sorted, IPv4
// first, as the lb unit's flag and the split's rules take them. A single
// address is a /32 or /128. A missing or empty list is no source.
func TestLbAltPortHashSourcesLoadSorted(t *testing.T) {
	version := loadLbAltVersion(t, lbAltPortHashYaml(t, lbAltSettings{connect: "true"}, `["2001:db8:c1::1/128", 198.51.100.0/27, "2001:db8:c0::/48", 192.0.2.7/32]`))
	sources, err := LbAltPortHashSources(version)
	if err != nil {
		t.Fatal(err)
	}
	want := []netip.Prefix{
		netip.MustParsePrefix("192.0.2.7/32"),
		netip.MustParsePrefix("198.51.100.0/27"),
		netip.MustParsePrefix("2001:db8:c0::/48"),
		netip.MustParsePrefix("2001:db8:c1::1/128"),
	}
	if !slices.Equal(sources, want) {
		t.Fatalf("port-hash sources %v, want %v", sources, want)
	}

	for _, servicesYaml := range []string{
		lbAltYaml(lbAltSettings{connect: "true"}),
		lbAltPortHashYaml(t, lbAltSettings{connect: "true"}, "[]"),
	} {
		version := loadLbAltVersion(t, servicesYaml)
		sources, err := LbAltPortHashSources(version)
		if err != nil || sources == nil || len(sources) != 0 {
			t.Fatalf("port-hash sources %#v (%v), want an empty list", sources, err)
		}
	}
	noLbVersion := &ServicesConfigVersion{Services: version.Services}
	for _, missingVersion := range []*ServicesConfigVersion{nil, noLbVersion} {
		if sources, err := LbAltPortHashSources(missingVersion); err != nil || sources == nil || len(sources) != 0 {
			t.Fatalf("port-hash sources %#v (%v), want an empty list", sources, err)
		}
	}
}

// Load refuses a list the split could not match or list back: an entry that
// is not a prefix with its length, an IPv4 range written as IPv4-mapped IPv6,
// which ip6tables would match against no IPv4 flow, a prefix with host bits
// set, which iptables lists masked, so its rules would be rewritten on every
// reconcile, a /0, and a prefix listed twice or inside another. Every version
// of the file is checked.
func TestLoadServicesConfigRefusesInvalidLbAltPortHashSources(t *testing.T) {
	for _, c := range []struct {
		name  string
		value string
		want  string
	}{
		{name: "an address with no length", value: "[203.0.113.4]", want: `lb.lb_alt_port_hash_sources: "203.0.113.4" is not an IPv4 or IPv6 prefix with its length`},
		{name: "a length past the family's", value: "[203.0.113.0/33]", want: `"203.0.113.0/33" is not an IPv4 or IPv6 prefix with its length`},
		{name: "a name", value: "[edge-0]", want: `"edge-0" is not an IPv4 or IPv6 prefix with its length`},
		{name: "an empty entry", value: `[""]`, want: `"" is not an IPv4 or IPv6 prefix with its length`},
		{name: "an IPv6 zone", value: `["fe80::/64%eth0"]`, want: `is not an IPv4 or IPv6 prefix with its length`},
		{name: "an IPv4-mapped IPv6 prefix", value: `["::ffff:203.0.113.0/123"]`, want: "::ffff:203.0.113.0/123 is an IPv4-mapped IPv6 prefix, which no IPv4 flow's source matches; list the IPv4 prefix"},
		{name: "IPv4 host bits", value: "[203.0.113.5/27]", want: "203.0.113.5/27 has host bits set; the prefix is 203.0.113.0/27"},
		{name: "IPv6 host bits", value: `["2001:db8:c0::1/48"]`, want: "2001:db8:c0::1/48 has host bits set; the prefix is 2001:db8:c0::/48"},
		{name: "every IPv4 source", value: "[0.0.0.0/0]", want: "0.0.0.0/0 is every source of its family"},
		{name: "every IPv6 source", value: `["::/0"]`, want: "::/0 is every source of its family"},
		{name: "a prefix twice", value: "[203.0.113.0/27, 203.0.113.0/27]", want: "203.0.113.0/27 overlaps 203.0.113.0/27"},
		{name: "a prefix inside another", value: "[203.0.113.0/27, 203.0.113.16/28]", want: "203.0.113.16/28 overlaps 203.0.113.0/27"},
	} {
		servicesYaml := lbAltPortHashYaml(t, lbAltSettings{connect: "true"}, c.value)
		_, err := loadInlineServicesConfig(t, servicesYaml)
		if err == nil || !strings.Contains(err.Error(), c.want) || !strings.Contains(err.Error(), "version 0") {
			t.Errorf("%s: load returned %v, want an error of version 0 with %q", c.name, err, c.want)
		}

		// in an older version too
		twoVersions := lbAltTwoVersions(t, lbAltYaml(lbAltSettings{connect: "true"}), servicesYaml)
		_, err = loadInlineServicesConfig(t, twoVersions)
		if err == nil || !strings.Contains(err.Error(), c.want) || !strings.Contains(err.Error(), "version 1") {
			t.Errorf("%s in the older version: load returned %v, want an error of version 1 with %q", c.name, err, c.want)
		}
	}
}

// The list is checked the same way where warpctl reads it back from the lb
// unit's flag, and returned sorted.
func TestParseLbAltPortHashSourcesChecksAndSorts(t *testing.T) {
	sources, err := ParseLbAltPortHashSources([]string{"2001:db8:c0::/48", "198.51.100.0/27", "192.0.2.0/27"})
	if err != nil {
		t.Fatal(err)
	}
	if got := []string{sources[0].String(), sources[1].String(), sources[2].String()}; !slices.Equal(got, []string{"192.0.2.0/27", "198.51.100.0/27", "2001:db8:c0::/48"}) {
		t.Fatalf("sources %v", got)
	}
	for _, refused := range [][]string{
		{"192.0.2.0"},
		{"192.0.2.1/27"},
		{"::ffff:192.0.2.0/123"},
		{"::/0"},
		{"192.0.2.0/27", "192.0.2.0/26"},
	} {
		if sources, err := ParseLbAltPortHashSources(refused); err == nil {
			t.Errorf("%v parsed to %v", refused, sources)
		}
	}
	if _, err := CheckLbAltPortHashSources([]netip.Prefix{{}}); err == nil {
		t.Error("the zero prefix checked")
	}
}
