package main

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"

	"github.com/urnetwork/warp/services"
)

// loadSiblingVaultServicesConfig reads <env>/services.yml of the vault
// checkout next to warp, skipping when there is none or it is locked.
func loadSiblingVaultServicesConfig(t *testing.T, env string) *services.ServicesConfig {
	t.Helper()
	vaultDir := filepath.Join("..", "..", "vault")
	data, err := os.ReadFile(filepath.Join(vaultDir, env, "services.yml"))
	if err != nil {
		t.Skipf("no sibling vault checkout: %s", err)
	}
	if bytes.HasPrefix(data, []byte("\x00GITCRYPT")) {
		t.Skip("sibling vault checkout is locked")
	}
	servicesConfig, err := services.LoadServicesConfigFrom(vaultDir, env)
	if err != nil {
		t.Fatal(err)
	}
	return servicesConfig
}

// What `warpctl dns sync main` publishes on bringyour.com for the lb and the
// family names the provider transports dial. The lb set names only addresses
// the hosts hold: edge-0 and edge-1 are behind routers that still run their
// legacy configuration, so their ipv6 is from the pre-convention /64 (none on
// eno3 and eno4), not the port convention /64 nobody advertises. The weights
// are the main-lb weights approved on 2026-10-11. connect-v4/-v6 alias the lb
// with one family each (connect/IPV6.md A2, A9) and alt-v4/-v6, which a
// pinned transport pairs with them (connect/EXTENDER.md L3), are the proxy
// hosts' own addresses of one family.
func TestVaultMainDnsDerivation(t *testing.T) {
	servicesConfig := loadSiblingVaultServicesConfig(t, "main")
	input := dnsPlanInput{Env: "main", ServicesConfig: servicesConfig}
	domains, err := dnsDerive(input)
	if err != nil {
		t.Fatal(err)
	}
	if len(domains) == 0 || domains[0].Domain != "bringyour.com" || !domains[0].Primary || domains[0].Registrar != "route53" {
		t.Fatalf("domains = %+v", domains)
	}
	com := domains[0]

	lb := findDnsName(t, com, "main-lb.bringyour.com")
	wantMembers := []dnsMember{
		{Id: "by-us-fmt-5-edge-0-eno2np1", Ipv4: "65.19.157.62", Ipv6: "2001:470:173:52:e643:4bff:fe23:a341", Weight: 10},
		{Id: "by-us-fmt-5-edge-0-eno3np2", Ipv4: "65.19.157.42", Weight: 10},
		{Id: "by-us-fmt-5-edge-0-eno4np3", Ipv4: "65.49.70.71", Ipv6: "2001:470:99:57:e643:4bff:fe23:a343", Weight: 150},
		{Id: "by-us-fmt-5-edge-1-eno2np1", Ipv4: "65.49.70.70", Ipv6: "2001:470:99:56:e643:4bff:fec3:8446", Weight: 150},
		{Id: "by-us-fmt-5-edge-1-eno3", Ipv4: "65.19.157.41", Ipv6: "2001:470:173:54:e643:4bff:fec3:8464", Weight: 10},
		{Id: "by-us-fmt-5-edge-1-eno4", Ipv4: "65.19.157.40", Weight: 10},
		{Id: "by-us-fmt-5-edge-3-eno1np0", Ipv4: "65.49.70.84", Ipv6: "2001:470:99:5880:e643:4bff:fe94:e380", Weight: 50},
		{Id: "by-us-fmt-5-edge-3-eno2np1", Ipv4: "65.49.70.85", Ipv6: "2001:470:99:5860:e643:4bff:fe94:e381", Weight: 50},
		{Id: "by-us-fmt-5-edge-4-eno3np2", Ipv4: "65.49.70.82", Ipv6: "2001:470:99:5870:e643:4bff:fe89:2bca", Weight: 50},
		{Id: "by-us-fmt-5-edge-4-eno4np3", Ipv4: "65.49.70.83", Ipv6: "2001:470:99:5850:e643:4bff:fe89:2bcb", Weight: 50},
	}
	if lb.Kind != dnsLbSet || !lb.HasIpv4 || !lb.HasIpv6 || !reflect.DeepEqual(lb.Members, wantMembers) {
		t.Fatalf("main-lb = %+v\nwant members %+v", lb, wantMembers)
	}
	// an interface with no ipv6 publishes no AAAA record of its own
	for _, name := range []string{"by-us-fmt-5-edge-0-eno3np2.bringyour.com", "by-us-fmt-5-edge-1-eno4.bringyour.com"} {
		if derived := findDnsName(t, com, name); derived.HasIpv6 || len(derived.Ipv6) != 0 {
			t.Errorf("%s = %+v, want no AAAA", name, derived)
		}
	}

	// the lb aliases: one family per -v4/-v6 name, both otherwise
	for name, families := range map[string][2]bool{
		"connect.bringyour.com":         {true, true},
		"connect-v4.bringyour.com":      {true, false},
		"connect-v6.bringyour.com":      {false, true},
		"main-connect-v4.bringyour.com": {true, false},
		"main-connect-v6.bringyour.com": {false, true},
		"api-v4.bringyour.com":          {true, false},
		"api-v6.bringyour.com":          {false, true},
	} {
		derived := findDnsName(t, com, name)
		if derived.Kind != dnsAliasTo || derived.Target != "main-lb.bringyour.com" || derived.HasIpv4 != families[0] || derived.HasIpv6 != families[1] {
			t.Errorf("%s = %+v, want an alias of main-lb.bringyour.com with families %v", name, derived, families)
		}
	}
	connectV6 := findDnsName(t, com, "connect-v6.bringyour.com")
	if len(connectV6.Ipv4) != 0 || len(connectV6.Ipv6) != 8 {
		t.Errorf("connect-v6 resolves to %v %v, want the 8 lb ipv6 addresses only", connectV6.Ipv4, connectV6.Ipv6)
	}

	// alt runs on the proxy hosts with no lb: their addresses, one family per name
	sorted := func(values []string) []string {
		out := append([]string{}, values...)
		sort.Strings(out)
		return out
	}
	altV4 := findDnsName(t, com, "alt-v4.bringyour.com")
	if altV4.Kind != dnsAddresses || altV4.HasIpv6 || !reflect.DeepEqual(sorted(altV4.Ipv4), []string{"65.49.70.92", "65.49.70.94"}) {
		t.Errorf("alt-v4 = %+v", altV4)
	}
	altV6 := findDnsName(t, com, "alt-v6.bringyour.com")
	if altV6.Kind != dnsAddresses || altV6.HasIpv4 || !reflect.DeepEqual(sorted(altV6.Ipv6), []string{"2001:470:99:5940:3a05:25ff:fe37:292a", "2001:470:99:5960:3a05:25ff:fe32:e5ab"}) {
		t.Errorf("alt-v6 = %+v", altV6)
	}
}
