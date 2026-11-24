package main

import (
	"bytes"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/urnetwork/warp/services"
)

// loadSiblingVaultServicesConfig reads <env>/services.yml of the vault
// checkout next to warp when explicitly requested and available.
func loadSiblingVaultServicesConfig(t *testing.T, env string) *services.ServicesConfig {
	t.Helper()
	if os.Getenv("WARP_VAULT_TESTS") != "1" {
		t.Skip("reads the sibling production vault; set WARP_VAULT_TESTS=1 to run")
	}
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

// What `warpctl dns sync main` publishes on the primary domain for the lb and
// the family names the provider transports dial, pinned by shape: names are
// spelled from the vault's own domain and site prefix, and the addresses and
// interface names, which only the vault holds, are checked by how they
// relate. The lb set names only addresses the hosts hold: edge-0 and edge-1
// are behind routers that still run their legacy configuration, so their
// ipv6 is from the pre-convention /64 (none on one interface of each), not
// the port convention /64 nobody advertises. The weights are the main-lb
// weights approved on 2026-10-11. connect-v4/-v6 alias the lb with one family
// each (connect/IPV6.md A2, A9). So do alt-v4/-v6, which a pinned transport
// pairs with them (connect/EXTENDER.md L3): every lb interface is lb_alt, so
// the alt names, which connect declares as the lb_alt service, are dns-only
// aliases of the lb set (server/LBALT.md D14). The head version has no alt
// service, so the main-alt names are no longer derived, and a record left at
// one is reported as stale for explicit removal.
func TestVaultMainDnsDerivation(t *testing.T) {
	servicesConfig := loadSiblingVaultServicesConfig(t, "main")
	input := dnsPlanInput{Env: "main", ServicesConfig: servicesConfig}
	domains, err := dnsDerive(input)
	if err != nil {
		t.Fatal(err)
	}
	domain := servicesConfig.GetDomain()
	if len(domains) == 0 || domains[0].Domain != domain || !domains[0].Primary || domains[0].Registrar != "route53" {
		t.Fatalf("domains = %+v", domains)
	}
	com := domains[0]
	// the lb hosts are named <site>-5-edge-<k>, after the routers' site
	routerNames := servicesConfig.RouterNames()
	if len(routerNames) == 0 {
		t.Fatal("main has no routers")
	}
	groups := services.RouterNamePattern.FindStringSubmatch(routerNames[0])
	if groups == nil {
		t.Fatalf("router %s does not follow the <site>-<n>-<m> convention", routerNames[0])
	}
	site := groups[1]

	lbName := "main-lb." + domain
	lb := findDnsName(t, com, lbName)
	if lb.Kind != dnsLbSet || !lb.HasIpv4 || !lb.HasIpv6 {
		t.Fatalf("main-lb = %+v", lb)
	}
	// per host, each member's weight and whether it has ipv6
	wantMembers := map[string][]string{
		site + "-5-edge-0": {"10", "10 ipv6", "150 ipv6"},
		site + "-5-edge-1": {"10", "10 ipv6", "150 ipv6"},
		site + "-5-edge-3": {"50 ipv6", "50 ipv6"},
		site + "-5-edge-4": {"50 ipv6", "50 ipv6"},
		site + "-5-edge-7": {"50 ipv6", "50 ipv6"},
	}
	gotMembers := map[string][]string{}
	addresses := map[string]bool{}
	for _, member := range lb.Members {
		dash := strings.LastIndex(member.Id, "-")
		if dash < 0 {
			t.Fatalf("member %s is not <host>-<interface>", member.Id)
		}
		host := member.Id[:dash]
		for _, address := range []string{member.Ipv4, member.Ipv6} {
			if address == "" {
				continue
			}
			if addresses[address] {
				t.Errorf("member %s shares an address", member.Id)
			}
			addresses[address] = true
		}
		front := strconv.Itoa(member.Weight)
		if member.Ipv6 != "" {
			front += " ipv6"
		} else if derived := findDnsName(t, com, member.Id+"."+domain); derived.HasIpv6 || len(derived.Ipv6) != 0 {
			// an interface with no ipv6 publishes no AAAA record of its own
			t.Errorf("%s = %+v, want no AAAA", derived.Name, derived)
		}
		gotMembers[host] = append(gotMembers[host], front)
	}
	if len(gotMembers) != len(wantMembers) {
		t.Errorf("main-lb members on %d hosts want %d", len(gotMembers), len(wantMembers))
	}
	for host, want := range wantMembers {
		got := gotMembers[host]
		slices.Sort(got)
		if !slices.Equal(got, want) {
			t.Errorf("main-lb members of %s = %v want %v", host, got, want)
		}
	}

	// the lb aliases: one family per -v4/-v6 name, both otherwise
	for label, families := range map[string][2]bool{
		"connect":         {true, true},
		"connect-v4":      {true, false},
		"connect-v6":      {false, true},
		"main-connect-v4": {true, false},
		"main-connect-v6": {false, true},
		"api-v4":          {true, false},
		"api-v6":          {false, true},
		"alt":             {true, true},
		"alt-v4":          {true, false},
		"alt-v6":          {false, true},
	} {
		name := label + "." + domain
		derived := findDnsName(t, com, name)
		if derived.Kind != dnsAliasTo || derived.Target != lbName || derived.HasIpv4 != families[0] || derived.HasIpv6 != families[1] {
			t.Errorf("%s = %+v, want an alias of %s with families %v", name, derived, lbName, families)
		}
	}
	connectV6 := findDnsName(t, com, "connect-v6."+domain)
	if len(connectV6.Ipv4) != 0 || len(connectV6.Ipv6) != 10 {
		t.Errorf("connect-v6 resolves to %v %v, want the 10 lb ipv6 addresses only", connectV6.Ipv4, connectV6.Ipv6)
	}

	// the alt names are connect's lb_alt dns aliases, each resolving to every
	// lb address of its families and nothing else
	lbIpv4s, lbIpv6s := []string{}, []string{}
	for _, member := range lb.Members {
		lbIpv4s = append(lbIpv4s, member.Ipv4)
		if member.Ipv6 != "" {
			lbIpv6s = append(lbIpv6s, member.Ipv6)
		}
	}
	for _, c := range []struct {
		label string
		ipv4s []string
		ipv6s []string
	}{
		{label: "alt", ipv4s: lbIpv4s, ipv6s: lbIpv6s},
		{label: "alt-v4", ipv4s: lbIpv4s, ipv6s: nil},
		{label: "alt-v6", ipv4s: nil, ipv6s: lbIpv6s},
	} {
		derived := findDnsName(t, com, c.label+"."+domain)
		if derived.Source != "service connect dns alias (lb_alt)" {
			t.Errorf("%s is derived as %s, want connect's lb_alt dns alias", derived.Name, derived.Source)
		}
		if !slices.Equal(slices.Sorted(slices.Values(derived.Ipv4)), slices.Sorted(slices.Values(c.ipv4s))) || !slices.Equal(slices.Sorted(slices.Values(derived.Ipv6)), slices.Sorted(slices.Values(c.ipv6s))) {
			t.Errorf("%s resolves to %v %v, want the lb's %v %v", derived.Name, derived.Ipv4, derived.Ipv6, c.ipv4s, c.ipv6s)
		}
	}

	// with no alt service in the head version, its main-alt names are not
	// derived, and their records are stale: reported, never deleted
	for _, label := range []string{"main-alt", "main-alt-v4", "main-alt-v6"} {
		name := label + "." + domain
		if slices.Contains(dnsNameList(com), name) {
			t.Errorf("%s is derived with no alt service: %+v", name, findDnsName(t, com, name))
		}
		if !com.isStaleCandidate(name) {
			t.Errorf("%s is not a stale candidate, so a record left at it would go unreported", name)
		}
	}
}
