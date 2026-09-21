package main

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/docopt/docopt-go"

	"github.com/urnetwork/warp/services"
	"github.com/urnetwork/warp/vyos"
)

func newVyosTestGenerator(t *testing.T) *VyosGenerator {
	t.Helper()
	return newVyosTestGeneratorWith(t, func(servicesYaml string) string { return servicesYaml })
}

// newVyosTestGeneratorWith loads the fixture after mutate has edited it.
func newVyosTestGeneratorWith(t *testing.T, mutate func(string) string) *VyosGenerator {
	t.Helper()
	generator, err := newVyosTestGeneratorWithSettings(t, mutate, func(settingsYaml string) string { return settingsYaml })
	if err != nil {
		t.Fatal(err)
	}
	return generator
}

// newVyosTestGeneratorWithSettings lays out the vault and the settings
// fixture (config/<env>/settings.yml, which the lan router renders from),
// both after their mutate, and builds the generator.
func newVyosTestGeneratorWithSettings(t *testing.T, mutate func(string) string, mutateSettings func(string) string) (*VyosGenerator, error) {
	t.Helper()
	servicesYaml, err := os.ReadFile(filepath.Join("testdata", "services-vyos.yml"))
	if err != nil {
		t.Fatal(err)
	}
	env := setupTestVault(t, []byte(mutate(string(servicesYaml))))
	settingsYaml, err := os.ReadFile(filepath.Join("testdata", "settings-vyos.yml"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(vyosTestSettingsPath(t, env), []byte(mutateSettings(string(settingsYaml))), 0644); err != nil {
		t.Fatal(err)
	}
	return NewVyosGenerator(env)
}

// vyosTestSettingsPath is config/<env>/settings.yml under the test warp home.
func vyosTestSettingsPath(t *testing.T, env string) string {
	t.Helper()
	configDir := filepath.Join(os.Getenv("WARP_HOME"), "config", env)
	if err := os.MkdirAll(configDir, 0755); err != nil {
		t.Fatal(err)
	}
	return filepath.Join(configDir, "settings.yml")
}

func vyosRuleSummary(chain *vyos.Node) []string {
	summary := []string{}
	for _, key := range chain.ContainerKeys() {
		if key.Name != "rule" {
			continue
		}
		number, err := strconv.Atoi(key.Tag)
		if err != nil || number < vyosHostRuleStart || strconv.Itoa(number) == vyosLogDropRuleNumber {
			continue
		}
		rule := chain.Container(key)
		summary = append(summary, fmt.Sprintf(
			"%s %s %s:%s %s",
			key.Tag,
			rule.LeafValues("protocol")[0],
			rule.LeafValues("destination", "address")[0],
			rule.LeafValues("destination", "port")[0],
			rule.LeafValues("description")[0],
		))
	}
	return summary
}

// The golden files are the complete generated config.boot of both routers.
// Set WARP_UPDATE_GOLDEN=1 to rewrite them after an intentional change.
func TestVyosGoldenConfigs(t *testing.T) {
	generator := newVyosTestGenerator(t)
	configs, err := generator.GenerateAll()
	if err != nil {
		t.Fatal(err)
	}
	if got := generator.Routers(); !reflect.DeepEqual(got, []string{"r-us-tst-5-1", "r-us-tst-5-2", "r-us-tst-5-3", "r-us-tst-5-8", "r-us-tst-5-9", "r-us-tst-5-gateway-3"}) {
		t.Fatalf("routers = %v", got)
	}
	for router, config := range configs {
		goldenPath := filepath.Join("testdata", "vyos", vyosConfigFileName(router))
		rendered := []byte(config.String())
		if os.Getenv("WARP_UPDATE_GOLDEN") == "1" {
			if err := os.WriteFile(goldenPath, rendered, 0644); err != nil {
				t.Fatal(err)
			}
		}
		golden, err := os.ReadFile(goldenPath)
		if err != nil {
			t.Fatalf("%s: %v (run with WARP_UPDATE_GOLDEN=1 to create it)", router, err)
		}
		if !bytes.Equal(golden, rendered) {
			t.Errorf("%s differs from %s; run with WARP_UPDATE_GOLDEN=1 after reviewing the change\n%s", router, goldenPath, rendered)
		}
		// the rendering is the device format: it parses back to the same tree
		// and migrates to itself with no commands
		parsed, err := vyos.Parse(string(rendered))
		if err != nil {
			t.Fatalf("%s: generated config does not parse: %v", router, err)
		}
		if !parsed.Root.Equal(config.Root) {
			t.Fatalf("%s: generated config does not round trip", router)
		}
		if parsed.String() != string(rendered) {
			t.Fatalf("%s: generated config is not in device order", router)
		}
		migration, err := vyos.Migrate(parsed.Root, config.Root, vyos.MigrateOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if !migration.Empty() {
			t.Fatalf("%s: self migration has %d commands", router, len(migration.Commands()))
		}
	}
}

// Everything the hostname convention derives: the router id nm from
// <site>-<n>-<m>, the WAN address <prefix>::nm, the /64 <prefix>:nmP0 on
// port ethP, and the 192.168.nm.0/24 management bridge with its dhcp range.
func TestVyosRouterConventions(t *testing.T) {
	generator := newVyosTestGenerator(t)
	config, err := generator.Generate("r-us-tst-5-8")
	if err != nil {
		t.Fatal(err)
	}
	root := config.Root
	cases := []struct {
		path []string
		want []string
	}{
		{[]string{"system", "host-name"}, []string{"r-us-tst-5-8"}},
		{[]string{"system", "gateway-address"}, []string{"203.0.113.65"}},
		{[]string{"interfaces", "ethernet", "eth1", "address"}, []string{"203.0.113.81/27", "2001:db8:99::58/64"}},
		{[]string{"interfaces", "ethernet", "eth3", "address"}, []string{"2001:db8:99:5830::1/64"}},
		{[]string{"interfaces", "ethernet", "eth6", "address"}, []string{"2001:db8:99:5860::1/64"}},
		{[]string{"interfaces", "ethernet", "eth8", "address"}, []string{"2001:db8:99:5880::1/64"}},
		{[]string{"interfaces", "ethernet", "eth8", "ipv6", "router-advert", "prefix", "2001:db8:99:5880::/64", "valid-lifetime"}, []string{"2592000"}},
		{[]string{"interfaces", "ethernet", "eth8", "ipv6", "router-advert", "name-server"}, []string{"2606:4700:4700::1111"}},
		{[]string{"interfaces", "bridge", "br0", "address"}, []string{"192.168.58.1/24"}},
		{[]string{"service", "dhcp-server", "shared-network-name", "LAN_BR", "subnet", "192.168.58.0/24", "default-router"}, []string{"192.168.58.1"}},
		{[]string{"service", "dhcp-server", "shared-network-name", "LAN_BR", "subnet", "192.168.58.0/24", "start", "192.168.58.38", "stop"}, []string{"192.168.58.243"}},
		{[]string{"protocols", "static", "route6", "::/0", "next-hop", "2001:db8:99::1", "interface"}, []string{"eth1"}},
		{[]string{"firewall", "name", "WAN_IN", "rule", "30", "source", "address"}, []string{"203.0.113.64/27"}},
		{[]string{"firewall", "ipv6-name", "WANv6_IN", "rule", "30", "source", "address"}, []string{"2001:db8:99::/48"}},
		{[]string{"service", "nat", "rule", "5000", "source", "address"}, []string{"203.0.113.64/27"}},
		{[]string{"service", "nat", "rule", "5001", "outbound-interface"}, []string{"eth1"}},
		{[]string{"system", "name-server"}, []string{"1.1.1.1", "9.9.9.9", "2606:4700:4700::1111"}},
		{[]string{"interfaces", "openvpn", "vtun1", "config-file"}, []string{"/config/by-pre.ovpn"}},
		{[]string{"service", "unms", "connection"}, []string{"wss://example.uisp.com:443+SCRUBBEDUISPKEYAAAA+allowUntrustedCertificate"}},
		{[]string{"system", "login", "user", "ubnt", "authentication", "encrypted-password"}, []string{"$5$SCRUBBEDSALT$SCRUBBEDHASH"}},
		{[]string{"system", "login", "user", "ubnt", "authentication", "public-keys", "fleet-2025.7.28", "type"}, []string{"ecdsa-sha2-nistp521"}},
		{[]string{"system", "login", "user", "ubnt", "level"}, []string{"admin"}},
		{[]string{"system", "conntrack", "modules", "sip", "disable"}, []string{}},
		{[]string{"interfaces", "ethernet", "eth0", "bridge-group", "bridge"}, []string{"br0"}},
		{[]string{"interfaces", "ethernet", "eth2", "bridge-group", "bridge"}, []string{"br0"}},
	}
	for _, c := range cases {
		got := root.LeafValues(c.path...)
		if got == nil {
			t.Errorf("%v is missing", c.path)
			continue
		}
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("%v = %v, want %v", c.path, got, c.want)
		}
	}
	// every listed lan port is configured, attached or not
	for _, port := range []string{"eth3", "eth4", "eth5", "eth6", "eth7", "eth8"} {
		if !root.HasLeaf("interfaces", "ethernet", port, "ip", "enable-proxy-arp") {
			t.Errorf("%s lacks proxy arp", port)
		}
		if root.LeafValues("interfaces", "ethernet", port, "ipv6", "router-advert", "send-advert") == nil {
			t.Errorf("%s lacks a router advert", port)
		}
	}
	// only attached interfaces get interface routes, in port order of the hosts
	if got := root.Lookup("protocols", "static").ContainerKeys(); !reflect.DeepEqual(got, []vyos.Key{
		{Name: "interface-route", Tag: "203.0.113.84/32"},
		{Name: "interface-route", Tag: "203.0.113.85/32"},
		{Name: "route6", Tag: "2001:db8:99:58::/64"},
		{Name: "route6", Tag: "2001:db8:99:5800::/56"},
		{Name: "route6", Tag: "::/0"},
	}) {
		t.Fatalf("static routes = %v", got)
	}
	if got := root.Lookup("protocols", "static", "interface-route", "203.0.113.84/32").ContainerKeys(); !reflect.DeepEqual(got, []vyos.Key{{Name: "next-hop-interface", Tag: "eth8"}}) {
		t.Fatalf("route to .84 = %v", got)
	}
	if got := root.Lookup("protocols", "static", "interface-route", "203.0.113.85/32").ContainerKeys(); !reflect.DeepEqual(got, []vyos.Key{{Name: "next-hop-interface", Tag: "eth6"}}) {
		t.Fatalf("route to .85 = %v", got)
	}
	// the footer carries the firmware markers
	if !reflect.DeepEqual(config.Comments, []string{
		"/* Warning: Do not remove the following line. */",
		`/* === vyatta-config-version: "config-management@1:conntrack@1:cron@1:dhcp-relay@1:dhcp-server@4:firewall@5:ipsec@5:nat@3:qos@1:quagga@2:suspend@1:system@5:ubnt-l2tp@1:ubnt-pptp@1:ubnt-udapi-server@1:ubnt-unms@2:ubnt-util@1:vrrp@1:vyatta-netflow@1:webgui@1:webproxy@1:zone-policy@1" === */`,
		"/* Release version: v3.0.1.5862409.250924.1408 */",
	}) {
		t.Fatalf("footer = %v", config.Comments)
	}

	// the second router: overrides for name servers, the vpn profile, an operator login
	other, err := generator.Generate("r-us-tst-5-9")
	if err != nil {
		t.Fatal(err)
	}
	otherCases := []struct {
		path []string
		want []string
	}{
		{[]string{"interfaces", "ethernet", "eth1", "address"}, []string{"203.0.113.89/27", "2001:db8:99::59/64"}},
		{[]string{"interfaces", "ethernet", "eth3", "address"}, []string{"2001:db8:99:5930::1/64"}},
		{[]string{"interfaces", "bridge", "br0", "address"}, []string{"192.168.59.1/24"}},
		{[]string{"system", "name-server"}, []string{"1.1.1.1", "2606:4700:4700::1111", "2606:4700:4700::1001"}},
		{[]string{"interfaces", "ethernet", "eth3", "ipv6", "router-advert", "name-server"}, []string{"2606:4700:4700::1111", "2606:4700:4700::1001"}},
		{[]string{"interfaces", "openvpn", "vtun1", "config-file"}, []string{"/config/tst-pre.ovpn"}},
		{[]string{"system", "login", "user", "audit", "level"}, []string{"operator"}},
		{[]string{"service", "unms", "connection"}, []string{"wss://example.uisp.com:443+SCRUBBEDUISPKEYBBBB+allowUntrustedCertificate"}},
	}
	for _, c := range otherCases {
		if got := other.Root.LeafValues(c.path...); !reflect.DeepEqual(got, c.want) {
			t.Errorf("r-us-tst-5-9 %v = %v, want %v", c.path, got, c.want)
		}
	}
}

// The lan router: every port but the WAN bridged, the bridge on the lan's
// /24 and on the first /64 of the router's /56, the hosts pinned by dhcp to
// the lan_hosts of settings.yml, no "allow local", the declared public
// ports forwarded, the lan masqueraded, and the same hardening as the edge.
func TestVyosLanRouter(t *testing.T) {
	generator := newVyosTestGenerator(t)
	if class, err := generator.Class("r-us-tst-5-1"); err != nil || class != services.RouterClassLan {
		t.Fatalf("class = %q, %v", class, err)
	}
	if class, _ := generator.Class("r-us-tst-5-8"); class != services.RouterClassEdge {
		t.Fatalf("r-us-tst-5-8 class = %q", class)
	}
	config, err := generator.Generate("r-us-tst-5-1")
	if err != nil {
		t.Fatal(err)
	}
	root := config.Root
	cases := []struct {
		path []string
		want []string
	}{
		{[]string{"system", "host-name"}, []string{"r-us-tst-5-1"}},
		{[]string{"interfaces", "bridge", "br0", "address"}, []string{"192.168.51.1/24", "2001:db8:99:5100::1/64"}},
		{[]string{"interfaces", "bridge", "br0", "ipv6", "router-advert", "prefix", "2001:db8:99:5100::/64", "valid-lifetime"}, []string{"2592000"}},
		{[]string{"interfaces", "bridge", "br0", "ipv6", "router-advert", "name-server"}, []string{"2001:db8:99:5100::1"}},
		{[]string{"interfaces", "ethernet", "eth1", "address"}, []string{"203.0.113.73/27", "2001:db8:99::51/64"}},
		{[]string{"service", "dhcp-server", "shared-network-name", "LAN_BR", "subnet", "192.168.51.0/24", "default-router"}, []string{"192.168.51.1"}},
		{[]string{"service", "dhcp-server", "shared-network-name", "LAN_BR", "subnet", "192.168.51.0/24", "dns-server"}, []string{"192.168.51.1"}},
		{[]string{"service", "dhcp-server", "shared-network-name", "LAN_BR", "subnet", "192.168.51.0/24", "static-mapping", "edge-2", "ip-address"}, []string{"192.168.51.43"}},
		{[]string{"service", "dhcp-server", "shared-network-name", "LAN_BR", "subnet", "192.168.51.0/24", "static-mapping", "edge-2", "mac-address"}, []string{"e4:43:4b:56:79:10"}},
		{[]string{"service", "dhcp-server", "shared-network-name", "LAN_BR", "subnet", "192.168.51.0/24", "static-mapping", "builder", "ip-address"}, []string{"192.168.51.176"}},
		{[]string{"service", "dns", "forwarding", "listen-on"}, []string{"br0"}},
		{[]string{"firewall", "name", "WAN_IN", "rule", "100", "destination", "address"}, []string{"192.168.51.43"}},
		{[]string{"firewall", "name", "WAN_IN", "rule", "100", "destination", "port"}, []string{"22"}},
		{[]string{"firewall", "name", "WAN_IN", "rule", "100", "protocol"}, []string{"tcp"}},
		{[]string{"firewall", "name", "WAN_IN", "rule", "100", "description"}, []string{"warp edge-2 backup ssh"}},
		{[]string{"firewall", "name", "WAN_IN", "rule", "110", "destination", "address"}, []string{"192.168.51.193"}},
		{[]string{"firewall", "name", "WAN_IN", "rule", "110", "description"}, []string{"warp edge-6 backup ssh redis"}},
		{[]string{"service", "nat", "rule", "100", "destination", "port"}, []string{"8022"}},
		{[]string{"service", "nat", "rule", "100", "inbound-interface"}, []string{"eth1"}},
		{[]string{"service", "nat", "rule", "100", "inside-address", "address"}, []string{"192.168.51.43"}},
		{[]string{"service", "nat", "rule", "100", "inside-address", "port"}, []string{"22"}},
		{[]string{"service", "nat", "rule", "100", "type"}, []string{"destination"}},
		{[]string{"service", "nat", "rule", "110", "destination", "port"}, []string{"8023"}},
		{[]string{"service", "nat", "rule", "110", "inside-address", "address"}, []string{"192.168.51.193"}},
		{[]string{"service", "nat", "rule", "5001", "type"}, []string{"masquerade"}},
		{[]string{"service", "unms", "connection"}, []string{"wss://example.uisp.com:443+SCRUBBEDUISPKEYLAN+allowUntrustedCertificate"}},
		{[]string{"service", "ssh", "disable-password-authentication"}, []string{}},
		{[]string{"system", "conntrack", "table-size"}, []string{"1048576"}},
		{[]string{"system", "gateway-address"}, []string{"203.0.113.65"}},
		{[]string{"firewall", "name", "WAN_LOCAL", "rule", "30", "icmp", "type"}, []string{"8"}},
		{[]string{"firewall", "ipv6-name", "WANv6_IN", "rule", "9000", "limit", "rate"}, []string{"5/second"}},
	}
	for _, c := range cases {
		got := root.LeafValues(c.path...)
		if got == nil {
			t.Errorf("%v is missing", c.path)
			continue
		}
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("%v = %v, want %v", c.path, got, c.want)
		}
	}
	// every port but the WAN is a bridge member, none is a routed port
	for _, port := range []string{"eth0", "eth2", "eth3", "eth4", "eth5", "eth6", "eth7", "eth8"} {
		if got := root.LeafValues("interfaces", "ethernet", port, "bridge-group", "bridge"); !reflect.DeepEqual(got, []string{"br0"}) {
			t.Errorf("%s bridge-group = %v", port, got)
		}
		if root.Lookup("interfaces", "ethernet", port, "ipv6") != nil || root.HasLeaf("interfaces", "ethernet", port, "address") {
			t.Errorf("%s is configured as a routed port", port)
		}
	}
	if root.HasLeaf("interfaces", "ethernet", "eth1", "ip", "enable-proxy-arp") {
		t.Error("a lan router has nothing to proxy arp for")
	}
	// the private lan admits nothing from the WAN block on its own
	for _, chain := range [][]string{{"firewall", "name", "WAN_IN"}, {"firewall", "ipv6-name", "WANv6_IN"}} {
		if root.Lookup(append(chain, "rule", "30")...) != nil {
			t.Errorf("%v has an allow local rule", chain)
		}
	}
	if root.Lookup("service", "nat", "rule", "5000") != nil {
		t.Error("the lan must be masqueraded without an exclusion")
	}
	// the routed /56 and the pre-convention /64 are blackholed; no host routes
	for _, prefix := range []string{"2001:db8:99:5100::/56", "2001:db8:99:51::/64"} {
		if root.Lookup("protocols", "static", "route6", prefix, "blackhole") == nil {
			t.Errorf("%s is not blackholed", prefix)
		}
	}
	for _, key := range root.Lookup("protocols", "static").ContainerKeys() {
		if key.Name == "interface-route" {
			t.Errorf("a lan router routes no host: %v", key)
		}
	}
	// only the hosts inside the lan are mapped, in name order
	subnet := root.Lookup("service", "dhcp-server", "shared-network-name", "LAN_BR", "subnet", "192.168.51.0/24")
	mappings := []string{}
	for _, key := range subnet.ContainerKeys() {
		if key.Name == "static-mapping" {
			mappings = append(mappings, key.Tag)
		}
	}
	if !reflect.DeepEqual(mappings, []string{"builder", "edge-2", "edge-3", "edge-6", "fireside"}) {
		t.Fatalf("static mappings = %v", mappings)
	}
}

// A gateway of ours: the isp link at the upper address of each point to
// point prefix, the block bridged over the downstream ports at the gateway
// addresses the routers behind it use, the /56 of each router behind it
// routed to that router, the rest of the /48 blackholed, bogons dropped on
// the isp link and everything else forwarded, the gateway itself protected,
// a management bridge on the reserved port, no nat.
func TestVyosGatewayRouter(t *testing.T) {
	generator := newVyosTestGenerator(t)
	config, err := generator.Generate("r-us-tst-5-gateway-3")
	if err != nil {
		t.Fatal(err)
	}
	root := config.Root
	cases := []struct {
		path []string
		want []string
	}{
		{[]string{"system", "host-name"}, []string{"r-us-tst-5-gateway-3"}},
		{[]string{"interfaces", "ethernet", "eth1", "address"}, []string{"192.0.2.194/27", "2001:db8:3c3:1::2/126"}},
		{[]string{"interfaces", "ethernet", "eth1", "description"}, []string{"ISP"}},
		{[]string{"interfaces", "ethernet", "eth1", "firewall", "in", "name"}, []string{"WAN_IN"}},
		{[]string{"interfaces", "ethernet", "eth1", "firewall", "local", "ipv6-name"}, []string{"WANv6_LOCAL"}},
		{[]string{"interfaces", "ethernet", "eth1", "ip", "enable-proxy-arp"}, []string{}},
		{[]string{"interfaces", "bridge", "br0", "address"}, []string{"2001:db8:535::1/64"}},
		{[]string{"interfaces", "bridge", "br0", "ip", "enable-proxy-arp"}, []string{}},
		{[]string{"interfaces", "bridge", "br1", "address"}, []string{"192.168.203.1/24"}},
		{[]string{"interfaces", "ethernet", "eth2", "bridge-group", "bridge"}, []string{"br1"}},
		{[]string{"system", "gateway-address"}, []string{"192.0.2.193"}},
		{[]string{"protocols", "static", "route6", "::/0", "next-hop", "2001:db8:3c3:1::1", "interface"}, []string{"eth1"}},
		{[]string{"protocols", "static", "route6", "2001:db8:535:5300::/56", "next-hop", "2001:db8:535::53", "interface"}, []string{"br0"}},
		{[]string{"firewall", "group", "network-group", "BOGONS", "network"}, append([]string{"192.0.2.192/27"}, vyosBogonsIpv4...)},
		{[]string{"firewall", "group", "ipv6-network-group", "BOGONS6", "ipv6-network"}, append([]string{"2001:db8:535::/48"}, vyosBogonsIpv6...)},
		{[]string{"firewall", "name", "WAN_IN", "default-action"}, []string{"accept"}},
		{[]string{"firewall", "name", "WAN_IN", "rule", "4", "action"}, []string{"accept"}},
		{[]string{"firewall", "name", "WAN_IN", "rule", "4", "protocol"}, []string{"icmp"}},
		{[]string{"firewall", "name", "WAN_IN", "rule", "4", "source", "address"}, []string{"192.0.2.193"}},
		{[]string{"firewall", "name", "WAN_IN", "rule", "5", "action"}, []string{"drop"}},
		{[]string{"firewall", "name", "WAN_IN", "rule", "5", "source", "group", "network-group"}, []string{"BOGONS"}},
		{[]string{"firewall", "ipv6-name", "WANv6_IN", "default-action"}, []string{"accept"}},
		{[]string{"firewall", "ipv6-name", "WANv6_IN", "rule", "5", "source", "group", "ipv6-network-group"}, []string{"BOGONS6"}},
		{[]string{"firewall", "name", "WAN_LOCAL", "default-action"}, []string{"drop"}},
		{[]string{"firewall", "name", "WAN_LOCAL", "rule", "4", "source", "address"}, []string{"192.0.2.193"}},
		{[]string{"firewall", "name", "WAN_LOCAL", "rule", "5", "source", "group", "network-group"}, []string{"BOGONS"}},
		{[]string{"firewall", "name", "WAN_LOCAL", "rule", "30", "icmp", "type"}, []string{"8"}},
		{[]string{"firewall", "name", "WAN_LOCAL", "rule", "9000", "limit", "rate"}, []string{"5/second"}},
		{[]string{"firewall", "ipv6-name", "WANv6_LOCAL", "rule", "30", "icmpv6", "type"}, []string{"echo-request"}},
		{[]string{"service", "dhcp-server", "shared-network-name", "LAN_BR", "subnet", "192.168.203.0/24", "default-router"}, []string{"192.168.203.1"}},
		{[]string{"service", "dns", "forwarding", "listen-on"}, []string{"br1"}},
		{[]string{"service", "ssh", "disable-password-authentication"}, []string{}},
		{[]string{"system", "conntrack", "table-size"}, []string{"1048576"}},
		{[]string{"system", "login", "user", "ubnt", "authentication", "public-keys", "fleet-2025.7.28", "type"}, []string{"ecdsa-sha2-nistp521"}},
	}
	for _, c := range cases {
		got := root.LeafValues(c.path...)
		if got == nil {
			t.Errorf("%v is missing", c.path)
			continue
		}
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("%v = %v, want %v", c.path, got, c.want)
		}
	}
	for _, port := range []string{"eth3", "eth4", "eth5", "eth6", "eth7", "eth8"} {
		if got := root.LeafValues("interfaces", "ethernet", port, "bridge-group", "bridge"); !reflect.DeepEqual(got, []string{"br0"}) {
			t.Errorf("%s bridge-group = %v", port, got)
		}
	}
	if root.Lookup("protocols", "static", "route6", "2001:db8:535::/48", "blackhole") == nil {
		t.Error("the rest of the /48 is not blackholed")
	}
	// the router behind it and its hosts are carried like an edge router's
	// hosts: /32s to the block bridge (r-us-tst-5-3 has no host yet)
	routes := root.Lookup("protocols", "static")
	if got := routes.ContainerKeys(); !reflect.DeepEqual(got, []vyos.Key{{Name: "interface-route", Tag: "192.0.2.195/32"}, {Name: "route6", Tag: "2001:db8:535:5300::/56"}, {Name: "route6", Tag: "2001:db8:535::/48"}, {Name: "route6", Tag: "::/0"}}) {
		t.Errorf("static routes = %v", got)
	}
	if got := routes.Lookup("interface-route", "192.0.2.195/32").ContainerKeys(); !reflect.DeepEqual(got, []vyos.Key{{Name: "next-hop-interface", Tag: "br0"}}) {
		t.Errorf("route to the router behind = %v", got)
	}
	if root.HasLeaf("interfaces", "ethernet", "eth1", "ipv6", "address") {
		t.Error("the /48 comes through the tunnel, not on-link")
	}
	// no nat, the pending uisp stanza
	if root.Lookup("service", "nat") != nil {
		t.Error("a gateway does not nat")
	}
	if unms := root.Lookup("service", "unms"); unms == nil || unms.HasLeaf("connection") {
		t.Error("a pending uisp attachment renders the empty stanza")
	}
	// the routers behind it derive their addressing from its blocks
	behind, err := generator.Generate("r-us-tst-5-3")
	if err != nil {
		t.Fatal(err)
	}
	if got := behind.Root.LeafValues("interfaces", "ethernet", "eth3", "address"); !reflect.DeepEqual(got, []string{"192.0.2.195/27", "2001:db8:535::53/64"}) {
		t.Errorf("r-us-tst-5-3 wan = %v", got)
	}
	if got := behind.Root.LeafValues("system", "gateway-address"); !reflect.DeepEqual(got, []string{"192.0.2.193"}) {
		t.Errorf("r-us-tst-5-3 gateway = %v", got)
	}
	if got := behind.Root.LeafValues("protocols", "static", "route6", "::/0", "next-hop", "2001:db8:535::1", "interface"); !reflect.DeepEqual(got, []string{"eth3"}) {
		t.Errorf("r-us-tst-5-3 default route = %v", got)
	}
	// a host attached to a router behind the gateway is routed by the gateway too
	withHost := newVyosTestGeneratorWith(t, func(servicesYaml string) string {
		return strings.Replace(servicesYaml, "        interfaces:\n            edge-3.example.com:\n", "        interfaces:\n            edge-9.example.com:\n                eno1:\n                    docker_network: warpeno1\n                    concurrent_clients: 1024\n                    cores: 4\n                    ipv4: 192.0.2.200\n                    ipv6: \"2001:db8:535:5300::200\"\n                    router: r-us-tst-5-3\n                    router_interface: eth0\n            edge-3.example.com:\n", 1)
	})
	config, err = withHost.Generate("r-us-tst-5-gateway-3")
	if err != nil {
		t.Fatal(err)
	}
	if got := config.Root.Lookup("protocols", "static").ContainerKeys()[:2]; !reflect.DeepEqual(got, []vyos.Key{{Name: "interface-route", Tag: "192.0.2.195/32"}, {Name: "interface-route", Tag: "192.0.2.200/32"}}) {
		t.Errorf("static routes with a host = %v", got)
	}
	// the migration guard covers the isp link
	protected, err := generator.ProtectedPaths("r-us-tst-5-gateway-3")
	if err != nil || !reflect.DeepEqual(protected[0], []string{"interfaces", "ethernet", "eth1"}) {
		t.Fatalf("protected = %v, %v", protected, err)
	}
}

// Planned routers are rendered but not listed for the rollout.
func TestVyosHostsLeavesPlannedRoutersOut(t *testing.T) {
	generator := newVyosTestGenerator(t)
	out := &bytes.Buffer{}
	previous := Out
	Out = log.New(out, "", 0)
	defer func() { Out = previous }()
	vyosHosts(docopt.Opts{"<env>": generator.env})
	want := "r-us-tst-5-1 172.28.208.181 lan\nr-us-tst-5-2 172.28.208.34 edge\nr-us-tst-5-8 172.28.208.161 edge\nr-us-tst-5-9 172.28.208.171 edge\n"
	if out.String() != want {
		t.Fatalf("hosts = %q", out.String())
	}
}

// The lan router refuses settings that disagree: a public port to a host
// the lan does not know, a `routes` address the lan_hosts block lacks, or a
// `routes` address that differs from its lan_hosts entry.
func TestVyosLanRouterChecksTheSettings(t *testing.T) {
	cases := map[string]struct {
		mutate         func(string) string
		mutateSettings func(string) string
		want           string
	}{
		"unknown public port host": {
			func(s string) string {
				return strings.Replace(s, "{host: edge-6, port: 22", "{host: redis, port: 22", 1)
			},
			func(s string) string { return s },
			"forwards to redis, which is not a lan_hosts entry",
		},
		"route without a lan host": {
			func(s string) string { return s },
			func(s string) string {
				return strings.Replace(s, "        snow: 172.28.208.185\n", "        snow: 172.28.208.185\n        crisp: 192.168.51.198\n", 1)
			},
			"routes crisp 192.168.51.198 lies in 192.168.51.0/24 but lan_hosts has no crisp entry; run run-routers.sh --update-settings",
		},
		"route disagreeing with the lan host": {
			func(s string) string { return s },
			func(s string) string {
				return strings.Replace(s, "        edge-3: 192.168.51.180\n", "        edge-3: 192.168.51.181\n", 1)
			},
			"routes edge-3 192.168.51.181 disagrees with lan_hosts 192.168.51.180",
		},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			generator, err := newVyosTestGeneratorWithSettings(t, c.mutate, c.mutateSettings)
			if err != nil {
				t.Fatal(err)
			}
			_, err = generator.Generate("r-us-tst-5-1")
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err = %v, want %q", err, c.want)
			}
			// the edge routers render regardless
			if _, err := generator.Generate("r-us-tst-5-8"); err != nil {
				t.Fatal(err)
			}
		})
	}
	// a lan router without the settings file cannot be generated
	servicesYaml, err := os.ReadFile(filepath.Join("testdata", "services-vyos.yml"))
	if err != nil {
		t.Fatal(err)
	}
	env := setupTestVault(t, servicesYaml)
	if _, err := NewVyosGenerator(env); err == nil || !strings.Contains(err.Error(), "settings.yml") {
		t.Fatalf("err = %v", err)
	}
}

// `update-settings`: the live capture's static mappings inside the lan are
// merged into the settings file; hosts outside the lan and dynamic leases
// are not.
func TestVyosUpdateSettingsMergesTheLiveLanHosts(t *testing.T) {
	generator := newVyosTestGenerator(t)
	config, err := generator.Generate("r-us-tst-5-1")
	if err != nil {
		t.Fatal(err)
	}
	// the live router knows two more hosts, one outside the lan, and a
	// different mac for fireside
	live := strings.Replace(config.String(), "                static-mapping fireside {\n                    ip-address 192.168.51.196\n                    mac-address 38:05:25:35:47:3f\n                }\n",
		"                static-mapping fireside {\n                    ip-address 192.168.51.196\n                    mac-address 38:05:25:35:47:40\n                }\n                static-mapping tinypilot {\n                    ip-address 192.168.51.42\n                    mac-address D8:3A:DD:31:58:2F\n                }\n                static-mapping elsewhere {\n                    ip-address 192.168.52.9\n                    mac-address 00:11:22:33:44:55\n                }\n", 1)
	if live == config.String() {
		t.Fatal("the fixture mapping was not replaced")
	}
	inDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(inDir, vyosLiveFileName("r-us-tst-5-1")), []byte(live), 0644); err != nil {
		t.Fatal(err)
	}
	hosts, err := vyosLiveLanHosts(generator, "r-us-tst-5-1", inDir)
	if err != nil {
		t.Fatal(err)
	}
	if hosts["tinypilot"] == nil || hosts["tinypilot"].Mac != "d8:3a:dd:31:58:2f" || hosts["elsewhere"] != nil || len(hosts) != 6 {
		t.Fatalf("live hosts = %+v", hosts)
	}
	document, err := os.ReadFile(generator.settingsPath)
	if err != nil {
		t.Fatal(err)
	}
	merge, err := services.MergeLanHosts(document, hosts)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(merge.Added, []string{"tinypilot"}) || len(merge.Conflicts) != 1 || !strings.Contains(merge.Conflicts[0], "fireside") {
		t.Fatalf("merge = %+v", merge)
	}
	if !strings.Contains(string(merge.Document), "edge-3.example.com: &tst\n") || !strings.Contains(string(merge.Document), "    <<: *tst\n") {
		t.Fatalf("the anchors did not survive:\n%s", merge.Document)
	}
	// a capture of another router is refused
	if err := os.WriteFile(filepath.Join(inDir, vyosLiveFileName("r-us-tst-5-1")), []byte(strings.Replace(live, "host-name r-us-tst-5-1", "host-name r-us-tst-5-8", 1)), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := vyosLiveLanHosts(generator, "r-us-tst-5-1", inDir); err == nil || !strings.Contains(err.Error(), "host-name") {
		t.Fatalf("err = %v", err)
	}
}

// A plain lb interface opens what the lb serves on it: the http ports on
// tcp, each stream port on the protocol of the service it maps to (svc-c
// runs on the edges, so tcp 444 and 1080 and udp 443), minus the forward
// target (4053) and the port kept private while the previous lb generation
// drains (8053), plus the forward port 53 on both families: warp's host-side
// dnat rewrites it to the lb's 4053 listener on these hosts, so the router
// only admits it.
func TestVyosRulesForAnLbInterface(t *testing.T) {
	generator := newVyosTestGenerator(t)
	config, err := generator.Generate("r-us-tst-5-8")
	if err != nil {
		t.Fatal(err)
	}
	wanIn := config.Root.Lookup("firewall", "name", "WAN_IN")
	// attachments are ordered by host, then interface name
	wantIpv4 := []string{
		"100 udp 203.0.113.84:53 warp edge-3 eno1np0 lb 53 udp",
		"110 tcp 203.0.113.84:80 warp edge-3 eno1np0 lb 80 tcp",
		"120 tcp_udp 203.0.113.84:443 warp edge-3 eno1np0 lb 443",
		"130 tcp 203.0.113.84:444 warp edge-3 eno1np0 lb 444 tcp",
		"140 tcp 203.0.113.84:1080 warp edge-3 eno1np0 lb 1080 tcp",
		"150 udp 203.0.113.85:53 warp edge-3 eno2np1 lb 53 udp",
		"160 tcp 203.0.113.85:80 warp edge-3 eno2np1 lb 80 tcp",
		"170 tcp_udp 203.0.113.85:443 warp edge-3 eno2np1 lb 443",
		"180 tcp 203.0.113.85:444 warp edge-3 eno2np1 lb 444 tcp",
		"190 tcp 203.0.113.85:1080 warp edge-3 eno2np1 lb 1080 tcp",
	}
	if got := vyosRuleSummary(wanIn); !reflect.DeepEqual(got, wantIpv4) {
		t.Fatalf("WAN_IN rules =\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(wantIpv4, "\n"))
	}
	wanIn6 := config.Root.Lookup("firewall", "ipv6-name", "WANv6_IN")
	wantIpv6 := []string{
		"100 udp 2001:db8:99:5880:e643:4bff:fe94:e380:53 warp edge-3 eno1np0 lb 53 udp",
		"110 tcp 2001:db8:99:5880:e643:4bff:fe94:e380:80 warp edge-3 eno1np0 lb 80 tcp",
		"120 tcp_udp 2001:db8:99:5880:e643:4bff:fe94:e380:443 warp edge-3 eno1np0 lb 443",
		"130 tcp 2001:db8:99:5880:e643:4bff:fe94:e380:444 warp edge-3 eno1np0 lb 444 tcp",
		"140 tcp 2001:db8:99:5880:e643:4bff:fe94:e380:1080 warp edge-3 eno1np0 lb 1080 tcp",
		"150 udp 2001:db8:99:5860:e643:4bff:fe94:e381:53 warp edge-3 eno2np1 lb 53 udp",
		"160 tcp 2001:db8:99:5860:e643:4bff:fe94:e381:80 warp edge-3 eno2np1 lb 80 tcp",
		"170 tcp_udp 2001:db8:99:5860:e643:4bff:fe94:e381:443 warp edge-3 eno2np1 lb 443",
		"180 tcp 2001:db8:99:5860:e643:4bff:fe94:e381:444 warp edge-3 eno2np1 lb 444 tcp",
		"190 tcp 2001:db8:99:5860:e643:4bff:fe94:e381:1080 warp edge-3 eno2np1 lb 1080 tcp",
	}
	if got := vyosRuleSummary(wanIn6); !reflect.DeepEqual(got, wantIpv6) {
		t.Fatalf("WANv6_IN rules =\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(wantIpv6, "\n"))
	}
	// warp's host-side dnat handles the 53 forward on these hosts, so the
	// router has no destination nat of its own: only the masquerade pair
	if got := config.Root.Lookup("service", "nat").ContainerKeys(); !reflect.DeepEqual(got, []vyos.Key{{Name: "rule", Tag: "5000"}, {Name: "rule", Tag: "5001"}}) {
		t.Fatalf("nat rules = %v", got)
	}
	// the base rules keep their numbers on both chains
	for _, chain := range []*vyos.Node{wanIn, wanIn6} {
		for number, want := range map[string]string{"10": "accept", "20": "drop", "30": "accept", "40": "accept"} {
			if got := chain.LeafValues("rule", number, "action"); !reflect.DeepEqual(got, []string{want}) {
				t.Errorf("rule %s action = %v", number, got)
			}
		}
		if got := chain.LeafValues("rule", "30", "protocol"); !reflect.DeepEqual(got, []string{"all"}) {
			t.Errorf("allow local protocol = %v", got)
		}
	}
	if got := wanIn.LeafValues("rule", "40", "protocol"); !reflect.DeepEqual(got, []string{"icmp"}) {
		t.Errorf("icmp rule = %v", got)
	}
	if got := wanIn6.LeafValues("rule", "40", "protocol"); !reflect.DeepEqual(got, []string{"ipv6-icmp"}) {
		t.Errorf("icmpv6 rule = %v", got)
	}
	for _, chain := range []string{"WAN_LOCAL", "WANv6_LOCAL"} {
		name := "name"
		if strings.HasPrefix(chain, "WANv6") {
			name = "ipv6-name"
		}
		local := config.Root.Lookup("firewall", name, chain)
		// state rules, the echo limit pair, other icmp and the drop-logging rule: no host rule reaches the router itself
		if got := local.ContainerKeys(); !reflect.DeepEqual(got, []vyos.Key{{Name: "rule", Tag: "10"}, {Name: "rule", Tag: "20"}, {Name: "rule", Tag: "30"}, {Name: "rule", Tag: "31"}, {Name: "rule", Tag: "32"}, {Name: "rule", Tag: "9000"}}) {
			t.Errorf("%s rules = %v", chain, got)
		}
		if got := local.LeafValues("default-action"); !reflect.DeepEqual(got, []string{"drop"}) {
			t.Errorf("%s default action = %v", chain, got)
		}
	}
}

// A transparent interface has no lb front, so none of the lb ports open
// there: only the public udp ports the host-pinned alt block owns, the
// public udp 53 its own dnat aliases to whodis, and the allocated external
// ports of the proxy blocks named in public_ports, all on both families.
// Port 80 of the proxy (the status route) stays closed, and so do the rest
// of the pool. edge-5 on the same router is a plain lb interface.
func TestVyosRulesForATransparentInterface(t *testing.T) {
	generator := newVyosTestGenerator(t)
	config, err := generator.Generate("r-us-tst-5-9")
	if err != nil {
		t.Fatal(err)
	}
	proxyPorts := map[string]map[string]int{}
	for _, block := range []string{"g1", "g2"} {
		proxyPorts[block] = map[string]int{}
		for servicePort, name := range map[int]string{8080: "socks", 8081: "http", 8082: "https", 8083: "api", 8084: "wg"} {
			portBlock := generator.portBlocks[""]["proxy"][block][servicePort]
			if portBlock == nil || portBlock.externalPort == 0 {
				t.Fatalf("proxy %s port %d has no external port", block, servicePort)
			}
			proxyPorts[block][name] = portBlock.externalPort
		}
	}
	statusPort := generator.portBlocks[""]["proxy"]["g1"][80].externalPort
	if statusPort == 0 {
		t.Fatal("proxy g1 port 80 has no external port")
	}

	wanIn := config.Root.Lookup("firewall", "name", "WAN_IN")
	got := vyosRuleSummary(wanIn)
	// hosts sort first: edge-5, then fireside
	// edge-5 also carries a custom forward, whose target the router opens
	wantHead := []string{
		"100 tcp 203.0.113.91:22 warp edge-5 enp33s0f1np1 forward 8022 to 22 tcp",
		"110 udp 203.0.113.91:53 warp edge-5 enp33s0f1np1 lb 53 udp",
		"120 tcp 203.0.113.91:80 warp edge-5 enp33s0f1np1 lb 80 tcp",
		"130 tcp_udp 203.0.113.91:443 warp edge-5 enp33s0f1np1 lb 443",
		"140 tcp 203.0.113.91:444 warp edge-5 enp33s0f1np1 lb 444 tcp",
		"150 tcp 203.0.113.91:1080 warp edge-5 enp33s0f1np1 lb 1080 tcp",
		"160 udp 203.0.113.92:53 warp fireside eno1np0 alt 53 udp",
		"170 udp 203.0.113.92:443 warp fireside eno1np0 alt 443 udp",
		"180 udp 203.0.113.92:4053 warp fireside eno1np0 alt 4053 udp",
	}
	if len(got) < len(wantHead) || !reflect.DeepEqual(got[:len(wantHead)], wantHead) {
		t.Fatalf("WAN_IN rules =\n%s\nwant a prefix of\n%s", strings.Join(got, "\n"), strings.Join(wantHead, "\n"))
	}
	// then the ten proxy ports in port order, each tcp_udp with its block and name
	proxyRules := got[len(wantHead):]
	if len(proxyRules) != 10 {
		t.Fatalf("proxy rules = %v", proxyRules)
	}
	seen := map[string]bool{}
	previousPort := 0
	for i, rule := range proxyRules {
		wantNumber := strconv.Itoa(vyosHostRuleStart + (len(wantHead)+i)*vyosHostRuleStride)
		fields := strings.Fields(rule)
		if fields[0] != wantNumber || fields[1] != "tcp_udp" {
			t.Errorf("proxy rule %d = %s, want number %s tcp_udp", i, rule, wantNumber)
		}
		address, portText, _ := strings.Cut(fields[2], ":")
		port, _ := strconv.Atoi(portText)
		if address != "203.0.113.92" || port <= previousPort {
			t.Errorf("proxy rule %d = %s: ports must ascend on the fireside address", i, rule)
		}
		previousPort = port
		block, name := fields[7], fields[8]
		if !strings.HasPrefix(rule, fields[0]+" tcp_udp 203.0.113.92:"+portText+" warp fireside eno1np0 proxy "+block+" "+name) {
			t.Errorf("proxy rule %d = %s", i, rule)
		}
		if proxyPorts[block][name] != port {
			t.Errorf("proxy rule %d = %s: %s %s is allocated external port %d", i, rule, block, name, proxyPorts[block][name])
		}
		seen[block+" "+name] = true
	}
	if len(seen) != 10 {
		t.Fatalf("proxy rules cover %d of 10 block ports", len(seen))
	}
	for _, rule := range got {
		if strings.Contains(rule, ":"+strconv.Itoa(statusPort)+" ") {
			t.Fatalf("the proxy status port %d is open: %s", statusPort, rule)
		}
		if strings.Contains(rule, ":8053 ") {
			t.Fatalf("the rolling-private port 8053 is open: %s", rule)
		}
		for _, lbPort := range []string{"53", "80", "443", "444", "1080"} {
			if strings.Contains(rule, "203.0.113.92:"+lbPort+" ") && !strings.Contains(rule, " alt ") {
				t.Fatalf("an lb port is open on the transparent fireside interface, which runs no lb front: %s", rule)
			}
		}
	}

	// IPv6: the same set minus the interface forward, which is EdgeOS nat
	// and therefore IPv4-only; the lb forward and the alt alias exist on both
	// families, so udp 53 opens on both
	wanIn6 := config.Root.Lookup("firewall", "ipv6-name", "WANv6_IN")
	got6 := vyosRuleSummary(wanIn6)
	wantHead6 := []string{
		"100 udp 2001:db8:99:5930:9a03:9bff:fe56:593:53 warp edge-5 enp33s0f1np1 lb 53 udp",
		"110 tcp 2001:db8:99:5930:9a03:9bff:fe56:593:80 warp edge-5 enp33s0f1np1 lb 80 tcp",
		"120 tcp_udp 2001:db8:99:5930:9a03:9bff:fe56:593:443 warp edge-5 enp33s0f1np1 lb 443",
		"130 tcp 2001:db8:99:5930:9a03:9bff:fe56:593:444 warp edge-5 enp33s0f1np1 lb 444 tcp",
		"140 tcp 2001:db8:99:5930:9a03:9bff:fe56:593:1080 warp edge-5 enp33s0f1np1 lb 1080 tcp",
		"150 udp 2001:db8:99:5960:3a05:25ff:fe32:e5ab:53 warp fireside eno1np0 alt 53 udp",
		"160 udp 2001:db8:99:5960:3a05:25ff:fe32:e5ab:443 warp fireside eno1np0 alt 443 udp",
		"170 udp 2001:db8:99:5960:3a05:25ff:fe32:e5ab:4053 warp fireside eno1np0 alt 4053 udp",
	}
	if len(got6) != len(wantHead6)+10 || !reflect.DeepEqual(got6[:len(wantHead6)], wantHead6) {
		t.Fatalf("WANv6_IN rules =\n%s\nwant a prefix of\n%s", strings.Join(got6, "\n"), strings.Join(wantHead6, "\n"))
	}
	for _, rule := range got6 {
		if strings.Contains(rule, ":22 ") || strings.Contains(rule, "forward ") {
			t.Fatalf("the interface forward is IPv4-only EdgeOS nat, its target must not open on IPv6: %s", rule)
		}
	}
}

// Destination nat on the router is only what an interface declares: edge-5
// forwards public tcp 8022 to 22, so the router rewrites it and opens 22,
// on IPv4 since EdgeOS nat is IPv4-only. The alt alias of udp 53 is the
// block's own dnat on the host, so the router admits 53 to fireside on both
// families and rewrites nothing there.
func TestVyosInterfaceForwardsBecomeRouterDnat(t *testing.T) {
	generator := newVyosTestGenerator(t)
	config, err := generator.Generate("r-us-tst-5-9")
	if err != nil {
		t.Fatal(err)
	}
	nat := config.Root.Lookup("service", "nat")
	// r-us-tst-5-9 masquerades its wan block, so there is no exclude rule 5000
	if got := nat.ContainerKeys(); !reflect.DeepEqual(got, []vyos.Key{{Name: "rule", Tag: "100"}, {Name: "rule", Tag: "5001"}}) {
		t.Fatalf("nat rules = %v", got)
	}
	rule := nat.Lookup("rule", "100")
	cases := []struct {
		path []string
		want []string
	}{
		{[]string{"description"}, []string{"warp edge-5 enp33s0f1np1 forward 8022 to 22 tcp"}},
		{[]string{"destination", "address"}, []string{"203.0.113.91"}},
		{[]string{"destination", "port"}, []string{"8022"}},
		{[]string{"inbound-interface"}, []string{"eth1"}},
		{[]string{"inside-address", "address"}, []string{"203.0.113.91"}},
		{[]string{"inside-address", "port"}, []string{"22"}},
		{[]string{"log"}, []string{"disable"}},
		{[]string{"protocol"}, []string{"tcp"}},
		{[]string{"type"}, []string{"destination"}},
	}
	for _, c := range cases {
		if got := rule.LeafValues(c.path...); !reflect.DeepEqual(got, c.want) {
			t.Errorf("nat rule 100 %v = %v, want %v", c.path, got, c.want)
		}
	}
	wanIn := config.Root.Lookup("firewall", "name", "WAN_IN")
	admitted := map[string]bool{}
	for _, summary := range vyosRuleSummary(wanIn) {
		if strings.HasSuffix(summary, "warp edge-5 enp33s0f1np1 forward 8022 to 22 tcp") && strings.Contains(summary, "203.0.113.91:22 ") {
			admitted["22"] = true
		}
		if strings.HasSuffix(summary, "warp fireside eno1np0 alt 53 udp") && strings.Contains(summary, "203.0.113.92:53 ") {
			admitted["53"] = true
		}
		if strings.Contains(summary, "203.0.113.91:8022 ") {
			t.Fatalf("a rewritten public port is opened instead: %s", summary)
		}
	}
	if !admitted["22"] || !admitted["53"] {
		t.Fatalf("expected ports are not admitted: %v", admitted)
	}
	admitted6 := false
	for _, summary := range vyosRuleSummary(config.Root.Lookup("firewall", "ipv6-name", "WANv6_IN")) {
		if strings.Contains(summary, "forward ") {
			t.Fatalf("a forward leaked into the IPv6 rules: %s", summary)
		}
		if strings.HasSuffix(summary, "warp fireside eno1np0 alt 53 udp") {
			admitted6 = true
		}
	}
	if !admitted6 {
		t.Fatal("the alt alias of udp 53 is not admitted on IPv6")
	}
	// nothing is rewritten on 5-8: only the masquerade pair
	other, err := generator.Generate("r-us-tst-5-8")
	if err != nil {
		t.Fatal(err)
	}
	if got := other.Root.Lookup("service", "nat").ContainerKeys(); !reflect.DeepEqual(got, []vyos.Key{{Name: "rule", Tag: "5000"}, {Name: "rule", Tag: "5001"}}) {
		t.Fatalf("5-8 nat rules = %v", got)
	}
}

// A rewrite that would capture a served port, or two rewrites of one public
// port, is refused rather than silently generated.
func TestVyosRefusesConflictingForwards(t *testing.T) {
	cases := map[string]struct {
		mutate func(string) string
		want   string
	}{
		"forward captures the lb https port": {
			func(s string) string {
				return strings.Replace(s, "                        8022: 22\n", "                        443: 22\n", 1)
			},
			"tcp port 443 is both served and rewritten",
		},
		"interface forward captures the alt whodis port": {
			func(s string) string {
				return strings.Replace(s, "                    router: r-us-tst-5-9\n                    router_interface: eth6\n", "                    router: r-us-tst-5-9\n                    router_interface: eth6\n                    router_udp_forward_ports:\n                        4053: 22\n", 1)
			},
			"udp port 4053 is both served and rewritten",
		},
		"interface forward captures the alt dns alias": {
			func(s string) string {
				return strings.Replace(s, "                    router: r-us-tst-5-9\n                    router_interface: eth6\n", "                    router: r-us-tst-5-9\n                    router_interface: eth6\n                    router_udp_forward_ports:\n                        53: 4053\n", 1)
			},
			"udp port 53 is both served and rewritten",
		},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			generator := newVyosTestGeneratorWith(t, c.mutate)
			_, err := generator.Generate("r-us-tst-5-9")
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err = %v, want %q", err, c.want)
			}
		})
	}
}

// An interface without a router (behind a legacy router) appears in no
// generated config.
func TestVyosSkipsLegacyInterfaces(t *testing.T) {
	generator := newVyosTestGenerator(t)
	configs, err := generator.GenerateAll()
	if err != nil {
		t.Fatal(err)
	}
	for router, config := range configs {
		if strings.Contains(config.String(), "198.51.100.62") || strings.Contains(config.String(), "legacy-0") {
			t.Fatalf("%s references the legacy host", router)
		}
	}
	if got := len(generator.attachments("r-us-tst-5-8")); got != 2 {
		t.Fatalf("r-us-tst-5-8 attachments = %d", got)
	}
	if got := len(generator.attachments("r-us-tst-5-9")); got != 2 {
		t.Fatalf("r-us-tst-5-9 attachments = %d", got)
	}
	if got := len(generator.attachments("r-us-tst-5-2")); got != 1 {
		t.Fatalf("r-us-tst-5-2 attachments = %d", got)
	}
}

func TestVyosProtectedPathsGuardTheManagementPath(t *testing.T) {
	generator := newVyosTestGenerator(t)
	protected, err := generator.ProtectedPaths("r-us-tst-5-8")
	if err != nil {
		t.Fatal(err)
	}
	want := [][]string{
		{"interfaces", "ethernet", "eth1"},
		{"interfaces", "openvpn"},
		{"service", "ssh"},
		{"system", "gateway-address"},
		{"system", "login"},
	}
	if !reflect.DeepEqual(protected, want) {
		t.Fatalf("protected = %v", protected)
	}
	if _, err := generator.ProtectedPaths("nope"); err == nil {
		t.Fatal("unknown router must be an error")
	}
}

// The migration command refuses a capture from another router and renders
// the fail-closed script for the right one.
func TestVyosMigrationScriptChecksTheCaptureHostName(t *testing.T) {
	generator := newVyosTestGenerator(t)
	inDir := t.TempDir()
	config, err := generator.Generate("r-us-tst-5-8")
	if err != nil {
		t.Fatal(err)
	}
	// a live capture: the generated config with one rule removed and one stale rule added
	live, err := vyos.Parse(config.String())
	if err != nil {
		t.Fatal(err)
	}
	liveWanIn := live.Root.Lookup("firewall", "name", "WAN_IN")
	stale := liveWanIn.Tag("rule", "240")
	stale.SetLeaf("action", "accept")
	stale.SetLeaf("protocol", "icmp")
	if err := os.WriteFile(filepath.Join(inDir, vyosLiveFileName("r-us-tst-5-8")), []byte(live.String()), 0644); err != nil {
		t.Fatal(err)
	}
	script, migration, err := vyosMigrationScript(generator, "test", "r-us-tst-5-8", inDir, 3)
	if err != nil {
		t.Fatal(err)
	}
	if got := len(migration.Deletes); got != 1 || migration.Deletes[0].String() != "delete firewall name WAN_IN rule 240" {
		t.Fatalf("deletes = %v", migration.Deletes)
	}
	if len(migration.Sets) != 0 {
		t.Fatalf("sets = %v", migration.Sets)
	}
	if !strings.Contains(script, "\ndelete firewall name WAN_IN rule 240 || fail $LINENO\ncommit-confirm 3 || fail $LINENO\nconfigure_exit\n") {
		t.Fatalf("script:\n%s", script)
	}
	if !strings.Contains(script, vyos.ChangesHeader+"1 deletes=1 sets=0\n") {
		t.Fatalf("script header:\n%s", script)
	}

	// the same capture under the other router's name is refused
	if err := os.WriteFile(filepath.Join(inDir, vyosLiveFileName("r-us-tst-5-9")), []byte(live.String()), 0644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := vyosMigrationScript(generator, "test", "r-us-tst-5-9", inDir, 0); err == nil || !strings.Contains(err.Error(), "host-name") {
		t.Fatalf("err = %v, want a host-name mismatch", err)
	}

	// a capture with uncommitted changes is refused
	if err := os.WriteFile(filepath.Join(inDir, vyosLiveFileName("r-us-tst-5-8")), []byte("firewall {\n+    all-ping enable\n}\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := vyosMigrationScript(generator, "test", "r-us-tst-5-8", inDir, 0); err == nil || !strings.Contains(err.Error(), "uncommitted") {
		t.Fatalf("err = %v, want an uncommitted capture error", err)
	}

	// a capture whose WAN interface differs would delete the protected address: refused
	drifted, err := vyos.Parse(config.String())
	if err != nil {
		t.Fatal(err)
	}
	drifted.Root.Lookup("interfaces", "ethernet", "eth1").AddLeafValue("address", "203.0.113.82/27")
	if err := os.WriteFile(filepath.Join(inDir, vyosLiveFileName("r-us-tst-5-8")), []byte(drifted.String()), 0644); err != nil {
		t.Fatal(err)
	}
	_, _, err = vyosMigrationScript(generator, "test", "r-us-tst-5-8", inDir, 0)
	var protectedErr *vyos.ProtectedPathError
	if err == nil || !errorsAs(err, &protectedErr) {
		t.Fatalf("err = %v, want a protected path error", err)
	}
}

// The address derivation helpers on their own.
func TestVyosAddressDerivation(t *testing.T) {
	router := &services.RouterConfig{WanIpv6Prefix: "2001:db8:99::/48", WanIpv4: "203.0.113.81/27"}
	wan, err := services.RouterWanIpv6("r-us-tst-5-8", router)
	if err != nil || wan.String() != "2001:db8:99::58/64" {
		t.Fatalf("wan = %v, %v", wan, err)
	}
	if block, err := services.RouterIpv6Block("r-us-tst-5-8", router); err != nil || block.String() != "2001:db8:99:5800::/56" {
		t.Fatalf("block = %v, %v", block, err)
	}
	if legacy, err := services.RouterLegacyIpv6Prefix("r-us-tst-5-8", router); err != nil || legacy.String() != "2001:db8:99:58::/64" {
		t.Fatalf("legacy = %v, %v", legacy, err)
	}
	// every port /64 lies inside the routed /56, and the legacy /64 outside
	block, _ := services.RouterIpv6Block("r-us-tst-5-8", router)
	for _, port := range []string{"eth0", "eth5", "eth9"} {
		lan, _ := services.RouterLanIpv6Prefix("r-us-tst-5-8", router, port)
		if !block.Contains(lan.Addr()) {
			t.Errorf("%s %s is outside %s", port, lan, block)
		}
	}
	if legacy, _ := services.RouterLegacyIpv6Prefix("r-us-tst-5-8", router); block.Contains(legacy.Addr()) {
		t.Errorf("legacy %s is inside %s", legacy, block)
	}
	for port, want := range map[string]string{"eth3": "2001:db8:99:5830::/64", "eth8": "2001:db8:99:5880::/64", "eth0": "2001:db8:99:5800::/64"} {
		lan, err := services.RouterLanIpv6Prefix("r-us-tst-5-8", router, port)
		if err != nil || lan.String() != want {
			t.Errorf("lan %s = %v, %v", port, lan, err)
		}
	}
	lan4, err := services.RouterLanIpv4("r-us-tst-5-8", router)
	if err != nil || lan4.String() != "192.168.58.1/24" {
		t.Fatalf("lan4 = %v, %v", lan4, err)
	}
	router.LanIpv4 = "192.168.62.1/24"
	lan4, err = services.RouterLanIpv4("r-us-tst-5-8", router)
	if err != nil || lan4.String() != "192.168.62.1/24" {
		t.Fatalf("lan4 override = %v, %v", lan4, err)
	}
	for _, bad := range []string{"r-us-tst-58", "r-us-tst-5-10", "r-us-tst-5-8-edge-3", "R-us-tst-5-8", "by-us-fmt-5-edge-3"} {
		if _, err := services.RouterId(bad); err == nil {
			t.Errorf("%q must not be a router name", bad)
		}
	}
	if _, err := services.RouterLanPort("eth10"); err == nil {
		t.Error("eth10 must not be a lan port")
	}
	if id, err := services.RouterId("by-us-fmt-5-9"); err != nil || id != "59" {
		t.Errorf("id = %q, %v", id, err)
	}
}

// The hardening every router gets, and the per-router toggles.
func TestVyosHardening(t *testing.T) {
	generator := newVyosTestGenerator(t)
	config, err := generator.Generate("r-us-tst-5-8")
	if err != nil {
		t.Fatal(err)
	}
	root := config.Root
	chains := map[string][]string{
		"WAN_IN":      {"firewall", "name", "WAN_IN"},
		"WAN_LOCAL":   {"firewall", "name", "WAN_LOCAL"},
		"WANv6_IN":    {"firewall", "ipv6-name", "WANv6_IN"},
		"WANv6_LOCAL": {"firewall", "ipv6-name", "WANv6_LOCAL"},
	}
	for name, path := range chains {
		chain := root.Lookup(path...)
		if chain == nil {
			t.Fatalf("%s is missing", name)
		}
		if chain.HasLeaf("enable-default-log") {
			t.Errorf("%s still logs every drop", name)
		}
		if got := chain.LeafValues("default-action"); !reflect.DeepEqual(got, []string{"drop"}) {
			t.Errorf("%s default-action = %v", name, got)
		}
		logDrop := chain.Lookup("rule", "9000")
		if logDrop == nil {
			t.Fatalf("%s has no drop-logging rule", name)
		}
		for leaf, want := range map[string]string{"action": "drop", "log": "enable", "protocol": "all"} {
			if got := logDrop.LeafValues(leaf); !reflect.DeepEqual(got, []string{want}) {
				t.Errorf("%s rule 9000 %s = %v", name, leaf, got)
			}
		}
		if got := logDrop.LeafValues("limit", "rate"); !reflect.DeepEqual(got, []string{"5/second"}) {
			t.Errorf("%s rule 9000 rate = %v", name, got)
		}
		if got := logDrop.LeafValues("limit", "burst"); !reflect.DeepEqual(got, []string{"10"}) {
			t.Errorf("%s rule 9000 burst = %v", name, got)
		}
		// the host rules all sit below it
		for _, key := range chain.ContainerKeys() {
			if number, err := strconv.Atoi(key.Tag); err == nil && number > 9000 {
				t.Errorf("%s rule %d is above the drop-logging rule", name, number)
			}
		}
	}
	// echo requests to the router are rate limited, other icmp is not
	for name, echo := range map[string][]string{
		"WAN_LOCAL":   {"icmp", "type", "8"},
		"WANv6_LOCAL": {"icmpv6", "type", "echo-request"},
	} {
		chain := root.Lookup(chains[name]...)
		accept := chain.Lookup("rule", "30")
		if got := accept.LeafValues(echo[0], echo[1]); !reflect.DeepEqual(got, []string{echo[2]}) {
			t.Errorf("%s rule 30 %v = %v", name, echo[:2], got)
		}
		if got := accept.LeafValues("action"); !reflect.DeepEqual(got, []string{"accept"}) {
			t.Errorf("%s rule 30 action = %v", name, got)
		}
		if got := accept.LeafValues("limit", "rate"); !reflect.DeepEqual(got, []string{"10/second"}) {
			t.Errorf("%s rule 30 rate = %v", name, got)
		}
		excess := chain.Lookup("rule", "31")
		if got := excess.LeafValues(echo[0], echo[1]); !reflect.DeepEqual(got, []string{echo[2]}) {
			t.Errorf("%s rule 31 %v = %v", name, echo[:2], got)
		}
		if got := excess.LeafValues("action"); !reflect.DeepEqual(got, []string{"drop"}) || excess.Lookup("limit") != nil {
			t.Errorf("%s rule 31 must drop the excess without a limit", name)
		}
		other := chain.Lookup("rule", "32")
		if other.Lookup("limit") != nil || other.Lookup(echo[0]) != nil || !reflect.DeepEqual(other.LeafValues("action"), []string{"accept"}) {
			t.Errorf("%s rule 32 must accept every other icmp type unconditionally", name)
		}
	}
	// forwarded icmp is never limited: path mtu discovery must reach the hosts
	for _, name := range []string{"WAN_IN", "WANv6_IN"} {
		icmp := root.Lookup(chains[name]...).Lookup("rule", "40")
		if icmp == nil || icmp.Lookup("limit") != nil || !reflect.DeepEqual(icmp.LeafValues("action"), []string{"accept"}) {
			t.Errorf("%s rule 40 must accept icmp without a limit", name)
		}
	}
	leaves := []struct {
		path []string
		want []string
	}{
		{[]string{"firewall", "send-redirects"}, []string{"disable"}},
		{[]string{"firewall", "receive-redirects"}, []string{"disable"}},
		{[]string{"service", "ssh", "disable-password-authentication"}, []string{}},
		{[]string{"service", "gui", "older-ciphers"}, []string{"disable"}},
		{[]string{"system", "analytics-handler", "send-analytics-report"}, []string{"false"}},
		{[]string{"system", "crash-handler", "send-crash-report"}, []string{"false"}},
		{[]string{"system", "offload", "ipv4", "forwarding"}, []string{"enable"}},
		{[]string{"system", "offload", "ipv6", "forwarding"}, []string{"disable"}},
		{[]string{"service", "nat", "rule", "5000", "exclude"}, []string{}},
		{[]string{"service", "nat", "rule", "5000", "source", "address"}, []string{"203.0.113.64/27"}},
		{[]string{"interfaces", "ethernet", "eth1", "address"}, []string{"203.0.113.81/27", "2001:db8:99::58/64"}},
		{[]string{"firewall", "ipv6-name", "WANv6_IN", "rule", "30", "source", "address"}, []string{"2001:db8:99::/48"}},
	}
	for _, c := range leaves {
		got := root.LeafValues(c.path...)
		if got == nil {
			t.Errorf("%v is missing", c.path)
			continue
		}
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("%v = %v, want %v", c.path, got, c.want)
		}
	}
	// the platform default conntrack sizing is left alone unless set
	for _, leaf := range []string{"table-size", "hash-size", "expect-table-size"} {
		if root.HasLeaf("system", "conntrack", leaf) {
			t.Errorf("r-us-tst-5-8 sets conntrack %s without asking", leaf)
		}
	}
	// the routed /56 and the pre-convention /64 are blackholed, the port /64s
	// stay connected routes
	for _, prefix := range []string{"2001:db8:99:5800::/56", "2001:db8:99:58::/64"} {
		if root.Lookup("protocols", "static", "route6", prefix, "blackhole") == nil {
			t.Errorf("%s is not blackholed", prefix)
		}
	}
	if root.Lookup("protocols", "static", "route6", "2001:db8:99:5880::/64") != nil {
		t.Error("an advertised port /64 must not carry a static route")
	}

	// the explicit toggles on r-us-tst-5-9
	other, err := generator.Generate("r-us-tst-5-9")
	if err != nil {
		t.Fatal(err)
	}
	otherLeaves := []struct {
		path []string
		want []string
	}{
		{[]string{"system", "conntrack", "table-size"}, []string{"1048576"}},
		{[]string{"system", "conntrack", "hash-size"}, []string{"131072"}},
		{[]string{"system", "offload", "ipv4", "forwarding"}, []string{"enable"}},
		{[]string{"system", "offload", "ipv6", "forwarding"}, []string{"enable"}},
		{[]string{"service", "nat", "rule", "5001", "type"}, []string{"masquerade"}},
	}
	for _, c := range otherLeaves {
		if got := other.Root.LeafValues(c.path...); !reflect.DeepEqual(got, c.want) {
			t.Errorf("r-us-tst-5-9 %v = %v, want %v", c.path, got, c.want)
		}
	}
	if other.Root.Lookup("service", "nat", "rule", "5000") != nil {
		t.Error("r-us-tst-5-9 masquerades the wan block but still excludes it")
	}

	// a router that is still on the /48 migrates to the /64 in one commit:
	// the address replacement passes the WAN interface guard
	liveText := strings.Replace(config.String(), "address 2001:db8:99::58/64", "address 2001:db8:99::58/48", 1)
	live, err := vyos.Parse(liveText)
	if err != nil {
		t.Fatal(err)
	}
	protected, err := generator.ProtectedPaths("r-us-tst-5-8")
	if err != nil {
		t.Fatal(err)
	}
	migration, err := vyos.Migrate(live.Root, root, vyos.MigrateOptions{Protected: protected})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"delete interfaces ethernet eth1 address 2001:db8:99::58/48",
		"set interfaces ethernet eth1 address 2001:db8:99::58/64",
	}
	got := []string{}
	for _, command := range migration.Commands() {
		got = append(got, command.String())
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("migration = %v, want %v", got, want)
	}
}

// What the upstream gateway of each WAN block must route: one IPv6 /56 per
// router to its WAN address, no IPv4 route, the legacy /64s to retire.
func TestVyosListGatewayRoutes(t *testing.T) {
	generator := newVyosTestGenerator(t)
	blocks, err := generator.GatewayRoutes(generator.Routers())
	if err != nil {
		t.Fatal(err)
	}
	if len(blocks) != 3 {
		t.Fatalf("blocks = %+v", blocks)
	}
	first, second, ours := blocks[0], blocks[1], blocks[2]
	if first.Name != "r-us-tst-5-gateway-1" || first.ManagedBy != "" || second.Name != "r-us-tst-5-gateway-2" || second.ManagedBy != "" || ours.Name != "r-us-tst-5-gateway-3" || ours.ManagedBy != "r-us-tst-5-gateway-3" {
		t.Fatalf("blocks = %+v", blocks)
	}
	if second.SitePrefix.String() != "2001:db8:173::/48" || second.Ipv4Block.String() != "198.51.100.32/27" || second.GatewayIpv4 != "198.51.100.33" || second.GatewayIpv6 != "2001:db8:173::1" {
		t.Fatalf("second block = %+v", second)
	}
	if len(second.Routers) != 1 || second.Routers[0].Name != "r-us-tst-5-2" || second.Routers[0].Ipv6Block.String() != "2001:db8:173:5200::/56" || second.Routers[0].WanIpv6.String() != "2001:db8:173::52" || second.Routers[0].LegacyIpv6.String() != "2001:db8:173:52::/64" || !reflect.DeepEqual(second.Routers[0].HostIpv4, []string{"198.51.100.42"}) {
		t.Fatalf("second block routers = %+v", second.Routers)
	}
	if first.SitePrefix.String() != "2001:db8:99::/48" || len(first.Routers) != 3 || first.Routers[0].Name != "r-us-tst-5-1" || first.Routers[1].Name != "r-us-tst-5-8" || first.Routers[2].Name != "r-us-tst-5-9" {
		t.Fatalf("first block = %+v", first)
	}
	if len(ours.Routers) != 1 || ours.Routers[0].Name != "r-us-tst-5-3" || ours.Routers[0].Ipv6Block.String() != "2001:db8:535:5300::/56" || ours.Routers[0].WanIpv6.String() != "2001:db8:535::53" {
		t.Fatalf("our block routers = %+v", ours.Routers)
	}
	if !reflect.DeepEqual(first.Routers[1].HostIpv4, []string{"203.0.113.84", "203.0.113.85"}) || !reflect.DeepEqual(first.Routers[2].HostIpv4, []string{"203.0.113.91", "203.0.113.92"}) {
		t.Fatalf("first block hosts = %+v", first.Routers)
	}
	if lan := first.Routers[0]; lan.Lan.String() != "192.168.51.0/24" || len(lan.HostIpv4) != 0 || lan.Ipv6Block.String() != "2001:db8:99:5100::/56" {
		t.Fatalf("lan router = %+v", lan)
	}
	text := vyosGatewayRoutesText(blocks)
	for _, want := range []string{
		"# r-us-tst-5-gateway-2: 2001:db8:173::/48 via 2001:db8:173::1 and 198.51.100.32/27 via 198.51.100.33 (tst 1gbps dedicated, the isp's)\n# the isp's: request these routes\n",
		"# r-us-tst-5-gateway-3: 2001:db8:535::/48 via 2001:db8:535::1 and 192.0.2.192/27 via 192.0.2.193 (tst2 10gbps, ours)\n# ours: warpctl vyos renders these routes into r-us-tst-5-gateway-3\n",
		"route 2001:db8:535:5300::/56 next-hop 2001:db8:535::53    # r-us-tst-5-3\n",
		"route 2001:db8:173:5200::/56 next-hop 2001:db8:173::52    # r-us-tst-5-2\n",
		"route 2001:db8:99:5100::/56 next-hop 2001:db8:99::51    # r-us-tst-5-1\n",
		"route 2001:db8:99:5800::/56 next-hop 2001:db8:99::58    # r-us-tst-5-8\n",
		"route 2001:db8:99:5900::/56 next-hop 2001:db8:99::59    # r-us-tst-5-9\n",
		"# IPv4: no route; 203.0.113.64/27 is on-link at 203.0.113.65 and each router proxy-arps for its hosts\n#   r-us-tst-5-1: lan 192.168.51.0/24 masqueraded, no public hosts\n#   r-us-tst-5-8: 203.0.113.84 203.0.113.85\n",
		"# IPv4: no route; 192.0.2.192/27 is on-link at the isp's 192.0.2.193 and r-us-tst-5-gateway-3 routes each router and its hosts to its block bridge, proxy-arping for them on the isp link\n#   r-us-tst-5-3 at 192.0.2.195: none attached\n",
		"#   no route 2001:db8:99:51::/64 next-hop 2001:db8:99::51    # r-us-tst-5-1\n",
		"#   no route 2001:db8:99:58::/64 next-hop 2001:db8:99::58    # r-us-tst-5-8\n",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("text lacks %q:\n%s", want, text)
		}
	}
	// the retire notes only for the isp's gateways
	if strings.Contains(strings.SplitN(text, "# r-us-tst-5-gateway-3:", 2)[1], "no route ") {
		t.Errorf("our gateway lists routes to retire:\n%s", text)
	}
	// one router only
	one, err := generator.GatewayRoutes([]string{"r-us-tst-5-9"})
	if err != nil || len(one) != 1 || len(one[0].Routers) != 1 || one[0].Routers[0].Name != "r-us-tst-5-9" {
		t.Fatalf("one = %+v, %v", one, err)
	}
	if _, err := generator.GatewayRoutes([]string{"nope"}); err == nil {
		t.Fatal("unknown router must be an error")
	}
}

func errorsAs(err error, target any) bool {
	switch target := target.(type) {
	case **vyos.ProtectedPathError:
		for err != nil {
			if protectedErr, ok := err.(*vyos.ProtectedPathError); ok {
				*target = protectedErr
				return true
			}
			unwrapper, ok := err.(interface{ Unwrap() error })
			if !ok {
				return false
			}
			err = unwrapper.Unwrap()
		}
	}
	return false
}
