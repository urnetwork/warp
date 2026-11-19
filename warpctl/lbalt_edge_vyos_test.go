package main

// Tests of the router firewall of lb_alt interfaces (VyosGenerator): the
// public port list on IPv4 and IPv6, the trailing numbering that keeps a
// switch from renumbering any rule before it, the plain lb interfaces left as
// they were, and the refusals.

import (
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/urnetwork/warp/services"
	"github.com/urnetwork/warp/vyos"
)

// The edge-3 interfaces of the vyos fixture (router r-us-tst-5-8) lb_alt is
// turned on for, each by its own override, and the other lb_alt settings of
// lbAltVyosServicesYaml.
type lbAltVyosInterfaces struct {
	eno1np0 bool
	eno2np1 bool
	// eno2np1 without its IPv6 address
	eno2np1Ipv4Only bool
	// connect's own default on, which turns lb_alt on for every front
	// interface of the hosts connect is placed on
	connectDefault bool
}

// Replaces the one occurrence of old in servicesYaml.
func lbAltEdgeReplace(t *testing.T, servicesYaml string, old string, new string) string {
	t.Helper()
	if strings.Count(servicesYaml, old) != 1 {
		t.Fatalf("%q does not occur once in the services fixture", old)
	}
	return strings.Replace(servicesYaml, old, new, 1)
}

// Replaces the one match of pattern in servicesYaml with replacement, which
// may refer to the match's groups ($1).
func lbAltEdgeReplacePattern(t *testing.T, servicesYaml string, pattern string, replacement string) string {
	t.Helper()
	compiled := regexp.MustCompile(pattern)
	if matches := compiled.FindAllStringIndex(servicesYaml, -1); len(matches) != 1 {
		t.Fatalf("%q matches %d times in the services fixture, want once", pattern, len(matches))
	}
	return compiled.ReplaceAllString(servicesYaml, replacement)
}

// The IPv6 address of an lb interface in a loaded services config. Tests read
// the fixture's IPv6 addresses rather than copy them: their interface ids have
// the EUI-64 form of a real network card's address, which no test source may
// repeat (TestLbAltEdgeSourcesHoldNoHiddenPrefixOrMacDerivedAddress).
func lbAltEdgeInterfaceIpv6(t *testing.T, servicesConfig *services.ServicesConfig, host string, interfaceName string) string {
	t.Helper()
	block := servicesConfig.Latest().Lb.Interfaces[host][interfaceName]
	if block == nil || block.Ipv6 == "" {
		t.Fatalf("%s %s has no IPv6 address in the fixture", host, interfaceName)
	}
	return block.Ipv6
}

// The vyos fixture (testdata/services-vyos.yml) with its latest version in
// main's lb_alt shape (server/LBALT.md §3.1): connect in the place of svc-c
// behind udp 443 and 4053, public udp 53 forwarded to 4053, no tcp streams,
// and connect the lb_alt service with its default off (lb_alt: false), so an
// interface turns lb_alt on with its own override, as the canary does (D2).
// The older version is left as it is.
func lbAltVyosServicesYaml(t *testing.T, servicesYaml string, interfaces lbAltVyosInterfaces) string {
	t.Helper()
	servicesYaml = lbAltEdgeReplace(t, servicesYaml,
		"        udp_stream_port_services:\n            443: svc-c\n            4053: svc-c\n            8053: svc-c\n        udp_forward_ports:\n            53: 4053\n        tcp_stream_port_services:\n            444: svc-c\n            1080: svc-c\n",
		"        udp_stream_port_services:\n            443: connect\n            4053: connect\n        udp_forward_ports:\n            53: 4053\n",
	)
	connectDefault := "false"
	if interfaces.connectDefault {
		connectDefault = "true"
	}
	servicesYaml = lbAltEdgeReplace(t, servicesYaml,
		"        svc-c:\n            websocket: true\n            ports:\n                - 80\n                - 5080+10\n            udp_stream_ports:\n                - 443\n                - 4053\n                - 8053\n            tcp_stream_ports:\n                - 444\n                - 1080\n",
		"        connect:\n            lb_alt: "+connectDefault+"\n            websocket: true\n            ports:\n                - 80\n                - 5080+10\n            udp_stream_ports:\n                - 443\n                - 4053\n",
	)
	if interfaces.eno1np0 {
		servicesYaml = lbAltEdgeReplace(t, servicesYaml,
			"                    router: r-us-tst-5-8\n                    router_interface: eth8\n",
			"                    router: r-us-tst-5-8\n                    router_interface: eth8\n                    lb_alt: true\n",
		)
	}
	if interfaces.eno2np1Ipv4Only {
		// eno2np1's IPv6 line, matched by the router port that follows it
		servicesYaml = lbAltEdgeReplacePattern(t, servicesYaml,
			`                    ipv6: "[^"\n]*"\n(                    router: r-us-tst-5-8\n                    router_interface: eth6\n)`,
			"${1}",
		)
	}
	if interfaces.eno2np1 {
		servicesYaml = lbAltEdgeReplace(t, servicesYaml,
			"                    router: r-us-tst-5-8\n                    router_interface: eth6\n",
			"                    router: r-us-tst-5-8\n                    router_interface: eth6\n                    lb_alt: true\n",
		)
	}
	return servicesYaml
}

func newLbAltVyosTestGenerator(t *testing.T, interfaces lbAltVyosInterfaces) *VyosGenerator {
	t.Helper()
	return newVyosTestGeneratorWith(t, func(servicesYaml string) string {
		return lbAltVyosServicesYaml(t, servicesYaml, interfaces)
	})
}

// the WAN_IN and WANv6_IN host rules of a router, numbered
func lbAltVyosHostRules(t *testing.T, generator *VyosGenerator, router string) (ipv4Rules []string, ipv6Rules []string) {
	t.Helper()
	config, err := generator.Generate(router)
	if err != nil {
		t.Fatal(err)
	}
	ipv4Rules = vyosRuleSummary(config.Root.Lookup("firewall", "name", "WAN_IN"))
	ipv6Rules = vyosRuleSummary(config.Root.Lookup("firewall", "ipv6-name", "WANv6_IN"))
	return ipv4Rules, ipv6Rules
}

// A dual-stack lb_alt interface (edge-3 eno1np0) opens exactly its public
// ports on both families: tcp 80 and 443, and udp 53, 443 and 4053. The rules
// a plain lb front also opens keep their place, and udp 4053, which a plain
// front keeps closed as the forward target, follows the router's other rules.
// The plain lb interface beside it (eno2np1) keeps its rules and numbers, and
// the router gets no destination nat of its own.
func TestVyosLbAltDualStackInterfaceGolden(t *testing.T) {
	generator := newLbAltVyosTestGenerator(t, lbAltVyosInterfaces{eno1np0: true})
	ipv4Rules, ipv6Rules := lbAltVyosHostRules(t, generator, "r-us-tst-5-8")
	wantIpv4 := []string{
		"100 udp 203.0.113.84:53 warp edge-3 eno1np0 lb 53 udp",
		"110 tcp 203.0.113.84:80 warp edge-3 eno1np0 lb 80 tcp",
		"120 tcp_udp 203.0.113.84:443 warp edge-3 eno1np0 lb 443",
		"130 udp 203.0.113.85:53 warp edge-3 eno2np1 lb 53 udp",
		"140 tcp 203.0.113.85:80 warp edge-3 eno2np1 lb 80 tcp",
		"150 tcp_udp 203.0.113.85:443 warp edge-3 eno2np1 lb 443",
		"160 udp 203.0.113.84:4053 warp edge-3 eno1np0 lb 4053 udp",
	}
	if !reflect.DeepEqual(ipv4Rules, wantIpv4) {
		t.Fatalf("WAN_IN rules =\n%s\nwant\n%s", strings.Join(ipv4Rules, "\n"), strings.Join(wantIpv4, "\n"))
	}
	eno1np0Ipv6 := lbAltEdgeInterfaceIpv6(t, generator.servicesConfig, "edge-3.example.com", "eno1np0")
	eno2np1Ipv6 := lbAltEdgeInterfaceIpv6(t, generator.servicesConfig, "edge-3.example.com", "eno2np1")
	wantIpv6 := []string{
		"100 udp " + eno1np0Ipv6 + ":53 warp edge-3 eno1np0 lb 53 udp",
		"110 tcp " + eno1np0Ipv6 + ":80 warp edge-3 eno1np0 lb 80 tcp",
		"120 tcp_udp " + eno1np0Ipv6 + ":443 warp edge-3 eno1np0 lb 443",
		"130 udp " + eno2np1Ipv6 + ":53 warp edge-3 eno2np1 lb 53 udp",
		"140 tcp " + eno2np1Ipv6 + ":80 warp edge-3 eno2np1 lb 80 tcp",
		"150 tcp_udp " + eno2np1Ipv6 + ":443 warp edge-3 eno2np1 lb 443",
		"160 udp " + eno1np0Ipv6 + ":4053 warp edge-3 eno1np0 lb 4053 udp",
	}
	if !reflect.DeepEqual(ipv6Rules, wantIpv6) {
		t.Fatalf("WANv6_IN rules =\n%s\nwant\n%s", strings.Join(ipv6Rules, "\n"), strings.Join(wantIpv6, "\n"))
	}

	config, err := generator.Generate("r-us-tst-5-8")
	if err != nil {
		t.Fatal(err)
	}
	// warp's host dnat serves the public ports: the router rewrites nothing
	if got := config.Root.Lookup("service", "nat").ContainerKeys(); !reflect.DeepEqual(got, []vyos.Key{{Name: "rule", Tag: "5000"}, {Name: "rule", Tag: "5001"}}) {
		t.Fatalf("nat rules = %v", got)
	}
	// the rendering is the device format, and migrates to itself with no
	// commands
	parsed, err := vyos.Parse(config.String())
	if err != nil {
		t.Fatal(err)
	}
	migration, err := vyos.Migrate(parsed.Root, config.Root, vyos.MigrateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !migration.Empty() {
		t.Fatalf("self migration has %d commands", len(migration.Commands()))
	}
}

// An IPv4-only lb_alt interface (edge-3 eno2np1 with no IPv6 address) opens
// its public ports on IPv4 only, and the IPv6 chain carries only the plain lb
// interface beside it, unchanged.
func TestVyosLbAltIpv4OnlyInterfaceGolden(t *testing.T) {
	generator := newLbAltVyosTestGenerator(t, lbAltVyosInterfaces{eno2np1: true, eno2np1Ipv4Only: true})
	ipv4Rules, ipv6Rules := lbAltVyosHostRules(t, generator, "r-us-tst-5-8")
	wantIpv4 := []string{
		"100 udp 203.0.113.84:53 warp edge-3 eno1np0 lb 53 udp",
		"110 tcp 203.0.113.84:80 warp edge-3 eno1np0 lb 80 tcp",
		"120 tcp_udp 203.0.113.84:443 warp edge-3 eno1np0 lb 443",
		"130 udp 203.0.113.85:53 warp edge-3 eno2np1 lb 53 udp",
		"140 tcp 203.0.113.85:80 warp edge-3 eno2np1 lb 80 tcp",
		"150 tcp_udp 203.0.113.85:443 warp edge-3 eno2np1 lb 443",
		"160 udp 203.0.113.85:4053 warp edge-3 eno2np1 lb 4053 udp",
	}
	if !reflect.DeepEqual(ipv4Rules, wantIpv4) {
		t.Fatalf("WAN_IN rules =\n%s\nwant\n%s", strings.Join(ipv4Rules, "\n"), strings.Join(wantIpv4, "\n"))
	}
	if block := generator.servicesConfig.Latest().Lb.Interfaces["edge-3.example.com"]["eno2np1"]; block == nil || block.Ipv6 != "" {
		t.Fatalf("eno2np1 = %+v, want it IPv4 only", block)
	}
	eno1np0Ipv6 := lbAltEdgeInterfaceIpv6(t, generator.servicesConfig, "edge-3.example.com", "eno1np0")
	wantIpv6 := []string{
		"100 udp " + eno1np0Ipv6 + ":53 warp edge-3 eno1np0 lb 53 udp",
		"110 tcp " + eno1np0Ipv6 + ":80 warp edge-3 eno1np0 lb 80 tcp",
		"120 tcp_udp " + eno1np0Ipv6 + ":443 warp edge-3 eno1np0 lb 443",
	}
	if !reflect.DeepEqual(ipv6Rules, wantIpv6) {
		t.Fatalf("WANv6_IN rules =\n%s\nwant\n%s", strings.Join(ipv6Rules, "\n"), strings.Join(wantIpv6, "\n"))
	}
}

// The renumbering diff of a switch. Turning lb_alt on for an interface only
// appends its trailing rules (udp 4053, one per family it has) after the
// router's last rule: the migration from the plain lb rendering sets those
// rules and deletes nothing, so no existing rule is renumbered. The only
// renumbering is among trailing rules: switching an earlier interface after a
// later one moves the later one's trailing rule up one stride (rule 160 takes
// the earlier interface's rule, and 170 is new). Routers with no lb_alt
// interface render exactly as before.
func TestVyosLbAltSwitchOnlyAppendsRules(t *testing.T) {
	renderAll := func(interfaces lbAltVyosInterfaces) map[string]*vyos.Config {
		t.Helper()
		configs, err := newLbAltVyosTestGenerator(t, interfaces).GenerateAll()
		if err != nil {
			t.Fatal(err)
		}
		return configs
	}
	// the distinct `<chain> <rule>` a migration deletes under and sets under,
	// in command order
	migrationRules := func(from *vyos.Config, to *vyos.Config) (deletedRules []string, setRules []string) {
		t.Helper()
		migration, err := vyos.Migrate(from.Root, to.Root, vyos.MigrateOptions{})
		if err != nil {
			t.Fatal(err)
		}
		distinct := func(commands []vyos.Command) []string {
			rules := []string{}
			for _, command := range commands {
				if len(command.Path) < 5 {
					t.Fatalf("the switch changes more than host rules: %s", command)
				}
				rule := strings.Join(command.Path[:5], " ")
				if len(rules) == 0 || rules[len(rules)-1] != rule {
					rules = append(rules, rule)
				}
			}
			return rules
		}
		return distinct(migration.Deletes), distinct(migration.Sets)
	}
	fixture := newLbAltVyosTestGenerator(t, lbAltVyosInterfaces{}).servicesConfig
	eno1np0Ipv6 := lbAltEdgeInterfaceIpv6(t, fixture, "edge-3.example.com", "eno1np0")
	eno2np1Ipv6 := lbAltEdgeInterfaceIpv6(t, fixture, "edge-3.example.com", "eno2np1")

	plain := renderAll(lbAltVyosInterfaces{})
	eno1np0 := renderAll(lbAltVyosInterfaces{eno1np0: true})
	eno2np1 := renderAll(lbAltVyosInterfaces{eno2np1: true})
	both := renderAll(lbAltVyosInterfaces{eno1np0: true, eno2np1: true})

	for _, c := range []struct {
		from             map[string]*vyos.Config
		to               map[string]*vyos.Config
		wantDeletedRules []string
		wantSetRules     []string
	}{
		{
			from:             plain,
			to:               eno1np0,
			wantDeletedRules: []string{},
			wantSetRules:     []string{"firewall ipv6-name WANv6_IN rule 160", "firewall name WAN_IN rule 160"},
		},
		{
			from:             plain,
			to:               eno2np1,
			wantDeletedRules: []string{},
			wantSetRules:     []string{"firewall ipv6-name WANv6_IN rule 160", "firewall name WAN_IN rule 160"},
		},
		{
			// switching back is the same diff the other way
			from:             eno1np0,
			to:               plain,
			wantDeletedRules: []string{"firewall ipv6-name WANv6_IN rule 160", "firewall name WAN_IN rule 160"},
			wantSetRules:     []string{},
		},
		{
			from:             eno2np1,
			to:               both,
			wantDeletedRules: []string{"firewall ipv6-name WANv6_IN rule 160", "firewall name WAN_IN rule 160"},
			wantSetRules:     []string{"firewall ipv6-name WANv6_IN rule 160", "firewall ipv6-name WANv6_IN rule 170", "firewall name WAN_IN rule 160", "firewall name WAN_IN rule 170"},
		},
	} {
		deletedRules, setRules := migrationRules(c.from["r-us-tst-5-8"], c.to["r-us-tst-5-8"])
		if !reflect.DeepEqual(deletedRules, c.wantDeletedRules) || !reflect.DeepEqual(setRules, c.wantSetRules) {
			t.Errorf("the switch deletes under %v and sets %v, want %v and %v", deletedRules, setRules, c.wantDeletedRules, c.wantSetRules)
		}
		for router, config := range c.from {
			if router == "r-us-tst-5-8" {
				continue
			}
			if config.String() != c.to[router].String() {
				t.Errorf("router %s changed though it fronts no lb_alt interface", router)
			}
		}
	}

	// the rules the plain rendering has keep their numbers and contents, and
	// the switch adds rule 160 on each family
	plainIpv4 := vyosRuleSummary(plain["r-us-tst-5-8"].Root.Lookup("firewall", "name", "WAN_IN"))
	plainIpv6 := vyosRuleSummary(plain["r-us-tst-5-8"].Root.Lookup("firewall", "ipv6-name", "WANv6_IN"))
	for _, c := range []struct {
		configs  map[string]*vyos.Config
		wantIpv4 []string
		wantIpv6 []string
	}{
		{
			configs:  eno1np0,
			wantIpv4: []string{"160 udp 203.0.113.84:4053 warp edge-3 eno1np0 lb 4053 udp"},
			wantIpv6: []string{"160 udp " + eno1np0Ipv6 + ":4053 warp edge-3 eno1np0 lb 4053 udp"},
		},
		{
			configs:  eno2np1,
			wantIpv4: []string{"160 udp 203.0.113.85:4053 warp edge-3 eno2np1 lb 4053 udp"},
			wantIpv6: []string{"160 udp " + eno2np1Ipv6 + ":4053 warp edge-3 eno2np1 lb 4053 udp"},
		},
		{
			// eno2np1's trailing rule moves from 160 to 170: the one
			// renumbering of switching eno1np0 after it
			configs: both,
			wantIpv4: []string{
				"160 udp 203.0.113.84:4053 warp edge-3 eno1np0 lb 4053 udp",
				"170 udp 203.0.113.85:4053 warp edge-3 eno2np1 lb 4053 udp",
			},
			wantIpv6: []string{
				"160 udp " + eno1np0Ipv6 + ":4053 warp edge-3 eno1np0 lb 4053 udp",
				"170 udp " + eno2np1Ipv6 + ":4053 warp edge-3 eno2np1 lb 4053 udp",
			},
		},
	} {
		ipv4Rules := vyosRuleSummary(c.configs["r-us-tst-5-8"].Root.Lookup("firewall", "name", "WAN_IN"))
		ipv6Rules := vyosRuleSummary(c.configs["r-us-tst-5-8"].Root.Lookup("firewall", "ipv6-name", "WANv6_IN"))
		if want := append(append([]string{}, plainIpv4...), c.wantIpv4...); !reflect.DeepEqual(ipv4Rules, want) {
			t.Errorf("WAN_IN rules =\n%s\nwant\n%s", strings.Join(ipv4Rules, "\n"), strings.Join(want, "\n"))
		}
		if want := append(append([]string{}, plainIpv6...), c.wantIpv6...); !reflect.DeepEqual(ipv6Rules, want) {
			t.Errorf("WANv6_IN rules =\n%s\nwant\n%s", strings.Join(ipv6Rules, "\n"), strings.Join(want, "\n"))
		}
	}
	// the plain rendering is the plain lb contract: 4053 stays closed
	for _, rule := range append(append([]string{}, plainIpv4...), plainIpv6...) {
		if strings.Contains(rule, ":4053 ") {
			t.Errorf("a plain lb interface opens its forward target: %s", rule)
		}
	}
}

// An lb_alt interface opens its public ports and nothing else: an lb-level
// stream port, which names no service and which a plain lb front opens, stays
// closed there, while the plain lb interface beside it keeps it. Dropping
// such a rule is the one way switching an interface renumbers the rules of
// the attachments after it.
func TestVyosLbAltOpensOnlyItsPublicPorts(t *testing.T) {
	generator := newVyosTestGeneratorWith(t, func(servicesYaml string) string {
		servicesYaml = lbAltVyosServicesYaml(t, servicesYaml, lbAltVyosInterfaces{eno1np0: true})
		return lbAltEdgeReplace(t, servicesYaml,
			"        ports:\n            - 80\n            - 443\n        udp_stream_port_services:\n            443: connect\n",
			"        ports:\n            - 80\n            - 443\n        tcp_stream_ports:\n            - 444\n        udp_stream_port_services:\n            443: connect\n",
		)
	})
	ipv4Rules, ipv6Rules := lbAltVyosHostRules(t, generator, "r-us-tst-5-8")
	wantIpv4 := []string{
		"100 udp 203.0.113.84:53 warp edge-3 eno1np0 lb 53 udp",
		"110 tcp 203.0.113.84:80 warp edge-3 eno1np0 lb 80 tcp",
		"120 tcp_udp 203.0.113.84:443 warp edge-3 eno1np0 lb 443",
		"130 udp 203.0.113.85:53 warp edge-3 eno2np1 lb 53 udp",
		"140 tcp 203.0.113.85:80 warp edge-3 eno2np1 lb 80 tcp",
		"150 tcp_udp 203.0.113.85:443 warp edge-3 eno2np1 lb 443",
		"160 tcp 203.0.113.85:444 warp edge-3 eno2np1 lb 444 tcp",
		"170 udp 203.0.113.84:4053 warp edge-3 eno1np0 lb 4053 udp",
	}
	if !reflect.DeepEqual(ipv4Rules, wantIpv4) {
		t.Fatalf("WAN_IN rules =\n%s\nwant\n%s", strings.Join(ipv4Rules, "\n"), strings.Join(wantIpv4, "\n"))
	}
	for _, rule := range ipv6Rules {
		if strings.Contains(rule, ":444 warp edge-3 eno1np0") {
			t.Fatalf("the lb_alt interface opens the lb stream port on IPv6: %s", rule)
		}
	}
}

// An lb_alt interface whose public port list holds a port no front socket
// serves (a wider lb `ports` list) fails generation instead of opening a port
// nothing answers.
func TestVyosLbAltRefusesAPortWithoutAFrontSocket(t *testing.T) {
	generator := newVyosTestGeneratorWith(t, func(servicesYaml string) string {
		servicesYaml = lbAltVyosServicesYaml(t, servicesYaml, lbAltVyosInterfaces{eno1np0: true})
		// the latest version's lb ports, which its connect stream services follow
		return lbAltEdgeReplace(t, servicesYaml,
			"        ports:\n            - 80\n            - 443\n        udp_stream_port_services:\n            443: connect\n",
			"        ports:\n            - 80\n            - 443\n            - 8443\n        udp_stream_port_services:\n            443: connect\n",
		)
	})
	if _, err := generator.Generate("r-us-tst-5-8"); err == nil || !strings.Contains(err.Error(), "edge-3.example.com eno1np0: lb_alt public tcp port 8443 has no front socket") {
		t.Fatalf("err = %v, want the tcp 8443 refusal", err)
	}
	// a router that fronts no lb_alt interface still renders
	if _, err := generator.Generate("r-us-tst-5-9"); err != nil {
		t.Fatal(err)
	}
}

// A router rewrite of udp 4053 on an lb_alt interface would capture whodis,
// which the interface serves there though a plain lb front would not, so it
// is refused like any rewrite of a served port.
func TestVyosLbAltRefusesARouterRewriteOfItsWhodisPort(t *testing.T) {
	rewrite := func(interfaces lbAltVyosInterfaces) error {
		generator := newVyosTestGeneratorWith(t, func(servicesYaml string) string {
			servicesYaml = lbAltVyosServicesYaml(t, servicesYaml, interfaces)
			return lbAltEdgeReplace(t, servicesYaml,
				"                    router: r-us-tst-5-8\n                    router_interface: eth8\n",
				"                    router: r-us-tst-5-8\n                    router_interface: eth8\n                    router_udp_forward_ports:\n                        4053: 14053\n",
			)
		})
		_, err := generator.Generate("r-us-tst-5-8")
		return err
	}
	// on the plain lb interface 4053 is closed, so the rewrite is allowed
	if err := rewrite(lbAltVyosInterfaces{}); err != nil {
		t.Fatalf("plain lb interface: %v", err)
	}
	if err := rewrite(lbAltVyosInterfaces{eno1np0: true}); err == nil || !strings.Contains(err.Error(), "udp port 4053 is both served and rewritten") {
		t.Fatalf("err = %v, want the rewrite refused", err)
	}
}
