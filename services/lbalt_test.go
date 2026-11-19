package services

import (
	"fmt"
	"math"
	"math/rand/v2"
	"reflect"
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// A synthetic edge in the shape of main's (server/LBALT.md §3.1). edge-a has
// two front interfaces, eth1 with the lb front settings a rollback needs, and
// eth2 with eth1's keepalive, which the route file holds one of per service,
// and a transparent eth3; connect is behind the fronts on udp 443 and 4053,
// public udp 53 is forwarded to 4053, and connect has main's five weighted
// blocks.
// edge-b is an lb host connect is not placed on. The slots are the lb_alt
// lines of edge-a eth1, edge-a eth2, edge-b eth1 and connect (lbAltYaml).
const lbAltServicesYaml = `
versions:
  - lb:
      ports: [80, 443]
      udp_stream_port_services:
        443: connect
        4053: connect
      udp_forward_ports:
        53: 4053
      interfaces:
        edge-a.example:
          eth1:
            docker_network: warpeth1
            ipv4: 198.51.100.1
            ipv6: "2001:db8:1::1"
            cores: 4
            concurrent_clients: 1000
            expected_connections_per_client: 8
            dns_weight: 10
            external_ports:
              7080: 80
            rate_limit:
              requests_per_minute: 450
              burst: 150
              net_connections: 50
            keepalive:
              keepalive: 16
%s
          eth2:
            docker_network: warpeth2
            keepalive:
              keepalive: 16
            ipv4: 198.51.100.2
%s
          eth3:
            transparent: true
            docker_network: warpeth3
            ipv4: 203.0.113.1
        edge-b.example:
          eth1:
            docker_network: warpeth1
            ipv4: 198.51.100.3
%s
    host_services:
      edge-a.example: [connect, api]
      edge-b.example: [api]
    services:
      connect:
%s
        ports: [80, 5080, 5090]
        udp_stream_ports: [443, 4053]
        blocks:
          - beta: 1
          - g1: 24
          - g2: 25
          - g3: 25
          - g4: 25
      api:
        ports: [80]
        blocks:
          - g1: 1
`

// connect's blocks in lbAltServicesYaml, for cases that replace them
const lbAltConnectBlocksYaml = `        blocks:
          - beta: 1
          - g1: 24
          - g2: 25
          - g3: 25
          - g4: 25
`

// The lb_alt values of lbAltServicesYaml's slots; "" leaves a setting out.
type lbAltSettings struct {
	edgeAEth1 string
	edgeAEth2 string
	edgeBEth1 string
	connect   string
}

func lbAltYaml(settings lbAltSettings) string {
	line := func(indent int, value string) string {
		if value == "" {
			return ""
		}
		return strings.Repeat(" ", indent) + "lb_alt: " + value
	}
	return fmt.Sprintf(
		lbAltServicesYaml,
		line(12, settings.edgeAEth1),
		line(12, settings.edgeAEth2),
		line(12, settings.edgeBEth1),
		line(8, settings.connect),
	)
}

// Inserts lines after the one line of servicesYaml that is anchor.
func lbAltInsertAfter(t *testing.T, servicesYaml string, anchor string, lines ...string) string {
	t.Helper()
	anchorLine := "\n" + anchor + "\n"
	if strings.Count(servicesYaml, anchorLine) != 1 {
		t.Fatalf("%q is not one line of the services yaml", anchor)
	}
	return strings.Replace(servicesYaml, anchorLine, anchorLine+strings.Join(lines, "\n")+"\n", 1)
}

// Replaces the one occurrence of old in servicesYaml.
func lbAltReplace(t *testing.T, servicesYaml string, old string, new string) string {
	t.Helper()
	if strings.Count(servicesYaml, old) != 1 {
		t.Fatalf("%q does not occur once in the services yaml", old)
	}
	return strings.Replace(servicesYaml, old, new, 1)
}

func loadLbAltVersion(t *testing.T, servicesYaml string) *ServicesConfigVersion {
	t.Helper()
	servicesConfig, err := loadInlineServicesConfig(t, servicesYaml)
	if err != nil {
		t.Fatal(err)
	}
	return servicesConfig.Latest()
}

// Parses the first version of a services document without the load
// validation, for accessor cases the loader refuses.
func parseLbAltVersion(t *testing.T, servicesYaml string) *ServicesConfigVersion {
	t.Helper()
	var servicesConfig ServicesConfig
	if err := yaml.Unmarshal([]byte(servicesYaml), &servicesConfig); err != nil {
		t.Fatal(err)
	}
	return servicesConfig.Versions[0]
}

// main's public ports (server/LBALT-IMPL.md §2.3)
var lbAltMainPublicPorts = map[string][]int{
	"tcp": {80, 443},
	"udp": {53, 443, 4053},
}

// D2, no override: connect's default reaches every front interface of the
// hosts connect is placed on, and no transparent interface and no interface
// of a host connect is not placed on.
func TestLbAltDefaultReachesTheFrontInterfacesOfPlacedHosts(t *testing.T) {
	version := loadLbAltVersion(t, lbAltYaml(lbAltSettings{connect: "true"}))

	if service, ok := LbAltService(version); !ok || service != "connect" {
		t.Fatalf("lb_alt service = %q, %t, want connect", service, ok)
	}
	if got, want := LbAltInterfaces(version), map[string][]string{"edge-a.example": {"eth1", "eth2"}}; !reflect.DeepEqual(got, want) {
		t.Fatalf("lb_alt interfaces = %v, want %v", got, want)
	}
	if IsLbAltInterface(version, "edge-a.example", "eth3") {
		t.Fatal("the default reached the transparent edge-a eth3")
	}
	if IsLbAltInterface(version, "edge-b.example", "eth1") {
		t.Fatal("the default reached edge-b, where connect is not placed")
	}
	if !IsLbAltHost(version, "edge-a.example") || IsLbAltHost(version, "edge-b.example") {
		t.Fatalf("lb_alt hosts: edge-a %t, edge-b %t, want true, false", IsLbAltHost(version, "edge-a.example"), IsLbAltHost(version, "edge-b.example"))
	}
	for _, interfaceName := range []string{"eth1", "eth2"} {
		if got := LbAltPublicPorts(version, "edge-a.example", interfaceName); !reflect.DeepEqual(got, lbAltMainPublicPorts) {
			t.Fatalf("edge-a %s public ports = %v, want %v", interfaceName, got, lbAltMainPublicPorts)
		}
	}
}

// D2, true under a disabled default: a declared false names connect as the
// lb_alt service without turning any interface on, but connect already binds
// every front interface of its hosts, so the blocks are ready before any
// interface switches. An interface override turns that one interface on, and
// leaves the hosts as they were.
func TestLbAltOverrideTurnsOneInterfaceOnUnderADisabledDefault(t *testing.T) {
	version := loadLbAltVersion(t, lbAltYaml(lbAltSettings{connect: "false"}))
	if service, ok := LbAltService(version); !ok || service != "connect" {
		t.Fatalf("lb_alt service = %q, %t, want connect", service, ok)
	}
	if got := LbAltInterfaces(version); len(got) != 0 {
		t.Fatalf("lb_alt interfaces = %v under a disabled default, want none", got)
	}
	if !IsLbAltHost(version, "edge-a.example") || IsLbAltHost(version, "edge-b.example") {
		t.Fatalf("lb_alt hosts under a disabled default: edge-a %t, edge-b %t, want true, false", IsLbAltHost(version, "edge-a.example"), IsLbAltHost(version, "edge-b.example"))
	}

	version = loadLbAltVersion(t, lbAltYaml(lbAltSettings{edgeAEth2: "true", connect: "false"}))
	if got, want := LbAltInterfaces(version), map[string][]string{"edge-a.example": {"eth2"}}; !reflect.DeepEqual(got, want) {
		t.Fatalf("lb_alt interfaces = %v, want %v", got, want)
	}
	if IsLbAltInterface(version, "edge-a.example", "eth1") {
		t.Fatal("edge-a eth1 is lb_alt with no override under a disabled default")
	}
	if !IsLbAltHost(version, "edge-a.example") {
		t.Fatal("edge-a is not an lb_alt host with its eth2 overridden to true")
	}
	if got := LbAltPublicPorts(version, "edge-a.example", "eth1"); len(got) != 0 {
		t.Fatalf("edge-a eth1 public ports = %v, want none", got)
	}
	if got := LbAltPublicPorts(version, "edge-a.example", "eth2"); !reflect.DeepEqual(got, lbAltMainPublicPorts) {
		t.Fatalf("edge-a eth2 public ports = %v, want %v", got, lbAltMainPublicPorts)
	}
}

// D2, true under an absent default: with no service declaring lb_alt there is
// no service to front the interface, so the override is refused.
func TestLoadServicesConfigRefusesALbAltOverrideWithNoLbAltService(t *testing.T) {
	_, err := loadInlineServicesConfig(t, lbAltYaml(lbAltSettings{edgeAEth2: "true"}))
	if err == nil {
		t.Fatal("an lb_alt override with no lb_alt service loaded")
	}
	if want := "edge-a.example eth2 sets lb_alt: true, but no service declares lb_alt"; !strings.Contains(err.Error(), want) {
		t.Fatalf("err = %v, want %q", err, want)
	}
}

// D2, false under an enabled default, the rollback switch: the interface
// leaves lb_alt, while the host stays an lb_alt host and connect keeps
// binding every front interface, so the rollback never changes connect's
// units.
func TestLbAltOverrideFalseRollsOneInterfaceBack(t *testing.T) {
	version := loadLbAltVersion(t, lbAltYaml(lbAltSettings{edgeAEth1: "false", connect: "true"}))
	if got, want := LbAltInterfaces(version), map[string][]string{"edge-a.example": {"eth2"}}; !reflect.DeepEqual(got, want) {
		t.Fatalf("lb_alt interfaces = %v, want %v", got, want)
	}
	if IsLbAltInterface(version, "edge-a.example", "eth1") {
		t.Fatal("edge-a eth1 is still lb_alt after its rollback")
	}
	if got := LbAltPublicPorts(version, "edge-a.example", "eth1"); len(got) != 0 {
		t.Fatalf("the rolled back edge-a eth1 has the public ports %v, want none", got)
	}
	if !IsLbAltHost(version, "edge-a.example") {
		t.Fatal("rolling one interface back took edge-a off lb_alt")
	}
	if got := LbInterfaceNames(version, "edge-a.example"); !slices.Equal(got, []string{"eth1", "eth2"}) {
		t.Fatalf("edge-a lb interfaces = %v, want [eth1 eth2]", got)
	}

	version = loadLbAltVersion(t, lbAltYaml(lbAltSettings{edgeAEth1: "false", edgeAEth2: "false", connect: "true"}))
	if got := LbAltInterfaces(version); len(got) != 0 {
		t.Fatalf("lb_alt interfaces = %v with every interface rolled back, want none", got)
	}
	if !IsLbAltHost(version, "edge-a.example") {
		t.Fatal("rolling every interface back took edge-a off lb_alt under an enabled default")
	}
}

// The rollback switch always loads: an interface overridden to false is not
// held to the lb_alt rules, even where they would refuse it.
func TestLoadServicesConfigAcceptsTheLbAltRollbackSwitch(t *testing.T) {
	tcpStreamLines := []string{"      tcp_stream_port_services:", "        8443: api"}

	servicesYaml := lbAltYaml(lbAltSettings{edgeAEth1: "false", edgeAEth2: "true", connect: "true"})
	_, err := loadInlineServicesConfig(t, lbAltInsertAfter(t, servicesYaml, "      ports: [80, 443]", tcpStreamLines...))
	if err == nil || !strings.Contains(err.Error(), "edge-a.example eth2 is lb_alt, but it maps the tcp stream port 8443") {
		t.Fatalf("err = %v, want the tcp stream refused on edge-a eth2", err)
	}

	servicesYaml = lbAltYaml(lbAltSettings{edgeAEth1: "false", edgeAEth2: "false", connect: "true"})
	version := loadLbAltVersion(t, lbAltInsertAfter(t, servicesYaml, "      ports: [80, 443]", tcpStreamLines...))
	if got := LbAltInterfaces(version); len(got) != 0 {
		t.Fatalf("lb_alt interfaces = %v, want none", got)
	}

	// an override to false with no lb_alt service is a no-op
	version = loadLbAltVersion(t, lbAltYaml(lbAltSettings{edgeAEth1: "false"}))
	if _, ok := LbAltService(version); ok {
		t.Fatal("an lb_alt service with no service declaring lb_alt")
	}
}

// The lb front settings stay allowed on an lb_alt interface (edge-a eth1 sets
// cores, concurrent_clients, expected_connections_per_client, dns_weight,
// external_ports, rate_limit and keepalive), since a rollback puts them back
// in use and the front and DNS read some of them.
func TestLoadServicesConfigAcceptsLbFrontSettingsOnAnLbAltInterface(t *testing.T) {
	version := loadLbAltVersion(t, lbAltYaml(lbAltSettings{edgeAEth1: "true", connect: "true"}))
	if !IsLbAltInterface(version, "edge-a.example", "eth1") {
		t.Fatal("edge-a eth1 is not lb_alt")
	}
	lbBlock := version.Lb.Interfaces["edge-a.example"]["eth1"]
	if lbBlock.Cores != 4 || lbBlock.GetDnsWeight() != 10 || lbBlock.GetRateLimit().NetConnections != 50 || lbBlock.Keepalive == nil || lbBlock.ExternalPorts[7080] != 80 {
		t.Fatalf("edge-a eth1 lost its lb front settings: %+v", lbBlock)
	}
	if lbBlock.Transparent {
		t.Fatal("edge-a eth1 is transparent")
	}
}

// Each lb_alt rule of D2 and D4 refuses its config.
func TestLoadServicesConfigRefusesInvalidLbAlt(t *testing.T) {
	enabledYaml := lbAltYaml(lbAltSettings{connect: "true"})
	withService := func(servicesYaml string, hostServices string, serviceLines ...string) string {
		servicesYaml = lbAltReplace(t, servicesYaml, "      edge-a.example: [connect, api]\n", "      edge-a.example: [connect, api, "+hostServices+"]\n")
		return servicesYaml + strings.Join(serviceLines, "\n") + "\n"
	}

	cases := []struct {
		name         string
		servicesYaml string
		want         string
	}{
		{
			name:         "two services declare lb_alt",
			servicesYaml: lbAltInsertAfter(t, enabledYaml, "      api:", "        lb_alt: false"),
			want:         `services "api" and "connect" both declare lb_alt`,
		},
		{
			name:         "a service other than connect declares lb_alt true",
			servicesYaml: lbAltInsertAfter(t, lbAltYaml(lbAltSettings{}), "      api:", "        lb_alt: true"),
			want:         `service "api" declares lb_alt, but only connect may front the lb interfaces`,
		},
		{
			name:         "a service other than connect declares lb_alt false",
			servicesYaml: lbAltInsertAfter(t, lbAltYaml(lbAltSettings{}), "      api:", "        lb_alt: false"),
			want:         `service "api" declares lb_alt, but only connect may front the lb interfaces`,
		},
		{
			name:         "an override to true with no lb_alt service",
			servicesYaml: lbAltYaml(lbAltSettings{edgeAEth1: "true"}),
			want:         "edge-a.example eth1 sets lb_alt: true, but no service declares lb_alt",
		},
		{
			name:         "an override to true on a host connect is not placed on, under an enabled default",
			servicesYaml: lbAltYaml(lbAltSettings{edgeBEth1: "true", connect: "true"}),
			want:         `edge-b.example eth1 is lb_alt, but the lb_alt service "connect" is not placed on edge-b.example`,
		},
		{
			name:         "an override to true on a host connect is not placed on, under a disabled default",
			servicesYaml: lbAltYaml(lbAltSettings{edgeBEth1: "true", connect: "false"}),
			want:         `edge-b.example eth1 is lb_alt, but the lb_alt service "connect" is not placed on edge-b.example`,
		},
		{
			name:         "connect has no blocks",
			servicesYaml: lbAltReplace(t, enabledYaml, lbAltConnectBlocksYaml, ""),
			want:         `edge-a.example eth1 is lb_alt, but the blocks of the lb_alt service "connect" cannot split its clients: no block has a positive weight`,
		},
		{
			name:         "connect has only zero weights",
			servicesYaml: lbAltReplace(t, enabledYaml, lbAltConnectBlocksYaml, "        blocks:\n          - beta: 0\n          - g1: 0\n"),
			want:         "cannot split its clients: no block has a positive weight",
		},
		{
			name:         "connect lists a block twice",
			servicesYaml: lbAltReplace(t, enabledYaml, lbAltConnectBlocksYaml, "        blocks:\n          - g1: 24\n          - g1: 25\n"),
			want:         `cannot split its clients: block "g1" is listed more than once`,
		},
		{
			name:         "connect declares a tcp stream port",
			servicesYaml: lbAltInsertAfter(t, enabledYaml, "        udp_stream_ports: [443, 4053]", "        tcp_stream_ports: [8443]"),
			want:         `edge-a.example eth1 is lb_alt, but the lb_alt service "connect" declares the tcp stream ports [8443]`,
		},
		{
			name:         "the lb maps a tcp stream",
			servicesYaml: lbAltInsertAfter(t, enabledYaml, "      ports: [80, 443]", "      tcp_stream_port_services:", "        8443: connect"),
			want:         `edge-a.example eth1 is lb_alt, but it maps the tcp stream port 8443 to "connect"`,
		},
		{
			name:         "an interface maps a tcp stream",
			servicesYaml: lbAltInsertAfter(t, enabledYaml, "            ipv4: 198.51.100.2", "            tcp_stream_port_services:", "              8443: api"),
			want:         `edge-a.example eth2 is lb_alt, but it maps the tcp stream port 8443 to "api"`,
		},
		{
			name:         "the lb maps a udp stream to another service",
			servicesYaml: lbAltInsertAfter(t, enabledYaml, "        4053: connect", "        5353: api"),
			want:         `edge-a.example eth1 is lb_alt, but it maps the udp stream port 5353 to "api"`,
		},
		{
			name:         "an interface maps a udp stream to another service",
			servicesYaml: lbAltInsertAfter(t, enabledYaml, "            ipv4: 198.51.100.2", "            udp_stream_port_services:", "              5353: api"),
			want:         `edge-a.example eth2 is lb_alt, but it maps the udp stream port 5353 to "api"`,
		},
		{
			name:         "the lb publishes a tcp port no connect socket serves",
			servicesYaml: lbAltReplace(t, enabledYaml, "      ports: [80, 443]\n", "      ports: [80, 443, 8080]\n"),
			want:         "edge-a.example eth1 is lb_alt, but it would publish the tcp port 8080, which no connect socket serves",
		},
		{
			name: "connect serves a udp stream port no connect socket serves",
			servicesYaml: lbAltReplace(t,
				lbAltInsertAfter(t, enabledYaml, "        4053: connect", "        5353: connect"),
				"        udp_stream_ports: [443, 4053]\n",
				"        udp_stream_ports: [443, 4053, 5353]\n",
			),
			want: "edge-a.example eth1 is lb_alt, but it would publish the udp port 5353, which no connect socket serves",
		},
		{
			name:         "connect lists the http port 443 under an enabled default",
			servicesYaml: lbAltReplace(t, enabledYaml, "        ports: [80, 5080, 5090]\n", "        ports: [80, 443, 5080, 5090]\n"),
			want:         `service "connect" lists the http port 443, which the tls socket of its lb_alt front takes; version 0 declares lb_alt for it`,
		},
		{
			name:         "connect lists the http port 443 under a declared-off default",
			servicesYaml: lbAltReplace(t, lbAltYaml(lbAltSettings{connect: "false"}), "        ports: [80, 5080, 5090]\n", "        ports: [80, 443, 5080, 5090]\n"),
			want:         `service "connect" lists the http port 443, which the tls socket of its lb_alt front takes; version 0 declares lb_alt for it`,
		},
		{
			// lb_alt is in effect nowhere, so the tcp stream ports of connect
			// are not refused as an lb_alt interface's are, but its tls port
			// block still takes 443
			name:         "connect lists the tcp stream port 443 under a declared-off default",
			servicesYaml: lbAltInsertAfter(t, lbAltYaml(lbAltSettings{connect: "false"}), "        udp_stream_ports: [443, 4053]", "        tcp_stream_ports: [443]"),
			want:         `service "connect" lists the tcp stream port 443, which the tls socket of its lb_alt front takes; version 0 declares lb_alt for it`,
		},
		{
			name: "a front interface named with a '-' on a host lb_alt is enabled on",
			servicesYaml: lbAltInsertAfter(t, enabledYaml, "            ipv4: 198.51.100.2",
				"          eth-4:",
				"            docker_network: warpeth4",
				"            ipv4: 198.51.100.4",
			),
			want: "edge-a.example eth-4: lb_alt is enabled on edge-a.example, whose lb interface names must hold no '-'",
		},
		{
			name: "a transparent interface named with a '-' on a host under a declared-off default",
			servicesYaml: lbAltInsertAfter(t, lbAltYaml(lbAltSettings{edgeAEth1: "true", connect: "false"}), "            ipv4: 198.51.100.2",
				"          eth-5:",
				"            transparent: true",
				"            docker_network: warpeth5",
				"            ipv4: 203.0.113.5",
			),
			want: "edge-a.example eth-5: lb_alt is enabled on edge-a.example, whose lb interface names must hold no '-'",
		},
		{
			name: "a service named lba",
			servicesYaml: withService(enabledYaml, "lba",
				"      lba:",
				"        ports: [80]",
				"        blocks:",
				"          - g1: 1",
			),
			want: `service "lba" is named like the lb_alt split chains`,
		},
		{
			name: "a service named LBT where no service declares lb_alt",
			servicesYaml: withService(lbAltYaml(lbAltSettings{}), "LBT",
				"      LBT:",
				"        ports: [80]",
				"        blocks:",
				"          - g1: 1",
			),
			want: `service "LBT" is named like the lb_alt split chains`,
		},
		{
			// iptablesChainName keeps a name of 10 characters, so its g1 block
			// chain would be connect g1's on eth1
			name: "a service named lba- and an interface",
			servicesYaml: withService(enabledYaml, "lba-eth1",
				"      lba-eth1:",
				"        ports: [80]",
				"        blocks:",
				"          - g1: 1",
			),
			want: `service "lba-eth1" is named like the lb_alt split chains`,
		},
		{
			name: "a service named LBT- and more",
			servicesYaml: withService(lbAltYaml(lbAltSettings{}), "LBT-x",
				"      LBT-x:",
				"        ports: [80]",
				"        blocks:",
				"          - g1: 1",
			),
			want: `service "LBT-x" is named like the lb_alt split chains`,
		},
		{
			name: "a front interface named with a '-' under a declared-off default",
			servicesYaml: lbAltInsertAfter(t, lbAltYaml(lbAltSettings{connect: "false"}), "            ipv4: 198.51.100.2",
				"          eth-4:",
				"            docker_network: warpeth4",
				"            ipv4: 198.51.100.4",
			),
			want: "edge-a.example eth-4: lb_alt is enabled on edge-a.example, whose lb interface names must hold no '-'",
		},
		{
			// WARP-TEST-LBA-<IFACE>-BETA is 29 characters for a 10-character
			// interface name, though the nginx lb chain fits
			name: "a front interface whose block chain names are over the iptables limit, under a declared-off default",
			servicesYaml: lbAltInsertAfter(t, lbAltYaml(lbAltSettings{connect: "false"}), "            ipv4: 198.51.100.2",
				"          eno12399np:",
				"            docker_network: warpeth4",
				"            ipv4: 198.51.100.4",
			),
			want: "edge-a.example eno12399np: lb_alt is enabled on edge-a.example, and block beta of \"connect\" would write the chain WARP-TEST-LBA-ENO12399NP-BETA there, over iptables' 28 characters",
		},
		{
			name: "a front interface whose block chain names are over the iptables limit, under an enabled default",
			servicesYaml: lbAltInsertAfter(t, enabledYaml, "            ipv4: 198.51.100.2",
				"          enp65s0f0np0:",
				"            docker_network: warpeth4",
				"            ipv4: 198.51.100.4",
			),
			want: "edge-a.example enp65s0f0np0: lb_alt is enabled on edge-a.example, and block beta of \"connect\" would write the chain WARP-TEST-LBA-ENP65S0F0NP0-BETA there",
		},
		{
			// edge-a's eth1 and eth2 share a keepalive, which eth2 changes;
			// api and connect set none of their own
			name: "front interfaces that give a service different keepalives, under a declared-off default",
			servicesYaml: lbAltReplace(t, lbAltYaml(lbAltSettings{connect: "false"}),
				"            keepalive:\n              keepalive: 16\n            ipv4: 198.51.100.2\n",
				"            keepalive:\n              keepalive: 32\n            ipv4: 198.51.100.2\n",
			),
			want: `edge-a.example: lb_alt is enabled on edge-a.example, and its lb interfaces eth1 and eth2 give service "api", which sets no keepalive of its own, different keepalives`,
		},
		{
			// eth2 without a keepalive takes the default
			name: "a front interface that sets a keepalive beside one that takes the default, under an enabled default",
			servicesYaml: lbAltReplace(t, enabledYaml,
				"            keepalive:\n              keepalive: 16\n            ipv4: 198.51.100.2\n",
				"            ipv4: 198.51.100.2\n",
			),
			want: `its lb interfaces eth1 and eth2 give service "api", which sets no keepalive of its own, different keepalives`,
		},
		{
			name: "another service claims a public udp port as an external udp port",
			servicesYaml: withService(enabledYaml, "whodis",
				"      whodis:",
				"        hosts: [edge-a.example]",
				"        exposed: false",
				"        external_udp_ports: [4053]",
				"        blocks:",
				"          - main: 1",
			),
			want: `edge-a.example eth1 is lb_alt and publishes the udp port 4053, which service "whodis" also claims on edge-a.example as an external udp port`,
		},
		{
			name: "another service claims a public udp port as an external udp forward port",
			servicesYaml: withService(enabledYaml, "whodis",
				"      whodis:",
				"        hosts: [edge-a.example]",
				"        exposed: false",
				"        external_udp_ports: [5353]",
				"        external_udp_forward_ports:",
				"          53: 5353",
				"        blocks:",
				"          - main: 1",
			),
			want: `edge-a.example eth1 is lb_alt and publishes the udp port 53, which service "whodis" also claims on edge-a.example as an external udp forward port`,
		},
	}
	for _, c := range cases {
		_, err := loadInlineServicesConfig(t, c.servicesYaml)
		if err == nil {
			t.Errorf("%s: loaded", c.name)
			continue
		}
		if !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err = %v, want %q", c.name, err, c.want)
		}
		if !strings.Contains(err.Error(), "version 0: ") {
			t.Errorf("%s: err = %v, want it wrapped with its version", c.name, err)
		}
	}
}

// A services document of two versions, latest first, from two documents of
// one version each.
func lbAltTwoVersions(t *testing.T, latestYaml string, olderYaml string) string {
	t.Helper()
	_, olderVersions, ok := strings.Cut(olderYaml, "versions:\n")
	if !ok {
		t.Fatal("the older document has no versions")
	}
	return latestYaml + olderVersions
}

// warpctl keeps one lb type for a service port across every version of the
// file, so once any version declares lb_alt, connect's tls port 443 is
// refused as an http or tcp stream port in every version, older or newer than
// the declaring one. Each of these files loaded before, and then failed every
// port allocation. A file that declares lb_alt in no version loads with
// either port.
func TestLoadServicesConfigRefusesTheLbAltTlsPortInEveryVersion(t *testing.T) {
	http443Yaml := func(settings lbAltSettings) string {
		return lbAltReplace(t, lbAltYaml(settings), "        ports: [80, 5080, 5090]\n", "        ports: [80, 443, 5080, 5090]\n")
	}
	tcpStream443Yaml := func(settings lbAltSettings) string {
		return lbAltInsertAfter(t, lbAltYaml(settings), "        udp_stream_ports: [443, 4053]", "        tcp_stream_ports: [443]")
	}
	cases := []struct {
		name         string
		servicesYaml string
		want         string
	}{
		{
			name:         "an older version lists the http port 443 and the latest declares lb_alt",
			servicesYaml: lbAltTwoVersions(t, lbAltYaml(lbAltSettings{connect: "true"}), http443Yaml(lbAltSettings{})),
			want:         `version 1: service "connect" lists the http port 443, which the tls socket of its lb_alt front takes; version 0 declares lb_alt for it`,
		},
		{
			name:         "an older version declares lb_alt and the latest lists the http port 443",
			servicesYaml: lbAltTwoVersions(t, http443Yaml(lbAltSettings{}), lbAltYaml(lbAltSettings{connect: "true"})),
			want:         `version 0: service "connect" lists the http port 443, which the tls socket of its lb_alt front takes; version 1 declares lb_alt for it`,
		},
		{
			name:         "an older version lists the tcp stream port 443 and the latest declares lb_alt",
			servicesYaml: lbAltTwoVersions(t, lbAltYaml(lbAltSettings{connect: "true"}), tcpStream443Yaml(lbAltSettings{})),
			want:         `version 1: service "connect" lists the tcp stream port 443, which the tls socket of its lb_alt front takes; version 0 declares lb_alt for it`,
		},
		{
			name:         "an older version declares lb_alt off and the latest lists the tcp stream port 443",
			servicesYaml: lbAltTwoVersions(t, tcpStream443Yaml(lbAltSettings{}), lbAltYaml(lbAltSettings{connect: "false"})),
			want:         `version 0: service "connect" lists the tcp stream port 443, which the tls socket of its lb_alt front takes; version 1 declares lb_alt for it`,
		},
	}
	for _, c := range cases {
		_, err := loadInlineServicesConfig(t, c.servicesYaml)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err = %v, want %q", c.name, err, c.want)
		}
	}

	for _, servicesYaml := range []string{
		lbAltTwoVersions(t, lbAltYaml(lbAltSettings{}), http443Yaml(lbAltSettings{})),
		lbAltTwoVersions(t, tcpStream443Yaml(lbAltSettings{}), lbAltYaml(lbAltSettings{})),
	} {
		if _, err := loadInlineServicesConfig(t, servicesYaml); err != nil {
			t.Errorf("a file that declares lb_alt in no version is refused: %v", err)
		}
	}
}

// The lb_alt rules hold only where lb_alt is in effect: the same claim of a
// public udp port loads while connect's default is off.
func TestLoadServicesConfigAcceptsAnExternalUdpClaimWhereLbAltIsOff(t *testing.T) {
	servicesYaml := lbAltReplace(t, lbAltYaml(lbAltSettings{connect: "false"}), "      edge-a.example: [connect, api]\n", "      edge-a.example: [connect, api, whodis]\n")
	servicesYaml += strings.Join([]string{
		"      whodis:",
		"        hosts: [edge-a.example]",
		"        exposed: false",
		"        external_udp_ports: [4053]",
		"        blocks:",
		"          - main: 1",
	}, "\n") + "\n"
	version := loadLbAltVersion(t, servicesYaml)
	if got := version.Services["whodis"].ExternalUdpPorts; !slices.Equal(got, []int{4053}) {
		t.Fatalf("whodis external udp ports = %v, want [4053]", got)
	}
}

// The '-' rule holds only on a host lb_alt is enabled on: an lb interface
// named with a '-' loads on a host connect is not placed on, and on a host
// where no service declares lb_alt.
func TestLoadServicesConfigAcceptsADashedInterfaceWhereLbAltIsNotEnabled(t *testing.T) {
	dashedEdgeB := lbAltInsertAfter(t, lbAltYaml(lbAltSettings{connect: "true"}), "            ipv4: 198.51.100.3",
		"          eth-4:",
		"            docker_network: warpeth4",
		"            ipv4: 198.51.100.4",
	)
	if version := loadLbAltVersion(t, dashedEdgeB); IsLbAltHost(version, "edge-b.example") {
		t.Fatal("edge-b is an lb_alt host, so this case checks nothing")
	}
	dashedEdgeA := lbAltInsertAfter(t, lbAltYaml(lbAltSettings{}), "            ipv4: 198.51.100.2",
		"          eth-4:",
		"            docker_network: warpeth4",
		"            ipv4: 198.51.100.4",
	)
	if version := loadLbAltVersion(t, dashedEdgeA); IsLbAltHost(version, "edge-a.example") {
		t.Fatal("edge-a is an lb_alt host, so this case checks nothing")
	}
}

// The chain name rules refuse only what warpctl would refuse: a front
// interface whose block chains are exactly at iptables' limit loads, as does
// a longer name on a transparent interface, which connect binds no chain on,
// and a service whose name starts with lba but not lba-, whose chains, such
// as WARP-TEST-LBAAS-G1, are not named like the split's.
func TestLoadServicesConfigAcceptsLbAltNamesWithinTheChainRules(t *testing.T) {
	// WARP-TEST-LBA-ENO1239NP-BETA, 28 characters
	atTheLimit := lbAltInsertAfter(t, lbAltYaml(lbAltSettings{connect: "false"}), "            ipv4: 198.51.100.2",
		"          eno1239np:",
		"            docker_network: warpeth4",
		"            ipv4: 198.51.100.4",
		"            keepalive:",
		"              keepalive: 16",
	)
	version := loadLbAltVersion(t, atTheLimit)
	if !IsLbAltHost(version, "edge-a.example") || !slices.Contains(LbInterfaceNames(version, "edge-a.example"), "eno1239np") {
		t.Fatal("edge-a's eno1239np is not a front interface of an lb_alt host, so this case checks nothing")
	}
	if chain := "WARP-TEST-LBA-ENO1239NP-BETA"; len(chain) != lbAltChainNameLimit {
		t.Fatalf("%s is %d characters, not the limit", chain, len(chain))
	}

	longTransparent := lbAltInsertAfter(t, lbAltYaml(lbAltSettings{connect: "true"}), "            ipv4: 203.0.113.1",
		"          enp65s0f0np0:",
		"            transparent: true",
		"            docker_network: warpeth5",
		"            ipv4: 203.0.113.5",
	)
	version = loadLbAltVersion(t, longTransparent)
	if !IsLbAltHost(version, "edge-a.example") || slices.Contains(LbInterfaceNames(version, "edge-a.example"), "enp65s0f0np0") {
		t.Fatal("edge-a's enp65s0f0np0 is not a transparent interface of an lb_alt host, so this case checks nothing")
	}

	servicesYaml := lbAltReplace(t, lbAltYaml(lbAltSettings{connect: "true"}), "      edge-a.example: [connect, api]\n", "      edge-a.example: [connect, api, lbaas]\n")
	servicesYaml += strings.Join([]string{
		"      lbaas:",
		"        ports: [80]",
		"        blocks:",
		"          - g1: 1",
	}, "\n") + "\n"
	if _, err := loadInlineServicesConfig(t, servicesYaml); err != nil {
		t.Fatalf("service lbaas is refused: %v", err)
	}
}

// The keepalive rule refuses only a host whose route file could not hold one
// keepalive per service: front interfaces that differ load when every service
// of the host with tcp port 80 sets its own keepalive, when they differ only
// in what nginx ignores without connections, and on a host where lb_alt is not
// enabled.
func TestLoadServicesConfigAcceptsLbAltKeepalivesTheRouteFileCanHold(t *testing.T) {
	eth2Keepalive := "            keepalive:\n              keepalive: 16\n            ipv4: 198.51.100.2\n"
	differing := func(servicesYaml string) string {
		return lbAltReplace(t, servicesYaml, eth2Keepalive, "            keepalive:\n              keepalive: 32\n            ipv4: 198.51.100.2\n")
	}

	ownKeepalives := differing(lbAltYaml(lbAltSettings{connect: "true"}))
	for _, service := range []string{"connect", "api"} {
		ownKeepalives = lbAltInsertAfter(t, ownKeepalives, "      "+service+":", "        keepalive:", "          keepalive: 8")
	}
	if _, err := loadInlineServicesConfig(t, ownKeepalives); err != nil {
		t.Fatalf("differing interface keepalives are refused where every service sets its own: %v", err)
	}

	noConnections := lbAltReplace(t, lbAltYaml(lbAltSettings{connect: "true"}), eth2Keepalive, "            keepalive:\n              keepalive: 0\n              keepalive_requests: 5\n            ipv4: 198.51.100.2\n")
	noConnections = lbAltReplace(t, noConnections,
		"              net_connections: 50\n            keepalive:\n              keepalive: 16\n",
		"              net_connections: 50\n            keepalive:\n              keepalive: 0\n",
	)
	if _, err := loadInlineServicesConfig(t, noConnections); err != nil {
		t.Fatalf("interface keepalives without connections are refused: %v", err)
	}

	if _, err := loadInlineServicesConfig(t, differing(lbAltYaml(lbAltSettings{}))); err != nil {
		t.Fatalf("differing interface keepalives are refused where lb_alt is not declared: %v", err)
	}
}

// The public port table (server/LBALT-IMPL.md §2.3): tcp 80 to the port-80
// handler, tcp 443 to tls and udp 443 to quic on service port 443, and udp
// 4053 and 53 to whodis. No other (protocol, port) has a connect socket.
func TestLbAltPublicPortTableIsTheContractMap(t *testing.T) {
	want := []LbAltPublicPort{
		{Protocol: "tcp", PublicPort: 80, ServicePort: 80},
		{Protocol: "tcp", PublicPort: 443, ServicePort: 443},
		{Protocol: "udp", PublicPort: 443, ServicePort: 443},
		{Protocol: "udp", PublicPort: 4053, ServicePort: 4053},
		{Protocol: "udp", PublicPort: 53, ServicePort: 4053},
	}
	if got := LbAltPublicPortTable(); !slices.Equal(got, want) {
		t.Fatalf("table = %v, want %v", got, want)
	}
	for _, row := range want {
		if servicePort, ok := LbAltPublicPortServicePort(row.Protocol, row.PublicPort); !ok || servicePort != row.ServicePort {
			t.Errorf("%s %d reaches service port %d (%t), want %d", row.Protocol, row.PublicPort, servicePort, ok, row.ServicePort)
		}
	}
	for _, refused := range []struct {
		protocol string
		port     int
	}{
		{protocol: "udp", port: 80},
		{protocol: "tcp", port: 53},
		{protocol: "tcp", port: 4053},
		{protocol: "tcp", port: 8080},
		{protocol: "udp", port: 5353},
		{protocol: "sctp", port: 443},
	} {
		if servicePort, ok := LbAltPublicPortServicePort(refused.protocol, refused.port); ok {
			t.Errorf("%s %d reaches service port %d", refused.protocol, refused.port, servicePort)
		}
	}

	// main's shape publishes exactly the table's public ports
	version := loadLbAltVersion(t, lbAltYaml(lbAltSettings{connect: "true"}))
	tablePorts := map[string][]int{}
	for _, row := range LbAltPublicPortTable() {
		tablePorts[row.Protocol] = append(tablePorts[row.Protocol], row.PublicPort)
	}
	for _, ports := range tablePorts {
		slices.Sort(ports)
	}
	if got := LbAltPublicPorts(version, "edge-a.example", "eth1"); !reflect.DeepEqual(got, tablePorts) {
		t.Fatalf("edge-a eth1 public ports = %v, want the table's %v", got, tablePorts)
	}
}

// The interfaces an nginx lb still fronts: every non-transparent lb interface
// lb_alt is not in effect on, by host. A host with none is left out.
func TestNginxLbInterfacesLeaveOutLbAltAndTransparentInterfaces(t *testing.T) {
	for _, c := range []struct {
		settings lbAltSettings
		want     map[string][]string
	}{
		{
			settings: lbAltSettings{},
			want:     map[string][]string{"edge-a.example": {"eth1", "eth2"}, "edge-b.example": {"eth1"}},
		},
		{
			settings: lbAltSettings{edgeAEth1: "true", connect: "false"},
			want:     map[string][]string{"edge-a.example": {"eth2"}, "edge-b.example": {"eth1"}},
		},
		{
			settings: lbAltSettings{connect: "true"},
			want:     map[string][]string{"edge-b.example": {"eth1"}},
		},
		{
			settings: lbAltSettings{edgeAEth1: "false", connect: "true"},
			want:     map[string][]string{"edge-a.example": {"eth1"}, "edge-b.example": {"eth1"}},
		},
	} {
		version := loadLbAltVersion(t, lbAltYaml(c.settings))
		if got := NginxLbInterfaces(version); !reflect.DeepEqual(got, c.want) {
			t.Errorf("%+v: nginx interfaces = %v, want %v", c.settings, got, c.want)
		}
	}
	if got := NginxLbInterfaces(nil); len(got) != 0 {
		t.Fatalf("a nil version has the nginx interfaces %v", got)
	}
}

// D2: lb_alt on a transparent interface is refused, true or false. The
// transparent rules refuse it first, as an lb front setting.
func TestLoadServicesConfigRefusesLbAltOnATransparentInterface(t *testing.T) {
	for _, value := range []string{"true", "false"} {
		servicesYaml := lbAltInsertAfter(t, lbAltYaml(lbAltSettings{connect: "true"}), "            transparent: true", "            lb_alt: "+value)
		_, err := loadInlineServicesConfig(t, servicesYaml)
		if err == nil {
			t.Errorf("lb_alt: %s on the transparent edge-a eth3 loaded", value)
			continue
		}
		if want := "edge-a.example eth3 is transparent, so no lb runs on it, but it sets the lb setting lb_alt"; !strings.Contains(err.Error(), want) {
			t.Errorf("lb_alt: %s: err = %v, want %q", value, err, want)
		}
	}
}

// validateLbAlt refuses lb_alt on a transparent interface on its own too, for
// a caller that runs it without the transparent rules.
func TestValidateLbAltRefusesATransparentOverride(t *testing.T) {
	for _, value := range []string{"true", "false"} {
		servicesYaml := lbAltInsertAfter(t, lbAltYaml(lbAltSettings{connect: "true"}), "            transparent: true", "            lb_alt: "+value)
		err := validateLbAlt(parseLbAltVersion(t, servicesYaml), "test")
		if err == nil {
			t.Errorf("lb_alt: %s on the transparent edge-a eth3 passed", value)
			continue
		}
		if want := "edge-a.example eth3 is transparent, so no lb runs on it, but it sets lb_alt"; err.Error() != want {
			t.Errorf("lb_alt: %s: err = %v, want %q", value, err, want)
		}
	}
	if err := validateLbAlt(parseLbAltVersion(t, lbAltYaml(lbAltSettings{connect: "true"})), "test"); err != nil {
		t.Fatalf("the plain fixture fails validateLbAlt: %v", err)
	}
	if err := validateLbAlt(nil, "test"); err != nil {
		t.Fatalf("a nil version fails validateLbAlt: %v", err)
	}
}

func TestServiceConfigIsLbAlt(t *testing.T) {
	enabled := true
	disabled := false
	cases := []struct {
		name          string
		serviceConfig *ServiceConfig
		want          bool
	}{
		{name: "nil", serviceConfig: nil, want: false},
		{name: "unset", serviceConfig: &ServiceConfig{}, want: false},
		{name: "false", serviceConfig: &ServiceConfig{LbAlt: &disabled}, want: false},
		{name: "true", serviceConfig: &ServiceConfig{LbAlt: &enabled}, want: true},
	}
	for _, c := range cases {
		if got := c.serviceConfig.IsLbAlt(); got != c.want {
			t.Errorf("%s: IsLbAlt = %t, want %t", c.name, got, c.want)
		}
	}
}

// The lb_alt service is the one service that declares lb_alt, whether its
// default is on or off, and there is none when two declare it.
func TestLbAltServiceNamesTheSingleDeclaringService(t *testing.T) {
	cases := []struct {
		name         string
		servicesYaml string
		wantService  string
		wantOk       bool
	}{
		{name: "none", servicesYaml: lbAltYaml(lbAltSettings{}), wantService: "", wantOk: false},
		{name: "enabled", servicesYaml: lbAltYaml(lbAltSettings{connect: "true"}), wantService: "connect", wantOk: true},
		{name: "disabled", servicesYaml: lbAltYaml(lbAltSettings{connect: "false"}), wantService: "connect", wantOk: true},
		{
			name:         "two",
			servicesYaml: lbAltInsertAfter(t, lbAltYaml(lbAltSettings{connect: "true"}), "      api:", "        lb_alt: false"),
			wantService:  "",
			wantOk:       false,
		},
		{
			name:         "a service with no settings",
			servicesYaml: lbAltYaml(lbAltSettings{connect: "true"}) + "      empty:\n",
			wantService:  "connect",
			wantOk:       true,
		},
	}
	for _, c := range cases {
		service, ok := LbAltService(parseLbAltVersion(t, c.servicesYaml))
		if service != c.wantService || ok != c.wantOk {
			t.Errorf("%s: lb_alt service = %q, %t, want %q, %t", c.name, service, ok, c.wantService, c.wantOk)
		}
	}
	if service, ok := LbAltService(nil); service != "" || ok {
		t.Errorf("nil version: lb_alt service = %q, %t, want none", service, ok)
	}
}

// server/LBALT-IMPL.md §2.2: an lb_alt host needs connect as the lb_alt
// service, so another service declaring lb_alt (which the loader refuses)
// makes no host an lb_alt host.
func TestIsLbAltHostNeedsConnect(t *testing.T) {
	servicesYaml := lbAltInsertAfter(t, lbAltYaml(lbAltSettings{}), "      api:", "        lb_alt: true")
	version := parseLbAltVersion(t, servicesYaml)
	if !IsLbAltInterface(version, "edge-a.example", "eth1") {
		t.Fatal("api's default did not reach edge-a eth1")
	}
	if IsLbAltHost(version, "edge-a.example") {
		t.Fatal("edge-a is an lb_alt host with api as the lb_alt service")
	}
}

// server/LBALT-IMPL.md §2.2: whether a host is an lb_alt host depends only on
// connect declaring lb_alt and being placed on the host with a front interface
// to bind, never on the default's value or on an override, so no switch
// changes connect's units. A host left with only a transparent interface has
// nothing for connect to bind.
func TestIsLbAltHostIgnoresTheSwitches(t *testing.T) {
	for _, settings := range []lbAltSettings{
		{connect: "false"},
		{connect: "true"},
		{edgeAEth1: "true", connect: "false"},
		{edgeAEth1: "true", edgeAEth2: "true", connect: "false"},
		{edgeAEth1: "false", connect: "true"},
		{edgeAEth1: "false", edgeAEth2: "false", connect: "true"},
		{edgeAEth1: "false", connect: "false"},
	} {
		version := loadLbAltVersion(t, lbAltYaml(settings))
		if !IsLbAltHost(version, "edge-a.example") || IsLbAltHost(version, "edge-b.example") {
			t.Errorf("%+v: lb_alt hosts edge-a %t, edge-b %t, want true, false", settings, IsLbAltHost(version, "edge-a.example"), IsLbAltHost(version, "edge-b.example"))
		}
	}
	if version := loadLbAltVersion(t, lbAltYaml(lbAltSettings{})); IsLbAltHost(version, "edge-a.example") {
		t.Error("edge-a is an lb_alt host with no service declaring lb_alt")
	}

	version := parseLbAltVersion(t, lbAltYaml(lbAltSettings{connect: "true"}))
	delete(version.Lb.Interfaces["edge-a.example"], "eth1")
	delete(version.Lb.Interfaces["edge-a.example"], "eth2")
	if IsLbAltHost(version, "edge-a.example") {
		t.Error("edge-a is an lb_alt host with only its transparent eth3")
	}
}

// Connect binds every front interface of an lb_alt host, lb_alt or not, so
// the list ignores the overrides and leaves out only transparent interfaces.
func TestLbInterfaceNamesListsEveryFrontInterface(t *testing.T) {
	for _, settings := range []lbAltSettings{
		{connect: "true"},
		{edgeAEth1: "false", connect: "true"},
		{edgeAEth2: "true", connect: "false"},
		{},
	} {
		version := loadLbAltVersion(t, lbAltYaml(settings))
		if got := LbInterfaceNames(version, "edge-a.example"); !slices.Equal(got, []string{"eth1", "eth2"}) {
			t.Errorf("%+v: edge-a lb interfaces = %v, want [eth1 eth2]", settings, got)
		}
		if got := LbInterfaceNames(version, "edge-b.example"); !slices.Equal(got, []string{"eth1"}) {
			t.Errorf("%+v: edge-b lb interfaces = %v, want [eth1]", settings, got)
		}
	}

	// an interface with no settings is a front interface
	version := parseLbAltVersion(t, lbAltInsertAfter(t, lbAltYaml(lbAltSettings{}), "        edge-b.example:", "          eth0:"))
	if version.Lb.Interfaces["edge-b.example"]["eth0"] != nil {
		t.Fatal("edge-b eth0 parsed with settings")
	}
	if got := LbInterfaceNames(version, "edge-b.example"); !slices.Equal(got, []string{"eth0", "eth1"}) {
		t.Fatalf("edge-b lb interfaces = %v, want [eth0 eth1]", got)
	}
}

// With no version, no lb, or an unknown host or interface, every accessor
// answers no lb_alt.
func TestLbAltAccessorsReadMissingConfigAsOff(t *testing.T) {
	version := loadLbAltVersion(t, lbAltYaml(lbAltSettings{connect: "true"}))
	noLbVersion := &ServicesConfigVersion{Services: version.Services}
	for _, c := range []struct {
		name          string
		version       *ServicesConfigVersion
		host          string
		interfaceName string
	}{
		{name: "nil version", version: nil, host: "edge-a.example", interfaceName: "eth1"},
		{name: "no lb", version: noLbVersion, host: "edge-a.example", interfaceName: "eth1"},
		{name: "unknown host", version: version, host: "edge-z.example", interfaceName: "eth1"},
		{name: "unknown interface", version: version, host: "edge-a.example", interfaceName: "eth9"},
	} {
		if IsLbAltInterface(c.version, c.host, c.interfaceName) {
			t.Errorf("%s: IsLbAltInterface", c.name)
		}
		if got := LbAltPublicPorts(c.version, c.host, c.interfaceName); got == nil || len(got) != 0 {
			t.Errorf("%s: public ports = %#v, want an empty map", c.name, got)
		}
		if c.interfaceName == "eth1" {
			if IsLbAltHost(c.version, c.host) {
				t.Errorf("%s: IsLbAltHost", c.name)
			}
			if got := LbInterfaceNames(c.version, c.host); got == nil || len(got) != 0 {
				t.Errorf("%s: lb interfaces = %#v, want an empty list", c.name, got)
			}
		}
	}
	for _, missingVersion := range []*ServicesConfigVersion{nil, noLbVersion} {
		if got := LbAltInterfaces(missingVersion); got == nil || len(got) != 0 {
			t.Errorf("lb_alt interfaces = %#v, want an empty map", got)
		}
	}
}

// The interface's entry for a port wins and the lb's entries fill the rest,
// as SetDefaultStreamPortServices merges them, into new maps that leave both
// inputs as they were.
func TestEffectivePortServicesMergesWithoutMutating(t *testing.T) {
	lb := &LbConfig{
		StreamPortServiceConfig: StreamPortServiceConfig{
			TcpStreamPortServices: map[int]string{8443: "grafana"},
			UdpStreamPortServices: map[int]string{443: "connect", 4053: "connect"},
		},
	}
	lbBlock := &LbBlock{
		StreamPortServiceConfig: StreamPortServiceConfig{
			UdpStreamPortServices: map[int]string{4053: "other", 5353: "api"},
		},
	}
	want := map[string]map[int]string{
		"tcp": {8443: "grafana"},
		"udp": {443: "connect", 4053: "other", 5353: "api"},
	}
	got := EffectivePortServices(lb, lbBlock)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("effective port services = %v, want %v", got, want)
	}
	if lbBlock.TcpStreamPortServices != nil || !reflect.DeepEqual(lbBlock.UdpStreamPortServices, map[int]string{4053: "other", 5353: "api"}) {
		t.Fatalf("the interface's port services changed to %v", lbBlock.AllPortServices())
	}
	got["udp"][443] = "changed"
	if lb.UdpStreamPortServices[443] != "connect" {
		t.Fatal("the result shares a map with the lb")
	}

	// the same answer as the in-place merge
	merged := StreamPortServiceConfig{
		UdpStreamPortServices: map[int]string{4053: "other", 5353: "api"},
	}
	merged.SetDefaultStreamPortServices(&lb.StreamPortServiceConfig)
	if !reflect.DeepEqual(merged.AllPortServices(), want) {
		t.Fatalf("SetDefaultStreamPortServices = %v, want %v", merged.AllPortServices(), want)
	}

	for _, c := range []struct {
		name    string
		lb      *LbConfig
		lbBlock *LbBlock
		want    map[string]map[int]string
	}{
		{name: "no lb", lb: nil, lbBlock: lbBlock, want: map[string]map[int]string{"tcp": {}, "udp": {4053: "other", 5353: "api"}}},
		{name: "no interface", lb: lb, lbBlock: nil, want: map[string]map[int]string{"tcp": {8443: "grafana"}, "udp": {443: "connect", 4053: "connect"}}},
		{name: "neither", lb: nil, lbBlock: nil, want: map[string]map[int]string{"tcp": {}, "udp": {}}},
	} {
		if got := EffectivePortServices(c.lb, c.lbBlock); !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: effective port services = %v, want %v", c.name, got, c.want)
		}
	}
}

// The public ports follow the stream port services in effect on each
// interface: an interface's own udp port for the lb_alt service is public
// there only, and a forward port is public only when its target maps to the
// lb_alt service. The lists are sorted and without repeats.
func TestLbAltPublicPortsFollowTheEffectivePortServices(t *testing.T) {
	// the loader refuses udp 8443, which no connect socket serves, so the
	// accessor reads the parsed version
	servicesYaml := lbAltInsertAfter(t, lbAltYaml(lbAltSettings{connect: "true"}), "            ipv4: 198.51.100.2", "            udp_stream_port_services:", "              8443: connect")
	version := parseLbAltVersion(t, servicesYaml)
	if got, want := LbAltPublicPorts(version, "edge-a.example", "eth2"), map[string][]int{"tcp": {80, 443}, "udp": {53, 443, 4053, 8443}}; !reflect.DeepEqual(got, want) {
		t.Fatalf("edge-a eth2 public ports = %v, want %v", got, want)
	}
	if got := LbAltPublicPorts(version, "edge-a.example", "eth1"); !reflect.DeepEqual(got, lbAltMainPublicPorts) {
		t.Fatalf("edge-a eth1 public ports = %v, want %v", got, lbAltMainPublicPorts)
	}
	if got := LbAltPublicPorts(version, "edge-a.example", "eth3"); len(got) != 0 {
		t.Fatalf("the transparent edge-a eth3 has the public ports %v, want none", got)
	}

	// a forward to another service's port, which the loader refuses, is not
	// public; the lb ports come sorted and without repeats
	servicesYaml = lbAltInsertAfter(t, lbAltYaml(lbAltSettings{connect: "true"}), "        4053: connect", "        5353: api")
	servicesYaml = lbAltInsertAfter(t, servicesYaml, "        53: 4053", "        5300: 5353")
	servicesYaml = lbAltReplace(t, servicesYaml, "      ports: [80, 443]\n", "      ports: [443, 80, \"80-81\"]\n")
	version = parseLbAltVersion(t, servicesYaml)
	if got, want := LbAltPublicPorts(version, "edge-a.example", "eth1"), map[string][]int{"tcp": {80, 81, 443}, "udp": {53, 443, 4053}}; !reflect.DeepEqual(got, want) {
		t.Fatalf("edge-a eth1 public ports = %v, want %v", got, want)
	}
}

// List order, with the blocks of one list entry sorted by name, as warpctl
// orders blocks.
func TestServiceBlockWeightsKeepListOrderAndSortEachEntry(t *testing.T) {
	serviceConfig := &ServiceConfig{
		Blocks: []map[string]int{
			{"g2": 25, "g1": 24},
			{"beta": 1},
			{"g4": 25, "g3": 25},
		},
	}
	want := []BlockWeight{
		{Block: "g1", Weight: 24},
		{Block: "g2", Weight: 25},
		{Block: "beta", Weight: 1},
		{Block: "g3", Weight: 25},
		{Block: "g4", Weight: 25},
	}
	if got := ServiceBlockWeights(serviceConfig); !slices.Equal(got, want) {
		t.Fatalf("block weights = %v, want %v", got, want)
	}

	version := loadLbAltVersion(t, lbAltYaml(lbAltSettings{connect: "true"}))
	want = []BlockWeight{
		{Block: "beta", Weight: 1},
		{Block: "g1", Weight: 24},
		{Block: "g2", Weight: 25},
		{Block: "g3", Weight: 25},
		{Block: "g4", Weight: 25},
	}
	if got := ServiceBlockWeights(version.Services["connect"]); !slices.Equal(got, want) {
		t.Fatalf("connect block weights = %v, want %v", got, want)
	}
	if got := ServiceBlockWeights(nil); got == nil || len(got) != 0 {
		t.Fatalf("nil service block weights = %#v, want an empty list", got)
	}
}

// The block of each bucket as runs of (block, count), in bucket order.
func lbAltBucketRuns(bucketBlocks []string) []BlockWeight {
	runs := []BlockWeight{}
	for _, block := range bucketBlocks {
		if 0 < len(runs) && runs[len(runs)-1].Block == block {
			runs[len(runs)-1].Weight += 1
		} else {
			runs = append(runs, BlockWeight{Block: block, Weight: 1})
		}
	}
	return runs
}

// main's connect weights over 100 buckets: one contiguous range per block, of
// exactly its weight, in list order.
func TestLbAltBucketBlocksSplitsMainWeightsExactly(t *testing.T) {
	blockWeights := []BlockWeight{
		{Block: "beta", Weight: 1},
		{Block: "g1", Weight: 24},
		{Block: "g2", Weight: 25},
		{Block: "g3", Weight: 25},
		{Block: "g4", Weight: 25},
	}
	bucketBlocks, err := LbAltBucketBlocks(blockWeights, LbAltBucketCount)
	if err != nil {
		t.Fatal(err)
	}
	if len(bucketBlocks) != 100 {
		t.Fatalf("%d buckets, want 100", len(bucketBlocks))
	}
	if got := lbAltBucketRuns(bucketBlocks); !slices.Equal(got, blockWeights) {
		t.Fatalf("bucket runs = %v, want %v", got, blockWeights)
	}
	if bucketBlocks[0] != "beta" || bucketBlocks[1] != "g1" || bucketBlocks[24] != "g1" || bucketBlocks[25] != "g2" || bucketBlocks[99] != "g4" {
		t.Fatalf("bucket blocks = %v", bucketBlocks)
	}
}

// Uneven and zero weights: the floor of each share, the leftover to the
// largest remainders with ties to the earlier block, at least one bucket for
// every positive weight taken from the block furthest over its share with
// ties to the later block, and none for a zero weight.
func TestLbAltBucketBlocksRoundsByLargestRemainder(t *testing.T) {
	cases := []struct {
		name         string
		blockWeights []BlockWeight
		buckets      int
		want         []BlockWeight
	}{
		{
			name:         "a tie goes to the earlier block",
			blockWeights: []BlockWeight{{Block: "a", Weight: 3}, {Block: "b", Weight: 3}, {Block: "c", Weight: 3}},
			buckets:      100,
			want:         []BlockWeight{{Block: "a", Weight: 34}, {Block: "b", Weight: 33}, {Block: "c", Weight: 33}},
		},
		{
			name:         "the largest remainder",
			blockWeights: []BlockWeight{{Block: "a", Weight: 1}, {Block: "b", Weight: 2}},
			buckets:      100,
			want:         []BlockWeight{{Block: "a", Weight: 33}, {Block: "b", Weight: 67}},
		},
		{
			name:         "weights that do not sum to the buckets",
			blockWeights: []BlockWeight{{Block: "beta", Weight: 1}, {Block: "g1", Weight: 24}, {Block: "g2", Weight: 25}, {Block: "g3", Weight: 25}, {Block: "g4", Weight: 25}, {Block: "g5", Weight: 25}},
			buckets:      100,
			want:         []BlockWeight{{Block: "beta", Weight: 1}, {Block: "g1", Weight: 19}, {Block: "g2", Weight: 20}, {Block: "g3", Weight: 20}, {Block: "g4", Weight: 20}, {Block: "g5", Weight: 20}},
		},
		{
			name:         "a small weight takes a bucket from the later of two blocks equally over",
			blockWeights: []BlockWeight{{Block: "beta", Weight: 1}, {Block: "g1", Weight: 1000}, {Block: "g2", Weight: 1000}},
			buckets:      10,
			want:         []BlockWeight{{Block: "beta", Weight: 1}, {Block: "g1", Weight: 5}, {Block: "g2", Weight: 4}},
		},
		{
			name:         "two small weights",
			blockWeights: []BlockWeight{{Block: "a", Weight: 1}, {Block: "b", Weight: 1}, {Block: "c", Weight: 98}},
			buckets:      10,
			want:         []BlockWeight{{Block: "a", Weight: 1}, {Block: "b", Weight: 1}, {Block: "c", Weight: 8}},
		},
		{
			name:         "as many positive weights as buckets",
			blockWeights: []BlockWeight{{Block: "a", Weight: 1}, {Block: "b", Weight: 1000}},
			buckets:      2,
			want:         []BlockWeight{{Block: "a", Weight: 1}, {Block: "b", Weight: 1}},
		},
		{
			name:         "zero weights get no bucket",
			blockWeights: []BlockWeight{{Block: "a", Weight: 0}, {Block: "b", Weight: 1}, {Block: "c", Weight: 0}, {Block: "d", Weight: 1}},
			buckets:      4,
			want:         []BlockWeight{{Block: "b", Weight: 2}, {Block: "d", Weight: 2}},
		},
	}
	for _, c := range cases {
		bucketBlocks, err := LbAltBucketBlocks(c.blockWeights, c.buckets)
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		if len(bucketBlocks) != c.buckets {
			t.Errorf("%s: %d buckets, want %d", c.name, len(bucketBlocks), c.buckets)
		}
		if got := lbAltBucketRuns(bucketBlocks); !slices.Equal(got, c.want) {
			t.Errorf("%s: bucket runs = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestLbAltBucketBlocksRefusesWeightsItCannotSplit(t *testing.T) {
	cases := []struct {
		name         string
		blockWeights []BlockWeight
		buckets      int
		want         string
	}{
		{name: "no blocks", blockWeights: nil, buckets: 100, want: "no block has a positive weight"},
		{name: "only zero weights", blockWeights: []BlockWeight{{Block: "a", Weight: 0}}, buckets: 100, want: "no block has a positive weight"},
		{
			name:         "more positive weights than buckets",
			blockWeights: []BlockWeight{{Block: "a", Weight: 1}, {Block: "b", Weight: 1}, {Block: "c", Weight: 1}},
			buckets:      2,
			want:         "more blocks have a positive weight (3) than there are buckets (2)",
		},
		{name: "no buckets", blockWeights: []BlockWeight{{Block: "a", Weight: 1}}, buckets: 0, want: "more blocks have a positive weight (1) than there are buckets (0)"},
		{name: "a negative weight", blockWeights: []BlockWeight{{Block: "a", Weight: 1}, {Block: "b", Weight: -1}}, buckets: 100, want: `block "b" has the negative weight -1`},
		{name: "a block listed twice", blockWeights: []BlockWeight{{Block: "a", Weight: 1}, {Block: "a", Weight: 2}}, buckets: 100, want: `block "a" is listed more than once`},
		{name: "a total that overflows", blockWeights: []BlockWeight{{Block: "a", Weight: math.MaxInt}, {Block: "b", Weight: 1}}, buckets: 100, want: `the block weights overflow at block "b"`},
		{name: "a share that overflows", blockWeights: []BlockWeight{{Block: "a", Weight: math.MaxInt / 10}}, buckets: 100, want: "too large to split into 100 buckets"},
	}
	for _, c := range cases {
		bucketBlocks, err := LbAltBucketBlocks(c.blockWeights, c.buckets)
		if err == nil {
			t.Errorf("%s: split into %v", c.name, bucketBlocks)
			continue
		}
		if !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err = %v, want %q", c.name, err, c.want)
		}
	}
}

// The split's invariants over generated weights: every bucket has a block,
// each block's buckets are one contiguous range in list order, a positive
// weight gets at least one bucket and a zero weight none, and when every
// share is at least one bucket, each count is its share rounded down or up.
// The generator has a fixed seed so a failure reproduces.
func TestLbAltBucketBlocksKeepsItsInvariants(t *testing.T) {
	random := rand.New(rand.NewPCG(0x4c42, 0x414c))
	for iteration := 0; iteration < 5000; iteration += 1 {
		blockWeights := []BlockWeight{}
		positiveCount := 0
		total := 0
		for i := range 1 + random.IntN(12) {
			weight := 0
			if random.IntN(4) != 0 {
				weight = 1 + random.IntN(60)
				positiveCount += 1
				total += weight
			}
			blockWeights = append(blockWeights, BlockWeight{Block: fmt.Sprintf("b%d", i), Weight: weight})
		}
		if positiveCount == 0 {
			continue
		}
		buckets := positiveCount + random.IntN(120)

		bucketBlocks, err := LbAltBucketBlocks(blockWeights, buckets)
		if err != nil {
			t.Fatalf("%v over %d: %v", blockWeights, buckets, err)
		}
		if len(bucketBlocks) != buckets {
			t.Fatalf("%v over %d: %d buckets", blockWeights, buckets, len(bucketBlocks))
		}
		runs := lbAltBucketRuns(bucketBlocks)
		everyShareIsABucket := true
		positiveWeights := []BlockWeight{}
		for _, blockWeight := range blockWeights {
			if 0 < blockWeight.Weight {
				positiveWeights = append(positiveWeights, blockWeight)
				everyShareIsABucket = everyShareIsABucket && total <= blockWeight.Weight*buckets
			}
		}
		if len(runs) != len(positiveWeights) {
			t.Fatalf("%v over %d: runs %v, want one per positive weight in order", blockWeights, buckets, runs)
		}
		for i, run := range runs {
			blockWeight := positiveWeights[i]
			if run.Block != blockWeight.Block {
				t.Fatalf("%v over %d: runs %v, want one per positive weight in order", blockWeights, buckets, runs)
			}
			// run.Weight is the bucket count, at least one by construction
			if everyShareIsABucket {
				deviation := run.Weight*total - blockWeight.Weight*buckets
				if deviation <= -total || total <= deviation {
					t.Fatalf("%v over %d: %s has %d buckets, not its share rounded", blockWeights, buckets, run.Block, run.Weight)
				}
			}
		}
	}
}
