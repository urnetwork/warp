package services

import (
	"strings"
	"testing"
)

const routerFixtureHead = `domain: example.com
domains:
    example.com: route53
routers:
    r-us-tst-5-8:
        management_ipv4: 172.28.208.161
        wan_interface: eth1
        wan_ipv4: 203.0.113.81/27
        wan_gateway_ipv4: 203.0.113.65
        wan_ipv6_prefix: 2001:db8:99::/48
        wan_gateway_ipv6: 2001:db8:99::1
        lan_interfaces: [eth3, eth8]
        bridge_interfaces: [eth0, eth2]
        edgeos_release: v3.0.1
        edgeos_config_version: "firewall@5"
        login:
            ubnt:
                encrypted_password: "$5$x$y"
                public_keys:
                    fleet:
                        type: ssh-ed25519
                        key: AAAA
`

const routerFixtureVersions = `versions:
-   external_ports: 7000-7200
    internal_ports: 7201-7442
    routing_tables: 100-120
    parallel_block_count: 30
    services_docker_network: testservices
    lb:
        ports:
            - 80
        interfaces:
            edge-3.example.com:
                eno1np0:
                    docker_network: warpeno1np0
                    ipv4: 203.0.113.84
                    ipv6: "2001:db8:99:5880:e643:4bff:fe94:e380"
                    router: r-us-tst-5-8
                    router_interface: eth8
                    router_tcp_forward_ports:
                        8022: 22
            fireside.example.com:
                eno1np0:
                    transparent: true
                    docker_network: warpeno1np0
                    ipv4: 203.0.113.92
                    ipv6: "2001:db8:99:5830:3a05:25ff:fe32:e5ab"
                    router: r-us-tst-5-8
                    router_interface: eth3
    host_services:
        fireside.example.com:
            - alt
            - proxy
    services:
        web:
            ports:
                - 80
            blocks:
                - g1: 1
        proxy:
            cap_net_admin: true
            hosts:
                - fireside.example.com
            ports:
                - 80
                - 8080
            public_ports:
                8080: socks
            blocks:
                - g1: 1
        alt:
            exposed: false
            hosts:
                - fireside.example.com
            ports:
                - 80
            external_udp_ports:
                - 443
                - 4053
            external_udp_forward_ports:
                53: 4053
            blocks:
                - g1: 1
`

func TestLoadServicesConfigAcceptsRouters(t *testing.T) {
	servicesConfig, err := loadInlineServicesConfig(t, routerFixtureHead+routerFixtureVersions)
	if err != nil {
		t.Fatal(err)
	}
	if got := servicesConfig.RouterNames(); len(got) != 1 || got[0] != "r-us-tst-5-8" {
		t.Fatalf("routers = %v", got)
	}
	router := servicesConfig.Routers["r-us-tst-5-8"]
	if got := router.GetNameServers(); len(got) != 3 || got[2] != "2606:4700:4700::1111" {
		t.Fatalf("default name servers = %v", got)
	}
	if got := router.GetManagementVpnConfigFile(); got != "/config/by-pre.ovpn" {
		t.Fatalf("default vpn profile = %s", got)
	}
	if got := router.Login["ubnt"].GetLevel(); got != "admin" {
		t.Fatalf("default level = %s", got)
	}
	lbBlock := servicesConfig.Latest().Lb.Interfaces["edge-3.example.com"]["eno1np0"]
	if lbBlock.Router != "r-us-tst-5-8" || lbBlock.RouterInterface != "eth8" || lbBlock.Ipv4 != "203.0.113.84" {
		t.Fatalf("attachment = %+v", lbBlock)
	}
	if got := servicesConfig.Latest().Services["proxy"].PublicPorts[8080]; got != "socks" {
		t.Fatalf("public port name = %q", got)
	}
}

func TestLoadServicesConfigRejectsBadRouters(t *testing.T) {
	cases := map[string]struct {
		mutate func(string) string
		want   string
	}{
		"multi digit id": {
			func(s string) string { return strings.ReplaceAll(s, "r-us-tst-5-8", "r-us-tst-5-10") },
			"hostname convention",
		},
		"duplicate management address": {
			func(s string) string {
				return strings.Replace(s, "routers:\n", "routers:\n    r-us-tst-5-9:\n        management_ipv4: 172.28.208.161\n        wan_interface: eth1\n        wan_ipv4: 203.0.113.89/27\n        wan_gateway_ipv4: 203.0.113.65\n        wan_ipv6_prefix: 2001:db8:99::/48\n        wan_gateway_ipv6: 2001:db8:99::1\n        lan_interfaces: [eth3]\n        edgeos_release: v3\n        edgeos_config_version: x\n        login:\n            ubnt:\n                encrypted_password: h\n", 1)
			},
			"share management_ipv4",
		},
		"gateway outside the wan block": {
			func(s string) string {
				return strings.Replace(s, "wan_gateway_ipv4: 203.0.113.65", "wan_gateway_ipv4: 203.0.113.1", 1)
			},
			"outside wan_ipv4",
		},
		"gateway is the router": {
			func(s string) string {
				return strings.Replace(s, "wan_gateway_ipv4: 203.0.113.65", "wan_gateway_ipv4: 203.0.113.81", 1)
			},
			"own address",
		},
		"ipv6 prefix not a /48": {
			func(s string) string {
				return strings.Replace(s, "wan_ipv6_prefix: 2001:db8:99::/48", "wan_ipv6_prefix: 2001:db8:99::/64", 1)
			},
			"/48",
		},
		"ipv6 prefix with host bits": {
			func(s string) string {
				return strings.Replace(s, "wan_ipv6_prefix: 2001:db8:99::/48", "wan_ipv6_prefix: 2001:db8:99::1/48", 1)
			},
			"zero host bits",
		},
		"ipv6 gateway outside the prefix": {
			func(s string) string {
				return strings.Replace(s, "wan_gateway_ipv6: 2001:db8:99::1", "wan_gateway_ipv6: 2001:db8:98::1", 1)
			},
			"outside wan_ipv6_prefix",
		},
		"lan port with two digits": {
			func(s string) string {
				return strings.Replace(s, "lan_interfaces: [eth3, eth8]", "lan_interfaces: [eth3, eth10]", 1)
			},
			"single digit",
		},
		"lan port listed twice": {
			func(s string) string {
				return strings.Replace(s, "lan_interfaces: [eth3, eth8]", "lan_interfaces: [eth3, eth3]", 1)
			},
			"twice",
		},
		"bridge port is the wan": {
			func(s string) string {
				return strings.Replace(s, "bridge_interfaces: [eth0, eth2]", "bridge_interfaces: [eth1]", 1)
			},
			"twice",
		},
		"lan override not a /24": {
			func(s string) string {
				return strings.Replace(s, "bridge_interfaces: [eth0, eth2]\n", "bridge_interfaces: [eth0, eth2]\n        lan_ipv4: 10.0.0.1/16\n", 1)
			},
			"/24",
		},
		"lan override is the network": {
			func(s string) string {
				return strings.Replace(s, "bridge_interfaces: [eth0, eth2]\n", "bridge_interfaces: [eth0, eth2]\n        lan_ipv4: 10.0.0.0/24\n", 1)
			},
			"bridge address",
		},
		"bad name server": {
			func(s string) string {
				return strings.Replace(s, "bridge_interfaces: [eth0, eth2]\n", "bridge_interfaces: [eth0, eth2]\n        name_servers: [one.one.one.one]\n", 1)
			},
			"not an ip address",
		},
		"missing footer markers": {
			func(s string) string { return strings.Replace(s, "        edgeos_release: v3.0.1\n", "", 1) },
			"edgeos_release",
		},
		"no admin": {
			func(s string) string {
				return strings.Replace(s, "encrypted_password: \"$5$x$y\"\n", "encrypted_password: \"$5$x$y\"\n                level: operator\n", 1)
			},
			"no admin login",
		},
		"bad level": {
			func(s string) string {
				return strings.Replace(s, "encrypted_password: \"$5$x$y\"\n", "encrypted_password: \"$5$x$y\"\n                level: root\n", 1)
			},
			"not admin or operator",
		},
		"no password": {
			func(s string) string {
				return strings.Replace(s, "                encrypted_password: \"$5$x$y\"\n", "", 1)
			},
			"encrypted_password",
		},
		"key without type": {
			func(s string) string { return strings.Replace(s, "                        type: ssh-ed25519\n", "", 1) },
			"needs a type and a key",
		},
		"bad management address": {
			func(s string) string {
				return strings.Replace(s, "management_ipv4: 172.28.208.161", "management_ipv4: 2001:db8::1", 1)
			},
			"management_ipv4",
		},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			err := loadInlineServices(t, c.mutate(routerFixtureHead+routerFixtureVersions))
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err = %v, want %q", err, c.want)
			}
		})
	}
}

func TestLoadServicesConfigRejectsBadRouterInterfaces(t *testing.T) {
	cases := map[string]struct {
		mutate func(string) string
		want   string
	}{
		"only router set": {
			func(s string) string {
				return strings.Replace(s, "                    router_interface: eth8\n", "", 1)
			},
			"only one of router and router_interface",
		},
		"only router_interface set": {
			func(s string) string {
				return strings.Replace(s, "                    router: r-us-tst-5-8\n                    router_interface: eth8\n", "                    router_interface: eth8\n", 1)
			},
			"only one of router and router_interface",
		},
		"unknown router": {
			func(s string) string {
				return strings.Replace(s, "router: r-us-tst-5-8\n                    router_interface: eth8", "router: r-us-tst-5-7\n                    router_interface: eth8", 1)
			},
			"unknown router",
		},
		"port not on the router": {
			func(s string) string {
				return strings.Replace(s, "router_interface: eth8", "router_interface: eth5", 1)
			},
			"not one of its lan_interfaces",
		},
		"port attached twice": {
			func(s string) string {
				return strings.Replace(s, "router_interface: eth3", "router_interface: eth8", 1)
			},
			"both attached to r-us-tst-5-8 eth8",
		},
		"ipv6 outside the port /64": {
			func(s string) string {
				return strings.Replace(s, "2001:db8:99:5880:e643:4bff:fe94:e380", "2001:db8:99:5870:e643:4bff:fe94:e380", 1)
			},
			"outside 2001:db8:99:5880::/64",
		},
		"ipv4 outside the wan block": {
			func(s string) string { return strings.Replace(s, "ipv4: 203.0.113.84", "ipv4: 203.0.113.24", 1) },
			"outside the r-us-tst-5-8 wan block",
		},
		"attached without ipv4": {
			func(s string) string { return strings.Replace(s, "                    ipv4: 203.0.113.84\n", "", 1) },
			"has no ipv4",
		},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			err := loadInlineServices(t, c.mutate(routerFixtureHead+routerFixtureVersions))
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err = %v, want %q", err, c.want)
			}
		})
	}
	// an interface with neither field is a legacy attachment and loads
	legacy := strings.Replace(routerFixtureHead+routerFixtureVersions, "                    router: r-us-tst-5-8\n                    router_interface: eth8\n                    router_tcp_forward_ports:\n                        8022: 22\n", "", 1)
	if err := loadInlineServices(t, legacy); err != nil {
		t.Fatal(err)
	}
	// an attached interface may omit ipv6 (no IPv6 service there)
	noIpv6 := strings.Replace(routerFixtureHead+routerFixtureVersions, "                    ipv6: \"2001:db8:99:5880:e643:4bff:fe94:e380\"\n", "", 1)
	if err := loadInlineServices(t, noIpv6); err != nil {
		t.Fatal(err)
	}
}

func TestLoadServicesConfigRejectsBadPublicPorts(t *testing.T) {
	cases := map[string]struct {
		mutate func(string) string
		want   string
	}{
		"not host pinned": {
			func(s string) string {
				return strings.Replace(s, "            hosts:\n                - fireside.example.com\n            ports:\n                - 80\n                - 8080\n", "            ports:\n                - 80\n                - 8080\n", 1)
			},
			"without a hosts list",
		},
		"not one of its ports": {
			func(s string) string { return strings.Replace(s, "8080: socks", "8081: socks", 1) },
			"not one of its ports",
		},
		"bad name": {
			func(s string) string { return strings.Replace(s, "8080: socks", "8080: SOCKS 5", 1) },
			"not a lowercase word",
		},
		"duplicate name": {
			func(s string) string {
				return strings.Replace(s, "                - 8080\n            public_ports:\n                8080: socks\n", "                - 8080\n                - 8081\n            public_ports:\n                8080: socks\n                8081: socks\n", 1)
			},
			"share the name",
		},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			err := loadInlineServices(t, c.mutate(routerFixtureHead+routerFixtureVersions))
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err = %v, want %q", err, c.want)
			}
		})
	}
}

func TestLoadServicesConfigAcceptsRouterForwards(t *testing.T) {
	servicesConfig, err := loadInlineServicesConfig(t, routerFixtureHead+routerFixtureVersions)
	if err != nil {
		t.Fatal(err)
	}
	latest := servicesConfig.Latest()
	if got := latest.Services["alt"].ExternalUdpForwardPorts; len(got) != 1 || got[53] != 4053 {
		t.Fatalf("alt external udp forwards = %v", got)
	}
	if got := latest.Services["alt"].AllExternalForwardPorts(); len(got) != 1 || got["udp"][53] != 4053 {
		t.Fatalf("alt forward ports by protocol = %v", got)
	}
	if got := latest.Services["proxy"].AllExternalForwardPorts(); len(got) != 0 {
		t.Fatalf("proxy forward ports by protocol = %v, want none", got)
	}
	if got := latest.Lb.Interfaces["edge-3.example.com"]["eno1np0"].RouterTcpForwardPorts; len(got) != 1 || got[8022] != 22 {
		t.Fatalf("edge-3 router tcp forwards = %v", got)
	}
}

func TestLoadServicesConfigRejectsBadRouterForwards(t *testing.T) {
	cases := map[string]struct {
		mutate func(string) string
		want   string
	}{
		"service forward without hosts": {
			func(s string) string {
				return strings.Replace(s, "            exposed: false\n            hosts:\n                - fireside.example.com\n            ports:\n                - 80\n            external_udp_ports:", "            exposed: false\n            ports:\n                - 80\n            external_udp_ports:", 1)
			},
			"without a hosts list",
		},
		"service forward to a port it does not own": {
			func(s string) string {
				return strings.Replace(s, "                53: 4053\n", "                53: 5353\n", 1)
			},
			"not one of its external_udp_ports",
		},
		"service forward from a port it owns": {
			func(s string) string {
				return strings.Replace(s, "                53: 4053\n", "                443: 4053\n", 1)
			},
			"already owns",
		},
		"service forward identity": {
			func(s string) string {
				return strings.Replace(s, "                53: 4053\n", "                4053: 4053\n", 1)
			},
			"identity mapping",
		},
		"service forward out of range": {
			func(s string) string {
				return strings.Replace(s, "                53: 4053\n", "                70000: 4053\n", 1)
			},
			"outside 1..65535",
		},
		"two services alias one public udp port on a host": {
			func(s string) string {
				s = strings.Replace(s, "            - alt\n            - proxy\n", "            - alt\n            - alt2\n            - proxy\n", 1)
				return s + `        alt2:
            exposed: false
            hosts:
                - fireside.example.com
            ports:
                - 80
            external_udp_ports:
                - 5443
            external_udp_forward_ports:
                53: 5443
            blocks:
                - g1: 1
`
			},
			`both claim public udp port 53 on fireside.example.com`,
		},
		"alias collides with a port another service owns": {
			func(s string) string {
				s = strings.Replace(s, "            - alt\n            - proxy\n", "            - alt\n            - alt2\n            - proxy\n", 1)
				return s + `        alt2:
            exposed: false
            hosts:
                - fireside.example.com
            ports:
                - 80
            external_udp_ports:
                - 5443
            external_udp_forward_ports:
                4053: 5443
            blocks:
                - g1: 1
`
			},
			`both claim public udp port 4053 on fireside.example.com`,
		},
		"interface forward without a router": {
			func(s string) string {
				return strings.Replace(s, "                    router: r-us-tst-5-8\n                    router_interface: eth8\n                    router_tcp_forward_ports:", "                    router_tcp_forward_ports:", 1)
			},
			"but no router",
		},
		"interface forward identity": {
			func(s string) string {
				return strings.Replace(s, "                        8022: 22\n", "                        22: 22\n", 1)
			},
			"identity mapping",
		},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			err := loadInlineServices(t, c.mutate(routerFixtureHead+routerFixtureVersions))
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err = %v, want %q", err, c.want)
			}
		})
	}
}
