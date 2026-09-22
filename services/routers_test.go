package services

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func loadRouterSafetyConfig(t *testing.T, mutate func(*ServicesConfig)) (*ServicesConfig, error) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "router-safety.yml"))
	if err != nil {
		t.Fatal(err)
	}
	config := &ServicesConfig{}
	if err := yaml.Unmarshal(data, config); err != nil {
		t.Fatal(err)
	}
	if mutate != nil {
		mutate(config)
	}
	data, err = yaml.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	return loadInlineServicesConfig(t, string(data))
}

func TestRouterSafetyAcceptsDisjointOwnership(t *testing.T) {
	config, err := loadRouterSafetyConfig(t, func(config *ServicesConfig) {
		// The same attachment in successive versions is not a second owner.
		config.Versions = append(config.Versions, config.Versions[0])
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(config.Routers) != 4 || len(config.Versions) != 2 {
		t.Fatal("synthetic fixture lost routers or versions")
	}
}

func TestRouterSafetyAddressOwnership(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*ServicesConfig)
	}{
		{name: "host network", mutate: func(config *ServicesConfig) {
			config.Latest().Lb.Interfaces["alpha.example"]["eth0"].Ipv4 = "203.0.113.0"
		}},
		{name: "host broadcast", mutate: func(config *ServicesConfig) {
			config.Latest().Lb.Interfaces["alpha.example"]["eth0"].Ipv4 = "203.0.113.31"
		}},
		{name: "host isp gateway", mutate: func(config *ServicesConfig) {
			config.Latest().Lb.Interfaces["alpha.example"]["eth0"].Ipv4 = "203.0.113.1"
		}},
		{name: "host own router", mutate: func(config *ServicesConfig) {
			config.Latest().Lb.Interfaces["alpha.example"]["eth0"].Ipv4 = "203.0.113.3"
		}},
		{name: "host sibling router", mutate: func(config *ServicesConfig) {
			config.Latest().Lb.Interfaces["alpha.example"]["eth0"].Ipv4 = "203.0.113.4"
		}},
		{name: "host managed gateway", mutate: func(config *ServicesConfig) {
			config.Latest().Lb.Interfaces["alpha.example"]["eth0"].Ipv4 = "203.0.113.2"
		}},
		{name: "hosts on same router", mutate: func(config *ServicesConfig) {
			config.Latest().Lb.Interfaces["alpha.example"]["eth1"].Ipv4 = "203.0.113.10"
		}},
		{name: "hosts across routers", mutate: func(config *ServicesConfig) {
			config.Latest().Lb.Interfaces["bravo.example"]["eth0"].Ipv4 = "203.0.113.10"
		}},
		{name: "host port router ipv6", mutate: func(config *ServicesConfig) {
			config.Latest().Lb.Interfaces["alpha.example"]["eth0"].Ipv6 = "2001:db8:10:1120::1"
		}},
		{name: "duplicate router wan", mutate: func(config *ServicesConfig) {
			config.Routers["r-test-1-2"].WanIpv4 = "203.0.113.3/27"
		}},
		{name: "router broadcast", mutate: func(config *ServicesConfig) {
			config.Routers["r-test-1-2"].WanIpv4 = "203.0.113.31/27"
		}},
		{name: "managed gateway broadcast", mutate: func(config *ServicesConfig) {
			config.Routers["r-test-1-gateway-1"].WanIpv4 = "203.0.113.31/27"
		}},
		{name: "duplicate derived ipv6", mutate: func(config *ServicesConfig) {
			config.Routers["r-other-1-1"] = config.Routers["r-test-1-2"]
			delete(config.Routers, "r-test-1-2")
			block := config.Latest().Lb.Interfaces["bravo.example"]["eth0"]
			block.Router = "r-other-1-1"
			block.Ipv6 = "2001:db8:10:1120::2"
		}},
		{name: "derived wan equals gateway ipv6", mutate: func(config *ServicesConfig) {
			config.Gateways["r-test-1-gateway-1"].Ipv6Gateway = "2001:db8:10::11"
		}},
	} {
		if _, err := loadRouterSafetyConfig(t, test.mutate); err == nil {
			t.Errorf("%s: loader accepted conflicting or reserved ownership", test.name)
		}
	}
}

func TestRouterSafetyRejectsSubnetRouterAnycast(t *testing.T) {
	_, err := loadRouterSafetyConfig(t, func(config *ServicesConfig) {
		config.Latest().Lb.Interfaces["alpha.example"]["eth0"].Ipv6 = "2001:db8:10:1120::"
	})
	if err == nil {
		t.Error("loader accepted the port's subnet-router anycast address as host unicast")
	}
}

func TestRouterSafetyGatewayCommonValidation(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*RouterConfig)
	}{
		{name: "name server", mutate: func(router *RouterConfig) {
			router.NameServers = []string{"not-an-address.example"}
		}},
		{name: "negative table", mutate: func(router *RouterConfig) {
			router.ConntrackTableSize = -1
		}},
		{name: "excess table", mutate: func(router *RouterConfig) {
			router.ConntrackTableSize = RouterConntrackSizeMax + 1
		}},
		{name: "negative hash", mutate: func(router *RouterConfig) {
			router.ConntrackHashSize = -1
		}},
		{name: "hash exceeds table", mutate: func(router *RouterConfig) {
			router.ConntrackTableSize = 1024
			router.ConntrackHashSize = 2048
		}},
		{name: "ipv6 offload without ipv4", mutate: func(router *RouterConfig) {
			ipv4, ipv6 := false, true
			router.OffloadIpv4Forwarding = &ipv4
			router.OffloadIpv6Forwarding = &ipv6
		}},
	} {
		_, err := loadRouterSafetyConfig(t, func(config *ServicesConfig) {
			test.mutate(config.Routers["r-test-1-gateway-1"])
		})
		if err == nil {
			t.Errorf("%s: gateway bypassed common validation", test.name)
		}
	}
}

func TestRouterSafetyGatewayBlockOwnership(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*ServicesConfig)
	}{
		{name: "gateway broadcast", mutate: func(config *ServicesConfig) {
			config.Gateways["r-test-1-gateway-1"].Ipv4Gateway = "203.0.113.31"
		}},
		{name: "overlapping ipv4 blocks", mutate: func(config *ServicesConfig) {
			gateway := config.Gateways["r-test-1-gateway-2"]
			gateway.Ipv4 = "203.0.113.16/28"
			gateway.Ipv4Gateway = "203.0.113.17"
		}},
	} {
		if _, err := loadRouterSafetyConfig(t, test.mutate); err == nil {
			t.Errorf("%s: loader accepted unsafe gateway block ownership", test.name)
		}
	}
}

const routerFixtureHead = `domain: example.com
domains:
    example.com: route53
gateways:
    r-us-tst-5-gateway-1:
        ipv4: 203.0.113.64/27
        ipv4_gateway: 203.0.113.65
        ipv6: 2001:db8:99::/48
        ipv6_gateway: 2001:db8:99::1
routers:
    r-us-tst-5-8:
        management_ipv4: 172.28.208.161
        gateway: r-us-tst-5-gateway-1
        wan_interface: eth1
        wan_ipv4: 203.0.113.81/27
        lan_interfaces: [eth3, eth8]
        bridge_interfaces: [eth0, eth2]
        unms: "wss://example.uisp.com:443+KEY+allowUntrustedCertificate"
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
				return strings.Replace(s, "routers:\n", "routers:\n    r-us-tst-5-9:\n        management_ipv4: 172.28.208.161\n        gateway: r-us-tst-5-gateway-1\n        wan_interface: eth1\n        wan_ipv4: 203.0.113.89/27\n        lan_interfaces: [eth3]\n        unms: k\n        edgeos_release: v3\n        edgeos_config_version: x\n        login:\n            ubnt:\n                encrypted_password: h\n", 1)
			},
			"share management_ipv4",
		},
		"gateway address outside its block": {
			func(s string) string {
				return strings.Replace(s, "ipv4_gateway: 203.0.113.65", "ipv4_gateway: 203.0.113.1", 1)
			},
			"not a usable address of 203.0.113.64/27",
		},
		"router address is the gateway": {
			func(s string) string {
				return strings.Replace(s, "wan_ipv4: 203.0.113.81/27", "wan_ipv4: 203.0.113.65/27", 1)
			},
			"not a usable address",
		},
		"router address off its block": {
			func(s string) string {
				return strings.Replace(s, "wan_ipv4: 203.0.113.81/27", "wan_ipv4: 203.0.113.81/28", 1)
			},
			"is not on the r-us-tst-5-gateway-1 block",
		},
		"gateway ipv6 not a /48": {
			func(s string) string {
				return strings.Replace(s, "ipv6: 2001:db8:99::/48", "ipv6: 2001:db8:99::/64", 1)
			},
			"/48",
		},
		"gateway ipv6 with host bits": {
			func(s string) string {
				return strings.Replace(s, "ipv6: 2001:db8:99::/48", "ipv6: 2001:db8:99::1/48", 1)
			},
			"zero host bits",
		},
		"ipv6 gateway off the first /64": {
			func(s string) string {
				return strings.Replace(s, "ipv6_gateway: 2001:db8:99::1", "ipv6_gateway: 2001:db8:99:1::1", 1)
			},
			"not on the first /64",
		},
		"gateway name convention": {
			func(s string) string { return strings.ReplaceAll(s, "r-us-tst-5-gateway-1", "r-us-tst-5-gw-1") },
			"gateway-<k> hostname convention",
		},
		"router without a gateway": {
			func(s string) string { return strings.Replace(s, "        gateway: r-us-tst-5-gateway-1\n", "", 1) },
			"names no gateway",
		},
		"router with the derived fields set by hand": {
			func(s string) string {
				return strings.Replace(s, "        gateway: r-us-tst-5-gateway-1\n", "        gateway: r-us-tst-5-gateway-1\n        wan_gateway_ipv4: 203.0.113.65\n", 1)
			},
			"come from its gateway",
		},
		"gateway router without a gateways entry": {
			func(s string) string {
				return strings.Replace(s, "routers:\n", "routers:\n    r-us-tst-5-gateway-9:\n        class: gateway\n        planned: true\n        isp_interface: eth1\n        isp_ipv6: 2001:db8:3c3:1::/126\n        block_interfaces: [eth3]\n        unms: pending\n        edgeos_release: v3\n        edgeos_config_version: x\n        login:\n            ubnt:\n                encrypted_password: h\n                public_keys:\n                    fleet:\n                        type: ssh-ed25519\n                        key: AAAA\n", 1)
			},
			"without a gateways entry",
		},
		"gateway router off its block": {
			func(s string) string {
				return strings.Replace(s, "routers:\n", "routers:\n    r-us-tst-5-gateway-1:\n        class: gateway\n        management_ipv4: 172.28.208.14\n        isp_interface: eth1\n        wan_ipv4: 203.0.113.33/27\n        isp_ipv6: 2001:db8:3c3:1::/126\n        block_interfaces: [eth3]\n        unms: k\n        edgeos_release: v3\n        edgeos_config_version: x\n        login:\n            ubnt:\n                encrypted_password: h\n                public_keys:\n                    fleet:\n                        type: ssh-ed25519\n                        key: AAAA\n", 1)
			},
			"not an address on its block",
		},
		"gateway router at the isp's address": {
			func(s string) string {
				return strings.Replace(s, "routers:\n", "routers:\n    r-us-tst-5-gateway-1:\n        class: gateway\n        management_ipv4: 172.28.208.14\n        isp_interface: eth1\n        wan_ipv4: 203.0.113.65/27\n        isp_ipv6: 2001:db8:3c3:1::/126\n        block_interfaces: [eth3]\n        unms: k\n        edgeos_release: v3\n        edgeos_config_version: x\n        login:\n            ubnt:\n                encrypted_password: h\n                public_keys:\n                    fleet:\n                        type: ssh-ed25519\n                        key: AAAA\n", 1)
			},
			"the isp holds 203.0.113.65",
		},
		"gateway router with a bad /126": {
			func(s string) string {
				return strings.Replace(s, "routers:\n", "routers:\n    r-us-tst-5-gateway-1:\n        class: gateway\n        management_ipv4: 172.28.208.14\n        isp_interface: eth1\n        wan_ipv4: 203.0.113.94/27\n        isp_ipv6: 2001:db8:3c3:1::/64\n        block_interfaces: [eth3]\n        unms: k\n        edgeos_release: v3\n        edgeos_config_version: x\n        login:\n            ubnt:\n                encrypted_password: h\n                public_keys:\n                    fleet:\n                        type: ssh-ed25519\n                        key: AAAA\n", 1)
			},
			"not a /126",
		},
		"gateway router without its address": {
			func(s string) string {
				return strings.Replace(s, "routers:\n", "routers:\n    r-us-tst-5-gateway-1:\n        class: gateway\n        management_ipv4: 172.28.208.14\n        isp_interface: eth1\n        isp_ipv6: 2001:db8:3c3:1::/126\n        block_interfaces: [eth3]\n        unms: k\n        edgeos_release: v3\n        edgeos_config_version: x\n        login:\n            ubnt:\n                encrypted_password: h\n                public_keys:\n                    fleet:\n                        type: ssh-ed25519\n                        key: AAAA\n", 1)
			},
			"not an address on its block",
		},
		"gateway router management bridge without lan_ipv4": {
			func(s string) string {
				return strings.Replace(s, "routers:\n", "routers:\n    r-us-tst-5-gateway-1:\n        class: gateway\n        management_ipv4: 172.28.208.14\n        isp_interface: eth1\n        wan_ipv4: 203.0.113.94/27\n        isp_ipv6: 2001:db8:3c3:1::/126\n        block_interfaces: [eth3]\n        bridge_interfaces: [eth2]\n        unms: k\n        edgeos_release: v3\n        edgeos_config_version: x\n        login:\n            ubnt:\n                encrypted_password: h\n                public_keys:\n                    fleet:\n                        type: ssh-ed25519\n                        key: AAAA\n", 1)
			},
			"has no lan_ipv4",
		},
		"planned router without management loads, unplanned does not": {
			func(s string) string { return strings.Replace(s, "        management_ipv4: 172.28.208.161\n", "", 1) },
			"management_ipv4",
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
		"conntrack table too large": {
			func(s string) string {
				return strings.Replace(s, "bridge_interfaces: [eth0, eth2]\n", "bridge_interfaces: [eth0, eth2]\n        conntrack_table_size: 50000001\n", 1)
			},
			"conntrack_table_size 50000001 is outside",
		},
		"conntrack hash larger than the table": {
			func(s string) string {
				return strings.Replace(s, "bridge_interfaces: [eth0, eth2]\n", "bridge_interfaces: [eth0, eth2]\n        conntrack_table_size: 262144\n        conntrack_hash_size: 524288\n", 1)
			},
			"conntrack_hash_size 524288 exceeds conntrack_table_size 262144",
		},
		"ipv6 offload without ipv4 offload": {
			func(s string) string {
				return strings.Replace(s, "bridge_interfaces: [eth0, eth2]\n", "bridge_interfaces: [eth0, eth2]\n        offload_ipv4_forwarding: false\n        offload_ipv6_forwarding: true\n", 1)
			},
			"offload_ipv6_forwarding needs offload_ipv4_forwarding",
		},
		"admin without a public key": {
			func(s string) string {
				return strings.Replace(s, "                public_keys:\n                    fleet:\n                        type: ssh-ed25519\n                        key: AAAA\n", "", 1)
			},
			"no admin login with a public key",
		},
		"only an operator carries a key": {
			func(s string) string {
				return strings.Replace(s, "encrypted_password: \"$5$x$y\"\n                public_keys:", "encrypted_password: \"$5$x$y\"\n            audit:\n                encrypted_password: \"$5$a$b\"\n                level: operator\n                public_keys:\n                    fleet:\n                        type: ssh-ed25519\n                        key: AAAA\n        r-us-tst-5-7:\n            management_ipv4: 172.28.208.162\n            wan_interface: eth1\n            wan_ipv4: 203.0.113.87/27\n            wan_gateway_ipv4: 203.0.113.65\n            wan_ipv6_prefix: 2001:db8:99::/48\n            wan_gateway_ipv6: 2001:db8:99::1\n            lan_interfaces: [eth3]\n            edgeos_release: v3\n            edgeos_config_version: x\n            login:\n                ubnt:\n                    encrypted_password: h\n                    public_keys:", 1)
			},
			"no admin login with a public key",
		},
		"no unms": {
			func(s string) string {
				return strings.Replace(s, "        unms: \"wss://example.uisp.com:443+KEY+allowUntrustedCertificate\"\n", "", 1)
			},
			"no unms connection",
		},
		"unknown class": {
			func(s string) string {
				return strings.Replace(s, "bridge_interfaces: [eth0, eth2]\n", "bridge_interfaces: [eth0, eth2]\n        class: core\n", 1)
			},
			"not edge, lan or gateway",
		},
		"edge router with public ports": {
			func(s string) string {
				return strings.Replace(s, "bridge_interfaces: [eth0, eth2]\n", "bridge_interfaces: [eth0, eth2]\n        public_ports:\n            8022: {host: edge-2, port: 22}\n", 1)
			},
			"public ports are declared on the lb interfaces",
		},
		"lan router with lan ports": {
			func(s string) string {
				return strings.Replace(s, "bridge_interfaces: [eth0, eth2]\n", "bridge_interfaces: [eth0, eth2]\n        class: lan\n", 1)
			},
			"every port but the WAN is a bridge_interfaces member",
		},
		"lan router without a bridge": {
			func(s string) string {
				return strings.Replace(s, "lan_interfaces: [eth3, eth8]\n        bridge_interfaces: [eth0, eth2]\n", "class: lan\n", 1)
			},
			"no bridge_interfaces",
		},
		"lan public port without a host": {
			func(s string) string {
				return strings.Replace(s, "lan_interfaces: [eth3, eth8]\n        bridge_interfaces: [eth0, eth2]\n", "class: lan\n        bridge_interfaces: [eth0]\n        public_ports:\n            8022: {port: 22}\n", 1)
			},
			"needs a lan host name",
		},
		"lan public port bad protocol": {
			func(s string) string {
				return strings.Replace(s, "lan_interfaces: [eth3, eth8]\n        bridge_interfaces: [eth0, eth2]\n", "class: lan\n        bridge_interfaces: [eth0]\n        public_ports:\n            8022: {host: edge-2, port: 22, protocol: sctp}\n", 1)
			},
			"not tcp, udp or tcp_udp",
		},
		"lan public port out of range": {
			func(s string) string {
				return strings.Replace(s, "lan_interfaces: [eth3, eth8]\n        bridge_interfaces: [eth0, eth2]\n", "class: lan\n        bridge_interfaces: [eth0]\n        public_ports:\n            70000: {host: edge-2, port: 22}\n", 1)
			},
			"outside 1..65535",
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
	// an attachment to a lan router is refused
	lanRouter := strings.Replace(routerFixtureHead+routerFixtureVersions, "lan_interfaces: [eth3, eth8]\n        bridge_interfaces: [eth0, eth2]\n", "class: lan\n        bridge_interfaces: [eth0, eth2, eth3, eth8]\n", 1)
	if err := loadInlineServices(t, lanRouter); err == nil || !strings.Contains(err.Error(), "is a lan router, not an edge router") {
		t.Fatalf("err = %v, want the lan attachment refused", err)
	}
	// a gateway of ours: its gateways entry, the isp link and the block ports
	gateway := strings.Replace(routerFixtureHead+routerFixtureVersions, "routers:\n", "routers:\n    r-us-tst-5-gateway-1:\n        class: gateway\n        management_ipv4: 172.28.208.14\n        isp_interface: eth1\n        wan_ipv4: 203.0.113.94/27\n        isp_ipv6: 2001:db8:3c3:1::/126\n        block_interfaces: [eth3, eth4]\n        bridge_interfaces: [eth2]\n        lan_ipv4: 192.168.201.1/24\n        unms: k\n        edgeos_release: v3\n        edgeos_config_version: x\n        login:\n            ubnt:\n                encrypted_password: h\n                public_keys:\n                    fleet:\n                        type: ssh-ed25519\n                        key: AAAA\n", 1)
	if err := loadInlineServices(t, gateway); err != nil {
		t.Fatal(err)
	}
	// a planned gateway waits for its vpn address
	planned := strings.Replace(gateway, "        management_ipv4: 172.28.208.14\n", "        planned: true\n", 1)
	if err := loadInlineServices(t, planned); err != nil {
		t.Fatal(err)
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
