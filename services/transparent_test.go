package services

import (
	"fmt"
	"strings"
	"testing"
)

// The shape of crisp and fireside: a transparent interface with its addresses
// and docker network, and nothing an lb front would use.
const transparentInterfaceServicesYaml = `
versions:
  - lb:
      ports: [80, 443]
      interfaces:
        edge-0.example.com:
          eth0:
            docker_network: warpeth0
            cores: 4
            concurrent_clients: 1000
            dns_weight: 10
        direct-0.example.com:
          eth0:
            transparent: true
            docker_network: warpeth0
            ipv4: 10.0.1.1
            ipv6: "fd00:1::1"
%s
    host_services:
      direct-0.example.com: [proxy]
    services:
      proxy:
        hosts: [direct-0.example.com]
        ports: [80, 8080]
        public_ports:
          8080: socks
`

func TestLoadServicesConfigAcceptsATransparentInterface(t *testing.T) {
	servicesConfig, err := loadInlineServicesConfig(t, fmt.Sprintf(transparentInterfaceServicesYaml, ""))
	if err != nil {
		t.Fatal(err)
	}
	if !servicesConfig.Latest().Lb.Interfaces["direct-0.example.com"]["eth0"].Transparent {
		t.Fatal("direct-0 eth0 did not load as transparent")
	}
}

// No lb runs on a transparent interface, so an lb front setting there would
// apply to nothing. The config refuses it rather than ignore it.
func TestLoadServicesConfigRefusesLbSettingsOnATransparentInterface(t *testing.T) {
	for setting, yaml := range map[string]string{
		"cores":                           "            cores: 4",
		"concurrent_clients":              "            concurrent_clients: 1000",
		"expected_connections_per_client": "            expected_connections_per_client: 8",
		"rate_limit":                      "            rate_limit:\n              requests_per_second: 5",
		"keepalive":                       "            keepalive:\n              keepalive: 16",
		"dns_weight":                      "            dns_weight: 10",
		"external_ports":                  "            external_ports:\n              7080: 80",
		"tcp_stream_port_services":        "            tcp_stream_port_services:\n              8080: proxy",
		"udp_stream_port_services":        "            udp_stream_port_services:\n              8080: proxy",
	} {
		t.Run(setting, func(t *testing.T) {
			_, err := loadInlineServicesConfig(t, fmt.Sprintf(transparentInterfaceServicesYaml, yaml))
			if err == nil {
				t.Fatalf("a transparent interface that sets %s loaded", setting)
			}
			if !strings.Contains(err.Error(), "direct-0.example.com eth0 is transparent") || !strings.Contains(err.Error(), setting) {
				t.Fatalf("err = %v, want direct-0.example.com eth0 refused for %s", err, setting)
			}
		})
	}
}

// The main env's direct interfaces load under the transparent rules.
func TestVaultMainTransparentInterfacesLoad(t *testing.T) {
	servicesConfig := loadSiblingVaultServicesConfig(t, "main")
	transparentCount := 0
	frontCount := 0
	for _, interfaces := range servicesConfig.Latest().Lb.Interfaces {
		for _, lbBlock := range interfaces {
			if lbBlock.Transparent {
				transparentCount += 1
			} else {
				frontCount += 1
			}
		}
	}
	if transparentCount == 0 || frontCount == 0 {
		t.Fatalf("main has %d transparent and %d front interfaces, want some of each", transparentCount, frontCount)
	}
}
