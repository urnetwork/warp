package services

// Tests of the lb type each port of warpctl's port allocation keeps across the
// versions of a services file (validatePortBlockLbTypes).

import (
	"fmt"
	"strings"
	"testing"
)

// One version of a synthetic edge: the lb on edge-a.example eth1, with lbLines
// under lb, and the api service on one block, with apiLines under api. The
// allocation ranges are those warpctl's port allocation reads.
func portLbTypeVersionYaml(lbLines string, apiBlock string, apiLines string) string {
	return fmt.Sprintf(`  - external_ports: 7001-7099
    internal_ports: 8001-8400
    routing_tables: 100-110
    parallel_block_count: 2
    lb:
%s      interfaces:
        edge-a.example:
          eth1:
            docker_network: warpeth1
            ipv4: 198.51.100.1
    services:
      api:
%s        blocks:
          - %s: 1
`, lbLines, apiLines, apiBlock)
}

// A services file of the given versions, latest first.
func portLbTypeServicesYaml(versionYamls ...string) string {
	return "versions:\n" + strings.Join(versionYamls, "")
}

const (
	portLbTypeLbHttpYaml      = "      ports: [80]\n"
	portLbTypeApiHttpYaml     = "        ports: [80]\n"
	portLbTypeApiHttp8080Yaml = "        ports: [80, 8080]\n"
)

// A port that is one lb type in one version and another in a second, or both
// in one version, on the same lb interface or service block, is refused at
// load: warpctl's port allocation panicked on each of these files, which
// loaded before.
func TestLoadServicesConfigRefusesAPortWhoseLbTypeChanges(t *testing.T) {
	cases := []struct {
		name         string
		servicesYaml string
		want         string
	}{
		{
			name: "an http port becomes a tcp stream port",
			servicesYaml: portLbTypeServicesYaml(
				portLbTypeVersionYaml(portLbTypeLbHttpYaml, "g1", portLbTypeApiHttpYaml+"        tcp_stream_ports: [8080]\n"),
				portLbTypeVersionYaml(portLbTypeLbHttpYaml, "g1", portLbTypeApiHttp8080Yaml),
			),
			want: `service "api" block "g1" lists the tcp port 8080 as an http port in version 1 and as a stream port in version 0`,
		},
		{
			name: "a tcp stream port becomes an http port",
			servicesYaml: portLbTypeServicesYaml(
				portLbTypeVersionYaml(portLbTypeLbHttpYaml, "g1", portLbTypeApiHttp8080Yaml),
				portLbTypeVersionYaml(portLbTypeLbHttpYaml, "g1", portLbTypeApiHttpYaml+"        tcp_stream_ports: [8080]\n"),
			),
			want: `service "api" block "g1" lists the tcp port 8080 as a stream port in version 1 and as an http port in version 0`,
		},
		{
			name: "one version lists a port as an http port and a tcp stream port",
			servicesYaml: portLbTypeServicesYaml(
				portLbTypeVersionYaml(portLbTypeLbHttpYaml, "g1", portLbTypeApiHttp8080Yaml+"        tcp_stream_ports: [8080]\n"),
			),
			want: `service "api" block "g1" lists the tcp port 8080 as both an http port and a stream port in version 0`,
		},
		{
			name: "a udp stream port becomes an external port",
			servicesYaml: portLbTypeServicesYaml(
				portLbTypeVersionYaml(portLbTypeLbHttpYaml, "g1", portLbTypeApiHttpYaml+"        hosts: [edge-a.example]\n        external_udp_ports: [4053]\n"),
				portLbTypeVersionYaml(portLbTypeLbHttpYaml, "g1", portLbTypeApiHttpYaml+"        udp_stream_ports: [4053]\n"),
			),
			want: `service "api" block "g1" lists the udp port 4053 as a stream port in version 1 and as an external port in version 0`,
		},
		{
			name: "an lb http port becomes an lb tcp stream port",
			servicesYaml: portLbTypeServicesYaml(
				portLbTypeVersionYaml(portLbTypeLbHttpYaml+"      tcp_stream_ports: [8443]\n", "g1", portLbTypeApiHttpYaml),
				portLbTypeVersionYaml("      ports: [80, 8443]\n", "g1", portLbTypeApiHttpYaml),
			),
			want: `lb interface edge-a.example eth1 lists the tcp port 8443 as an http port in version 1 and as a stream port in version 0`,
		},
	}
	for _, c := range cases {
		_, err := loadInlineServicesConfig(t, c.servicesYaml)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err = %v, want %q", c.name, err, c.want)
		}
	}
}

// A port block belongs to one block of a service, and keeps an lb type for
// each of tcp and udp, so a port may change lb type on a block the other
// version does not list, or move from tcp to udp. warpctl allocates both
// files.
func TestLoadServicesConfigAcceptsAPortThatChangesTypeOnAnotherBlockOrProtocol(t *testing.T) {
	servicesYamls := []string{
		portLbTypeServicesYaml(
			portLbTypeVersionYaml(portLbTypeLbHttpYaml, "g2", portLbTypeApiHttpYaml+"        tcp_stream_ports: [8080]\n"),
			portLbTypeVersionYaml(portLbTypeLbHttpYaml, "g1", portLbTypeApiHttp8080Yaml),
		),
		portLbTypeServicesYaml(
			portLbTypeVersionYaml(portLbTypeLbHttpYaml, "g1", portLbTypeApiHttpYaml+"        udp_stream_ports: [8080]\n"),
			portLbTypeVersionYaml(portLbTypeLbHttpYaml, "g1", portLbTypeApiHttp8080Yaml),
		),
	}
	for _, servicesYaml := range servicesYamls {
		if _, err := loadInlineServicesConfig(t, servicesYaml); err != nil {
			t.Errorf("refused:\n%s\n%v", servicesYaml, err)
		}
	}
}
