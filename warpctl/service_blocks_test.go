// Tests of what warpctl does with §19.4's service blocks, which the recipe in
// warp's README and each service's own W6 task rest on.

package main

import (
	"fmt"
	"strings"
	"testing"
)

// The service blocks of DESIGN §19.4 in warp's own terms. Each service's own
// task lands its W6 artifacts in server and build, by the recipe in warp's
// README, and that recipe rests on what warpctl does with these blocks, so this
// is that contract: warp accepts each block as §19.4 shapes it, and can run the
// rollout class D-OPS-11 gives it. smtpedge holds §19.4's cap_net_admin, which
// warp grants to it and proxy alone, and dnsedge is on one host, since a block
// runs on every host of its service. The names and addresses are synthetic, and
// the ports stand in for W4's and W7's.
const sidecarServiceBlocksYaml = `
domain: example.com
domains:
    example.com: route53
versions:
-   external_ports: 7000-7200,7443-7449
    internal_ports: 7201-7442,7450-10000
    routing_tables: 100-120
    parallel_block_count: 30
    services_docker_network: testservices
    lb:
        ports:
            - 80
            - 443
        tcp_stream_port_services:
            25: mxedge
            8443: tlsedge
        interfaces:
            edge-0.example.com:
                eth0:
                    docker_network: warpeth0
                    ipv4: 10.0.0.1
                    ipv6: "fd00::1"
            ns1.example.com:
                eth0:
                    transparent: true
                    docker_network: warpeth0
                    ipv4: 10.0.0.2
                    ipv6: "fd00::2"
    host_services:
        ns1.example.com:
            - dnsedge
    services:
        evs:
            mount: &sidecar_mount
                vault: no
                config: yes
                site: no
            user: "65532"
            secret_files:
                - evs.yml
            streamable_paths:
                - /evs/seg/.*
            ports:
                - 80
            blocks: &sidecar_blocks
                - beta: 1
                - g1: 99
        gkm:
            mount: *sidecar_mount
            user: "65532"
            ports:
                - 80
            blocks: *sidecar_blocks
        sockets:
            mount: *sidecar_mount
            user: "65532"
            ports:
                - 80
            blocks: *sidecar_blocks
        dns:
            mount: *sidecar_mount
            user: "65532"
            ports:
                - 80
            blocks: *sidecar_blocks
        tlsedge:
            mount: *sidecar_mount
            user: "65532"
            ports:
                - 80
            tcp_stream_ports:
                - 8443
            blocks: *sidecar_blocks
        mxedge:
            mount: *sidecar_mount
            user: "65532"
            ports:
                - 80
            tcp_stream_ports:
                - 25
            blocks: *sidecar_blocks
        smtpedge:
            exposed: false
            cap_net_admin: true
            hosts:
                - edge-0.example.com
            mount: *sidecar_mount
            user: "65532"
            ports:
                - 80
            blocks:
                - g1: 1
        dnsedge:
            exposed: false
            hosts:
                - ns1.example.com
            mount: *sidecar_mount
            user: "65532"
            ports:
                - 80
            external_udp_ports:
                - 4053
            external_udp_forward_ports:
                53: 4053
            blocks:
                - g1: 1
`

// A vault whose services.yml holds §19.4's blocks, for the tests that generate from
// them. Returns the env.
func setupSidecarServiceBlocks(t *testing.T) string {
	t.Helper()
	env, _ := setupTestVaultWithTLS(t, []byte(sidecarServiceBlocksYaml))
	return env
}

// D-OPS-11's staged class deploys with --only-older, which warpctl refuses for
// any service whose running versions it cannot sample through the lb.
func TestStagedSidecarServicesCanBeSampledForOnlyOlder(t *testing.T) {
	env := setupSidecarServiceBlocks(t)

	for _, service := range []string{"evs", "gkm", "sockets", "dns", "tlsedge", "mxedge"} {
		if err := validateBlockStatusSampling(env, service); err != nil {
			t.Errorf("%s cannot deploy staged: %v", service, err)
		}
	}
}

// dnsedge must deploy in a single pass: on a transparent interface it has no lb
// status route, so warpctl refuses --only-older for it. smtpedge's single pass
// is D-OPS-11's choice, and warp neither forces nor prevents it.
func TestDnsEdgeCannotDeployStaged(t *testing.T) {
	env := setupSidecarServiceBlocks(t)

	err := validateBlockStatusSampling(env, "dnsedge")
	if err == nil || !strings.Contains(err.Error(), "transparent") {
		t.Fatalf("sampling error = %v, want dnsedge refused as transparent", err)
	}
}

// The status routes --only-older reads must exist for the staged class, stream
// services included, where a service's traffic never touches an http server.
func TestStagedSidecarServicesHaveLbStatusRoutes(t *testing.T) {
	env := setupSidecarServiceBlocks(t)
	nginxConfig, err := NewNginxConfig(env, nil)
	if err != nil {
		t.Fatal(err)
	}

	config := nginxConfig.Generate()["edge-0.example.com-eth0"]
	if config == "" {
		t.Fatal("no config for the lb block")
	}
	for _, service := range []string{"evs", "gkm", "sockets", "dns", "tlsedge", "mxedge"} {
		for _, block := range []string{"beta", "g1"} {
			route := fmt.Sprintf("/by/b/%s/%s/status", service, block)
			if !strings.Contains(config, route) {
				t.Errorf("the lb has no %s route", route)
			}
		}
	}
}

// New blocks mount only config and run unprivileged (§19.4), and a unit is where
// that reaches a host.
func TestSidecarServiceUnitsCarryTheirIsolation(t *testing.T) {
	env := setupSidecarServiceBlocks(t)

	units := NewSystemdUnits(env, "/srv/warp/test", "/usr/local/sbin/warpctl", true).Generate()
	serviceUnit := units["edge-0.example.com"]["evs"]["g1"]
	if serviceUnit == nil {
		t.Fatalf("no evs unit: %v", units["edge-0.example.com"])
	}
	for _, want := range []string{
		"--mount_vault=no",
		"--mount_config=yes",
		"--mount_site=no",
		"--mount_docker=no",
		"--cap_net_admin=no",
		"--user=65532",
		"--secret-file=evs.yml",
		"--status=standard",
	} {
		if !strings.Contains(serviceUnit.serviceUnit, want) {
			t.Errorf("the evs unit lacks %s:\n%s", want, serviceUnit.serviceUnit)
		}
	}
}

// smtpedge's unit (§19.4's row; plan-OPS-small-readings #14): unexposed on a
// host whose lb interface runs a front, so behind no transparent interface, it
// still gets a mark, its host's lb interface's routing table, which that lb's
// unit already routes by, and with it the capability SO_MARK needs, under its
// unprivileged user. It gets no routing table of its own, no lb status route
// and no stream port. No other block on the host is given the capability or a
// mark.
func TestSmtpEdgeUnitCarriesItsMarkAndCapability(t *testing.T) {
	env := setupSidecarServiceBlocks(t)

	units := NewSystemdUnits(env, "/srv/warp/test", "/usr/local/sbin/warpctl", true).Generate()
	hostUnits := units["edge-0.example.com"]
	smtpEdgeUnit := hostUnits["smtpedge"]["g1"]
	if smtpEdgeUnit == nil {
		t.Fatalf("no smtpedge unit: %v", hostUnits)
	}
	lbUnit := hostUnits["lb"]
	if len(lbUnit) != 1 {
		t.Fatalf("lb units = %v", lbUnit)
	}
	var lbMark string
	for _, unit := range lbUnit {
		for _, field := range strings.Fields(unit.serviceUnit) {
			if strings.HasPrefix(field, "--fwmark=") {
				lbMark = field
			}
		}
	}
	if lbMark == "" || lbMark == "--fwmark=0" {
		t.Fatalf("the lb unit has no mark: %q", lbMark)
	}
	for _, want := range []string{
		"--cap_net_admin=yes",
		"--user=65532",
		"--mount_vault=no",
		"--mount_docker=no",
		"--host_networking=yes",
		lbMark,
	} {
		if !strings.Contains(smtpEdgeUnit.serviceUnit, want) {
			t.Errorf("the smtpedge unit lacks %s:\n%s", want, smtpEdgeUnit.serviceUnit)
		}
	}
	for _, absent := range []string{"--rttable", "--dockernet=", "--transparent"} {
		if strings.Contains(smtpEdgeUnit.serviceUnit, absent) {
			t.Errorf("the smtpedge unit carries %s:\n%s", absent, smtpEdgeUnit.serviceUnit)
		}
	}
	for service, serviceUnits := range hostUnits {
		if service == "smtpedge" || service == "lb" {
			continue
		}
		for block, unit := range serviceUnits {
			if strings.Contains(unit.serviceUnit, "--cap_net_admin=yes") || strings.Contains(unit.serviceUnit, "--fwmark=") {
				t.Errorf("%s %s holds the capability or a mark:\n%s", service, block, unit.serviceUnit)
			}
		}
	}
	// the unit is one warpctl's own run accepts
	if _, err := containerIsolationArgs("smtpedge", true, "65532", MOUNT_MODE_NO); err != nil {
		t.Error(err)
	}
}

// With several lb interfaces on its host the block's mark is the first's by
// name, whatever order the config lists them in, so a config always renders
// the same unit; another interface's sending address names that interface's
// table in smtpedge.yml.
func TestSmtpEdgeUnitTakesItsHostsFirstLbInterfaceMark(t *testing.T) {
	servicesYaml := strings.Replace(sidecarServiceBlocksYaml,
		"            edge-0.example.com:\n                eth0:\n                    docker_network: warpeth0\n                    ipv4: 10.0.0.1\n                    ipv6: \"fd00::1\"\n",
		"            edge-0.example.com:\n                eth9:\n                    docker_network: warpeth9\n                    ipv4: 10.0.0.9\n                eth0:\n                    docker_network: warpeth0\n                    ipv4: 10.0.0.1\n                    ipv6: \"fd00::1\"\n", 1)
	if servicesYaml == sidecarServiceBlocksYaml {
		t.Fatal("the fixture's lb interface moved")
	}
	env, _ := setupTestVaultWithTLS(t, []byte(servicesYaml))
	hostUnits := NewSystemdUnits(env, "/srv/warp/test", "/usr/local/sbin/warpctl", true).Generate()["edge-0.example.com"]
	marks := map[string]string{}
	for _, unit := range hostUnits["lb"] {
		for _, field := range strings.Fields(unit.serviceUnit) {
			if strings.HasPrefix(field, "--fwmark=") {
				marks[unit.shortBlock] = field
			}
		}
	}
	if len(marks) != 2 || marks["eth0"] == "" || marks["eth0"] == marks["eth9"] {
		t.Fatalf("the lb units' marks are %v", marks)
	}
	smtpEdgeUnit := hostUnits["smtpedge"]["g1"]
	if smtpEdgeUnit == nil {
		t.Fatalf("no smtpedge unit: %v", hostUnits)
	}
	if !strings.Contains(smtpEdgeUnit.serviceUnit, marks["eth0"]) || strings.Contains(smtpEdgeUnit.serviceUnit, marks["eth9"]) {
		t.Errorf("the smtpedge unit's mark is not eth0's %s:\n%s", marks["eth0"], smtpEdgeUnit.serviceUnit)
	}
}
