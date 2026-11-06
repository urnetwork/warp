package main

import (
	"fmt"
	"strings"
	"testing"
)

// The service blocks of DESIGN §19.4 in warp's own terms. server and build hold
// W6's artifacts (see warp/README.md's "Adding a service"), but what they plan
// rests on what warpctl does with these blocks, so this is that contract: warp
// accepts each block as §19.4 shapes it, and can run the rollout class D-OPS-11
// gives it. smtpedge omits §19.4's cap_net_admin, which warp grants only to
// proxy today, and dnsedge is on one host, since a block runs on every host of
// its service. The names and addresses are synthetic, and the ports stand in for
// W4's and W7's.
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
