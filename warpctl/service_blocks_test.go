// Tests of what warpctl does with §19.4's service blocks, which the recipe in
// warp's README and each service's own W6 task rest on.

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/urnetwork/warp/services"
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

// The mail breakers' credentials for their outside measures, which taskworker's fragment names (QD-1069, owner
// decision 611).
var taskworkerMailBreakerCredentialFiles = []string{"abuse-postmaster-tools.yml", "abuse-snds.yml"}

// taskworker's block as services/sidecar-blocks/taskworker.yml extends it (§19.4's taskworker row; §21.5, §21.16),
// the real fragment applied to a synthetic block as it stands before it: the unit hands warpctl run every vault file
// the block names, the mail breakers' Postmaster Tools and SNDS credentials among them, and run mounts each read only
// where a block's secrets go. While either credential is missing from the vault, run refuses to start the block, which
// is why the owner places both, {} for an account not made yet, before the fragment is applied.
func TestTaskworkerUnitMountsTheMailBreakersCredentials(t *testing.T) {
	fragmentPath := filepath.Join("..", "services", "sidecar-blocks", "taskworker.yml")
	fragmentData, err := os.ReadFile(fragmentPath)
	if err != nil {
		t.Fatal(err)
	}
	fragment, err := services.ParseServicesFragment(fragmentPath, fragmentData)
	if err != nil {
		t.Fatal(err)
	}
	baseYaml := strings.Replace(sidecarServiceBlocksYaml,
		"    services:\n",
		"    services:\n        taskworker:\n            exposed: false\n            ports:\n                - 80\n            blocks:\n                - g1: 1\n", 1)
	if baseYaml == sidecarServiceBlocksYaml {
		t.Fatal("the fixture's services moved")
	}
	result, err := services.ApplyServicesFragments([]byte(baseYaml), "services.yml", fragment)
	if err != nil {
		t.Fatal(err)
	}
	env, vaultDir := setupTestVaultWithTLS(t, result.Text)

	hostUnits := NewSystemdUnits(env, "/srv/warp/test", "/usr/local/sbin/warpctl", true).Generate()["edge-0.example.com"]
	taskworkerUnit := hostUnits["taskworker"]["g1"]
	if taskworkerUnit == nil {
		t.Fatalf("no taskworker unit: %v", hostUnits)
	}
	secretFiles := []string{}
	for _, field := range strings.Fields(taskworkerUnit.serviceUnit) {
		if secretFile, ok := strings.CutPrefix(field, "--secret-file="); ok {
			secretFiles = append(secretFiles, secretFile)
		}
	}
	for _, credentialFile := range taskworkerMailBreakerCredentialFiles {
		if !slices.Contains(secretFiles, credentialFile) {
			t.Errorf("the taskworker unit hands run %q, without %s:\n%s", secretFiles, credentialFile, taskworkerUnit.serviceUnit)
		}
	}

	// with every file in the vault, each is mounted read only where the block's secrets go
	writeSecretFile := func(secretFile string) {
		if err := os.WriteFile(filepath.Join(vaultDir, secretFile), []byte("{}\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, secretFile := range secretFiles {
		writeSecretFile(secretFile)
	}
	vaultHome := filepath.Dir(vaultDir)
	mountArgs, err := scopedSecretMountArgs(vaultHome, env, secretFiles)
	if err != nil {
		t.Fatal(err)
	}
	for _, secretFile := range secretFiles {
		mount := fmt.Sprintf("type=bind,source=%s,target=/srv/warp/secrets/%s,readonly", filepath.Join(vaultDir, secretFile), secretFile)
		if !slices.Contains(mountArgs, mount) {
			t.Errorf("run does not mount %s: %q", secretFile, mountArgs)
		}
	}

	// a credential the vault does not hold stops the block before it starts
	for _, credentialFile := range taskworkerMailBreakerCredentialFiles {
		if err := os.Remove(filepath.Join(vaultDir, credentialFile)); err != nil {
			t.Fatal(err)
		}
		if _, err := scopedSecretMountArgs(vaultHome, env, secretFiles); err == nil || !strings.Contains(err.Error(), credentialFile) {
			t.Errorf("with no %s, run's mounts answer %v", credentialFile, err)
		}
		writeSecretFile(credentialFile)
	}
}

// The monitor's own vault file, whose pager webhook api and taskworker read at start to page §21.8's notices
// (QD-1070, owner decision 612), which both fragments name.
const noticePagerSecretFile = "monitor.yml"

// api's and taskworker's blocks as services/sidecar-blocks/api.yml and taskworker.yml extend them (§19.4's api and
// taskworker rows; §21.8), the real fragments applied to synthetic blocks as they stand before them: each unit hands
// warpctl run monitor.yml beside its other vault files, and run mounts it read only where a block's secrets go. While
// the file is missing from the vault, run refuses to start either block, so the pager's webhook is there whenever
// api or taskworker runs.
func TestApiAndTaskworkerUnitsMountTheNoticePagersFile(t *testing.T) {
	fragments := []*services.ServicesFragment{}
	for _, name := range []string{"api.yml", "taskworker.yml"} {
		fragmentPath := filepath.Join("..", "services", "sidecar-blocks", name)
		fragmentData, err := os.ReadFile(fragmentPath)
		if err != nil {
			t.Fatal(err)
		}
		fragment, err := services.ParseServicesFragment(fragmentPath, fragmentData)
		if err != nil {
			t.Fatal(err)
		}
		fragments = append(fragments, fragment)
	}
	baseYaml := strings.Replace(sidecarServiceBlocksYaml,
		"    services:\n",
		"    services:\n"+
			"        api:\n            ports:\n                - 80\n            blocks:\n                - g1: 1\n"+
			"        taskworker:\n            exposed: false\n            ports:\n                - 80\n            blocks:\n                - g1: 1\n", 1)
	if baseYaml == sidecarServiceBlocksYaml {
		t.Fatal("the fixture's services moved")
	}
	result, err := services.ApplyServicesFragments([]byte(baseYaml), "services.yml", fragments...)
	if err != nil {
		t.Fatal(err)
	}
	env, vaultDir := setupTestVaultWithTLS(t, result.Text)
	vaultHome := filepath.Dir(vaultDir)
	hostUnits := NewSystemdUnits(env, "/srv/warp/test", "/usr/local/sbin/warpctl", true).Generate()["edge-0.example.com"]
	for _, service := range []string{"api", "taskworker"} {
		unit := hostUnits[service]["g1"]
		if unit == nil {
			t.Fatalf("no %s unit: %v", service, hostUnits)
		}
		secretFiles := []string{}
		for _, field := range strings.Fields(unit.serviceUnit) {
			if secretFile, ok := strings.CutPrefix(field, "--secret-file="); ok {
				secretFiles = append(secretFiles, secretFile)
			}
		}
		if !slices.Contains(secretFiles, noticePagerSecretFile) {
			t.Errorf("the %s unit hands run %q, without %s:\n%s", service, secretFiles, noticePagerSecretFile, unit.serviceUnit)
			continue
		}

		// with every file in the vault, the pager's file is mounted read only where the block's secrets go
		for _, secretFile := range secretFiles {
			if err := os.WriteFile(filepath.Join(vaultDir, secretFile), []byte("{}\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		mountArgs, err := scopedSecretMountArgs(vaultHome, env, secretFiles)
		if err != nil {
			t.Fatal(err)
		}
		mount := fmt.Sprintf("type=bind,source=%s,target=/srv/warp/secrets/%s,readonly", filepath.Join(vaultDir, noticePagerSecretFile), noticePagerSecretFile)
		if !slices.Contains(mountArgs, mount) {
			t.Errorf("run does not mount %s for %s: %q", noticePagerSecretFile, service, mountArgs)
		}

		// without it in the vault the block does not start
		if err := os.Remove(filepath.Join(vaultDir, noticePagerSecretFile)); err != nil {
			t.Fatal(err)
		}
		if _, err := scopedSecretMountArgs(vaultHome, env, secretFiles); err == nil || !strings.Contains(err.Error(), noticePagerSecretFile) {
			t.Errorf("with no %s, run's mounts for %s answer %v", noticePagerSecretFile, service, err)
		}
	}
}
