package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"golang.org/x/exp/maps"
)

// Two lb fronts on edge-0, and two transparent ("direct lb") interfaces in the
// shape of crisp and fireside: the proxy is pinned to the transparent hosts and
// binds their addresses itself, and no lb runs there. The older version is the
// history in which the transparent interfaces came first, so their port
// reservations decide where the later blocks land.
const transparentInterfacesServicesYaml = `
domain: example.com
domains:
    example.com: route53

versions:
-   external_ports: 7000-7200,7443-7449
    internal_ports: 7201-7442,7450-10000
    routing_tables: 100-120
    parallel_block_count: 4
    services_docker_network: testservices
    lb:
        ports:
            - 80
            - 443
        interfaces:
            edge-0.example.com:
                eth0:
                    docker_network: warpeth0
                    concurrent_clients: 1000
                    cores: 4
                    ipv4: 10.0.0.1
                    ipv6: "fd00::1"
                eth1:
                    docker_network: warpeth1
                    concurrent_clients: 1000
                    cores: 4
                    ipv4: 10.0.0.2
            direct-0.example.com:
                eth0:
                    transparent: true
                    docker_network: warpeth0
                    ipv4: 10.0.1.1
                    ipv6: "fd00:1::1"
            direct-1.example.com:
                eth0:
                    transparent: true
                    docker_network: warpeth0
                    ipv4: 10.0.1.2
    host_services:
        direct-0.example.com:
            - proxy
        direct-1.example.com:
            - proxy
    services:
        api:
            ports:
                - 80
            blocks:
                - g1: 1
        proxy:
            hosts:
                - direct-0.example.com
                - direct-1.example.com
            ports:
                - 80
                - 8080
            public_ports:
                8080: socks
            blocks:
                - g1: 1
                - g2: 1
-   external_ports: 7000-7200,7443-7449
    internal_ports: 7201-7442,7450-10000
    routing_tables: 100-120
    parallel_block_count: 4
    services_docker_network: testservices
    lb:
        ports:
            - 80
            - 443
        interfaces:
            direct-0.example.com:
                eth0:
                    transparent: true
                    docker_network: warpeth0
                    ipv4: 10.0.1.1
                    ipv6: "fd00:1::1"
            direct-1.example.com:
                eth0:
                    transparent: true
                    docker_network: warpeth0
                    ipv4: 10.0.1.2
    host_services:
        direct-0.example.com:
            - proxy
        direct-1.example.com:
            - proxy
    services:
        proxy:
            hosts:
                - direct-0.example.com
                - direct-1.example.com
            ports:
                - 80
                - 8080
            public_ports:
                8080: socks
            blocks:
                - g1: 1
                - g2: 1
`

var transparentFixtureFronts = []string{"edge-0.example.com-eth0", "edge-0.example.com-eth1"}

// The routing unit of direct-0's transparent interface, byte for byte as
// warpctl generated it while transparent interfaces were still lb blocks
// (warp 14c5bfb). It keeps the interface's policy routing and masquerade
// for the proxy, so the hosts must see no change in it.
const transparentFixtureRoutingUnit = `[Unit]
Description=Warpctl test lb direct-0.example.com-eth0
Requires=network-online.target
After=network-online.target
Requires=docker.service
After=docker.service
ReloadPropagatedFrom=network-online.target docker.service

[Service]
Type=simple
Environment="WARP_HOME=/srv/warp/test"
ExecStart=/usr/local/sbin/warpctl service run test lb direct-0.example.com-eth0 --rttable="eth0:100" --dockernet=warpeth0 --transparent=true --fwmark=100 --portblocks="80:7000:7201-7204;443:7001:7205-7208" --services_dockernet=testservices --mount_vault=yes --mount_config=no --mount_site=no --status=standard --domain=example.com --host_networking=yes
ExecStop=/bin/kill -s TERM $MAINPID
TimeoutStopSec=60
Restart=always
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target`

// Runs the real CLI and returns what it printed and the value it panicked
// with, if any.
func runWarpctlCommand(t *testing.T, args ...string) (output string, failure any) {
	t.Helper()
	previousArgs := os.Args
	previousOut, previousErr := Out.Writer(), Err.Writer()
	buffer := &bytes.Buffer{}
	Out.SetOutput(buffer)
	Err.SetOutput(io.Discard)
	defer func() {
		os.Args = previousArgs
		Out.SetOutput(previousOut)
		Err.SetOutput(previousErr)
		failure = recover()
		output = buffer.String()
	}()
	os.Args = append([]string{"warpctl"}, args...)
	main()
	return
}

func readDirNames(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	names := []string{}
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	slices.Sort(names)
	return names
}

// No lb runs on a transparent interface, so it is not an lb block. The
// services placed behind it keep their blocks.
func TestTransparentInterfacesAreNotLbBlocks(t *testing.T) {
	env := setupTestVault(t, []byte(transparentInterfacesServicesYaml))

	lbBlocks := maps.Keys(getBlockInfos(env)["lb"])
	slices.Sort(lbBlocks)
	if !slices.Equal(lbBlocks, transparentFixtureFronts) {
		t.Fatalf("lb blocks = %v, want the fronts %v", lbBlocks, transparentFixtureFronts)
	}
	blocks, transparent := getBlocksSummary(env, "lb")
	if !slices.Equal(blocks, transparentFixtureFronts) || transparent {
		t.Fatalf("lb blocks summary = %v transparent=%t, want %v transparent=false", blocks, transparent, transparentFixtureFronts)
	}

	output, failure := runWarpctlCommand(t, "lb", "blocks", env)
	if failure != nil {
		t.Fatalf("lb blocks: %v", failure)
	}
	if got := strings.Fields(output); !slices.Equal(got, transparentFixtureFronts) {
		t.Fatalf("lb blocks printed %v, want %v", got, transparentFixtureFronts)
	}

	// the proxy runs behind the transparent interfaces only, so no lb can
	// reach its status
	blocks, transparent = getBlocksSummary(env, "proxy")
	if !slices.Equal(blocks, []string{"g1", "g2"}) || !transparent {
		t.Fatalf("proxy blocks summary = %v transparent=%t, want [g1 g2] transparent=true", blocks, transparent)
	}
	blocks, transparent = getBlocksSummary(env, "api")
	if !slices.Equal(blocks, []string{"g1"}) || transparent {
		t.Fatalf("api blocks summary = %v transparent=%t, want [g1] transparent=false", blocks, transparent)
	}
}

// `lb create-config` writes one config per front and none for a transparent
// interface, even when asked for it by name.
func TestLbCreateConfigWritesOnlyTheFronts(t *testing.T) {
	env, _ := setupTestVaultWithTLS(t, []byte(transparentInterfacesServicesYaml))

	outDir := t.TempDir()
	if _, failure := runWarpctlCommand(t, "lb", "create-config", env, "--out="+outDir); failure != nil {
		t.Fatalf("lb create-config: %v", failure)
	}
	want := []string{"edge-0.example.com-eth0.conf", "edge-0.example.com-eth1.conf"}
	if got := readDirNames(t, outDir); !slices.Equal(got, want) {
		t.Fatalf("lb create-config wrote %v, want %v", got, want)
	}

	outDir = t.TempDir()
	if _, failure := runWarpctlCommand(t, "lb", "create-config", env, "direct-0.example.com-eth0", "--out="+outDir); failure != nil {
		t.Fatalf("lb create-config direct-0.example.com-eth0: %v", failure)
	}
	if got := readDirNames(t, outDir); len(got) != 0 {
		t.Fatalf("lb create-config direct-0.example.com-eth0 wrote %v, want nothing", got)
	}
}

// An lb deploy promotes the fronts only. A transparent interface is no target,
// so a rollout never waits on an lb that cannot start there.
func TestDeployLbTargetsOnlyTheFronts(t *testing.T) {
	t.Run("percent", func(t *testing.T) {
		f := newDeployFixture(t, []byte(transparentInterfacesServicesYaml), "")
		if failure := f.deploy("lb", "--percent=100", "--timeout=0"); failure != nil {
			t.Fatalf("lb deploy: %v", failure)
		}
		want := []string{}
		for _, block := range transparentFixtureFronts {
			want = append(want,
				fmt.Sprintf("tag:fixture/test-lb:%s-latest<-fixture/test-lb:2.0.0", block),
				fmt.Sprintf("version:test-lb-%s=2.0.0", block),
			)
		}
		f.assertEvents(t, want)
	})
	t.Run("named", func(t *testing.T) {
		f := newDeployFixture(t, []byte(transparentInterfacesServicesYaml), "")
		if failure := f.deploy("lb", "direct-0.example.com-eth0", "--timeout=0"); failure != "No matching blocks." {
			t.Fatalf("lb deploy to a transparent interface: failure = %v, want No matching blocks.", failure)
		}
		f.assertEvents(t, nil)
	})
}

// `ls versions` lists the fronts' deployment records and never reads one for a
// transparent interface.
func TestLsVersionsListsOnlyTheFronts(t *testing.T) {
	env := setupTestVault(t, []byte(transparentInterfacesServicesYaml))
	var mu sync.Mutex
	readKeys := []string{}
	records := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Amz-Target") != "DynamoDB_20120810.GetItem" {
			t.Errorf("unexpected deployment record operation %q", r.Header.Get("X-Amz-Target"))
			http.Error(w, "unexpected operation", http.StatusBadRequest)
			return
		}
		var read struct {
			Key map[string]struct{ S string }
		}
		if err := json.NewDecoder(r.Body).Decode(&read); err != nil {
			t.Error(err)
			return
		}
		mu.Lock()
		readKeys = append(readKeys, read.Key["env-service-block"].S)
		mu.Unlock()
		w.Header().Set("Content-Type", "application/x-amz-json-1.0")
		io.WriteString(w, `{"Item":{"version":{"S":"2.0.0"}}}`)
	}))
	t.Cleanup(records.Close)
	useLoopbackDynamo(t, os.Getenv("WARP_HOME"), records.URL)

	output, failure := runWarpctlCommand(t, "ls", "versions", env, "lb")
	if failure != nil {
		t.Fatalf("ls versions: %v", failure)
	}
	want := "[lb]\n[lb][edge-0.example.com-eth0] 2.0.0\n[lb][edge-0.example.com-eth1] 2.0.0\n"
	if output != want {
		t.Fatalf("ls versions printed:\n%s\nwant:\n%s", output, want)
	}
	mu.Lock()
	defer mu.Unlock()
	if want := []string{"test-lb-edge-0.example.com-eth0", "test-lb-edge-0.example.com-eth1"}; !slices.Equal(readKeys, want) {
		t.Fatalf("ls versions read the records %v, want %v", readKeys, want)
	}
}

// The transparent interface keeps the unit that keeps its routing, exactly as
// before, and the services behind it route by the same table and mark.
func TestTransparentInterfaceKeepsItsRoutingUnit(t *testing.T) {
	env := setupTestVault(t, []byte(transparentInterfacesServicesYaml))
	outDir := t.TempDir()
	if _, failure := runWarpctlCommand(t,
		"service", "create-units", env,
		"--out="+outDir,
		"--target_warp_home=/srv/warp/test",
		"--target_warpctl=/usr/local/sbin/warpctl",
	); failure != nil {
		t.Fatalf("service create-units: %v", failure)
	}

	for host, want := range map[string][]string{
		"direct-0.example.com": {"warp-test-config-updater-main.service", "warp-test-lb-eth0.service", "warp-test-proxy-eth0-g1.service", "warp-test-proxy-eth0-g2.service"},
		"direct-1.example.com": {"warp-test-config-updater-main.service", "warp-test-lb-eth0.service", "warp-test-proxy-eth0-g1.service", "warp-test-proxy-eth0-g2.service"},
		"edge-0.example.com":   {"warp-test-api-g1.service", "warp-test-config-updater-main.service", "warp-test-lb-eth0.service", "warp-test-lb-eth1.service"},
	} {
		if got := readDirNames(t, filepath.Join(outDir, host)); !slices.Equal(got, want) {
			t.Fatalf("%s units = %v, want %v", host, got, want)
		}
	}
	if got := readDirNames(t, outDir); !slices.Equal(got, []string{"direct-0.example.com", "direct-1.example.com", "edge-0.example.com"}) {
		t.Fatalf("create-units hosts = %v", got)
	}

	routingUnit, err := os.ReadFile(filepath.Join(outDir, "direct-0.example.com", "warp-test-lb-eth0.service"))
	if err != nil {
		t.Fatal(err)
	}
	if string(routingUnit) != transparentFixtureRoutingUnit {
		t.Fatalf("direct-0 routing unit changed:\n%s\nwant:\n%s", routingUnit, transparentFixtureRoutingUnit)
	}

	for _, block := range []string{"g1", "g2"} {
		proxyUnit, err := os.ReadFile(filepath.Join(outDir, "direct-0.example.com", fmt.Sprintf("warp-test-proxy-eth0-%s.service", block)))
		if err != nil {
			t.Fatal(err)
		}
		if want := `--rttable="eth0:100" --dockernet=warpeth0 --transparent=true --fwmark=100 `; !strings.Contains(string(proxyUnit), want) {
			t.Fatalf("proxy %s unit does not route by the interface's table:\n%s", block, proxyUnit)
		}
	}
}

// A transparent interface is not an lb block, but it keeps its routing table
// and its lb port reservations. Dropping the reservations would move every
// block allocated after it: here the proxy would take 7000-7003 and the
// front on edge-0 would move off 7000 and 7001, a new port for every running
// service the next time its units are generated.
func TestTransparentInterfacesKeepTheirAllocation(t *testing.T) {
	env := setupTestVault(t, []byte(transparentInterfacesServicesYaml))
	portBlocks := getPortBlocks(env)
	for _, want := range []struct {
		host          string
		service       string
		block         string
		port          int
		externalPort  int
		internalPorts string
		routingTable  int
	}{
		{"direct-0.example.com", "lb", "direct-0.example.com-eth0", 80, 7000, "7201-7204", 100},
		{"direct-0.example.com", "lb", "direct-0.example.com-eth0", 443, 7001, "7205-7208", 100},
		{"direct-1.example.com", "lb", "direct-1.example.com-eth0", 80, 7000, "7201-7204", 100},
		{"direct-1.example.com", "lb", "direct-1.example.com-eth0", 443, 7001, "7205-7208", 100},
		{"", "proxy", "g1", 80, 7002, "7209-7212", 0},
		{"", "proxy", "g1", 8080, 7003, "7213-7216", 0},
		{"", "proxy", "g2", 80, 7004, "7217-7220", 0},
		{"", "proxy", "g2", 8080, 7005, "7221-7224", 0},
		{"edge-0.example.com", "lb", "edge-0.example.com-eth0", 80, 7000, "7201-7204", 100},
		{"edge-0.example.com", "lb", "edge-0.example.com-eth0", 443, 7001, "7205-7208", 100},
		{"edge-0.example.com", "lb", "edge-0.example.com-eth1", 80, 7006, "7225-7228", 101},
		{"edge-0.example.com", "lb", "edge-0.example.com-eth1", 443, 7007, "7229-7232", 101},
		{"", "api", "g1", 80, 7008, "7233-7236", 0},
	} {
		portBlock, ok := portBlocks[want.host][want.service][want.block][want.port]
		if !ok {
			t.Fatalf("%s %s %s port %d has no allocation", want.host, want.service, want.block, want.port)
		}
		got := fmt.Sprintf("%d:%s rt %d", portBlock.externalPort, collapsePorts(portBlock.internalPorts), portBlock.routingTable)
		if wantStr := fmt.Sprintf("%d:%s rt %d", want.externalPort, want.internalPorts, want.routingTable); got != wantStr {
			t.Fatalf("%s %s %s port %d = %s, want %s", want.host, want.service, want.block, want.port, got, wantStr)
		}
	}
}
