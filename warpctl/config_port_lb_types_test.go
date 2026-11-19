package main

// Tests that load refuses exactly the services files whose port allocation
// (portBlocksOf) would change a port's lb type, which it panics on
// (services validatePortBlockLbTypes).

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/urnetwork/warp/services"
)

// One version of a synthetic edge: the lb on edge-a.example eth1, with lbLines
// under lb, and the api service on one block, with apiLines under api, with
// the allocation ranges portBlocksOf reads. The same shape as the services
// package's tests.
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

// Whether portBlocksOf panics on the file as written, without load's checks,
// and the panic.
func portBlocksOfPanic(t *testing.T, servicesYaml string) (panicked bool, recovered any) {
	t.Helper()
	servicesConfig := &services.ServicesConfig{}
	if err := yaml.Unmarshal([]byte(servicesYaml), servicesConfig); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if recovered = recover(); recovered != nil {
			panicked = true
		}
	}()
	portBlocksOf(servicesConfig, nil)
	return false, nil
}

// Loads the file from a vault of its own, as getServicesConfig does.
func loadPortLbTypeServicesConfig(t *testing.T, servicesYaml string) error {
	t.Helper()
	vaultDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(vaultDir, "test"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(vaultDir, "test", "services.yml"), []byte(servicesYaml), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := services.LoadServicesConfigFrom(vaultDir, "test")
	return err
}

// Each file that changes the lb type of one port block, across versions or in
// one, makes the allocation panic, and load refuses it, so no warpctl command
// or worker reaches the allocation with it. A port that changes lb type on a
// block the other version does not list, or moves from tcp to udp, is
// allocated, and load accepts it.
func TestLoadRefusesExactlyThePortLbTypeChangesTheAllocationPanicsOn(t *testing.T) {
	const (
		lbHttp      = "      ports: [80]\n"
		apiHttp     = "        ports: [80]\n"
		apiHttp8080 = "        ports: [80, 8080]\n"
	)
	versions := func(versionYamls ...string) string {
		return "versions:\n" + strings.Join(versionYamls, "")
	}
	refusedYamls := []string{
		versions(
			portLbTypeVersionYaml(lbHttp, "g1", apiHttp+"        tcp_stream_ports: [8080]\n"),
			portLbTypeVersionYaml(lbHttp, "g1", apiHttp8080),
		),
		versions(
			portLbTypeVersionYaml(lbHttp, "g1", apiHttp8080),
			portLbTypeVersionYaml(lbHttp, "g1", apiHttp+"        tcp_stream_ports: [8080]\n"),
		),
		versions(
			portLbTypeVersionYaml(lbHttp, "g1", apiHttp8080+"        tcp_stream_ports: [8080]\n"),
		),
		versions(
			portLbTypeVersionYaml(lbHttp, "g1", apiHttp+"        hosts: [edge-a.example]\n        external_udp_ports: [4053]\n"),
			portLbTypeVersionYaml(lbHttp, "g1", apiHttp+"        udp_stream_ports: [4053]\n"),
		),
		versions(
			portLbTypeVersionYaml(lbHttp+"      tcp_stream_ports: [8443]\n", "g1", apiHttp),
			portLbTypeVersionYaml("      ports: [80, 8443]\n", "g1", apiHttp),
		),
	}
	for _, servicesYaml := range refusedYamls {
		panicked, recovered := portBlocksOfPanic(t, servicesYaml)
		if !panicked || !strings.Contains(fmt.Sprint(recovered), "The lb type of a port block cannot change.") {
			t.Errorf("the allocation did not panic on an lb type change (%v):\n%s", recovered, servicesYaml)
		}
		if err := loadPortLbTypeServicesConfig(t, servicesYaml); err == nil {
			t.Errorf("load accepted a file the allocation panics on:\n%s", servicesYaml)
		}
	}

	acceptedYamls := []string{
		versions(
			portLbTypeVersionYaml(lbHttp, "g2", apiHttp+"        tcp_stream_ports: [8080]\n"),
			portLbTypeVersionYaml(lbHttp, "g1", apiHttp8080),
		),
		versions(
			portLbTypeVersionYaml(lbHttp, "g1", apiHttp+"        udp_stream_ports: [8080]\n"),
			portLbTypeVersionYaml(lbHttp, "g1", apiHttp8080),
		),
	}
	for _, servicesYaml := range acceptedYamls {
		if panicked, recovered := portBlocksOfPanic(t, servicesYaml); panicked {
			t.Errorf("the allocation panicked (%v):\n%s", recovered, servicesYaml)
		}
		if err := loadPortLbTypeServicesConfig(t, servicesYaml); err != nil {
			t.Errorf("load refused a file the allocation allocates: %v\n%s", err, servicesYaml)
		}
	}
}
