package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/urnetwork/warp/services"
	"github.com/urnetwork/warp/vyos"
)

func syntheticComparisonConfig() *vyos.Config {
	config := syntheticMigrationConfig("eth1", "203.0.113.9/27")
	root := config.Root
	wan := root.Lookup("interfaces", "ethernet", "eth1")
	wan.AddLeafValue("address", "2001:db8:1::2/64")
	port := root.Child("interfaces").Tag("ethernet", "eth2")
	port.SetLeaf("address", "2001:db8:2::1/64")
	root.Child("firewall").Tag("ipv6-name", "WANv6_IN").Tag("rule", "100").Child("destination").SetLeaf("address", "2001:db8:2::10")
	static := root.Child("protocols").Child("static")
	static.Tag("interface-route", "203.0.113.10/32").Tag("next-hop-interface", "eth2")
	static.Tag("route6", "::/0").Tag("next-hop", "2001:db8:1::1").SetLeaf("interface", "eth1")
	static.Tag("route6", "2001:db8:3::/64").Child("blackhole")
	system := root.Child("system")
	system.SetLeaf("gateway-address", "203.0.113.1")
	system.Child("conntrack").SetLeaf("table-size", "1024")
	system.Child("conntrack").SetLeaf("hash-size", "64")
	system.Child("login").Tag("user", "synthetic").Child("authentication").SetLeaf("encrypted-password", "synthetic-password-never-in-output")
	return config
}

func syntheticComparisonFiles(t *testing.T, desired *vyos.Config, running *vyos.Config, saved *vyos.Config) (string, string) {
	t.Helper()
	desiredDir, inDir := t.TempDir(), t.TempDir()
	if desired != nil {
		writeSyntheticMigrationConfig(t, desiredDir, vyosConfigFileName("synthetic-router"), desired)
	}
	if running != nil {
		writeSyntheticMigrationConfig(t, inDir, vyosLiveFileName("synthetic-router"), running)
	}
	if saved != nil {
		writeSyntheticMigrationConfig(t, inDir, vyosSavedFileName("synthetic-router"), saved)
	}
	return desiredDir, inDir
}

func TestVyosCompareConfigCommandUsesOnlySnapshotFiles(t *testing.T) {
	config := syntheticComparisonConfig()
	desiredDir, inDir := syntheticComparisonFiles(t, config, config, config)
	t.Setenv("WARP_HOME", t.TempDir())
	oldArgs, oldWriter := os.Args, Out.Writer()
	defer func() { os.Args = oldArgs; Out.SetOutput(oldWriter) }()
	var output bytes.Buffer
	Out.SetOutput(&output)
	os.Args = []string{"warpctl", "vyos", "compare-config", "synthetic-router", "--desired=" + desiredDir, "--in=" + inDir}
	main()
	var summary vyosComparisonSummary
	if err := json.Unmarshal(output.Bytes(), &summary); err != nil {
		t.Fatal("actual command did not emit only a single JSON document")
	}
	if summary.SchemaVersion != 1 || !summary.Complete || !summary.Running.Complete || !summary.Saved.Complete || summary.Running.Changes != 0 || summary.Saved.Changes != 0 {
		t.Fatal("visible equal snapshots did not establish independent complete comparisons")
	}
	if strings.Contains(output.String(), "synthetic-password-never-in-output") || strings.Contains(output.String(), "encrypted-password") || strings.Contains(output.String(), "set system") {
		t.Fatal("JSON output disclosed private configuration or command text")
	}
}

func TestVyosCompareConfigCountsProtectedDriftWithoutHidingIt(t *testing.T) {
	desired, live := syntheticComparisonConfig(), syntheticComparisonConfig()
	live.Root.Lookup("system", "login", "user", "synthetic", "authentication").SetLeaf("encrypted-password", "synthetic-old-password")
	desiredDir, inDir := syntheticComparisonFiles(t, desired, live, desired)
	summary := vyosCompareSnapshots("synthetic-router", desiredDir, inDir)
	if !summary.Running.Complete || !summary.Running.ProtectedDelete || summary.Running.Deletes != 1 || summary.Running.Sets != 1 || summary.Running.Changes != 2 || summary.Saved.Changes != 0 {
		t.Fatal("protected deletion was hidden or conflated with the saved comparison")
	}
	encoded, err := json.Marshal(summary)
	if err != nil || strings.Contains(string(encoded), "synthetic-old-password") || strings.Contains(string(encoded), "synthetic-password-never-in-output") {
		t.Fatal("private protected drift values reached comparison JSON")
	}
}

func TestVyosCompareConfigMaskedValuesRemainUnknown(t *testing.T) {
	for _, desiredValue := range []string{"synthetic-password-a", "synthetic-password-b", vyos.MaskedSecret} {
		desired, live := syntheticComparisonConfig(), syntheticComparisonConfig()
		desired.Root.Lookup("system", "login", "user", "synthetic", "authentication").SetLeaf("encrypted-password", desiredValue)
		live.Root.Lookup("system", "login", "user", "synthetic", "authentication").SetLeaf("encrypted-password", vyos.MaskedSecret)
		desiredDir, inDir := syntheticComparisonFiles(t, desired, live, live)
		summary := vyosCompareSnapshots("synthetic-router", desiredDir, inDir)
		if summary.Complete || summary.Running.Complete || summary.Running.Changes != 0 || summary.Running.Unverified != 1 || summary.Running.Reason != "concealed-values" || !summary.Topology.Complete {
			t.Fatal("masked equality was asserted or independent topology authority was lost")
		}
	}
}

func TestVyosCompareConfigTopologyOnlyNeedsNoRouterCaptures(t *testing.T) {
	desiredDir, inDir := syntheticComparisonFiles(t, syntheticComparisonConfig(), nil, nil)
	summary := vyosCompareSnapshots("synthetic-router", desiredDir, inDir)
	if summary.Complete || summary.Running.Complete || summary.Saved.Complete || summary.Running.Reason != "input-unavailable" || summary.Saved.Reason != "input-unavailable" || !summary.Topology.Complete || !summary.Topology.Conntrack.Explicit {
		t.Fatal("absent comparisons erased independent desired topology or became healthy")
	}
}

func TestVyosCompareConfigRejectsMalformedAndPartialInputsPrivately(t *testing.T) {
	config := syntheticComparisonConfig()
	for _, testCase := range []struct {
		text   string
		reason string
	}{
		{text: "system {\n secret \"synthetic-secret-do-not-report\n", reason: "input-invalid"},
		{text: "system {\n host-name synthetic-other\n}\n", reason: "hostname-mismatch"},
		{text: "system {\n host-name synthetic-router\n}\n", reason: "input-shape-incomplete"},
		{text: strings.Repeat("x", vyosCompareInputBytes+1), reason: "input-invalid"},
	} {
		desiredDir, inDir := syntheticComparisonFiles(t, config, nil, config)
		if err := os.WriteFile(filepath.Join(inDir, vyosLiveFileName("synthetic-router")), []byte(testCase.text), 0600); err != nil {
			t.Fatal(err)
		}
		summary := vyosCompareSnapshots("synthetic-router", desiredDir, inDir)
		if summary.Running.Complete || summary.Running.Reason != testCase.reason || !summary.Saved.Complete || !summary.Topology.Complete {
			t.Errorf("invalid running input did not preserve independent authorities: %s", testCase.reason)
		}
		encoded, err := json.Marshal(summary)
		if err != nil || strings.Contains(string(encoded), "synthetic-secret-do-not-report") || strings.Contains(string(encoded), "synthetic-other") || strings.Contains(string(encoded), inDir) {
			t.Fatal("an input error disclosed private text or a path")
		}
	}
}

func TestVyosCompareConfigMissingDesiredCannotBecomeHealthy(t *testing.T) {
	desiredDir, inDir := syntheticComparisonFiles(t, nil, syntheticComparisonConfig(), syntheticComparisonConfig())
	summary := vyosCompareSnapshots("synthetic-router", desiredDir, inDir)
	if summary.Complete || summary.Running.Complete || summary.Saved.Complete || summary.Topology.Complete || summary.Topology.Conntrack.Explicit || len(summary.Topology.Neighbors) != 0 {
		t.Fatal("missing desired snapshot inherited an authority from a capture")
	}
	for _, name := range []string{"", "../synthetic-router", "synthetic/router", "Synthetic-Router"} {
		if actual := vyosCompareSnapshots(name, desiredDir, inDir); actual.Complete || actual.Reason != "request-invalid" {
			t.Fatal("invalid target request was not rejected")
		}
	}
}

func TestVyosCompareConfigTopologyExtractsExactSupportedNeighbors(t *testing.T) {
	topology := vyosCompareTopology(syntheticComparisonConfig().Root)
	expected := []vyosComparisonNeighbor{
		{Interface: "eth1", Family: "ipv4", Address: "203.0.113.1", Role: "upstream"},
		{Interface: "eth1", Family: "ipv6", Address: "2001:db8:1::1", Role: "upstream"},
		{Interface: "eth2", Family: "ipv4", Address: "203.0.113.10", Role: "port"},
		{Interface: "eth2", Family: "ipv6", Address: "2001:db8:2::10", Role: "port"},
	}
	if !topology.Complete || !reflect.DeepEqual(topology.Neighbors, expected) || topology.Conntrack != (vyosComparisonConntrack{Explicit: true, TableSize: 1024, HashSize: 64}) {
		t.Fatal("exact supported desired neighbors or capacity were not derived")
	}
}

func TestVyosCompareConfigAmbiguousTopologyPreservesOtherAuthorities(t *testing.T) {
	config := syntheticComparisonConfig()
	config.Root.Child("interfaces").Tag("ethernet", "eth3").SetLeaf("address", "2001:db8:2::2/64")
	desiredDir, inDir := syntheticComparisonFiles(t, config, config, config)
	summary := vyosCompareSnapshots("synthetic-router", desiredDir, inDir)
	if summary.Complete || !summary.Running.Complete || !summary.Saved.Complete || summary.Topology.Complete || len(summary.Topology.Neighbors) != 0 || summary.Topology.Reason != "ipv6-host-interface-ambiguous" || !summary.Topology.Conntrack.Explicit {
		t.Fatal("ambiguous topology was guessed, partially emitted or erased independent authorities")
	}
}

func TestVyosCompareConfigCapacityIsExplicitNotADefault(t *testing.T) {
	for _, value := range []string{"", "0", "-1", "not-a-number", "4294967296"} {
		config := syntheticComparisonConfig()
		config.Root.Lookup("system", "conntrack").SetLeaf("hash-size", value)
		topology := vyosCompareTopology(config.Root)
		if !topology.Complete || topology.Conntrack != (vyosComparisonConntrack{Explicit: true, TableSize: 1024}) {
			t.Fatal("invalid hash size erased the known table size or became a platform default")
		}
	}
}

func TestVyosCompareConfigCapacityFieldsRemainIndependent(t *testing.T) {
	for _, testCase := range []struct {
		table    string
		hash     string
		expected vyosComparisonConntrack
	}{
		{table: "1024", expected: vyosComparisonConntrack{Explicit: true, TableSize: 1024}},
		{hash: "64", expected: vyosComparisonConntrack{Explicit: true, HashSize: 64}},
		{table: "invalid", hash: "64", expected: vyosComparisonConntrack{Explicit: true, HashSize: 64}},
		{expected: vyosComparisonConntrack{}},
	} {
		config := syntheticComparisonConfig()
		config.Root.Lookup("system", "conntrack").SetLeaf("table-size", testCase.table)
		config.Root.Lookup("system", "conntrack").SetLeaf("hash-size", testCase.hash)
		topology := vyosCompareTopology(config.Root)
		if !topology.Complete || topology.Conntrack != testCase.expected {
			t.Fatal("independent explicit capacity field was discarded or defaulted")
		}
	}
}

func TestVyosCompareConfigUnsupportedTopologyNeverPublishesPartialNeighbors(t *testing.T) {
	for _, change := range []func(*vyos.Node){
		func(root *vyos.Node) { root.Child("system").SetLeaf("gateway-address") },
		func(root *vyos.Node) { root.Child("interfaces").Tag("ethernet", "eth2").SetLeaf("address", "dhcp") },
		func(root *vyos.Node) { root.Child("protocols").Child("static").Tag("route", "192.0.2.0/24") },
		func(root *vyos.Node) {
			root.Lookup("protocols", "static", "route6", "::/0", "next-hop", "2001:db8:1::1").SetLeaf("interface", "synthetic-missing")
		},
		func(root *vyos.Node) {
			root.Lookup("interfaces", "ethernet", "eth2").Child("bridge-group").SetLeaf("bridge", "br0")
		},
		func(root *vyos.Node) {
			root.Lookup("firewall", "ipv6-name", "WANv6_IN", "rule", "100", "destination").SetLeaf("address", "2001:db8:9::10")
		},
	} {
		config := syntheticComparisonConfig()
		change(config.Root)
		topology := vyosCompareTopology(config.Root)
		if topology.Complete || len(topology.Neighbors) != 0 || !topology.Conntrack.Explicit {
			t.Fatal("unsupported topology published partial neighbors or lost independent capacity")
		}
	}
}

func TestVyosCompareConfigBridgeRoutesNameNoPhysicalHost(t *testing.T) {
	config := syntheticComparisonConfig()
	config.Root.Child("interfaces").Tag("bridge", "br0").SetLeaf("address", "2001:db8:4::1/64")
	config.Root.Lookup("protocols", "static").Tag("interface-route", "198.51.100.10/32").Tag("next-hop-interface", "br0")
	config.Root.Lookup("protocols", "static").Tag("route6", "2001:db8:5::/64").Tag("next-hop", "2001:db8:4::10").SetLeaf("interface", "br0")
	topology := vyosCompareTopology(config.Root)
	if !topology.Complete || len(topology.Neighbors) != 6 {
		t.Fatal("explicit bridge routes were not retained as next-hop expectations")
	}
	for _, neighbor := range topology.Neighbors[:2] {
		if neighbor.Interface != "br0" || neighbor.Role != "port" {
			t.Fatal("bridge route was guessed to belong to a physical member")
		}
	}
}

func TestVyosCompareConfigBareAdvertisedPrefixIsNotHostInventory(t *testing.T) {
	config := syntheticComparisonConfig()
	config.Root.Child("interfaces").Tag("ethernet", "eth3").Child("ipv6").Child("router-advert").Tag("prefix", "2001:db8:7::/64").SetLeaf("on-link-flag", "true")
	topology := vyosCompareTopology(config.Root)
	if !topology.Complete || topology.Reason != "derived-explicit-neighbors-only" || len(topology.Neighbors) != 4 || !topology.Conntrack.Explicit {
		t.Fatal("bare advertised prefix invented hosts, claimed a full census or erased known neighbor authority")
	}
	for _, neighbor := range topology.Neighbors {
		if neighbor.Interface == "eth3" {
			t.Fatal("bare advertised prefix invented a neighbor")
		}
	}
}

func TestVyosCompareConfigAdvertisedPrefixCanJoinAnExactHost(t *testing.T) {
	config := syntheticComparisonConfig()
	port := config.Root.Lookup("interfaces", "ethernet", "eth2")
	port.SetLeaf("address")
	port.Child("ipv6").Child("router-advert").Tag("prefix", "2001:db8:2::/64").SetLeaf("on-link-flag", "true")
	topology := vyosCompareTopology(config.Root)
	if !topology.Complete || len(topology.Neighbors) != 4 {
		t.Fatal("unambiguous on-link prefix did not join the separately authoritative exact host")
	}
}

func TestVyosCompareConfigConsumesGeneratedEdgeLanAndGatewaySnapshots(t *testing.T) {
	generator, err := newVyosSafetyGenerator(t, func(config *services.ServicesConfig) {
		// A normal spare port is advertised but has no attached exact host.
		router := config.Routers["r-test-1-1"]
		router.LanInterfaces = append(router.LanInterfaces, "eth4")
	}, "")
	if err != nil {
		t.Fatal(err)
	}
	configs, err := generator.GenerateAll()
	if err != nil {
		t.Fatal(err)
	}
	desiredDir, inDir := t.TempDir(), t.TempDir()
	expectedCounts := map[string]int{"r-test-1-1": 6, "r-test-1-2": 4, "r-test-1-3": 2, "r-test-1-gateway-1": 11}
	classes := map[string]bool{}
	for router, config := range configs {
		writeSyntheticMigrationConfig(t, desiredDir, vyosConfigFileName(router), config)
		writeSyntheticMigrationConfig(t, inDir, vyosLiveFileName(router), config)
		writeSyntheticMigrationConfig(t, inDir, vyosSavedFileName(router), config)
		summary := vyosCompareSnapshots(router, desiredDir, inDir)
		if !summary.Complete || summary.Running.Changes != 0 || summary.Saved.Changes != 0 || summary.Running.Unverified != 0 || len(summary.Topology.Neighbors) != expectedCounts[router] {
			t.Fatalf("generated synthetic router %s failed comparison: complete=%t reason=%s neighbors=%d", router, summary.Complete, summary.Topology.Reason, len(summary.Topology.Neighbors))
		}
		upstreamCount := 0
		for _, neighbor := range summary.Topology.Neighbors {
			if neighbor.Role == "upstream" {
				upstreamCount++
			}
			if router == "r-test-1-1" && neighbor.Interface == "eth4" {
				t.Fatal("generated spare port invented a downstream host")
			}
		}
		if upstreamCount != 2 {
			t.Fatal("generated router lost an exact upstream family")
		}
		if (router == "r-test-1-1" || router == "r-test-1-3") && summary.Topology.Reason != "derived-explicit-neighbors-only" {
			t.Fatal("spare or dynamic advertised host coverage was not qualified")
		}
		class, err := generator.Class(router)
		if err != nil {
			t.Fatal(err)
		}
		classes[class] = true
	}
	if len(configs) != 4 || !classes[services.RouterClassEdge] || !classes[services.RouterClassLan] || !classes[services.RouterClassGateway] {
		t.Fatal("generator acceptance did not exercise all three actual router classes")
	}
}
