package main

// Tests of the lb_alt units, port blocks and lb configs (lbalt_worker.go;
// server/LBALT-IMPL.md §2.2, §2.3), and of the flags the units carry.

import (
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/docopt/docopt-go"

	"github.com/urnetwork/warp/services"
)

// Two edges in the shape of main's (server/LBALT.md §3.1): edge-a has two
// front interfaces and edge-b one. connect is behind them on udp 443 and
// 4053, public udp 53 is forwarded to 4053, and connect has main's five
// weighted blocks; api has one. The slots are the lb_alt lines of edge-a eth1,
// edge-a eth2 and connect (lbAltUnitsYaml).
const lbAltUnitsServicesYaml = `
domain: example.com
domains:
    example.com: route53
versions:
-   external_ports: 7000-7200
    internal_ports: 7201-7999
    routing_tables: 100-120
    parallel_block_count: 4
    services_docker_network: warpservices
    lb:
        ports:
            - 80
            - 443
        udp_stream_port_services:
            443: connect
            4053: connect
        udp_forward_ports:
            53: 4053
        interfaces:
            edge-a.example:
                eth1:
                    docker_network: warpeth1
                    ipv4: 198.51.100.1
                    ipv6: "2001:db8:1::1"
                    cores: 4
                    concurrent_clients: 1000
%s
                eth2:
                    docker_network: warpeth2
                    ipv4: 198.51.100.2
                    cores: 4
                    concurrent_clients: 1000
%s
            edge-b.example:
                eth1:
                    docker_network: warpeth1
                    ipv4: 203.0.113.1
                    ipv6: "2001:db8:2::1"
                    cores: 4
                    concurrent_clients: 1000
    services:
        connect:
%s
            ports:
                - 80
                - 5080
            udp_stream_ports:
                - 443
                - 4053
            blocks:
                - beta: 1
                - g1: 24
                - g2: 25
                - g3: 25
                - g4: 25
        api:
            ports:
                - 80
            blocks:
                - g1: 1
`

// The lb_alt values of lbAltUnitsServicesYaml's slots; "" leaves a setting
// out.
type lbAltUnitsSettings struct {
	edgeAEth1 string
	edgeAEth2 string
	connect   string
}

func lbAltUnitsYaml(settings lbAltUnitsSettings) []byte {
	line := func(indent int, value string) string {
		if value == "" {
			return ""
		}
		return strings.Repeat(" ", indent) + "lb_alt: " + value
	}
	return []byte(fmt.Sprintf(
		lbAltUnitsServicesYaml,
		line(20, settings.edgeAEth1),
		line(20, settings.edgeAEth2),
		line(12, settings.connect),
	))
}

// main's connect blocks as --lbaltblocks carries them
const lbAltUnitsBlocksArg = `--lbaltblocks="beta:1;g1:24;g2:25;g3:25;g4:25"`

func lbAltGenerateUnits(t *testing.T, settings lbAltUnitsSettings) map[string]map[string]map[string]*Units {
	t.Helper()
	env := setupTestVault(t, lbAltUnitsYaml(settings))
	return NewSystemdUnits(env, "/srv/warp/test", "/usr/local/sbin/warpctl", true).Generate()
}

// The ExecStart arguments of a unit after the warpctl binary, with the double
// quotes systemd removes when it splits the command line removed. No value in
// a generated unit holds a space.
func lbAltUnitArgs(t *testing.T, unit string) []string {
	t.Helper()
	for _, line := range strings.Split(unit, "\n") {
		if command, ok := strings.CutPrefix(line, "ExecStart="); ok {
			args := []string{}
			for _, field := range strings.Fields(command)[1:] {
				args = append(args, strings.ReplaceAll(field, `"`, ""))
			}
			return args
		}
	}
	t.Fatalf("unit has no ExecStart:\n%s", unit)
	return nil
}

// The arguments of a unit's ExecStart that start with prefix.
func lbAltUnitArgsWithPrefix(t *testing.T, unit string, prefix string) []string {
	t.Helper()
	args := []string{}
	for _, field := range strings.Fields(unit) {
		if strings.HasPrefix(field, prefix) {
			args = append(args, field)
		}
	}
	return args
}

// Every lb interface of a host lb_alt is in effect on gets the routing-only
// flag and the split's blocks, in services.ServiceBlockWeights order, beside
// its routing flags, which stay those of a non-transparent lb. connect's
// blocks bind every lb interface of their host. The host's lb units still
// count as non-transparent lbs, so the host keeps its plain service units,
// connect's and api's, and gets no per-interface ones.
func TestLbAltCreateUnitsOnAnAllLbAltHost(t *testing.T) {
	hostsUnits := lbAltGenerateUnits(t, lbAltUnitsSettings{connect: "true"})

	for host, wantNets := range map[string]string{
		"edge-a.example": `--lbaltnets="eth1:warpeth1;eth2:warpeth2"`,
		"edge-b.example": `--lbaltnets="eth1:warpeth1"`,
	} {
		hostUnits := hostsUnits[host]
		if got, want := slices.Sorted(maps.Keys(hostUnits)), []string{"api", "config-updater", "connect", "lb"}; !slices.Equal(got, want) {
			t.Fatalf("%s unit groups = %v, want %v", host, got, want)
		}
		for block, lbUnits := range hostUnits["lb"] {
			unit := lbUnits.serviceUnit
			for _, want := range []string{"--transparent=false", "--lbalt=true", lbAltUnitsBlocksArg} {
				if got := lbAltUnitArgsWithPrefix(t, unit, strings.SplitN(want, "=", 2)[0]+"="); !slices.Equal(got, []string{want}) {
					t.Errorf("%s lb unit carries %v, want %s:\n%s", block, got, want, unit)
				}
			}
			if !strings.Contains(unit, " --fwmark=") || !strings.Contains(unit, " --rttable=") {
				t.Errorf("%s lb unit lost its routing flags:\n%s", block, unit)
			}
		}
		for block, connectUnits := range hostUnits["connect"] {
			unit := connectUnits.serviceUnit
			if got := lbAltUnitArgsWithPrefix(t, unit, "--lbaltnets="); !slices.Equal(got, []string{wantNets}) {
				t.Errorf("%s connect %s unit carries %v, want %s:\n%s", host, block, got, wantNets, unit)
			}
			for _, flag := range []string{"--lbalt=", "--lbaltblocks=", "--fwmark=", "--rttable=", "--dockernet=", "--transparent="} {
				if strings.Contains(unit, " "+flag) {
					t.Errorf("%s connect %s unit carries %s:\n%s", host, block, flag, unit)
				}
			}
		}
		if got := slices.Sorted(maps.Keys(hostUnits["connect"])); !slices.Equal(got, []string{"beta", "g1", "g2", "g3", "g4"}) {
			t.Errorf("%s connect units = %v", host, got)
		}
		for block, apiUnits := range hostUnits["api"] {
			if strings.Contains(apiUnits.serviceUnit, "--lbalt") {
				t.Errorf("%s api %s unit carries an lb_alt flag:\n%s", host, block, apiUnits.serviceUnit)
			}
		}
	}
}

// With connect's default declared off and one interface turned on by its
// override, only that interface's lb unit is lb_alt. connect on the host binds
// both interfaces, so turning the other on later needs no connect redeploy.
// edge-b has no lb_alt interface, so its units are nginx units.
func TestLbAltCreateUnitsOnAMixedHost(t *testing.T) {
	hostsUnits := lbAltGenerateUnits(t, lbAltUnitsSettings{edgeAEth1: "true", connect: "false"})

	lbAltUnit := hostsUnits["edge-a.example"]["lb"]["edge-a.example-eth1"].serviceUnit
	if got := lbAltUnitArgsWithPrefix(t, lbAltUnit, "--lbalt"); !slices.Equal(got, []string{"--lbalt=true", lbAltUnitsBlocksArg}) {
		t.Fatalf("edge-a eth1 lb unit carries %v:\n%s", got, lbAltUnit)
	}
	for _, block := range []string{"edge-a.example-eth2"} {
		unit := hostsUnits["edge-a.example"]["lb"][block].serviceUnit
		if strings.Contains(unit, "--lbalt") {
			t.Fatalf("%s lb unit is lb_alt:\n%s", block, unit)
		}
	}
	for block, connectUnits := range hostsUnits["edge-a.example"]["connect"] {
		if got := lbAltUnitArgsWithPrefix(t, connectUnits.serviceUnit, "--lbaltnets="); !slices.Equal(got, []string{`--lbaltnets="eth1:warpeth1;eth2:warpeth2"`}) {
			t.Fatalf("edge-a connect %s unit carries %v:\n%s", block, got, connectUnits.serviceUnit)
		}
	}
	for service, serviceUnits := range hostsUnits["edge-b.example"] {
		for block, units := range serviceUnits {
			if strings.Contains(units.serviceUnit, "--lbalt") {
				t.Fatalf("edge-b %s %s unit carries an lb_alt flag:\n%s", service, block, units.serviceUnit)
			}
		}
	}
}

// A per-interface flip on a host lb_alt stays on (§2.2) changes only that
// interface's lb unit: turning a second interface on under a declared-off
// default, and the rollback switch, false under an on default. Every other
// unit of every host is byte for byte what it was, so no connect block
// redeploys.
func TestLbAltInterfaceFlipChangesOnlyItsLbUnit(t *testing.T) {
	for _, flip := range []struct {
		before      lbAltUnitsSettings
		after       lbAltUnitsSettings
		changedUnit string
		afterLbAlt  bool
	}{
		{
			before:      lbAltUnitsSettings{edgeAEth1: "true", connect: "false"},
			after:       lbAltUnitsSettings{edgeAEth1: "true", edgeAEth2: "true", connect: "false"},
			changedUnit: "edge-a.example-eth2",
			afterLbAlt:  true,
		},
		{
			before:      lbAltUnitsSettings{connect: "true"},
			after:       lbAltUnitsSettings{edgeAEth1: "false", connect: "true"},
			changedUnit: "edge-a.example-eth1",
			afterLbAlt:  false,
		},
	} {
		beforeUnits := lbAltGenerateUnits(t, flip.before)
		afterUnits := lbAltGenerateUnits(t, flip.after)
		changed := []string{}
		for host, serviceUnits := range afterUnits {
			if !reflect.DeepEqual(slices.Sorted(maps.Keys(serviceUnits)), slices.Sorted(maps.Keys(beforeUnits[host]))) {
				t.Fatalf("%v -> %v: %s unit groups changed", flip.before, flip.after, host)
			}
			for service, blockUnits := range serviceUnits {
				if !reflect.DeepEqual(slices.Sorted(maps.Keys(blockUnits)), slices.Sorted(maps.Keys(beforeUnits[host][service]))) {
					t.Fatalf("%v -> %v: %s %s units changed", flip.before, flip.after, host, service)
				}
				for block, units := range blockUnits {
					if units.serviceUnit != beforeUnits[host][service][block].serviceUnit {
						changed = append(changed, fmt.Sprintf("%s %s %s", host, service, block))
					}
				}
			}
		}
		if want := []string{"edge-a.example lb " + flip.changedUnit}; !slices.Equal(changed, want) {
			t.Fatalf("%v -> %v changed the units %v, want only %v", flip.before, flip.after, changed, want)
		}
		unit := afterUnits["edge-a.example"]["lb"][flip.changedUnit].serviceUnit
		if strings.Contains(unit, "--lbalt=true") != flip.afterLbAlt {
			t.Fatalf("%v -> %v: %s lb_alt = %t, want %t:\n%s", flip.before, flip.after, flip.changedUnit, !flip.afterLbAlt, flip.afterLbAlt, unit)
		}
	}
}

// connect's public tcp 443 is allocated as its own lb type, on the port block
// of service port 443 that udp 443 already has: the same external port and
// internal ports, so declaring lb_alt moves no port of any block on any host.
// The nginx http generator does not see the tcp side.
func TestLbAltPortBlockSharesServicePort443(t *testing.T) {
	env := setupTestVault(t, lbAltUnitsYaml(lbAltUnitsSettings{}))
	plainPortBlocks := getPortBlocks(env)
	env = setupTestVault(t, lbAltUnitsYaml(lbAltUnitsSettings{connect: "false"}))
	lbAltPortBlocks := getPortBlocks(env)

	if got, want := collectPortAssignments(lbAltPortBlocks), collectPortAssignments(plainPortBlocks); !reflect.DeepEqual(got, want) {
		t.Fatalf("declaring lb_alt moved ports:\n%v\nwant:\n%v", got, want)
	}
	for _, block := range []string{"beta", "g1", "g2", "g3", "g4"} {
		portBlock := lbAltPortBlocks[""]["connect"][block][443]
		if portBlock == nil {
			t.Fatalf("connect %s has no port block for 443", block)
		}
		if want := map[string]string{"tcp": lbAltWorkerTcpLbType, "udp": "stream"}; !reflect.DeepEqual(portBlock.lbTypes, want) {
			t.Fatalf("connect %s 443 lb types = %v, want %v", block, portBlock.lbTypes, want)
		}
		if want := map[string]bool{"tcp": true, "udp": true}; !reflect.DeepEqual(portBlock.externalPortTypes, want) {
			t.Fatalf("connect %s 443 port types = %v, want %v", block, portBlock.externalPortTypes, want)
		}
		if want := map[string]string{"udp": "stream"}; !reflect.DeepEqual(plainPortBlocks[""]["connect"][block][443].lbTypes, want) {
			t.Fatalf("connect %s 443 lb types without lb_alt = %v, want %v", block, plainPortBlocks[""]["connect"][block][443].lbTypes, want)
		}
	}
	for _, service := range []string{"api"} {
		for block, portBlocks := range lbAltPortBlocks[""][service] {
			if _, ok := portBlocks[443]; ok {
				t.Fatalf("%s %s got a 443 port block", service, block)
			}
		}
	}

	nginxConfig := &NginxConfig{
		env:            env,
		servicesConfig: getServicesConfig(env),
		portBlocks:     lbAltPortBlocks,
		blockInfos:     getBlockInfos(env),
		lbBlockInfo:    getBlockInfos(env)["lb"]["edge-a.example-eth1"],
	}
	httpPortBlocks := nginxConfig.httpPortBlocks()
	for block, portBlocks := range httpPortBlocks["connect"] {
		if got := slices.Sorted(maps.Keys(portBlocks)); !slices.Equal(got, []int{80, 5080}) {
			t.Fatalf("nginx http ports of connect %s = %v, want [80 5080]", block, got)
		}
	}
}

// `lb create-config` writes the same nginx configs whether connect declares
// lb_alt or not, and an lb_alt interface keeps its config and its place in
// the lb blocks: a rollback deploys that config.
func TestLbAltLbCreateConfigIsUnchanged(t *testing.T) {
	createConfig := func(settings lbAltUnitsSettings) map[string]string {
		env, _ := setupTestVaultWithTLS(t, lbAltUnitsYaml(settings))
		outDir := t.TempDir()
		if _, failure := runWarpctlCommand(t, "lb", "create-config", env, "--out="+outDir); failure != nil {
			t.Fatalf("lb create-config: %v", failure)
		}
		configs := map[string]string{}
		for _, name := range readDirNames(t, outDir) {
			config, err := os.ReadFile(filepath.Join(outDir, name))
			if err != nil {
				t.Fatal(err)
			}
			configs[name] = string(config)
		}
		return configs
	}
	plainConfigs := createConfig(lbAltUnitsSettings{})
	lbAltConfigs := createConfig(lbAltUnitsSettings{connect: "true"})
	want := []string{"edge-a.example-eth1.conf", "edge-a.example-eth2.conf", "edge-b.example-eth1.conf"}
	if got := slices.Sorted(maps.Keys(lbAltConfigs)); !slices.Equal(got, want) {
		t.Fatalf("lb create-config wrote %v under lb_alt, want %v", got, want)
	}
	for name, config := range plainConfigs {
		if lbAltConfigs[name] != config {
			t.Fatalf("%s changed under lb_alt:\n%s\nwant:\n%s", name, lbAltConfigs[name], config)
		}
	}

	env := setupTestVault(t, lbAltUnitsYaml(lbAltUnitsSettings{connect: "true"}))
	if got := slices.Sorted(maps.Keys(getBlockInfos(env)["lb"])); !slices.Equal(got, []string{"edge-a.example-eth1", "edge-a.example-eth2", "edge-b.example-eth1"}) {
		t.Fatalf("lb blocks under lb_alt = %v", got)
	}
	if _, transparent := getBlocksSummary(env, "connect"); transparent {
		t.Fatal("connect is transparent under lb_alt, so deploys would not poll its blocks")
	}
}

// Looks addresses up from a fixed table, as getNetworkInterfaces would on a
// host: name -> IPv4 addresses, IPv6 addresses.
func lbAltFakeNetworkInterfaces(addresses map[string][2][]string) func(string) ([]*NetworkInterface, []*NetworkInterface, error) {
	return func(name string) ([]*NetworkInterface, []*NetworkInterface, error) {
		familyAddresses, ok := addresses[name]
		if !ok {
			return nil, nil, fmt.Errorf("Could not find interface for %s", name)
		}
		families := [2][]*NetworkInterface{{}, {}}
		for i, ips := range familyAddresses {
			for _, ip := range ips {
				families[i] = append(families[i], &NetworkInterface{
					interfaceName: name,
					interfaceIp:   ip,
				})
			}
		}
		return families[0], families[1], nil
	}
}

// edge-a's interfaces and bridges in lbAltUnitsServicesYaml
var lbAltFakeEdgeAAddresses = map[string][2][]string{
	"eth1":     {{"198.51.100.1"}, {"2001:db8:1::1"}},
	"eth2":     {{"198.51.100.2"}, {}},
	"warpeth1": {{"192.0.2.1"}, {"2001:db8:f1::1"}},
	"warpeth2": {{"192.0.2.65"}, {"2001:db8:f2::1"}},
}

// Parses a unit's ExecStart with the real usage, as `service run` does.
func lbAltParseUnitOpts(t *testing.T, unit string) docopt.Opts {
	t.Helper()
	parser := &docopt.Parser{HelpHandler: docopt.NoHelpHandler}
	opts, err := parser.ParseArgs(usage, lbAltUnitArgs(t, unit), "")
	if err != nil {
		t.Fatalf("usage refuses the unit: %s\n%s", err, unit)
	}
	return opts
}

// The flags the generator writes are the ones `service run` accepts: the
// lb_alt lb unit parses to the routing-only flag and its blocks, and a
// connect unit to every interface of its host, each with its own public
// addresses and its docker network's bridge addresses.
func TestLbAltWorkerParsesItsGeneratedUnits(t *testing.T) {
	hostsUnits := lbAltGenerateUnits(t, lbAltUnitsSettings{edgeAEth1: "true", connect: "false"})
	loadNetworkInterfaces := lbAltFakeNetworkInterfaces(lbAltFakeEdgeAAddresses)

	routingTable := &RoutingTable{interfaceName: "eth1", tableNumber: 100}
	lbAlt, lbAltInterfaces, lbAltBlocks := parseLbAltWorkerFlags(
		lbAltParseUnitOpts(t, hostsUnits["edge-a.example"]["lb"]["edge-a.example-eth1"].serviceUnit),
		"lb",
		routingTable,
		loadNetworkInterfaces,
	)
	wantBlocks := []services.BlockWeight{
		{Block: "beta", Weight: 1},
		{Block: "g1", Weight: 24},
		{Block: "g2", Weight: 25},
		{Block: "g3", Weight: 25},
		{Block: "g4", Weight: 25},
	}
	if !lbAlt || lbAltInterfaces != nil || !reflect.DeepEqual(lbAltBlocks, wantBlocks) {
		t.Fatalf("lb unit parsed to lb_alt %t, interfaces %v, blocks %v", lbAlt, lbAltInterfaces, lbAltBlocks)
	}

	lbAlt, lbAltInterfaces, lbAltBlocks = parseLbAltWorkerFlags(
		lbAltParseUnitOpts(t, hostsUnits["edge-a.example"]["lb"]["edge-a.example-eth2"].serviceUnit),
		"lb",
		routingTable,
		loadNetworkInterfaces,
	)
	if lbAlt || lbAltInterfaces != nil || lbAltBlocks != nil {
		t.Fatalf("nginx lb unit parsed to lb_alt %t, interfaces %v, blocks %v", lbAlt, lbAltInterfaces, lbAltBlocks)
	}

	lbAlt, lbAltInterfaces, lbAltBlocks = parseLbAltWorkerFlags(
		lbAltParseUnitOpts(t, hostsUnits["edge-a.example"]["connect"]["g1"].serviceUnit),
		"connect",
		nil,
		loadNetworkInterfaces,
	)
	if lbAlt || lbAltBlocks != nil {
		t.Fatalf("connect unit parsed to lb_alt %t, blocks %v", lbAlt, lbAltBlocks)
	}
	got := []string{}
	for _, lbAltInterface := range lbAltInterfaces {
		split := lbAltInterface.splitInterface()
		got = append(got, fmt.Sprintf("%s %s %s %s %s %s", split.name, lbAltInterface.dockerNetwork.networkName, split.publicIpv4, split.publicIpv6, split.bridgeIpv4, split.bridgeIpv6))
	}
	want := []string{
		"eth1 warpeth1 198.51.100.1 2001:db8:1::1 192.0.2.1 2001:db8:f1::1",
		"eth2 warpeth2 198.51.100.2  192.0.2.65 2001:db8:f2::1",
	}
	if !slices.Equal(got, want) {
		t.Fatalf("connect unit parsed to the interfaces\n%v\nwant\n%v", got, want)
	}
}

// Calls f and returns what it panicked with, nil when it returned.
func lbAltRecoverPanic(f func()) (recovered any) {
	defer func() {
		recovered = recover()
	}()
	f()
	return nil
}

// Malformed and misplaced lb_alt flags stop the worker at start, as the other
// flags do, instead of running a split with no blocks or binding a wrong
// interface.
func TestLbAltWorkerRefusesMalformedFlags(t *testing.T) {
	loadNetworkInterfaces := lbAltFakeNetworkInterfaces(lbAltFakeEdgeAAddresses)
	routingTable := &RoutingTable{interfaceName: "eth1", tableNumber: 100}
	for _, refused := range []struct {
		opts         docopt.Opts
		service      string
		routingTable *RoutingTable
		want         string
	}{
		{opts: docopt.Opts{"--lbalt": "yes"}, service: "lb", routingTable: routingTable, want: "--lbalt must be true or false"},
		{opts: docopt.Opts{"--lbalt": "true"}, service: "lb", routingTable: routingTable, want: "--lbalt needs the blocks"},
		{opts: docopt.Opts{"--lbalt": "true", "--lbaltblocks": "beta:1"}, service: "lb", routingTable: nil, want: "--lbalt needs the interface's routing table"},
		{opts: docopt.Opts{"--lbalt": "true", "--lbaltblocks": "beta:1"}, service: "connect", routingTable: nil, want: "--lbalt is for an lb unit"},
		{opts: docopt.Opts{"--lbaltblocks": "beta:1"}, service: "lb", routingTable: routingTable, want: "--lbaltblocks needs --lbalt=true"},
		{opts: docopt.Opts{"--lbalt": "true", "--lbaltblocks": "beta"}, service: "lb", routingTable: routingTable, want: "must be block:weight"},
		{opts: docopt.Opts{"--lbalt": "true", "--lbaltblocks": "beta:x"}, service: "lb", routingTable: routingTable, want: "must be a non-negative int"},
		{opts: docopt.Opts{"--lbalt": "true", "--lbaltblocks": "beta:-1"}, service: "lb", routingTable: routingTable, want: "must be a non-negative int"},
		{opts: docopt.Opts{"--lbalt": "true", "--lbaltblocks": "beta:1;beta:2"}, service: "lb", routingTable: routingTable, want: "repeats beta"},
		{opts: docopt.Opts{"--lbaltnets": "eth1:warpeth1"}, service: "lb", routingTable: routingTable, want: "--lbaltnets is for the blocks"},
		{opts: docopt.Opts{"--lbaltnets": "eth1"}, service: "connect", routingTable: nil, want: "must be interface:docker_network"},
		{opts: docopt.Opts{"--lbaltnets": "eth1:warpeth1;eth1:warpeth2"}, service: "connect", routingTable: nil, want: "repeats the interface eth1"},
		{opts: docopt.Opts{"--lbaltnets": "eth1:warpeth1;eth2:warpeth1"}, service: "connect", routingTable: nil, want: "repeats the docker network warpeth1"},
		{opts: docopt.Opts{"--lbaltnets": "eth9:warpeth1"}, service: "connect", routingTable: nil, want: "Could not find interface for eth9"},
	} {
		recovered := lbAltRecoverPanic(func() {
			parseLbAltWorkerFlags(refused.opts, refused.service, refused.routingTable, loadNetworkInterfaces)
		})
		if recovered == nil || !strings.Contains(fmt.Sprint(recovered), refused.want) {
			t.Errorf("%v on %s: recovered %v, want a panic with %q", refused.opts, refused.service, recovered, refused.want)
		}
	}
}

// An interface with several global IPv6 addresses does not stop a block, which
// binds every interface of its host: the lowest is used, whatever order the
// kernel lists them in, and the choice is logged. An interface still needs
// exactly one IPv4 address, as --rttable and --dockernet require.
func TestLbAltWorkerPicksOneOfSeveralIpv6Addresses(t *testing.T) {
	errOutput := captureErrOutput(t)
	for _, ipv6Addresses := range [][]string{
		{"2001:db8:1::9", "2001:db8:1::1", "2001:db8:1::5"},
		{"2001:db8:1::5", "2001:db8:1::9", "2001:db8:1::1"},
	} {
		addresses := maps.Clone(lbAltFakeEdgeAAddresses)
		addresses["eth1"] = [2][]string{{"198.51.100.1"}, ipv6Addresses}
		addresses["warpeth1"] = [2][]string{{"192.0.2.1"}, {"2001:db8:f1::2", "2001:db8:f1::1"}}
		lbAltInterfaces := parseLbAltWorkerInterfaces("eth1:warpeth1", lbAltFakeNetworkInterfaces(addresses))
		split := lbAltInterfaces[0].splitInterface()
		if split.publicIpv6 != "2001:db8:1::1" || split.bridgeIpv6 != "2001:db8:f1::1" {
			t.Fatalf("%v: public IPv6 %s, bridge IPv6 %s, want the lowest of each", ipv6Addresses, split.publicIpv6, split.bridgeIpv6)
		}
	}
	if !strings.Contains(errOutput.String(), "interface eth1 has 3 addresses of one family; using the lowest, 2001:db8:1::1") {
		t.Fatalf("the choice was not logged:\n%s", errOutput.String())
	}

	for _, ipv4Addresses := range [][]string{{}, {"198.51.100.1", "198.51.100.9"}} {
		addresses := maps.Clone(lbAltFakeEdgeAAddresses)
		addresses["eth1"] = [2][]string{ipv4Addresses, {"2001:db8:1::1"}}
		recovered := lbAltRecoverPanic(func() {
			parseLbAltWorkerInterfaces("eth1:warpeth1", lbAltFakeNetworkInterfaces(addresses))
		})
		if recovered == nil {
			t.Fatalf("IPv4 addresses %v were accepted", ipv4Addresses)
		}
	}
}
