package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/docopt/docopt-go"
)

// A services config whose connect blocks run a per-block core limit a/b: the
// service runs 16 cores, its g1 block 10. api keeps its service cores on
// every block, and taskworker has no cores of its own but one block override.
var blockCoresServicesYaml = []byte(`
domain: example.com
versions:
  - external_ports: 7000-7400
    internal_ports: 7401-7800
    routing_tables: 100-120
    parallel_block_count: 4
    services_docker_network: services
    lb:
      ports: [80]
      interfaces:
        edge-a.example.com:
          eth0:
            docker_network: warpeth0
        edge-b.example.com:
          eth0:
            docker_network: warpeth0
    services:
      connect:
        ports: [80]
        cores: 16
        block_overrides:
          g1:
            cores: 10
        blocks:
          - beta: 1
          - g1: 49
          - g2: 50
      api:
        ports: [80]
        cores: 8
        blocks:
          - beta: 1
          - g1: 49
          - g2: 50
      taskworker:
        exposed: false
        ports: [80]
        block_overrides:
          g2:
            cores: 2
        blocks:
          - g1: 50
          - g2: 50
`)

var coreLimitFlagRegex = regexp.MustCompile(`--core-limit=(\d+)`)

// unitCoreLimit returns the unit's core limit flag value, 0 when the unit has
// none; it fails the test when the unit carries the flag more than once.
func unitCoreLimit(t *testing.T, unit string) int {
	t.Helper()
	matches := coreLimitFlagRegex.FindAllStringSubmatch(unit, -1)
	switch len(matches) {
	case 0:
		return 0
	case 1:
		coreLimit, err := strconv.Atoi(matches[0][1])
		if err != nil {
			t.Fatal(err)
		}
		return coreLimit
	default:
		t.Fatalf("unit carries %d core limits:\n%s", len(matches), unit)
		return 0
	}
}

// The block override reaches only its block's unit, on every host the block
// runs on; every other block keeps the service's cores, and a service with no
// cores of its own gets a limit only on its overridden block.
func TestSystemdUnitsRenderBlockCoresOverride(t *testing.T) {
	env := setupTestVault(t, blockCoresServicesYaml)
	hostsUnits := NewSystemdUnits(env, "/srv/warp/main", "/usr/local/bin/warpctl", true).Generate()
	wantServiceBlockCores := map[string]map[string]int{
		"connect":    {"beta": 16, "g1": 10, "g2": 16},
		"api":        {"beta": 8, "g1": 8, "g2": 8},
		"taskworker": {"g1": 0, "g2": 2},
	}
	for _, host := range []string{"edge-a.example.com", "edge-b.example.com"} {
		hostUnits, ok := hostsUnits[host]
		if !ok {
			t.Fatalf("no units for %s", host)
		}
		for service, wantBlockCores := range wantServiceBlockCores {
			blocks := []string{}
			for block := range hostUnits[service] {
				blocks = append(blocks, block)
			}
			slices.Sort(blocks)
			wantBlocks := []string{}
			for block := range wantBlockCores {
				wantBlocks = append(wantBlocks, block)
			}
			slices.Sort(wantBlocks)
			if !slices.Equal(blocks, wantBlocks) {
				t.Fatalf("%s %s blocks = %v want %v", host, service, blocks, wantBlocks)
			}
			for block, wantCores := range wantBlockCores {
				unit := hostUnits[service][block].serviceUnit
				if got := unitCoreLimit(t, unit); got != wantCores {
					t.Errorf("%s %s %s core limit = %d want %d:\n%s", host, service, block, got, wantCores, unit)
				}
			}
		}
	}
}

// `service create-units <env> <service> <block>` writes only that block's
// unit, one per host, carrying the block's override. This is what installs
// an a/b on its own block without touching the units of any other block.
func TestCreateUnitsForOneBlockWritesOnlyThatBlocksUnits(t *testing.T) {
	setupTestVault(t, blockCoresServicesYaml)
	outDir := t.TempDir()
	createUnits(docopt.Opts{
		"<env>":              "test",
		"<service>":          "connect",
		"<block>":            "g1",
		"--target_warp_home": "/srv/warp/main",
		"--target_warpctl":   "/usr/local/sbin/warpctl",
		"--host_networking":  "yes",
		"--out":              outDir,
	})
	paths, err := filepath.Glob(filepath.Join(outDir, "*", "*"))
	if err != nil {
		t.Fatal(err)
	}
	slices.Sort(paths)
	wantPaths := []string{
		filepath.Join(outDir, "edge-a.example.com", "warp-test-connect-g1.service"),
		filepath.Join(outDir, "edge-b.example.com", "warp-test-connect-g1.service"),
	}
	if !slices.Equal(paths, wantPaths) {
		t.Fatalf("written units = %v want %v", paths, wantPaths)
	}
	for _, path := range paths {
		unit, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if got := unitCoreLimit(t, string(unit)); got != 10 {
			t.Fatalf("%s core limit = %d want 10:\n%s", path, got, unit)
		}
		if !strings.Contains(string(unit), "ExecStart=/usr/local/sbin/warpctl service run test connect g1 ") {
			t.Fatalf("%s runs another block:\n%s", path, unit)
		}
	}
}

// The deploy path: the run worker of each generated unit starts its container
// with GOMAXPROCS equal to the unit's core limit, so the overridden block's
// containers run 10 while its sibling's run the service's 16.
func TestBlockCoresOverrideReachesContainerGomaxprocs(t *testing.T) {
	env := setupTestVault(t, blockCoresServicesYaml)
	hostUnits := NewSystemdUnits(env, "/srv/warp/main", "/usr/local/bin/warpctl", true).Generate()["edge-a.example.com"]
	unitCoreLimits := []int{
		unitCoreLimit(t, hostUnits["connect"]["g1"].serviceUnit),
		unitCoreLimit(t, hostUnits["connect"]["g2"].serviceUnit),
	}
	if !slices.Equal(unitCoreLimits, []int{10, 16}) {
		t.Fatalf("connect g1, g2 unit core limits = %v want [10 16]", unitCoreLimits)
	}

	// the fixture's two run workers are connect g1 and g2 of env test
	f := newPromotionLeaseFixture(t, false)
	runArgs := map[string][]string{}
	outAndLogFunc = func(cmd *exec.Cmd) ([]byte, error) {
		args := strings.Join(cmd.Args, " ")
		if strings.Contains(args, "docker run ") {
			for _, block := range []string{"g1", "g2"} {
				if slices.Contains(cmd.Args, "WARP_BLOCK="+block) {
					runArgs[block] = slices.Clone(cmd.Args)
				}
			}
		}
		return f.output(cmd)
	}
	for i, block := range []string{"g1", "g2"} {
		worker := f.workers[i]
		if worker.block != block {
			t.Fatalf("fixture worker %d runs block %s want %s", i, worker.block, block)
		}
		worker.coreLimit = unitCoreLimits[i]
		if _, err := worker.startContainer(map[int]int{80: 41080 + i}); err != nil {
			t.Fatalf("%s start: %s", block, err)
		}
		gomaxprocs := []string{}
		for j, arg := range runArgs[block] {
			if arg == "-e" && j+1 < len(runArgs[block]) && strings.HasPrefix(runArgs[block][j+1], "GOMAXPROCS=") {
				gomaxprocs = append(gomaxprocs, runArgs[block][j+1])
			}
		}
		want := []string{"GOMAXPROCS=" + strconv.Itoa(unitCoreLimits[i])}
		if !slices.Equal(gomaxprocs, want) {
			t.Fatalf("%s container env %v want %v (docker run %v)", block, gomaxprocs, want, runArgs[block])
		}
	}
}
