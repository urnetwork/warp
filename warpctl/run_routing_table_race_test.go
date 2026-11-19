package main

// A race test of the routing table's IPv6 address, which Run's routing
// reconcile can set while a retirement goroutine reads the table
// (RoutingTable, getNetworkConfigs). It fails only under -race, which
// test.sh runs.

import (
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/urnetwork/warp"
)

// An nginx lb unit restarts beside two of its containers, the current one on
// pool port 8001, which its chain targets, and an older one, which the
// startup reconcile drains on a goroutine of its own. While that drain stops
// the older container, Run's routing reconcile finds the IPv6 address the
// interface lacked at start and sets it in the routing table, and the drain
// then reads the table for its conntrack cleanup. Nothing orders the drain's
// read after the reconcile's write but the table's own lock: the test opens
// the drain's stop just before the reconcile, and joins the drain only after
// both, so -race reports the two accesses unless the lock orders them.
//
// The window keeps the goroutines from synchronizing any other way: logs go
// to io.Discard, which the logger checks with an atomic load, and the
// commands both run after the stop opens end in hooks that share no lock and
// start no process.
func TestOrphanDrainReadsTheRoutingTableWhileRunSetsItsIpv6(t *testing.T) {
	home := t.TempDir()
	bin := filepath.Join(home, "bin")
	if err := os.Mkdir(bin, 0o700); err != nil {
		t.Fatal(err)
	}
	writeSudoFixture(t, bin, `#!/bin/sh
case "$*" in
  "docker ps "*) printf 'c0ffee0000a1\nc0ffee0000a2\n' ;;
  *) printf 'unexpected fixture command\n' >&2; exit 97 ;;
esac
`)
	t.Setenv("PATH", bin)

	previousWriter := Err.Writer()
	Err.SetOutput(io.Discard)
	oldRun, oldOut, oldQuiet, oldSudo2 := runAndLogFunc, outAndLogFunc, runQuietFunc, sudo2Func
	t.Cleanup(func() {
		runAndLogFunc, outAndLogFunc, runQuietFunc, sudo2Func = oldRun, oldOut, oldQuiet, oldSudo2
		Err.SetOutput(previousWriter)
	})

	// opened by the test, just before the reconcile that sets the address
	openStop := make(chan struct{})
	// written by the drain, read after it is joined
	stoppedIds := []string{}
	runAndLogFunc = func(cmd *exec.Cmd) error {
		args := strings.Join(cmd.Args, " ")
		if strings.Contains(args, "docker container stop ") {
			<-openStop
			stoppedIds = append(stoppedIds, cmd.Args[len(cmd.Args)-1])
		}
		// docker update and the routing commands succeed
		return nil
	}
	outAndLogFunc = func(cmd *exec.Cmd) ([]byte, error) {
		if strings.Contains(strings.Join(cmd.Args, " "), "docker inspect ") {
			return []byte(`[
  {"Id": "c0ffee0000a1", "Config": {"Env": ["WARP_PORTS=80:8001"]}},
  {"Id": "c0ffee0000a2", "Config": {"Env": ["WARP_PORTS=80:8002"]}}
]`), nil
		}
		return nil, errors.New("unexpected fixture output command")
	}
	runQuietFunc = func(cmd *exec.Cmd) (commandOutput, error) {
		args := slices.Clone(cmd.Args)
		if 0 < len(args) && args[0] == "sudo" {
			args = args[1:]
		}
		switch {
		case slices.Equal(args, []string{"ss", "-Htuln"}):
			// the current container listens; the older one has closed its sockets
			return commandOutput{stdout: []byte("tcp   LISTEN 0      4096       192.0.2.65:8001        0.0.0.0:*\n")}, nil
		case 0 < len(args) && args[0] == "conntrack":
			return commandOutput{}, nil
		}
		return commandOutput{}, errors.New("unexpected fixture quiet command")
	}
	listing := func(output string) *exec.Cmd {
		return exec.Command("/bin/sh", "-c", `printf '%s\n' "$1"`, "sh", output)
	}
	sudo2Func = func(name []string, args ...string) *exec.Cmd {
		commandArgs := append(slices.Clone(name), args...)
		switch strings.Join(commandArgs, " ") {
		case "iptables -t nat -S WARP-TEST-LB-ETH1":
			return listing("-A WARP-TEST-LB-ETH1 -p tcp -m tcp --dport 7080 -j DNAT --to-destination 192.0.2.65:8001")
		case "ip6tables -t nat -S WARP-TEST-LB-ETH1":
			return listing("-A WARP-TEST-LB-ETH1 -p tcp -m tcp --dport 7080 -j DNAT --to-destination [2001:db8:2::1]:8001")
		case "iptables -t nat -L WARP-TEST-LB-ETH1 -n":
			return listing("DNAT       tcp  --  0.0.0.0/0            0.0.0.0/0            tcp dpt:7080 to:192.0.2.65:8001")
		case "ip6tables -t nat -L WARP-TEST-LB-ETH1 -n":
			return listing("DNAT       tcp      ::/0                 ::/0                 tcp dpt:7080 to:[2001:db8:2::1]:8001")
		case "iptables -w -t nat -L -n":
			return listing("Chain WARP-TEST-LB-ETH1 (2 references)")
		}
		// the routing reconcile's listings fail without starting a process,
		// which it tolerates; its changes reach runAndLogFunc
		return &exec.Cmd{Args: commandArgs}
	}

	publicIpv4 := &NetworkInterface{
		interfaceName:    "eth1",
		interfaceIp:      "198.51.100.1",
		interfaceSubnet:  "198.51.100.0/24",
		interfaceGateway: "198.51.100.254",
	}
	publicIpv6 := &NetworkInterface{
		interfaceName:    "eth1",
		interfaceIp:      "2001:db8:1::1",
		interfaceSubnet:  "2001:db8:1::/64",
		interfaceGateway: "2001:db8:1::fffe",
	}
	interfaceLookups := 0
	worker := &RunWorker{
		env:            "test",
		service:        "lb",
		block:          "edge-a.example-eth1",
		hostNetworking: true,
		quitEvent:      warp.NewEvent(),
		portBlocks:     parsePortBlocks("80:7080:8001-8002"),
		servicesDockerNetwork: &DockerNetwork{
			networkName: "warpservices",
			ipv4: &NetworkInterface{
				interfaceName:   "warpservices",
				interfaceIp:     "192.0.2.1",
				interfaceSubnet: "192.0.2.0/26",
			},
		},
		dockerNetwork: &DockerNetwork{
			networkName: "warpeth1",
			ipv4: &NetworkInterface{
				interfaceName:   "warpeth1",
				interfaceIp:     "192.0.2.65",
				interfaceSubnet: "192.0.2.64/26",
			},
			ipv6: &NetworkInterface{
				interfaceName:   "warpeth1",
				interfaceIp:     "2001:db8:2::1",
				interfaceSubnet: "2001:db8:2::/64",
			},
		},
		routingTable: &RoutingTable{
			interfaceName: "eth1",
			tableNumber:   100,
			tableName:     "warp100",
			ipv4:          publicIpv4,
		},
		// no IPv6 address at start, one by the next reconcile
		networkInterfaces: func(string) ([]*NetworkInterface, []*NetworkInterface, error) {
			interfaceLookups += 1
			if interfaceLookups == 1 {
				return []*NetworkInterface{publicIpv4}, nil, nil
			}
			return []*NetworkInterface{publicIpv4}, []*NetworkInterface{publicIpv6}, nil
		},
	}

	// as Run starts: the routing reconcile, then the orphan reconcile, whose
	// drain waits in the older container's stop
	started := time.Now()
	worker.reconcileRoutingTableIfDue(started)
	if err := worker.reconcileOrphanedServiceBlockContainers(); err != nil {
		t.Fatal(err)
	}
	if worker.orphanDrain == nil {
		t.Fatal("the startup reconcile started no drain")
	}

	// as Run's loop does on its next routing reconcile, while the drain runs
	close(openStop)
	worker.reconcileRoutingTableIfDue(started.Add(RoutingTableReconcileTimeout))

	if err := <-worker.orphanDrain; err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(stoppedIds, []string{"c0ffee0000a2"}) {
		t.Fatalf("the drain stopped %v, want the older container alone", stoppedIds)
	}
	if ipv6 := worker.routingTable.ipv6; ipv6 != publicIpv6 {
		t.Fatalf("the routing table's IPv6 address is %v, want the one the reconcile found", ipv6)
	}
}
