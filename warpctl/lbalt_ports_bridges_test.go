package main

// Tests of the conntrack cleanup on the lb_alt bridges a connect block binds
// (lbalt_ports.go), with the quiet command fixture of lbalt_ports_test.go.

import (
	"fmt"
	"strings"
	"testing"
)

// The bridges a connect block binds (--lbaltnets) are cleaned even when no
// generation of the block listens on them any more, as when the generation
// retired last there was the only one: its udp tuples to the bridge's
// addresses, in both families, go with it rather than wait for conntrack's
// timeout.
func TestCleanupStaleConntrackCleansTheBridgesTheWorkerBinds(t *testing.T) {
	quietCommands := &lbAltTestQuietCommands{
		// the current generation on 14100 listens on the services bridge
		// only; nothing listens on the lb_alt bridge
		listenRows: "udp   UNCONN 0      0           192.0.2.1:14100        0.0.0.0:*\n",
		conntrackResponder: func(args []string) (commandOutput, error) {
			replySource := flagValue(args, "--reply-src")
			switch args[1] {
			case "-L":
				return commandOutput{stdout: []byte(conntrackSaveEntry(replySource, 14098, "fixture"))}, nil
			case "-D":
				return commandOutput{stdout: []byte(conntrackSaveEntry(replySource, 14098, "fixture"))}, nil
			}
			return commandOutput{}, nil
		},
	}
	installLbAltTestQuietCommands(t, quietCommands)
	captureErrOutput(t)
	worker := &RunWorker{
		env:            "main",
		service:        "connect",
		block:          "g1",
		hostNetworking: true,
		servicesDockerNetwork: &DockerNetwork{
			networkName: "warpservices",
			ipv4: &NetworkInterface{
				interfaceName: "warpservices",
				interfaceIp:   "192.0.2.1",
			},
		},
		portBlocks: parsePortBlocks("443:7124:14098-14101"),
		lbAltInterfaces: []*lbAltWorkerInterface{
			{
				interfaceName: "eth4",
				dockerNetwork: &DockerNetwork{
					networkName: "warpeth4",
					ipv4:        &NetworkInterface{interfaceName: "warpeth4", interfaceIp: "198.51.100.4"},
					ipv6:        &NetworkInterface{interfaceName: "warpeth4", interfaceIp: "2001:db8:4::1"},
				},
			},
		},
	}

	worker.cleanupStaleConntrack()

	listed := []string{}
	deleted := []string{}
	for _, args := range quietCommands.conntrackCommands {
		command := fmt.Sprintf("%s %s", flagValue(args, "-f"), flagValue(args, "--reply-src"))
		switch args[1] {
		case "-L":
			listed = append(listed, command)
		case "-D":
			deleted = append(deleted, command+" "+flagValue(args, "--reply-port-src"))
		}
	}
	requireLbAltRules(t, "listed bridges", listed, []string{
		"ipv4 192.0.2.1",
		"ipv4 198.51.100.4",
		"ipv6 2001:db8:4::1",
	})
	requireLbAltRules(t, "deleted tuples", deleted, []string{
		"ipv4 192.0.2.1 14098",
		"ipv4 198.51.100.4 14098",
		"ipv6 2001:db8:4::1 14098",
	})
	for _, args := range quietCommands.conntrackCommands {
		if strings.Contains(strings.Join(args, " "), "14100") {
			t.Fatalf("the live generation's port was cleaned: %v", args)
		}
	}
}
