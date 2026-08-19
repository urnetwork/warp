package main

import (
	"fmt"
	"os/exec"
	"strings"
	"sync"
	"testing"

	"github.com/go-playground/assert/v2"
)

type iptablesRule struct {
	op    string
	chain string
	args  []string
}

func (r iptablesRule) String() string {
	return fmt.Sprintf("%s %s %s", r.op, r.chain, strings.Join(r.args, " "))
}

type iptablesRecorder struct {
	mu    sync.Mutex
	rules []iptablesRule
	// chain -> mock listing output
	listings map[string]string
}

func newIptablesRecorder() *iptablesRecorder {
	return &iptablesRecorder{
		listings: map[string]string{},
	}
}

func (r *iptablesRecorder) record(rule iptablesRule) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.rules = append(r.rules, rule)
}

func (r *iptablesRecorder) getRules() []iptablesRule {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]iptablesRule, len(r.rules))
	copy(out, r.rules)
	return out
}

func (r *iptablesRecorder) findRules(op string) []iptablesRule {
	r.mu.Lock()
	defer r.mu.Unlock()
	var matched []iptablesRule
	for _, rule := range r.rules {
		if rule.op == op {
			matched = append(matched, rule)
		}
	}
	return matched
}

func (r *iptablesRecorder) clear() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.rules = nil
}

func parseIptablesArgs(allArgs []string) (op, chain string, rest []string) {
	for i := 0; i < len(allArgs); i++ {
		switch allArgs[i] {
		case "-I", "-D", "-C", "-A":
			op = allArgs[i]
			if i+1 < len(allArgs) {
				chain = allArgs[i+1]
				i++
			}
		}
	}
	rest = allArgs
	return
}

func installRecorder(t *testing.T, rec *iptablesRecorder) {
	t.Helper()

	origRunAndLog := runAndLogFunc
	origSudo2 := sudo2Func

	deleteSeen := map[string]bool{}
	var deleteMu sync.Mutex

	runAndLogFunc = func(cmd *exec.Cmd) error {
		args := cmd.Args
		// skip "sudo" prefix
		if len(args) > 0 && args[0] == "sudo" {
			args = args[1:]
		}
		// skip iptables/ip6tables command name
		iptablesIdx := -1
		for i, a := range args {
			if a == "iptables" || a == "ip6tables" {
				iptablesIdx = i
				break
			}
		}
		if iptablesIdx < 0 {
			return nil
		}
		args = args[iptablesIdx+1:]

		op, chain, _ := parseIptablesArgs(args)
		if op != "" {
			rec.record(iptablesRule{op: op, chain: chain, args: args})
		}

		// -C (check): return error to indicate rule doesn't exist (trigger insert)
		if op == "-C" {
			return fmt.Errorf("rule not found")
		}
		// -D (delete): succeed once per unique rule, then error (rule gone)
		if op == "-D" {
			key := strings.Join(args, " ")
			deleteMu.Lock()
			defer deleteMu.Unlock()
			if deleteSeen[key] {
				return fmt.Errorf("rule not found")
			}
			deleteSeen[key] = true
			return nil
		}
		return nil
	}

	sudo2Func = func(name []string, args ...string) *exec.Cmd {
		allArgs := append(name, args...)

		// detect listing calls: -L <chain> -n
		isListing := false
		var listChain string
		for i, a := range allArgs {
			if a == "-L" && i+1 < len(allArgs) {
				isListing = true
				listChain = allArgs[i+1]
			}
		}

		if isListing {
			output := ""
			if listing, ok := rec.listings[listChain]; ok {
				output = listing
			}
			return exec.Command("echo", output)
		}

		isIptables := false
		for _, a := range allArgs {
			if a == "iptables" || a == "ip6tables" {
				isIptables = true
				break
			}
		}
		if !isIptables {
			return exec.Command("echo", "")
		}

		// for iptables calls, build a cmd with "sudo" prefix + original args
		// so runAndLogFunc can parse them
		cmdArgs := []string{}
		cmdArgs = append(cmdArgs, allArgs...)
		cmd := exec.Command("sudo", cmdArgs...)
		return cmd
	}

	t.Cleanup(func() {
		runAndLogFunc = origRunAndLog
		sudo2Func = origSudo2
	})
}

func TestIptablesRedirectFirstDeploy(t *testing.T) {
	rec := newIptablesRecorder()
	installRecorder(t, rec)

	worker := &RunWorker{
		env:            "test",
		service:        "lb",
		block:          "edge-0-eth0",
		hostNetworking: true,
		dockerNetwork: &DockerNetwork{
			networkName: "warpeth0",
			ipv4: &NetworkInterface{
				interfaceName: "warpeth0",
				interfaceIp:   "10.100.0.2",
			},
		},
		servicesDockerNetwork: &DockerNetwork{
			networkName: "testservices",
			ipv4: &NetworkInterface{
				interfaceName: "testservices",
				interfaceIp:   "10.200.0.2",
			},
		},
		routingTable: &RoutingTable{
			tableNumber: 100,
			tableName:   "warp_eth0",
			ipv4: &NetworkInterface{
				interfaceName: "eth0",
				interfaceIp:   "10.0.0.1",
			},
		},
	}

	externalPortsToInternalPort := map[int]int{
		7080: 7201,
		7443: 7231,
	}
	servicePortsToInternalPort := map[int]int{
		80:  7201,
		443: 7231,
	}

	worker.redirect(externalPortsToInternalPort, servicePortsToInternalPort, "abc123")

	rules := rec.getRules()
	assert.NotEqual(t, len(rules), 0)

	insertRules := rec.findRules("-I")
	assert.NotEqual(t, len(insertRules), 0)

	deleteRules := rec.findRules("-D")
	assert.Equal(t, len(deleteRules), 0)

	chainName := worker.iptablesChainName()
	foundDNAT := map[string]bool{}
	for _, rule := range insertRules {
		argsStr := strings.Join(rule.args, " ")
		if strings.Contains(argsStr, "DNAT") && rule.chain == chainName {
			for _, port := range []string{"7080", "7443", "7201", "7231"} {
				if strings.Contains(argsStr, "--dport "+port) {
					foundDNAT[port] = true
				}
			}
		}
	}
	for _, port := range []string{"7080", "7443", "7201", "7231"} {
		assert.Equal(t, foundDNAT[port], true)
	}

	for _, rule := range insertRules {
		argsStr := strings.Join(rule.args, " ")
		if strings.Contains(argsStr, "DNAT") && rule.chain == chainName {
			assert.Equal(t, strings.Contains(argsStr, "10.100.0.2:"), true)
		}
	}

	foundPublicDNAT := map[string]bool{}
	for _, rule := range insertRules {
		argsStr := strings.Join(rule.args, " ")
		if strings.Contains(argsStr, "DNAT") && strings.Contains(argsStr, "-d 10.0.0.1") {
			for _, port := range []string{"80", "443"} {
				if strings.Contains(argsStr, "--dport "+port) {
					foundPublicDNAT[port] = true
				}
			}
		}
	}
	for _, port := range []string{"80", "443"} {
		assert.Equal(t, foundPublicDNAT[port], true)
	}

	foundSNAT := false
	for _, rule := range insertRules {
		argsStr := strings.Join(rule.args, " ")
		if strings.Contains(argsStr, "SNAT") {
			foundSNAT = true
			assert.Equal(t, strings.Contains(argsStr, "POSTROUTING"), true)
		}
	}
	assert.Equal(t, foundSNAT, true)
}

func TestIptablesRedirectSecondDeploy(t *testing.T) {
	rec := newIptablesRecorder()
	installRecorder(t, rec)

	worker := &RunWorker{
		env:            "test",
		service:        "lb",
		block:          "edge-0-eth0",
		hostNetworking: true,
		dockerNetwork: &DockerNetwork{
			networkName: "warpeth0",
			ipv4: &NetworkInterface{
				interfaceName: "warpeth0",
				interfaceIp:   "10.100.0.2",
			},
		},
		servicesDockerNetwork: &DockerNetwork{
			networkName: "testservices",
			ipv4: &NetworkInterface{
				interfaceName: "testservices",
				interfaceIp:   "10.200.0.2",
			},
		},
		routingTable: &RoutingTable{
			tableNumber: 100,
			tableName:   "warp_eth0",
			ipv4: &NetworkInterface{
				interfaceName: "eth0",
				interfaceIp:   "10.0.0.1",
			},
		},
		// this block owns both the old (8001/8031) and new (7201/7231) internal
		// ports, so the stale SNAT cleanup recognizes the old rules as its own
		portBlocks: &PortBlocks{
			externalsToInternals: map[int][]int{
				7080: {7201, 8001},
				7443: {7231, 8031},
			},
			externalsToService: map[int]int{
				7080: 80,
				7443: 443,
			},
		},
	}

	chainName := worker.iptablesChainName()

	// simulate existing DNAT rules from a previous deploy with different internal ports
	rec.listings[chainName] = fmt.Sprintf(`Chain %s (2 references)
target     prot opt source               destination
DNAT       tcp  --  0.0.0.0/0            0.0.0.0/0            tcp dpt:7080 to:10.100.0.2:8001
DNAT       tcp  --  0.0.0.0/0            0.0.0.0/0            tcp dpt:8001 to:10.100.0.2:8001
DNAT       tcp  --  0.0.0.0/0            0.0.0.0/0            tcp dpt:7443 to:10.100.0.2:8031
DNAT       tcp  --  0.0.0.0/0            0.0.0.0/0            tcp dpt:8031 to:10.100.0.2:8031
DNAT       tcp  --  0.0.0.0/0            10.0.0.1             tcp dpt:80 to:10.100.0.2:8001
DNAT       tcp  --  0.0.0.0/0            10.0.0.1             tcp dpt:443 to:10.100.0.2:8031`, chainName)

	rec.listings["POSTROUTING"] = `Chain POSTROUTING (policy ACCEPT)
target     prot opt source               destination
SNAT       udp  --  0.0.0.0/0            0.0.0.0/0            udp spt:8001 to:10.0.0.1:7080
SNAT       udp  --  0.0.0.0/0            0.0.0.0/0            udp spt:8031 to:10.0.0.1:7443`

	// new deploy: internal ports changed from 8001/8031 to 7201/7231
	externalPortsToInternalPort := map[int]int{
		7080: 7201,
		7443: 7231,
	}
	servicePortsToInternalPort := map[int]int{
		80:  7201,
		443: 7231,
	}

	worker.redirect(externalPortsToInternalPort, servicePortsToInternalPort, "def456")

	rules := rec.getRules()
	assert.NotEqual(t, len(rules), 0)

	insertRules := rec.findRules("-I")
	deleteRules := rec.findRules("-D")
	assert.NotEqual(t, len(insertRules), 0)
	assert.NotEqual(t, len(deleteRules), 0)

	oldPortsDeleted := map[string]bool{}
	for _, rule := range deleteRules {
		argsStr := strings.Join(rule.args, " ")
		if strings.Contains(argsStr, "DNAT") {
			if strings.Contains(argsStr, "8001") {
				oldPortsDeleted["8001"] = true
			}
			if strings.Contains(argsStr, "8031") {
				oldPortsDeleted["8031"] = true
			}
		}
	}
	for _, port := range []string{"8001", "8031"} {
		assert.Equal(t, oldPortsDeleted[port], true)
	}

	newPortsInserted := map[string]bool{}
	for _, rule := range insertRules {
		argsStr := strings.Join(rule.args, " ")
		if strings.Contains(argsStr, "DNAT") && rule.chain == chainName {
			if strings.Contains(argsStr, "10.100.0.2:7201") {
				newPortsInserted["7201"] = true
			}
			if strings.Contains(argsStr, "10.100.0.2:7231") {
				newPortsInserted["7231"] = true
			}
		}
	}
	for _, port := range []string{"7201", "7231"} {
		assert.Equal(t, newPortsInserted[port], true)
	}

	newSNATInserted := map[string]bool{}
	for _, rule := range insertRules {
		argsStr := strings.Join(rule.args, " ")
		if strings.Contains(argsStr, "SNAT") {
			if strings.Contains(argsStr, "--sport 7201") {
				newSNATInserted["7201"] = true
			}
			if strings.Contains(argsStr, "--sport 7231") {
				newSNATInserted["7231"] = true
			}
		}
	}
	for _, port := range []string{"7201", "7231"} {
		assert.Equal(t, newSNATInserted[port], true)
	}

	oldSNATDeleted := map[string]bool{}
	for _, rule := range deleteRules {
		argsStr := strings.Join(rule.args, " ")
		if strings.Contains(argsStr, "SNAT") {
			if strings.Contains(argsStr, "--sport 8001") {
				oldSNATDeleted["8001"] = true
			}
			if strings.Contains(argsStr, "--sport 8031") {
				oldSNATDeleted["8031"] = true
			}
		}
	}
	for _, port := range []string{"8001", "8031"} {
		assert.Equal(t, oldSNATDeleted[port], true)
	}
}

func TestPublicPortServiceTargetsForwardOnlyAndIpv4(t *testing.T) {
	servicePorts := map[int]int{
		443:  7231,
		8053: 7250,
	}
	forwardPorts := parseForwardPorts("udp:53:8053")

	ipv4Udp, err := publicPortServiceTargets("udp", servicePorts, forwardPorts, false)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := fmt.Sprint(ipv4Udp), "map[53:8053 443:443]"; got != want {
		t.Fatalf("IPv4 UDP targets=%s want=%s", got, want)
	}

	ipv6Udp, err := publicPortServiceTargets("udp", servicePorts, forwardPorts, true)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := fmt.Sprint(ipv6Udp), "map[443:443]"; got != want {
		t.Fatalf("IPv6 UDP targets=%s want=%s", got, want)
	}

	ipv4Tcp, err := publicPortServiceTargets("tcp", servicePorts, forwardPorts, false)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := fmt.Sprint(ipv4Tcp), "map[443:443]"; got != want {
		t.Fatalf("IPv4 TCP targets=%s want=%s", got, want)
	}
}

func TestForwardPortRejectsRuntimeExternalPortConflict(t *testing.T) {
	worker := &RunWorker{forwardPorts: parseForwardPorts("udp:53:8053")}
	deferredPanic := false
	func() {
		defer func() {
			deferredPanic = recover() != nil
		}()
		worker.redirect(
			map[int]int{53: 7201},
			map[int]int{8053: 7250},
			"conflict",
		)
	}()
	if !deferredPanic {
		t.Fatal("hand-written runtime configuration accepted a forward/external port conflict")
	}
}

func TestIptablesForwardPortInstallUsesExactIpv4Interface(t *testing.T) {
	rec := newIptablesRecorder()
	installRecorder(t, rec)

	worker := &RunWorker{
		env:            "test",
		service:        "lb",
		block:          "edge-0-eth0",
		hostNetworking: true,
		forwardPorts:   parseForwardPorts("udp:53:8053"),
		dockerNetwork: &DockerNetwork{
			networkName: "warpeth0",
			ipv4: &NetworkInterface{
				interfaceName: "warpeth0",
				interfaceIp:   "10.100.0.2",
			},
			ipv6: &NetworkInterface{
				interfaceName: "warpeth0",
				interfaceIp:   "fd00:100::2",
			},
		},
		servicesDockerNetwork: &DockerNetwork{
			networkName: "testservices",
			ipv4: &NetworkInterface{
				interfaceName: "testservices",
				interfaceIp:   "10.200.0.2",
			},
		},
		routingTable: &RoutingTable{
			tableNumber: 100,
			tableName:   "warp_eth0",
			ipv4: &NetworkInterface{
				interfaceName: "eth0",
				interfaceIp:   "10.0.0.1",
			},
			ipv6: &NetworkInterface{
				interfaceName: "eth0",
				interfaceIp:   "2001:db8::1",
			},
		},
	}

	worker.redirect(
		map[int]int{7443: 7231, 7450: 7250},
		map[int]int{443: 7231, 8053: 7250},
		"abc123",
	)

	foundForward := false
	for _, rule := range rec.findRules("-I") {
		args := strings.Join(rule.args, " ")
		isScopedPublicRule := strings.Contains(args, " DNAT ") && strings.Contains(args, " -d ")
		if strings.Contains(args, "-p udp -m udp -d 10.0.0.1 --dport 53") &&
			strings.Contains(args, "--to-destination 10.100.0.2:7250") {
			foundForward = true
		}
		if !isScopedPublicRule {
			continue
		}
		if strings.Contains(args, "--dport 8053") {
			t.Errorf("forward target was also exposed directly: %s", args)
		}
		if strings.Contains(args, "-d 2001:db8::1 --dport 53") {
			t.Errorf("IPv4-only forward was advertised on IPv6: %s", args)
		}
		if strings.Contains(args, "-p tcp -m tcp -d 10.0.0.1 --dport 53") {
			t.Errorf("UDP forward was installed for TCP: %s", args)
		}
	}
	if !foundForward {
		t.Fatal("missing UDP 10.0.0.1:53 -> 10.100.0.2:7250 DNAT")
	}
}

func TestIptablesForwardPortReconcileIsAtomicAndScoped(t *testing.T) {
	rec := newIptablesRecorder()
	installRecorder(t, rec)

	worker := &RunWorker{
		env:            "test",
		service:        "lb",
		block:          "edge-0-eth0",
		hostNetworking: true,
		forwardPorts:   parseForwardPorts("udp:53:8053"),
		dockerNetwork: &DockerNetwork{
			networkName: "warpeth0",
			ipv4: &NetworkInterface{
				interfaceName: "warpeth0",
				interfaceIp:   "10.100.0.2",
			},
		},
		servicesDockerNetwork: &DockerNetwork{
			networkName: "testservices",
			ipv4: &NetworkInterface{
				interfaceName: "testservices",
				interfaceIp:   "10.200.0.2",
			},
		},
		routingTable: &RoutingTable{
			tableNumber: 100,
			tableName:   "warp_eth0",
			ipv4: &NetworkInterface{
				interfaceName: "eth0",
				interfaceIp:   "10.0.0.1",
			},
		},
	}
	chainName := worker.iptablesChainName()
	rec.listings[chainName] = fmt.Sprintf(`Chain %s (2 references)
target     prot opt source               destination
DNAT       udp  --  0.0.0.0/0            10.0.0.1             udp dpt:53 to:10.100.0.9:7999
DNAT       udp  --  0.0.0.0/0            10.0.0.1             udp dpt:8053 to:10.100.0.2:7250
DNAT       udp  --  0.0.0.0/0            10.99.0.1            udp dpt:53 to:10.99.0.2:7250
DNAT       udp  --  0.0.0.0/0            0.0.0.0/0            udp dpt:7450 to:10.100.0.2:7250`, chainName)

	worker.redirect(
		map[int]int{7443: 7231, 7450: 7250},
		map[int]int{443: 7231, 8053: 7250},
		"def456",
	)

	insertIndex := -1
	firstDeleteIndex := -1
	deletedOldForward := false
	deletedDirectTarget := false
	for i, rule := range rec.getRules() {
		args := strings.Join(rule.args, " ")
		if rule.op == "-I" && strings.Contains(args, "-p udp -m udp -d 10.0.0.1 --dport 53") &&
			strings.Contains(args, "--to-destination 10.100.0.2:7250") {
			insertIndex = i
		}
		if rule.op != "-D" {
			continue
		}
		if firstDeleteIndex == -1 {
			firstDeleteIndex = i
		}
		if strings.Contains(args, "-d 10.0.0.1 --dport 53") && strings.Contains(args, "10.100.0.9:7999") {
			deletedOldForward = true
		}
		if strings.Contains(args, "-d 10.0.0.1 --dport 8053") {
			deletedDirectTarget = true
		}
		if strings.Contains(args, "10.99.0.1") || strings.Contains(args, "--dport 7450") {
			t.Errorf("reconcile touched a rule it does not own: %s", args)
		}
	}
	if insertIndex == -1 || firstDeleteIndex == -1 || firstDeleteIndex < insertIndex {
		t.Fatalf("new rule was not installed before cleanup: insert=%d first-delete=%d", insertIndex, firstDeleteIndex)
	}
	if !deletedOldForward || !deletedDirectTarget {
		t.Fatalf("stale cleanup old-forward=%t direct-target=%t", deletedOldForward, deletedDirectTarget)
	}
}

func TestIptablesForwardPortRemovalDeletesOwnedAlias(t *testing.T) {
	rec := newIptablesRecorder()
	installRecorder(t, rec)

	worker := &RunWorker{
		env:            "test",
		service:        "lb",
		block:          "edge-0-eth0",
		hostNetworking: true,
		forwardPorts:   newForwardPorts(),
		dockerNetwork: &DockerNetwork{
			ipv4: &NetworkInterface{interfaceName: "warpeth0", interfaceIp: "10.100.0.2"},
		},
		servicesDockerNetwork: &DockerNetwork{
			ipv4: &NetworkInterface{interfaceName: "testservices", interfaceIp: "10.200.0.2"},
		},
		routingTable: &RoutingTable{
			ipv4: &NetworkInterface{interfaceName: "eth0", interfaceIp: "10.0.0.1"},
		},
	}
	chainName := worker.iptablesChainName()
	rec.listings[chainName] = fmt.Sprintf(`Chain %s (2 references)
target     prot opt source               destination
DNAT       udp  --  0.0.0.0/0            10.0.0.1             udp dpt:53 to:10.100.0.2:7250`, chainName)

	worker.redirect(
		map[int]int{7443: 7231},
		map[int]int{443: 7231},
		"ghi789",
	)

	for _, rule := range rec.findRules("-D") {
		args := strings.Join(rule.args, " ")
		if strings.Contains(args, "-p udp -m udp -d 10.0.0.1 --dport 53") &&
			strings.Contains(args, "--to-destination 10.100.0.2:7250") {
			return
		}
	}
	t.Fatal("withdrawn forward alias was not removed")
}

// The udp SNAT rules live in the shared POSTROUTING chain, so every service
// block on the host sees every other block's rules. A deploy of one block must
// only ever touch its own rules. This reproduces the regression where a g8
// deploy deleted g9/g10's active SNAT rules (dropping the source rewrite on
// their udp/wg return path), and asserts the deploy now leaves them intact.
func TestIptablesRedirectSnatBlockIsolationAcrossBlocks(t *testing.T) {
	rec := newIptablesRecorder()
	installRecorder(t, rec)

	// this worker is block g8: it owns external ports 7158-7163, each backed by
	// an internal port range. g9 (731x/143xx) and g10 (717x/144xx) are other
	// blocks on the same host and are NOT in g8's ranges.
	worker := &RunWorker{
		env:            "main",
		service:        "proxy",
		block:          "g8",
		hostNetworking: true,
		dockerNetwork: &DockerNetwork{
			networkName: "warpeno1np0",
			ipv4: &NetworkInterface{
				interfaceName: "warpeno1np0",
				interfaceIp:   "172.19.0.1",
			},
		},
		servicesDockerNetwork: &DockerNetwork{
			networkName: "warpservices",
			ipv4: &NetworkInterface{
				interfaceName: "warpservices",
				interfaceIp:   "172.20.0.1",
			},
		},
		routingTable: &RoutingTable{
			tableNumber: 100,
			tableName:   "warp100",
			ipv4: &NetworkInterface{
				interfaceName: "eno1np0",
				interfaceIp:   "65.49.70.94",
			},
		},
		portBlocks: &PortBlocks{
			externalsToInternals: map[int][]int{
				7158: {13948, 13949},
				7159: {13978, 13979},
				7160: {14008, 14009},
				7161: {14038, 14039},
				7162: {14068, 14069},
				7163: {14098, 14099},
			},
			externalsToService: map[int]int{
				7158: 80, 7159: 8080, 7160: 8081, 7161: 8082, 7162: 8083, 7163: 8084,
			},
		},
	}

	// existing POSTROUTING: g8 has one stale rule (14098, no longer active) plus
	// its active wg rule (14099); g9 and g10 have active rules a g8 deploy must
	// not touch.
	rec.listings["POSTROUTING"] = `Chain POSTROUTING (policy ACCEPT)
target     prot opt source               destination
SNAT       udp  --  0.0.0.0/0            0.0.0.0/0            udp spt:14098 to:65.49.70.94:7163
SNAT       udp  --  0.0.0.0/0            0.0.0.0/0            udp spt:14099 to:65.49.70.94:7163
SNAT       udp  --  0.0.0.0/0            0.0.0.0/0            udp spt:14308 to:65.49.70.94:7170
SNAT       udp  --  0.0.0.0/0            0.0.0.0/0            udp spt:14338 to:65.49.70.94:7171
SNAT       udp  --  0.0.0.0/0            0.0.0.0/0            udp spt:14458 to:65.49.70.94:7175
MASQUERADE  all  --  172.17.0.0/16        anywhere`

	// g8 deploy: external -> active internal port
	externalPortsToInternalPort := map[int]int{
		7158: 13949,
		7159: 13979,
		7160: 14009,
		7161: 14039,
		7162: 14069,
		7163: 14099,
	}
	servicePortsToInternalPort := map[int]int{
		80: 13949, 8080: 13979, 8081: 14009, 8082: 14039, 8083: 14069, 8084: 14099,
	}

	worker.redirect(externalPortsToInternalPort, servicePortsToInternalPort, "g8container")

	// collect the internal (sport) ports of every SNAT rule this deploy deleted
	snatDeletedSports := map[string]bool{}
	for _, rule := range rec.findRules("-D") {
		argsStr := strings.Join(rule.args, " ")
		if !strings.Contains(argsStr, "SNAT") {
			continue
		}
		for _, sport := range []string{"14098", "14099", "14308", "14338", "14458"} {
			if strings.Contains(argsStr, "--sport "+sport) {
				snatDeletedSports[sport] = true
			}
		}
	}

	// g9/g10 rules must be untouched
	for _, sport := range []string{"14308", "14338", "14458"} {
		assert.Equal(t, snatDeletedSports[sport], false)
	}
	// g8's own stale rule must still be cleaned up
	assert.Equal(t, snatDeletedSports["14098"], true)
	// g8's active rule must not be deleted
	assert.Equal(t, snatDeletedSports["14099"], false)

	// and g8's active wg SNAT must be (re)inserted to 65.49.70.94:7163
	foundActiveSnat := false
	for _, rule := range rec.findRules("-I") {
		argsStr := strings.Join(rule.args, " ")
		if strings.Contains(argsStr, "SNAT") &&
			strings.Contains(argsStr, "--sport 14099") &&
			strings.Contains(argsStr, "65.49.70.94:7163") {
			foundActiveSnat = true
		}
	}
	assert.Equal(t, foundActiveSnat, true)
}

func TestIptablesRedirectNonHostNetworking(t *testing.T) {
	rec := newIptablesRecorder()
	installRecorder(t, rec)

	worker := &RunWorker{
		env:            "test",
		service:        "api",
		block:          "g1",
		hostNetworking: false,
		servicesDockerNetwork: &DockerNetwork{
			networkName: "testservices",
			ipv4: &NetworkInterface{
				interfaceName: "testservices",
				interfaceIp:   "10.200.0.2",
			},
		},
	}

	externalPortsToInternalPort := map[int]int{
		7010: 7401,
	}
	servicePortsToInternalPort := map[int]int{
		80: 7401,
	}

	worker.redirect(externalPortsToInternalPort, servicePortsToInternalPort, "ghi789")

	insertRules := rec.findRules("-I")
	assert.NotEqual(t, len(insertRules), 0)

	foundRedirect := false
	foundDNAT := false
	for _, rule := range insertRules {
		argsStr := strings.Join(rule.args, " ")
		if strings.Contains(argsStr, "REDIRECT") {
			foundRedirect = true
			assert.Equal(t, strings.Contains(argsStr, "--dport 7010"), true)
			assert.Equal(t, strings.Contains(argsStr, "--to-ports 7401"), true)
		}
		if strings.Contains(argsStr, "DNAT") {
			foundDNAT = true
		}
	}
	assert.Equal(t, foundRedirect, true)
	assert.Equal(t, foundDNAT, false)
}

// The block chain is entered from OUTPUT for LOCAL destinations, so it also
// sees the host's own loopback traffic -- a service front dialing its children
// at 127.0.0.1:<internal port>. Without a loopback RETURN ahead of the DNAT
// rules those dials are rewritten to the docker network ip, where a
// host-networked service has no listener, so every child read fails
// "connection refused" while the child is still LISTENing on loopback. That is
// the 2026-08-11 grafana outage and the mechanism behind the older "bind
// paradox". The DNAT rules are inserted at the HEAD of the chain on every
// deploy, so the exemption has to be reinserted after them rather than added
// once at chain creation.
func TestIptablesLoopbackExcludedFromOutputEntry(t *testing.T) {
	rec := newIptablesRecorder()
	installRecorder(t, rec)

	worker := &RunWorker{
		env:            "test",
		service:        "grafana",
		block:          "g1",
		hostNetworking: true,
		dockerNetwork: &DockerNetwork{
			networkName: "warpeth0",
			ipv4: &NetworkInterface{
				interfaceName: "warpeth0",
				interfaceIp:   "10.100.0.2",
			},
		},
		servicesDockerNetwork: &DockerNetwork{
			networkName: "testservices",
			ipv4: &NetworkInterface{
				interfaceName: "testservices",
				interfaceIp:   "10.200.0.2",
			},
		},
		routingTable: &RoutingTable{
			tableNumber: 100,
			tableName:   "warp_eth0",
			ipv4: &NetworkInterface{
				interfaceName: "eth0",
				interfaceIp:   "10.0.0.1",
			},
		},
	}

	worker.initBlockRedirect()

	outputInserts := 0
	preroutingInserts := 0
	for _, rule := range rec.findRules("-I") {
		argsStr := strings.Join(rule.args, " ")
		switch rule.chain {
		case "OUTPUT":
			outputInserts += 1
			// the service's own loopback dials must not enter the block chain
			assert.Equal(t, strings.Contains(argsStr, "! -d 127.0.0.0/8"), true)
		case "PREROUTING":
			preroutingInserts += 1
			// external traffic is never destined to loopback, so the entry for
			// it is left alone
			assert.Equal(t, strings.Contains(argsStr, "127.0.0.0/8"), false)
		}
	}
	assert.NotEqual(t, outputInserts, 0)
	assert.NotEqual(t, preroutingInserts, 0)
}

// A service in a docker network is legitimately reached through the DNAT, and
// the docker network ip is where its container actually listens, so its entry
// rule keeps matching every LOCAL destination.
func TestIptablesLoopbackNotExcludedForDockerNetworking(t *testing.T) {
	rec := newIptablesRecorder()
	installRecorder(t, rec)

	worker := &RunWorker{
		env:            "test",
		service:        "api",
		block:          "g1",
		hostNetworking: false,
		servicesDockerNetwork: &DockerNetwork{
			networkName: "testservices",
			ipv4: &NetworkInterface{
				interfaceName: "testservices",
				interfaceIp:   "10.200.0.2",
			},
		},
		routingTable: &RoutingTable{
			tableNumber: 100,
			tableName:   "warp_eth0",
			ipv4: &NetworkInterface{
				interfaceName: "eth0",
				interfaceIp:   "10.0.0.1",
			},
		},
	}

	worker.initBlockRedirect()

	for _, rule := range rec.getRules() {
		argsStr := strings.Join(rule.args, " ")
		assert.Equal(t, strings.Contains(argsStr, "127.0.0.0/8"), false)
	}
	// and nothing is deleted: the legacy cleanup is host-networking only
	assert.Equal(t, len(rec.findRules("-D")), 0)
}

// assignDeployPorts takes the first internal port in each block with no
// listener, so findOccupiedPorts has to see every listener in the block however
// it is bound. A service may keep its children on loopback rather than the
// docker network ip -- the grafana bundle does, behind its authenticated front
// -- and a scan anchored only on the docker network ip cannot see them. The
// allocator then hands a live port to the next deploy, whose children crash
// loop "address already in use" while the previous container keeps serving.
func TestFindOccupiedPortsSeesLoopbackListeners(t *testing.T) {
	netstatOut := `Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State
tcp        0      0 172.18.0.1:14488        0.0.0.0:*               LISTEN
tcp        0      0 127.0.0.1:14518         0.0.0.0:*               LISTEN
tcp        0      0 127.0.0.1:14548         0.0.0.0:*               LISTEN
tcp        0      0 0.0.0.0:14608           0.0.0.0:*               LISTEN
tcp6       0      0 ::1:14638               :::*                    LISTEN
udp        0      0 127.0.0.1:14668         0.0.0.0:*
`
	origOut := outAndLogFunc
	outAndLogFunc = func(cmd *exec.Cmd) ([]byte, error) {
		return []byte(netstatOut), nil
	}
	t.Cleanup(func() { outAndLogFunc = origOut })

	worker := &RunWorker{
		env:            "test",
		service:        "grafana",
		block:          "g1",
		hostNetworking: true,
		dockerNetwork: &DockerNetwork{
			networkName: "warpeth0",
			ipv4: &NetworkInterface{
				interfaceName: "warpeth0",
				interfaceIp:   "172.18.0.1",
			},
		},
		portBlocks: &PortBlocks{
			externalsToInternals: map[int][]int{
				80:   {14488, 14489},
				3000: {14518, 14519},
				3101: {14548, 14549},
				6490: {14608, 14609},
				6491: {14638, 14639},
				6492: {14668, 14669},
			},
			externalsToService: map[int]int{
				80: 80, 3000: 3000, 3101: 3101, 6490: 6490, 6491: 6491, 6492: 6492,
			},
		},
	}

	occupied, err := worker.findOccupiedPorts()
	assert.Equal(t, err, nil)

	// the docker network ip listener is seen, as it always was
	assert.Equal(t, occupied[14488], true)
	// loopback listeners are seen -- this is the regression
	assert.Equal(t, occupied[14518], true)
	assert.Equal(t, occupied[14548], true)
	assert.Equal(t, occupied[14668], true)
	// wildcard binds, v4 and v6 loopback
	assert.Equal(t, occupied[14608], true)
	assert.Equal(t, occupied[14638], true)
	// the free alternate in each block stays free, so a deploy can still land
	for _, freePort := range []int{14489, 14519, 14549, 14609, 14639, 14669} {
		assert.Equal(t, occupied[freePort], false)
	}
}

func TestIptablesChainName(t *testing.T) {
	tests := []struct {
		env     string
		service string
		block   string
	}{
		{"main", "lb", "edge-0-eth0"},
		{"main", "connect", "g1"},
		{"main", "config-updater", "main"},
		{"canary", "lb", "edge-0-eno2"},
	}

	for _, tt := range tests {
		worker := &RunWorker{
			env:     tt.env,
			service: tt.service,
			block:   tt.block,
		}
		chainName := worker.iptablesChainName()
		assert.Equal(t, len(chainName) <= 28, true)
		assert.NotEqual(t, chainName, "")
	}
}

func TestIptablesRuleSymmetry(t *testing.T) {
	rec := newIptablesRecorder()
	installRecorder(t, rec)

	worker := &RunWorker{
		env:            "test",
		service:        "lb",
		block:          "edge-0-eth0",
		hostNetworking: true,
		dockerNetwork: &DockerNetwork{
			networkName: "warpeth0",
			ipv4: &NetworkInterface{
				interfaceName: "warpeth0",
				interfaceIp:   "10.100.0.2",
			},
		},
		servicesDockerNetwork: &DockerNetwork{
			networkName: "testservices",
			ipv4: &NetworkInterface{
				interfaceName: "testservices",
				interfaceIp:   "10.200.0.2",
			},
		},
		routingTable: &RoutingTable{
			tableNumber: 100,
			tableName:   "warp_eth0",
			ipv4: &NetworkInterface{
				interfaceName: "eth0",
				interfaceIp:   "10.0.0.1",
			},
		},
	}

	ports := map[int]int{
		7080: 7201,
		7443: 7231,
	}
	servicePorts := map[int]int{
		80:  7201,
		443: 7231,
	}

	// deploy v1
	worker.redirect(ports, servicePorts, "abc123")
	v1Rules := rec.getRules()
	rec.clear()

	// deploy v2 with same ports — no rules should change
	chainName := worker.iptablesChainName()
	rec.listings[chainName] = fmt.Sprintf(`Chain %s (2 references)
target     prot opt source               destination
DNAT       tcp  --  0.0.0.0/0            0.0.0.0/0            tcp dpt:7080 to:10.100.0.2:7201
DNAT       tcp  --  0.0.0.0/0            0.0.0.0/0            tcp dpt:7201 to:10.100.0.2:7201
DNAT       tcp  --  0.0.0.0/0            0.0.0.0/0            tcp dpt:7443 to:10.100.0.2:7231
DNAT       tcp  --  0.0.0.0/0            0.0.0.0/0            tcp dpt:7231 to:10.100.0.2:7231
DNAT       tcp  --  0.0.0.0/0            10.0.0.1             tcp dpt:80 to:10.100.0.2:7201
DNAT       tcp  --  0.0.0.0/0            10.0.0.1             tcp dpt:443 to:10.100.0.2:7231`, chainName)

	rec.listings["POSTROUTING"] = `Chain POSTROUTING (policy ACCEPT)
target     prot opt source               destination
SNAT       udp  --  0.0.0.0/0            0.0.0.0/0            udp spt:7201 to:10.0.0.1:7080
SNAT       udp  --  0.0.0.0/0            0.0.0.0/0            udp spt:7231 to:10.0.0.1:7443`

	// now make -C succeed for existing rules
	origRunAndLog := runAndLogFunc
	runAndLogFunc = func(cmd *exec.Cmd) error {
		args := cmd.Args
		if len(args) > 0 && args[0] == "sudo" {
			args = args[1:]
		}
		iptablesIdx := -1
		for i, a := range args {
			if a == "iptables" || a == "ip6tables" {
				iptablesIdx = i
				break
			}
		}
		if iptablesIdx < 0 {
			return nil
		}
		args = args[iptablesIdx+1:]
		op, chain, _ := parseIptablesArgs(args)
		if op != "" {
			rec.record(iptablesRule{op: op, chain: chain, args: args})
		}
		// -C succeeds for existing rules
		if op == "-C" {
			return nil
		}
		return nil
	}
	defer func() { runAndLogFunc = origRunAndLog }()

	worker.redirect(ports, servicePorts, "abc123")
	v2Rules := rec.getRules()

	v2Inserts := 0
	v2Deletes := 0
	for _, rule := range v2Rules {
		if rule.op == "-I" {
			v2Inserts++
		}
		if rule.op == "-D" {
			v2Deletes++
		}
	}
	assert.Equal(t, v2Inserts, 0)
	assert.Equal(t, v2Deletes, 0)

	v1Inserts := 0
	for _, rule := range v1Rules {
		if rule.op == "-I" {
			v1Inserts++
		}
	}
	assert.NotEqual(t, v1Inserts, 0)
}

func TestIptablesPortCoverage(t *testing.T) {
	rec := newIptablesRecorder()
	installRecorder(t, rec)

	worker := &RunWorker{
		env:            "test",
		service:        "lb",
		block:          "edge-0-eth0",
		hostNetworking: true,
		dockerNetwork: &DockerNetwork{
			networkName: "warpeth0",
			ipv4: &NetworkInterface{
				interfaceName: "warpeth0",
				interfaceIp:   "10.100.0.2",
			},
		},
		servicesDockerNetwork: &DockerNetwork{
			networkName: "testservices",
			ipv4: &NetworkInterface{
				interfaceName: "testservices",
				interfaceIp:   "10.200.0.2",
			},
		},
		routingTable: &RoutingTable{
			tableNumber: 100,
			tableName:   "warp_eth0",
			ipv4: &NetworkInterface{
				interfaceName: "eth0",
				interfaceIp:   "10.0.0.1",
			},
		},
	}

	externalPorts := map[int]int{
		7080: 7201,
		7443: 7231,
	}
	servicePorts := map[int]int{
		80:  7201,
		443: 7231,
	}

	worker.redirect(externalPorts, servicePorts, "abc123")

	insertRules := rec.findRules("-I")

	// collect all dports from insert rules
	dports := map[string]bool{}
	for _, rule := range insertRules {
		for i, arg := range rule.args {
			if arg == "--dport" && i+1 < len(rule.args) {
				dports[rule.args[i+1]] = true
			}
		}
	}

	requiredPorts := []string{"7080", "7443", "7201", "7231", "80", "443"}
	for _, port := range requiredPorts {
		assert.Equal(t, dports[port], true)
	}

	destinations := map[string]bool{}
	for _, rule := range insertRules {
		for i, arg := range rule.args {
			if arg == "--to-destination" && i+1 < len(rule.args) {
				destinations[rule.args[i+1]] = true
			}
		}
	}

	for _, dest := range []string{"10.100.0.2:7201", "10.100.0.2:7231"} {
		assert.Equal(t, destinations[dest], true)
	}
}

// conntrackRecorder captures `conntrack` invocations made via runAndLog.
type conntrackRecorder struct {
	mu       sync.Mutex
	commands [][]string
}

func (r *conntrackRecorder) getCommands() [][]string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([][]string, len(r.commands))
	copy(out, r.commands)
	return out
}

func installConntrackRecorder(t *testing.T, rec *conntrackRecorder) {
	t.Helper()

	origRunAndLog := runAndLogFunc
	runAndLogFunc = func(cmd *exec.Cmd) error {
		args := cmd.Args
		// skip "sudo" prefix
		if len(args) > 0 && args[0] == "sudo" {
			args = args[1:]
		}
		if len(args) == 0 || args[0] != "conntrack" {
			return nil
		}
		rec.mu.Lock()
		defer rec.mu.Unlock()
		rec.commands = append(rec.commands, args)
		return nil
	}
	t.Cleanup(func() {
		runAndLogFunc = origRunAndLog
	})
}

// flagValue returns the value following the given flag, or "".
func flagValue(args []string, flag string) string {
	for i, arg := range args {
		if arg == flag && i+1 < len(args) {
			return args[i+1]
		}
	}
	return ""
}

// A wireguard (udp) client flow is pinned by its conntrack entry to the
// internal port that was the DNAT target when the flow started. Ports whose
// container stopped (drain end or crash) must have their entries deleted so
// the flow re-resolves to the live container; ports that still have a
// listener (the new container, and draining containers) must be left alone.
func TestCleanupStaleConntrack(t *testing.T) {
	rec := &conntrackRecorder{}
	installConntrackRecorder(t, rec)

	worker := &RunWorker{
		env:            "test",
		service:        "proxy",
		block:          "g8",
		hostNetworking: true,
		// wg block: external udp 7163, internal pool 14098-14101
		portBlocks: parsePortBlocks("8084:7163:14098-14101"),
		dockerNetwork: &DockerNetwork{
			networkName: "warpeno1np0",
			ipv4: &NetworkInterface{
				interfaceName: "warpeno1np0",
				interfaceIp:   "172.19.0.1",
			},
		},
	}

	// 14099 = current container, 14100 = draining container: both listening.
	// 14098, 14101 = previous generations, no listener: stale.
	worker.cleanupStaleConntrackForOccupiedPorts(map[int]bool{
		14099: true,
		14100: true,
	})

	commands := rec.getCommands()
	assert.Equal(t, len(commands), 2)

	deletedPorts := map[string]bool{}
	for _, args := range commands {
		assert.Equal(t, args[0], "conntrack")
		assert.Equal(t, args[1], "-D")
		assert.Equal(t, flagValue(args, "-f"), "ipv4")
		assert.Equal(t, flagValue(args, "-p"), "udp")
		assert.Equal(t, flagValue(args, "--reply-src"), "172.19.0.1")
		deletedPorts[flagValue(args, "--reply-port-src")] = true
	}
	assert.Equal(t, deletedPorts["14098"], true)
	assert.Equal(t, deletedPorts["14101"], true)
	// live listeners are never flushed
	assert.Equal(t, deletedPorts["14099"], false)
	assert.Equal(t, deletedPorts["14100"], false)
}

func TestCleanupStaleConntrackIpv6(t *testing.T) {
	rec := &conntrackRecorder{}
	installConntrackRecorder(t, rec)

	worker := &RunWorker{
		env:            "test",
		service:        "proxy",
		block:          "g8",
		hostNetworking: true,
		portBlocks:     parsePortBlocks("8084:7163:14098-14099"),
		dockerNetwork: &DockerNetwork{
			networkName: "warpeno1np0",
			ipv4: &NetworkInterface{
				interfaceName: "warpeno1np0",
				interfaceIp:   "172.19.0.1",
			},
			ipv6: &NetworkInterface{
				interfaceName: "warpeno1np0",
				interfaceIp:   "fd00:f1a4:349b:bc6e::1",
			},
		},
	}

	worker.cleanupStaleConntrackForOccupiedPorts(map[int]bool{
		14099: true,
	})

	commands := rec.getCommands()
	// one stale port, flushed once per address family
	assert.Equal(t, len(commands), 2)

	replySrcsByFamily := map[string]string{}
	for _, args := range commands {
		assert.Equal(t, flagValue(args, "--reply-port-src"), "14098")
		replySrcsByFamily[flagValue(args, "-f")] = flagValue(args, "--reply-src")
	}
	assert.Equal(t, replySrcsByFamily["ipv4"], "172.19.0.1")
	assert.Equal(t, replySrcsByFamily["ipv6"], "fd00:f1a4:349b:bc6e::1")
}

// cleanupStaleConntrack is a no-op outside host networking (docker-proxy owns
// the ports there) and without port blocks; it must return before shelling out
// to netstat/conntrack.
func TestCleanupStaleConntrackNonHostNetworking(t *testing.T) {
	rec := &conntrackRecorder{}
	installConntrackRecorder(t, rec)

	worker := &RunWorker{
		env:            "test",
		service:        "proxy",
		block:          "g8",
		hostNetworking: false,
		portBlocks:     parsePortBlocks("8084:7163:14098-14101"),
	}
	worker.cleanupStaleConntrack()

	noBlocksWorker := &RunWorker{
		env:            "test",
		service:        "proxy",
		block:          "g8",
		hostNetworking: true,
	}
	noBlocksWorker.cleanupStaleConntrack()

	assert.Equal(t, len(rec.getCommands()), 0)
}
