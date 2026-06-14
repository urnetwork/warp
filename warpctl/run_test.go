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
