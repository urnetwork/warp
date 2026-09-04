package main

import (
	"bytes"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"regexp"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-playground/assert/v2"
	warp "github.com/urnetwork/warp"
	"golang.org/x/exp/maps"
)

func captureErrOutput(t *testing.T) *bytes.Buffer {
	t.Helper()
	previousOutput := Err.Writer()
	output := &bytes.Buffer{}
	Err.SetOutput(output)
	t.Cleanup(func() {
		Err.SetOutput(previousOutput)
	})
	return output
}

func TestContainerNamePrefixFilterSeparatesG1FromG10(t *testing.T) {
	filter := containerNamePrefixFilter("main-proxy-g1-2026.9.2-outerwerld-1035614810-")
	pattern := strings.TrimPrefix(filter, "name=")
	tests := []struct {
		name    string
		matches bool
	}{
		{"/main-proxy-g1-2026.9.2-outerwerld-1035614810-1788465918741", true},
		{"/main-proxy-g10-2026.9.2-outerwerld-1035614810-1788466104262", false},
		{"/main-proxy-g1-2026x9x2-outerwerld-1035614810-1788465918741", false},
		{"/prefix-main-proxy-g1-2026.9.2-outerwerld-1035614810-1788465918741", false},
	}
	for _, test := range tests {
		matches, err := regexp.MatchString(pattern, test.name)
		if err != nil {
			t.Fatal(err)
		}
		if matches != test.matches {
			t.Errorf("filter %q matching %q = %t, want %t", filter, test.name, matches, test.matches)
		}
	}
}

func TestInspectPulledImageDigestReturnsExactDockerIdentity(t *testing.T) {
	previousOutAndLog := outAndLogFunc
	want := "sha256:" + strings.Repeat("a", 64)
	var commandArgs []string
	outAndLogFunc = func(cmd *exec.Cmd) ([]byte, error) {
		commandArgs = append([]string(nil), cmd.Args...)
		return []byte(want + "\n"), nil
	}
	t.Cleanup(func() { outAndLogFunc = previousOutAndLog })

	got, err := inspectPulledImageDigest("example.invalid/main-api:release")
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("image digest = %q, want %q", got, want)
	}
	command := strings.Join(commandArgs, " ")
	if !strings.Contains(command, "docker image inspect --format={{.Id}} example.invalid/main-api:release") {
		t.Fatalf("inspect command = %q", command)
	}
}

func TestInspectPulledImageDigestRejectsMutableOrMalformedIdentity(t *testing.T) {
	previousOutAndLog := outAndLogFunc
	outAndLogFunc = func(*exec.Cmd) ([]byte, error) {
		return []byte("example.invalid/main-api:latest\n"), nil
	}
	t.Cleanup(func() { outAndLogFunc = previousOutAndLog })

	if _, err := inspectPulledImageDigest("example.invalid/main-api:latest"); err == nil {
		t.Fatal("mutable image tag accepted as a content identity")
	}
}

func TestTransparentLbRestoresCrispPolicyRoutingAfterNetworkdRestart(t *testing.T) {
	previousRunAndLog := runAndLogFunc
	previousSudo2 := sudo2Func
	commands := []string{}
	runAndLogFunc = func(cmd *exec.Cmd) error {
		commands = append(commands, strings.Join(cmd.Args, " "))
		return nil
	}
	sudo2Func = func(name []string, args ...string) *exec.Cmd {
		commandArgs := append([]string{}, name...)
		commandArgs = append(commandArgs, args...)
		command := strings.Join(commandArgs, " ")
		switch command {
		case "ip route show table main default":
			return exec.Command("printf", "%s", `default via 192.168.51.1 dev eno3 proto dhcp src 192.168.51.198 metric 50
default via 65.49.70.65 dev eno1np0 proto static metric 100
`)
		case "ip -6 route show table main default":
			return exec.Command("printf", "%s", `default via fe80::1 dev eno3 proto ra metric 50 pref medium
default via fe80::f6e2:c6ff:fe20:4d01 dev eno1np0 proto ra metric 1024 pref medium
`)
		}
		if strings.Contains(command, " rule list") {
			return exec.Command("printf", "%s", "")
		}
		return exec.Command("sudo", commandArgs...)
	}
	t.Cleanup(func() {
		runAndLogFunc = previousRunAndLog
		sudo2Func = previousSudo2
	})

	worker := &RunWorker{
		servicesDockerNetwork: &DockerNetwork{
			networkName: "warpservices",
			ipv4: &NetworkInterface{
				interfaceName:   "warpservices",
				interfaceIp:     "172.18.0.1",
				interfaceSubnet: "172.18.0.0/16",
			},
		},
		dockerNetwork: &DockerNetwork{
			networkName: "warpeno1np0",
			ipv4: &NetworkInterface{
				interfaceName:   "warpeno1np0",
				interfaceIp:     "172.19.0.1",
				interfaceSubnet: "172.19.0.0/16",
			},
			ipv6: &NetworkInterface{
				interfaceName:   "warpeno1np0",
				interfaceIp:     "fd00:eb56:c09b:adef::1",
				interfaceSubnet: "fd00:eb56:c09b:adef::/64",
			},
		},
		routingTable: &RoutingTable{
			tableNumber: 100,
			tableName:   "warp100",
			ipv4: &NetworkInterface{
				interfaceName:    "eno1np0",
				interfaceIp:      "65.49.70.94",
				interfaceSubnet:  "65.49.70.64/27",
				interfaceGateway: "65.49.70.65",
			},
			ipv6: &NetworkInterface{
				interfaceName:    "eno1np0",
				interfaceIp:      "2001:470:99:5940:3a05:25ff:fe37:292a",
				interfaceSubnet:  "2001:470:99:5940::/64",
				interfaceGateway: "2001:470:99:5940::1",
			},
		},
		fwMark: 100,
	}

	worker.initRoutingTable()
	commands = nil
	waits := 0
	reconcileRoutingTableUntilQuit(func(timeout time.Duration) bool {
		if timeout != RoutingTableReconcileTimeout {
			t.Fatalf("reconcile timeout=%s", timeout)
		}
		waits++
		return waits == 2
	}, worker.initRoutingTable)

	joinedCommands := "\n" + strings.Join(commands, "\n") + "\n"
	for _, expected := range []string{
		"sudo ip route replace 65.49.70.64/27 dev eno1np0 src 65.49.70.94 table 100",
		"sudo ip route replace default via 65.49.70.65 dev eno1np0 table 100",
		"sudo ip rule add from 65.49.70.94 table 100",
		"sudo ip rule add from 172.19.0.0/16 table 100",
		"sudo ip rule add fwmark 100 table 100",
		"sudo ip -6 route replace 2001:470:99:5940::/64 dev eno1np0 src 2001:470:99:5940:3a05:25ff:fe37:292a table 100",
		"sudo ip -6 route replace default via fe80::f6e2:c6ff:fe20:4d01 dev eno1np0 table 100",
		"sudo ip -6 rule add from 2001:470:99:5940:3a05:25ff:fe37:292a table 100",
		"sudo ip -6 rule add from fd00:eb56:c09b:adef::/64 table 100",
		"sudo ip -6 rule add fwmark 100 table 100",
	} {
		if !strings.Contains(joinedCommands, "\n"+expected+"\n") {
			t.Errorf("missing reconciled command %q in:\n%s", expected, strings.TrimSpace(joinedCommands))
		}
	}
	if strings.Contains(joinedCommands, " route add default ") {
		t.Fatalf("default route reconciliation is not replay-safe:\n%s", strings.TrimSpace(joinedCommands))
	}
}

// A non-transparent edge LB remains alive when its public carrier drops. The
// kernel/network manager may remove its foreign policy rules and table routes
// while the service worker continues version polling. Replaying only at
// process startup leaves replies on the lower-metric management default until
// an operator restart; the ordinary poll loop must restore them on its bounded
// routing cadence.
func TestNonTransparentLbRestoresPolicyRoutingAfterCarrierCycle(t *testing.T) {
	previousRunAndLog := runAndLogFunc
	previousSudo2 := sudo2Func
	commands := []string{}
	runAndLogFunc = func(cmd *exec.Cmd) error {
		commands = append(commands, strings.Join(cmd.Args, " "))
		return nil
	}
	sudo2Func = func(name []string, args ...string) *exec.Cmd {
		commandArgs := append([]string{}, name...)
		commandArgs = append(commandArgs, args...)
		command := strings.Join(commandArgs, " ")
		switch command {
		case "ip route show table main default":
			return exec.Command("printf", "%s", "default via 65.49.70.65 dev eno3 metric 100\n")
		case "ip -6 route show table main default":
			return exec.Command("printf", "%s", "default via fe80::f6e2:c6ff:fed6:e779 dev eno3 metric 1024\n")
		}
		if strings.Contains(command, " rule list") {
			// Empty listings model the routes and rules removed during the
			// carrier cycle.
			return exec.Command("printf", "%s", "")
		}
		return exec.Command("sudo", commandArgs...)
	}
	t.Cleanup(func() {
		runAndLogFunc = previousRunAndLog
		sudo2Func = previousSudo2
	})

	worker := &RunWorker{
		service:     "lb",
		transparent: false,
		servicesDockerNetwork: &DockerNetwork{
			networkName: "warpservices",
			ipv4: &NetworkInterface{
				interfaceName:   "warpservices",
				interfaceIp:     "172.18.0.1",
				interfaceSubnet: "172.18.0.0/16",
			},
		},
		dockerNetwork: &DockerNetwork{
			networkName: "warpeno3",
			ipv4: &NetworkInterface{
				interfaceName:   "warpeno3",
				interfaceIp:     "172.19.0.1",
				interfaceSubnet: "172.19.0.0/16",
			},
			ipv6: &NetworkInterface{
				interfaceName:   "warpeno3",
				interfaceIp:     "fd00:e769:4ad:6eb3::1",
				interfaceSubnet: "fd00:e769:4ad:6eb3::/64",
			},
		},
		routingTable: &RoutingTable{
			interfaceName: "eno3",
			tableNumber:   100,
			tableName:     "warp100",
			ipv4: &NetworkInterface{
				interfaceName:    "eno3",
				interfaceIp:      "65.49.70.82",
				interfaceSubnet:  "65.49.70.64/27",
				interfaceGateway: "65.49.70.65",
			},
			ipv6: &NetworkInterface{
				interfaceName:    "eno3",
				interfaceIp:      "2001:470:99:5870:e643:4bff:fe89:2bca",
				interfaceSubnet:  "2001:470:99:5870::/64",
				interfaceGateway: "2001:470:99:5870::1",
			},
		},
		fwMark: 100,
	}

	first := time.Date(2026, 9, 3, 6, 46, 55, 0, time.UTC)
	worker.reconcileRoutingTableIfDue(first)
	commands = nil

	worker.reconcileRoutingTableIfDue(first.Add(RoutingTableReconcileTimeout - time.Second))
	if len(commands) != 0 {
		t.Fatalf("routing reconciled before cadence: %v", commands)
	}

	worker.reconcileRoutingTableIfDue(first.Add(RoutingTableReconcileTimeout))
	joinedCommands := "\n" + strings.Join(commands, "\n") + "\n"
	for _, expected := range []string{
		"sudo ip route replace 65.49.70.64/27 dev eno3 src 65.49.70.82 table 100",
		"sudo ip route replace default via 65.49.70.65 dev eno3 table 100",
		"sudo ip rule add from 65.49.70.82 table 100",
		"sudo ip -6 route replace 2001:470:99:5870::/64 dev eno3 src 2001:470:99:5870:e643:4bff:fe89:2bca table 100",
		"sudo ip -6 route replace default via fe80::f6e2:c6ff:fed6:e779 dev eno3 table 100",
		"sudo ip -6 rule add from 2001:470:99:5870:e643:4bff:fe89:2bca table 100",
		"sudo ip -6 rule add from fd00:e769:4ad:6eb3::/64 table 100",
		"sudo ip -6 rule add fwmark 100 table 100",
	} {
		if !strings.Contains(joinedCommands, "\n"+expected+"\n") {
			t.Errorf("missing carrier-recovery command %q in:\n%s", expected, strings.TrimSpace(joinedCommands))
		}
	}
	if want := first.Add(2 * RoutingTableReconcileTimeout); !worker.nextRoutingTableReconcile.Equal(want) {
		t.Fatalf("next routing reconciliation = %s, want %s", worker.nextRoutingTableReconcile, want)
	}
}

// network-online.target does not guarantee that an SLAAC/RA address has
// arrived. The transparent LB must learn a public IPv6 address that appears
// after startup; otherwise every reconciliation remains IPv4-only and IPv6
// proxy replies follow the lower-metric LAN default route.
func TestTransparentLbDiscoversIpv6AfterNetworkOnline(t *testing.T) {
	previousRunAndLog := runAndLogFunc
	previousSudo2 := sudo2Func
	commands := []string{}
	runAndLogFunc = func(cmd *exec.Cmd) error {
		commands = append(commands, strings.Join(cmd.Args, " "))
		return nil
	}
	sudo2Func = func(name []string, args ...string) *exec.Cmd {
		commandArgs := append([]string{}, name...)
		commandArgs = append(commandArgs, args...)
		command := strings.Join(commandArgs, " ")
		switch command {
		case "ip route show table main default":
			return exec.Command("printf", "%s", "default via 65.49.70.65 dev eno1np0 metric 100\n")
		case "ip -6 route show table main default":
			return exec.Command("printf", "%s", "default via fe80::f6e2:c6ff:fed6:71bb dev eno1np0 metric 1024\n")
		}
		if strings.Contains(command, " rule list") {
			return exec.Command("printf", "%s", "")
		}
		return exec.Command("sudo", commandArgs...)
	}
	t.Cleanup(func() {
		runAndLogFunc = previousRunAndLog
		sudo2Func = previousSudo2
	})

	publicIpv4 := &NetworkInterface{
		interfaceName:    "eno1np0",
		interfaceIp:      "65.49.70.92",
		interfaceSubnet:  "65.49.70.64/27",
		interfaceGateway: "65.49.70.65",
	}
	publicIpv6 := &NetworkInterface{
		interfaceName:    "eno1np0",
		interfaceIp:      "2001:470:99:5960:3a05:25ff:fe32:e5ab",
		interfaceSubnet:  "2001:470:99:5960::/64",
		interfaceGateway: "2001:470:99:5960::1",
	}
	discoveries := 0
	worker := &RunWorker{
		servicesDockerNetwork: &DockerNetwork{
			networkName: "warpservices",
			ipv4: &NetworkInterface{
				interfaceName:   "warpservices",
				interfaceIp:     "172.18.0.1",
				interfaceSubnet: "172.18.0.0/16",
			},
		},
		dockerNetwork: &DockerNetwork{
			networkName: "warpeno1np0",
			ipv4: &NetworkInterface{
				interfaceName:   "warpeno1np0",
				interfaceIp:     "172.19.0.1",
				interfaceSubnet: "172.19.0.0/16",
			},
			ipv6: &NetworkInterface{
				interfaceName:   "warpeno1np0",
				interfaceIp:     "fd00:eb56:c09b:adef::1",
				interfaceSubnet: "fd00:eb56:c09b:adef::/64",
			},
		},
		routingTable: &RoutingTable{
			interfaceName: "eno1np0",
			tableNumber:   100,
			tableName:     "warp100",
			ipv4:          publicIpv4,
			ipv6:          nil,
		},
		fwMark: 100,
		networkInterfaces: func(string) ([]*NetworkInterface, []*NetworkInterface, error) {
			discoveries++
			if discoveries == 1 {
				return []*NetworkInterface{publicIpv4}, nil, nil
			}
			return []*NetworkInterface{publicIpv4}, []*NetworkInterface{publicIpv6}, nil
		},
	}

	worker.initRoutingTable()
	firstCommands := "\n" + strings.Join(commands, "\n") + "\n"
	if strings.Contains(firstCommands, "sudo ip -6 route replace") {
		t.Fatalf("configured IPv6 before it appeared:\n%s", strings.TrimSpace(firstCommands))
	}

	commands = nil
	worker.initRoutingTable()
	secondCommands := "\n" + strings.Join(commands, "\n") + "\n"
	for _, expected := range []string{
		"sudo ip -6 route replace 2001:470:99:5960::/64 dev eno1np0 src 2001:470:99:5960:3a05:25ff:fe32:e5ab table 100",
		"sudo ip -6 route replace default via fe80::f6e2:c6ff:fed6:71bb dev eno1np0 table 100",
		"sudo ip -6 rule add from 2001:470:99:5960:3a05:25ff:fe32:e5ab table 100",
		"sudo ip -6 rule add from fd00:eb56:c09b:adef::/64 table 100",
		"sudo ip -6 rule add fwmark 100 table 100",
	} {
		if !strings.Contains(secondCommands, "\n"+expected+"\n") {
			t.Errorf("missing late-IPv6 reconciliation command %q in:\n%s", expected, strings.TrimSpace(secondCommands))
		}
	}
	if discoveries != 2 {
		t.Fatalf("interface discoveries=%d, want 2", discoveries)
	}
}

func TestPollConnectListenerStatusRequiresExplicitReadySignal(t *testing.T) {
	var ready atomic.Bool
	var listenerPorts atomic.Value
	listenerPorts.Store("443")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != "main-connect.example.com" {
			http.Error(w, "wrong host", http.StatusBadRequest)
			return
		}
		if ready.Load() {
			w.Header().Set(connectListenersReadyHeader, "1")
			w.Header().Set(connectUdpListenersHeader, listenerPorts.Load().(string))
		}
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}))
	defer server.Close()

	err := pollConnectListenerStatus(server.Client(), server.URL, "main-connect.example.com", []int{443, 4053})
	if err == nil || !strings.Contains(err.Error(), connectListenersReadyHeader) {
		t.Fatalf("old constant-ok status was accepted: %v", err)
	}
	ready.Store(true)
	err = pollConnectListenerStatus(server.Client(), server.URL, "main-connect.example.com", []int{443, 4053})
	if err == nil || !strings.Contains(err.Error(), "required UDP/4053") {
		t.Fatalf("stale Connect port allocation was accepted: %v", err)
	}
	listenerPorts.Store("443,4053,8053")
	if err := pollConnectListenerStatus(server.Client(), server.URL, "main-connect.example.com", []int{443, 4053}); err != nil {
		t.Fatalf("listener-ready status rejected: %v", err)
	}
}

type iptablesRule struct {
	op    string
	chain string
	args  []string
}

func (r iptablesRule) String() string {
	return fmt.Sprintf("%s %s %s", r.op, r.chain, strings.Join(r.args, " "))
}

type iptablesRecorder struct {
	mu         sync.Mutex
	rules      []iptablesRule
	ruleExists func([]string) bool
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

		// -C (check): return error to indicate rule doesn't exist (trigger insert),
		// unless a test supplies the exact pre-existing-rule behavior it needs.
		if op == "-C" {
			if rec.ruleExists != nil && rec.ruleExists(args) {
				return nil
			}
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

		// detect listing calls: -L/-S <chain>
		isListing := false
		listingOperation := ""
		var listChain string
		for i, a := range allArgs {
			if (a == "-L" || a == "-S") && i+1 < len(allArgs) {
				isListing = true
				listingOperation = strings.TrimPrefix(a, "-")
				listChain = allArgs[i+1]
			}
		}

		if isListing {
			output := ""
			commandName := name[len(name)-1]
			if listing, ok := rec.listings[commandName+":"+listingOperation+":"+listChain]; ok {
				output = listing
			} else if listing, ok := rec.listings[listingOperation+":"+listChain]; ok {
				output = listing
			} else if listing, ok := rec.listings[listChain]; ok {
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

func TestSelectOrphanedServiceBlockContainersPreservesActiveOwners(t *testing.T) {
	containers := ContainerList{
		&Container{
			ContainerId: "active-current",
			Config: &ContainerConfig{Env: []string{
				"WARP_PORTS=80:7290,443:7320,444:9607,1080:9367",
			}},
		},
		&Container{
			ContainerId: "orphan-z",
			Config: &ContainerConfig{Env: []string{
				"WARP_PORTS=80:7289,443:7319,444:9606,1080:9366",
			}},
		},
		&Container{
			ContainerId: "active-transition",
			Config: &ContainerConfig{Env: []string{
				"WARP_PORTS=4053:15027,8053:14547",
			}},
		},
		&Container{
			ContainerId: "orphan-a",
			Config: &ContainerConfig{Env: []string{
				"WARP_PORTS=80:7288,443:7318,444:9605,1080:9365",
			}},
		},
	}

	orphaned, err := selectOrphanedServiceBlockContainers(
		containers,
		map[int]bool{7320: true, 14547: true},
	)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := strings.Join(orphaned, ","), "orphan-a,orphan-z"; got != want {
		t.Fatalf("orphaned containers=%q want=%q", got, want)
	}
}

func TestSelectOrphanedServiceBlockContainersFailsClosedWithoutOwner(t *testing.T) {
	containers := ContainerList{
		&Container{
			ContainerId: "one",
			Config: &ContainerConfig{Env: []string{
				"WARP_PORTS=443:7319",
			}},
		},
		&Container{
			ContainerId: "two",
			Config: &ContainerConfig{Env: []string{
				"WARP_PORTS=443:7320",
			}},
		},
	}

	orphaned, err := selectOrphanedServiceBlockContainers(
		containers,
		map[int]bool{7001: true},
	)
	if err == nil || !strings.Contains(err.Error(), "no running container owns") {
		t.Fatalf("missing active owner was accepted: orphaned=%v err=%v", orphaned, err)
	}
	if len(orphaned) != 0 {
		t.Fatalf("fail-closed selection returned destructive targets: %v", orphaned)
	}
}

func TestCommittedDeploymentSurvivesPostCutoverDiscoveryFailure(t *testing.T) {
	output := captureErrOutput(t)
	killedContainerIds := []string{}
	cutover := newDeploymentCutover("public-candidate")
	cutover.kill = func(containerId string) {
		killedContainerIds = append(killedContainerIds, containerId)
	}
	cutover.commit()

	housekeepingCalls := 0
	completeDeploymentCutover(cutover, func() error {
		housekeepingCalls++
		return errors.New("docker ps temporarily unavailable")
	})
	cutover.rollbackIfUncommitted()

	if housekeepingCalls != 1 {
		t.Fatalf("housekeeping calls=%d want=1", housekeepingCalls)
	}
	if len(killedContainerIds) != 0 {
		t.Fatalf("public candidate was rolled back after cutover: %v", killedContainerIds)
	}
	if !strings.Contains(output.String(), "cutover committed; housekeeping deferred") {
		t.Fatalf("missing recoverable post-cutover signal: %s", output.String())
	}
}

func TestUncommittedDeploymentStillStopsFailedCandidate(t *testing.T) {
	killedContainerIds := []string{}
	cutover := newDeploymentCutover("failed-candidate")
	cutover.kill = func(containerId string) {
		killedContainerIds = append(killedContainerIds, containerId)
	}

	cutover.rollbackIfUncommitted()

	if got, want := strings.Join(killedContainerIds, ","), "failed-candidate"; got != want {
		t.Fatalf("killed candidates=%q want=%q", got, want)
	}
}

func TestReconcileDuplicateVersionRedirectRulesUsesLiveSocketsDuringGracefulStop(t *testing.T) {
	rec := newIptablesRecorder()
	installRecorder(t, rec)
	origRunQuiet := runQuietFunc
	runQuietFunc = func(cmd *exec.Cmd) (commandOutput, error) {
		return commandOutput{stdout: []byte(`Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State
tcp        0      0 172.20.0.1:7231         0.0.0.0:*               LISTEN
udp        0      0 172.20.0.1:7231         0.0.0.0:*
`)}, nil
	}
	t.Cleanup(func() { runQuietFunc = origRunQuiet })

	worker := &RunWorker{
		env:            "main",
		service:        "lb",
		block:          "edge-1-eno2",
		hostNetworking: true,
		portBlocks:     parsePortBlocks("443:7443:7231-7232"),
		dockerNetwork: &DockerNetwork{
			networkName: "warpeno2",
			ipv4: &NetworkInterface{
				interfaceName: "warpeno2",
				interfaceIp:   "172.20.0.1",
			},
			ipv6: &NetworkInterface{
				interfaceName: "warpeno2",
				interfaceIp:   "fd00:f1a4:349b:bc6e::1",
			},
		},
	}
	chainName := worker.iptablesChainName()
	rec.listings["iptables:S:"+chainName] = strings.Join([]string{
		fmt.Sprintf("-A %s -d 65.49.70.94/32 -p tcp -m tcp --dport 443 -j DNAT --to-destination 172.20.0.1:7232", chainName),
		fmt.Sprintf("-A %s -d 65.49.70.94/32 -p tcp -m tcp --dport 443 -j DNAT --to-destination 172.20.0.1:7231", chainName),
		fmt.Sprintf("-A %s -p tcp --dport 7443 -j DNAT --to-destination 172.20.0.1:7232", chainName),
	}, "\n")
	rec.listings["ip6tables:S:"+chainName] = strings.Join([]string{
		fmt.Sprintf("-A %s -d 2001:470:99:56:e643:4bff:fec3:8446/128 -p tcp -m tcp --dport 443 -j DNAT --to-destination [fd00:f1a4:349b:bc6e::1]:7232", chainName),
		fmt.Sprintf("-A %s -d 2001:470:99:56:e643:4bff:fec3:8446/128 -p tcp -m tcp --dport 443 -j DNAT --to-destination [fd00:f1a4:349b:bc6e::1]:7231", chainName),
		fmt.Sprintf("-A %s -p tcp --dport 7443 -j DNAT --to-destination [fd00:f1a4:349b:bc6e::1]:7232", chainName),
		fmt.Sprintf("-A %s -p tcp --dport 9999 -j DNAT --to-destination [fd00:f1a4:349b:bc6e::1]:9999", chainName),
		"-A WARP-MAIN-LB-OTHER -p tcp --dport 443 -j DNAT --to-destination [fd00:f1a4:349b:bc6e::1]:7232",
	}, "\n")
	// Docker can still report both 7231 and 7232 containers as running while
	// `docker stop -t 3600` waits, even though the draining nginx has already
	// closed 7232. The socket snapshot is therefore the ownership authority.
	now := time.Unix(1_788_123_200, 0)
	if err := worker.reconcileDuplicateVersionRedirectRules(
		[]string{"live-container", "gracefully-stopping-container"},
		now,
	); err != nil {
		t.Fatal(err)
	}
	deleteRules := rec.findRules("-D")
	if len(deleteRules) != 4 {
		t.Fatalf("deleted rules=%d want=4: %v", len(deleteRules), deleteRules)
	}
	for _, rule := range deleteRules {
		args := strings.Join(rule.args, " ")
		if !strings.Contains(args, "--to-destination [fd00:f1a4:349b:bc6e::1]:7232") &&
			!strings.Contains(args, "--to-destination 172.20.0.1:7232") {
			t.Fatalf("deleted a live or foreign target: %s", args)
		}
	}

	// Duplicate reconciliation is repeated after the listener can close, but
	// not on every five-second version poll while a one-hour drain is active.
	if err := worker.reconcileDuplicateVersionRedirectRules(
		[]string{"live-container", "gracefully-stopping-container"},
		now.Add(DuplicateRedirectReconcileInterval-time.Second),
	); err != nil {
		t.Fatal(err)
	}
	if got := len(rec.findRules("-D")); got != 4 {
		t.Fatalf("deleted rules inside bounded cadence=%d want=4", got)
	}
}

func TestReconcileDuplicateVersionRedirectRulesScansAfterLastContainerDisappears(t *testing.T) {
	rec := newIptablesRecorder()
	installRecorder(t, rec)
	occupiedPorts := `Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State
tcp        0      0 172.20.0.1:7231         0.0.0.0:*               LISTEN
tcp        0      0 172.20.0.1:7232         0.0.0.0:*               LISTEN
`
	origRunQuiet := runQuietFunc
	runQuietFunc = func(cmd *exec.Cmd) (commandOutput, error) {
		return commandOutput{stdout: []byte(occupiedPorts)}, nil
	}
	t.Cleanup(func() { runQuietFunc = origRunQuiet })

	worker := &RunWorker{
		env:            "main",
		service:        "lb",
		block:          "edge-0-eno2",
		hostNetworking: true,
		portBlocks:     parsePortBlocks("443:7443:7231-7232"),
		dockerNetwork: &DockerNetwork{
			networkName: "warpeno2",
			ipv4: &NetworkInterface{
				interfaceName: "warpeno2",
				interfaceIp:   "172.20.0.1",
			},
			ipv6: &NetworkInterface{
				interfaceName: "warpeno2",
				interfaceIp:   "fd00:f1a4:349b:bc6e::1",
			},
		},
	}
	chainName := worker.iptablesChainName()
	rec.listings["iptables:S:"+chainName] = strings.Join([]string{
		fmt.Sprintf("-A %s -d 65.19.157.62/32 -p tcp -m tcp --dport 443 -j DNAT --to-destination 172.20.0.1:7232", chainName),
		fmt.Sprintf("-A %s -d 65.19.157.62/32 -p tcp -m tcp --dport 443 -j DNAT --to-destination 172.20.0.1:7231", chainName),
	}, "\n")
	rec.listings["ip6tables:S:"+chainName] = strings.Join([]string{
		fmt.Sprintf("-A %s -d 2001:470:173:52:e643:4bff:fe23:a341/128 -p tcp -m tcp --dport 443 -j DNAT --to-destination [fd00:f1a4:349b:bc6e::1]:7232", chainName),
		fmt.Sprintf("-A %s -d 2001:470:173:52:e643:4bff:fe23:a341/128 -p tcp -m tcp --dport 443 -j DNAT --to-destination [fd00:f1a4:349b:bc6e::1]:7231", chainName),
	}, "\n")

	now := time.Unix(1_788_130_800, 0)
	if err := worker.reconcileDuplicateVersionRedirectRules(
		[]string{"live-container", "draining-container"},
		now,
	); err != nil {
		t.Fatal(err)
	}
	if got := len(rec.findRules("-D")); got != 0 {
		t.Fatalf("deleted a target while both listeners were live: %v", rec.findRules("-D"))
	}

	// The old listener closes just after the overlap scan and Docker removes
	// that container before the next 30-second cadence. Production reached
	// exactly this state with dead-first IPv6 7232/7659 rules.
	occupiedPorts = `Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State
tcp        0      0 172.20.0.1:7231         0.0.0.0:*               LISTEN
`
	if err := worker.reconcileDuplicateVersionRedirectRules(
		[]string{"live-container"},
		now.Add(time.Second),
	); err != nil {
		t.Fatal(err)
	}
	deleteRules := rec.findRules("-D")
	if len(deleteRules) != 2 {
		t.Fatalf("final duplicate-to-single scan deleted %d rules, want IPv4+IPv6 dead targets: %v", len(deleteRules), deleteRules)
	}
	for _, rule := range deleteRules {
		if !strings.Contains(strings.Join(rule.args, " "), ":7232") {
			t.Fatalf("final scan deleted a live target: %v", rule.args)
		}
	}
}

func TestPruneUnownedRedirectRulesRejectsEmptySocketSnapshot(t *testing.T) {
	worker := &RunWorker{
		portBlocks: parsePortBlocks("443:7443:7231-7232"),
	}

	err := worker.pruneUnownedRedirectRules(nil)
	if err == nil || !strings.Contains(err.Error(), "no live configured internal ports") {
		t.Fatalf("pruneUnownedRedirectRules(nil) = %v, want fail-closed socket error", err)
	}
}

func TestActiveRedirectInternalPortsUsesCurrentPoolTargets(t *testing.T) {
	rec := newIptablesRecorder()
	installRecorder(t, rec)

	worker := &RunWorker{
		env:            "main",
		service:        "lb",
		block:          "edge-0-eno3",
		hostNetworking: true,
		portBlocks: parsePortBlocks(
			"80:7081:7261-7290;443:7444:7291-7320;444:7071:9578-9607;1080:7059:9338-9367",
		),
		dockerNetwork: &DockerNetwork{
			networkName: "warpeno3",
			ipv4: &NetworkInterface{
				interfaceName: "warpeno3",
				interfaceIp:   "172.20.0.1",
			},
		},
	}
	chainName := worker.iptablesChainName()
	rec.listings[chainName] = fmt.Sprintf(`Chain %s (2 references)
target     prot opt source               destination
DNAT       udp  --  0.0.0.0/0            192.168.53.39        udp dpt:443 to:172.20.0.1:7320
DNAT       tcp  --  0.0.0.0/0            0.0.0.0/0            tcp dpt:7081 to:172.20.0.1:7290
DNAT       udp  --  0.0.0.0/0            0.0.0.0/0            udp dpt:9999 to:172.20.0.1:9999
SNAT       udp  --  0.0.0.0/0            0.0.0.0/0            udp spt:7320 to:192.168.53.39:443`, chainName)

	active, err := worker.activeRedirectInternalPorts()
	if err != nil {
		t.Fatal(err)
	}
	activePorts := maps.Keys(active)
	slices.Sort(activePorts)
	if got, want := fmt.Sprint(activePorts), "[7290 7320]"; got != want {
		t.Fatalf("active redirect ports=%s want=%s", got, want)
	}
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

// Some edge interfaces have a dual-stack Docker bridge but only an IPv4
// public route. IPv6 still needs the private deployment DNATs, but there is no
// IPv6 public source address against which Warp can build an SNAT rule.
func TestIptablesRedirectSkipsSnatWithoutFamilyRoutingTable(t *testing.T) {
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
			ipv6: &NetworkInterface{
				interfaceName: "warpeth0",
				interfaceIp:   "fd00:1234::2",
			},
		},
		routingTable: &RoutingTable{
			tableNumber: 100,
			tableName:   "warp_eth0",
			ipv4: &NetworkInterface{
				interfaceName: "eth0",
				interfaceIp:   "10.0.0.1",
			},
			// No public IPv6 route on this interface.
			ipv6: nil,
		},
	}

	err := worker.redirect(
		map[int]int{7443: 7231},
		map[int]int{443: 7231},
		"abc123",
	)
	if err != nil {
		t.Fatal(err)
	}

	foundIpv4Snat := false
	foundIpv6Dnat := false
	for _, rule := range rec.findRules("-I") {
		args := strings.Join(rule.args, " ")
		if strings.Contains(args, "SNAT") && strings.Contains(args, "10.0.0.1:7443") {
			foundIpv4Snat = true
		}
		if strings.Contains(args, "DNAT") && strings.Contains(args, "[fd00:1234::2]:7231") {
			foundIpv6Dnat = true
		}
		if strings.Contains(args, "SNAT") && strings.Contains(args, "fd00:1234") {
			t.Fatalf("created IPv6 SNAT without an IPv6 routing table: %s", args)
		}
	}
	assert.Equal(t, foundIpv4Snat, true)
	assert.Equal(t, foundIpv6Dnat, true)
}

func TestRedirectRejectsPortOwnedByAnotherWarpChain(t *testing.T) {
	rec := newIptablesRecorder()
	installRecorder(t, rec)
	rec.listings["-n"] = `Chain PREROUTING (policy ACCEPT)
target     prot opt source               destination

Chain WARP-TEST-GRAFANA-G1 (2 references)
target     prot opt source               destination
DNAT       udp  --  0.0.0.0/0            0.0.0.0/0            udp dpt:7178 to:172.18.0.1:14548

Chain WARP-TEST-CONNECT-G1 (2 references)
target     prot opt source               destination`

	worker := &RunWorker{
		env:            "test",
		service:        "connect",
		block:          "g1",
		hostNetworking: true,
		servicesDockerNetwork: &DockerNetwork{
			networkName: "testservices",
			ipv4: &NetworkInterface{
				interfaceName: "testservices",
				interfaceIp:   "172.18.0.1",
			},
		},
	}

	err := worker.validateRedirectPortOwnership(map[int]int{7178: 14578})
	if err == nil || !strings.Contains(err.Error(), "WARP-TEST-GRAFANA-G1") {
		t.Fatalf("ownership error=%v", err)
	}
	if len(rec.getRules()) != 0 {
		t.Fatalf("ownership validation mutated iptables: %v", rec.getRules())
	}
}

func TestRedirectRemovesWithdrawnRulesButPreservesPublicAliases(t *testing.T) {
	rec := newIptablesRecorder()
	installRecorder(t, rec)

	worker := &RunWorker{
		env:            "test",
		service:        "grafana",
		block:          "g1",
		hostNetworking: true,
		servicesDockerNetwork: &DockerNetwork{
			networkName: "testservices",
			ipv4: &NetworkInterface{
				interfaceName: "testservices",
				interfaceIp:   "172.18.0.1",
			},
		},
		portBlocks: &PortBlocks{
			externalsToInternals: map[int][]int{
				7183: {14728, 14729},
			},
			externalsToService: map[int]int{
				7183: 80,
			},
		},
	}

	chainName := worker.iptablesChainName()
	rec.listings[chainName] = fmt.Sprintf(`Chain %s (2 references)
target     prot opt source               destination
DNAT       udp  --  0.0.0.0/0            0.0.0.0/0            udp dpt:7178 to:172.18.0.1:14548
DNAT       udp  --  0.0.0.0/0            0.0.0.0/0            udp dpt:14548 to:172.18.0.1:14548
DNAT       udp  --  0.0.0.0/0            65.49.70.82          udp dpt:53 to:172.18.0.1:14548`, chainName)

	err := worker.redirect(
		map[int]int{7183: 14728},
		map[int]int{80: 14728},
		"grafana-container",
	)
	if err != nil {
		t.Fatalf("redirect failed: %v", err)
	}

	deletedPorts := map[string]bool{}
	for _, rule := range rec.findRules("-D") {
		args := strings.Join(rule.args, " ")
		for _, port := range []string{"7178", "14548", "53"} {
			if strings.Contains(args, "--dport "+port+" ") {
				deletedPorts[port] = true
			}
		}
	}
	if !deletedPorts["7178"] || !deletedPorts["14548"] {
		t.Fatalf("withdrawn rules were not removed: %v", rec.findRules("-D"))
	}
	if deletedPorts["53"] {
		t.Fatalf("interface-scoped public alias was removed: %v", rec.findRules("-D"))
	}
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

// Production's nft-backed ip6tables renderer omits the legacy `opt` column:
//
//	DNAT tcp ::/0 2001:db8::10 tcp dpt:443 to:[fd00::1]:7231
//
// If that form is not parsed, an old public rule can remain ahead of the new
// target while nginx drains. New IPv6 connections then reach a closed listener
// even though the replacement container is healthy.
func TestIptablesRedirectRemovesIPv6PublicRuleWithoutOptColumn(t *testing.T) {
	rec := newIptablesRecorder()
	rec.ruleExists = func(args []string) bool {
		rule := strings.Join(args, " ")
		return strings.Contains(rule, "-d 2001:470:99:56:e643:4bff:fec3:8446") &&
			strings.Contains(rule, "--dport 443") &&
			strings.Contains(rule, "--to-destination [fd00:f1a4:349b:bc6e::1]:7232")
	}
	installRecorder(t, rec)

	worker := &RunWorker{
		env:            "main",
		service:        "lb",
		block:          "edge-1-eno2",
		hostNetworking: true,
		dockerNetwork: &DockerNetwork{
			networkName: "warpeno2",
			ipv6: &NetworkInterface{
				interfaceName: "warpeno2",
				interfaceIp:   "fd00:f1a4:349b:bc6e::1",
			},
		},
		routingTable: &RoutingTable{
			tableNumber: 100,
			tableName:   "warp100",
			ipv6: &NetworkInterface{
				interfaceName: "eno2",
				interfaceIp:   "2001:470:99:56:e643:4bff:fec3:8446",
			},
		},
		portBlocks: &PortBlocks{
			externalsToInternals: map[int][]int{7443: {7231, 7232}},
			externalsToService:   map[int]int{7443: 443},
		},
	}
	chainName := worker.iptablesChainName()
	rec.listings["ip6tables:L:"+chainName] = fmt.Sprintf(`Chain %s (2 references)
target     prot source               destination
DNAT       udp  ::/0                 2001:470:99:56:e643:4bff:fec3:8446  udp dpt:443 to:[fd00:f1a4:349b:bc6e::1]:7231
DNAT       tcp  ::/0                 2001:470:99:56:e643:4bff:fec3:8446  tcp dpt:443 to:[fd00:f1a4:349b:bc6e::1]:7231
DNAT       udp  ::/0                 2001:470:99:56:e643:4bff:fec3:8446  udp dpt:443 to:[fd00:f1a4:349b:bc6e::1]:7232
DNAT       tcp  ::/0                 2001:470:99:56:e643:4bff:fec3:8446  tcp dpt:443 to:[fd00:f1a4:349b:bc6e::1]:7232`, chainName)

	if err := worker.redirect(
		map[int]int{7443: 7232},
		map[int]int{443: 7232},
		"replacement",
	); err != nil {
		t.Fatal(err)
	}

	deletedProtocols := map[string]bool{}
	for _, rule := range rec.findRules("-D") {
		args := strings.Join(rule.args, " ")
		if !strings.Contains(args, "-d 2001:470:99:56:e643:4bff:fec3:8446") ||
			!strings.Contains(args, "--dport 443") ||
			!strings.Contains(args, "--to-destination [fd00:f1a4:349b:bc6e::1]:7231") {
			continue
		}
		if strings.Contains(args, "-p tcp") {
			deletedProtocols["tcp"] = true
		}
		if strings.Contains(args, "-p udp") {
			deletedProtocols["udp"] = true
		}
	}
	if got, want := fmt.Sprint(deletedProtocols), "map[tcp:true udp:true]"; got != want {
		t.Fatalf("deleted stale IPv6 public rules=%s want=%s; all deletes=%v", got, want, rec.findRules("-D"))
	}
	for _, rule := range rec.findRules("-I") {
		args := strings.Join(rule.args, " ")
		if strings.Contains(args, "-d 2001:470:99:56:e643:4bff:fec3:8446") &&
			strings.Contains(args, "--dport 443") {
			t.Fatalf("reinserted an already-present IPv6 public target instead of cleaning the stale predecessor: %s", args)
		}
	}
}

func TestPublicPortServiceTargetsForwardOnlyAndIpv4(t *testing.T) {
	servicePorts := map[int]int{
		443:  7231,
		8053: 7250,
	}
	forwardPorts := parseForwardPorts("udp:53:8053")

	ipv4Udp, err := publicPortServiceTargets("udp", servicePorts, forwardPorts, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := fmt.Sprint(ipv4Udp), "map[53:8053 443:443]"; got != want {
		t.Fatalf("IPv4 UDP targets=%s want=%s", got, want)
	}

	ipv6Udp, err := publicPortServiceTargets("udp", servicePorts, forwardPorts, nil, true)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := fmt.Sprint(ipv6Udp), "map[443:443]"; got != want {
		t.Fatalf("IPv6 UDP targets=%s want=%s", got, want)
	}

	ipv4Tcp, err := publicPortServiceTargets("tcp", servicePorts, forwardPorts, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := fmt.Sprint(ipv4Tcp), "map[443:443]"; got != want {
		t.Fatalf("IPv4 TCP targets=%s want=%s", got, want)
	}
}

// Covers the pure target selection for both address families and protocols so
// a private UDP compatibility port cannot leak through the TCP pass.
func TestPublicPortServiceTargetsKeepsPreviousAliasTargetPrivate(t *testing.T) {
	servicePorts := map[int]int{
		443:  7231,
		4053: 15027,
		8053: 14547,
	}
	forwardPorts := parseForwardPorts("udp:53:4053")
	privateServicePorts := parsePrivatePorts("8053")

	ipv4Udp, err := publicPortServiceTargets("udp", servicePorts, forwardPorts, privateServicePorts, false)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := fmt.Sprint(ipv4Udp), "map[53:4053 443:443]"; got != want {
		t.Fatalf("IPv4 UDP targets=%s want=%s", got, want)
	}

	ipv6Udp, err := publicPortServiceTargets("udp", servicePorts, forwardPorts, privateServicePorts, true)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := fmt.Sprint(ipv6Udp), "map[443:443]"; got != want {
		t.Fatalf("IPv6 UDP targets=%s want=%s", got, want)
	}

	ipv4Tcp, err := publicPortServiceTargets("tcp", servicePorts, forwardPorts, privateServicePorts, false)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := fmt.Sprint(ipv4Tcp), "map[443:443]"; got != want {
		t.Fatalf("IPv4 TCP targets=%s want=%s", got, want)
	}
}

// Reproduces the 8053-to-4053 alias migration at the observable firewall
// layer, including stale rules left by the broken public-port calculation.
func TestIptablesForwardPortMigrationKeepsCurrentAndPreviousTargetsPrivate(t *testing.T) {
	recorder := newIptablesRecorder()
	installRecorder(t, recorder)

	worker := &RunWorker{
		env:                   "test",
		service:               "lb",
		block:                 "edge-0-eth0",
		hostNetworking:        true,
		forwardPorts:          parseForwardPorts("udp:53:4053"),
		privateServicePorts:   parsePrivatePorts("8053"),
		dockerNetwork:         &DockerNetwork{networkName: "warpeth0", ipv4: &NetworkInterface{interfaceName: "warpeth0", interfaceIp: "10.100.0.2"}},
		servicesDockerNetwork: &DockerNetwork{networkName: "testservices", ipv4: &NetworkInterface{interfaceName: "testservices", interfaceIp: "10.200.0.2"}},
		routingTable: &RoutingTable{
			tableNumber: 100,
			tableName:   "warp_eth0",
			ipv4:        &NetworkInterface{interfaceName: "eth0", interfaceIp: "10.0.0.1"},
		},
	}
	chainName := worker.iptablesChainName()
	recorder.listings[chainName] = fmt.Sprintf(`Chain %s (2 references)
target     prot opt source               destination
DNAT       udp  --  0.0.0.0/0            10.0.0.1             udp dpt:53 to:10.100.0.9:7999
DNAT       udp  --  0.0.0.0/0            10.0.0.1             udp dpt:4053 to:10.100.0.2:15027
DNAT       tcp  --  0.0.0.0/0            10.0.0.1             tcp dpt:4053 to:10.100.0.2:15027
DNAT       udp  --  0.0.0.0/0            10.0.0.1             udp dpt:8053 to:10.100.0.2:14547
DNAT       tcp  --  0.0.0.0/0            10.0.0.1             tcp dpt:8053 to:10.100.0.2:14547
DNAT       udp  --  0.0.0.0/0            0.0.0.0/0            udp dpt:7191 to:10.100.0.2:15027`, chainName)

	err := worker.redirect(
		map[int]int{7178: 14547, 7191: 15027, 7443: 7231},
		map[int]int{443: 7231, 4053: 15027, 8053: 14547},
		"migration-container",
	)
	if err != nil {
		t.Fatal(err)
	}

	foundCurrentAlias := false
	deletedPublicPorts := map[string]bool{}
	for _, rule := range recorder.getRules() {
		arguments := strings.Join(rule.args, " ")
		isPublicRule := strings.Contains(arguments, " -d 10.0.0.1 ")
		if rule.op == "-I" && strings.Contains(arguments, "-p udp -m udp -d 10.0.0.1 --dport 53") &&
			strings.Contains(arguments, "--to-destination 10.100.0.2:15027") {
			foundCurrentAlias = true
		}
		if rule.op == "-I" && isPublicRule &&
			(strings.Contains(arguments, "--dport 4053") || strings.Contains(arguments, "--dport 8053")) {
			t.Errorf("private migration target was published: %s", arguments)
		}
		if rule.op == "-D" && isPublicRule {
			for _, protocol := range []string{"tcp", "udp"} {
				for _, port := range []string{"4053", "8053"} {
					if strings.Contains(arguments, "-p "+protocol) && strings.Contains(arguments, "--dport "+port) {
						deletedPublicPorts[protocol+"/"+port] = true
					}
				}
			}
		}
		if rule.op == "-D" && strings.Contains(arguments, "--dport 7191") {
			t.Errorf("public reconciliation deleted the private allocation rule: %s", arguments)
		}
	}
	if !foundCurrentAlias {
		t.Fatal("missing public UDP/53 to private 4053 alias")
	}
	for _, protocolPort := range []string{"tcp/4053", "udp/4053", "tcp/8053", "udp/8053"} {
		if !deletedPublicPorts[protocolPort] {
			t.Errorf("stale public %s rule was not deleted", protocolPort)
		}
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
	logOutput := captureErrOutput(t)
	netstatOut := `Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State
tcp        0      0 172.18.0.1:14488        0.0.0.0:*               LISTEN
tcp        0      0 127.0.0.1:14518         0.0.0.0:*               LISTEN
tcp        0      0 127.0.0.1:14548         0.0.0.0:*               LISTEN
tcp        0      0 0.0.0.0:14608           0.0.0.0:*               LISTEN
tcp6       0      0 ::1:14638               :::*                    LISTEN
udp        0      0 127.0.0.1:14668         0.0.0.0:*
`
	origRunQuiet := runQuietFunc
	runQuietFunc = func(cmd *exec.Cmd) (commandOutput, error) {
		return commandOutput{stdout: []byte(netstatOut)}, nil
	}
	t.Cleanup(func() { runQuietFunc = origRunQuiet })

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
	assert.Equal(t, strings.Contains(logOutput.String(), "scanned=6"), true)
	assert.Equal(t, strings.Contains(logOutput.String(), "occupied_pool_ports=6"), true)
	// Socket discovery must never copy the raw snapshot into journald.
	assert.Equal(t, strings.Contains(logOutput.String(), "127.0.0.1:14518"), false)
}

// Port exhaustion must return control to Run so it can repoll the desired
// image/config. Waiting inside assignDeployPorts captures an obsolete target;
// when a port eventually opens, that stale deployment is started immediately.
func TestAssignDeployPortsDoesNotWaitOnOccupiedPool(t *testing.T) {
	origRunQuiet := runQuietFunc
	runQuietFunc = func(cmd *exec.Cmd) (commandOutput, error) {
		return commandOutput{stdout: []byte(`Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State
tcp        0      0 0.0.0.0:7201            0.0.0.0:*               LISTEN
tcp        0      0 0.0.0.0:7231            0.0.0.0:*               LISTEN
`)}, nil
	}
	t.Cleanup(func() { runQuietFunc = origRunQuiet })

	worker := &RunWorker{
		env:            "test",
		service:        "lb",
		block:          "edge-0-eth0",
		hostNetworking: true,
		quitEvent:      warp.NewEvent(),
		portBlocks:     parsePortBlocks("80:7080:7201;443:7443:7231"),
		dockerNetwork: &DockerNetwork{
			networkName: "warpeth0",
			ipv4: &NetworkInterface{
				interfaceName: "warpeth0",
				interfaceIp:   "10.100.0.2",
			},
		},
	}

	done := make(chan struct{})
	var externalPorts map[int]int
	var servicePorts map[int]int
	go func() {
		externalPorts, servicePorts = worker.assignDeployPorts()
		close(done)
	}()

	select {
	case <-done:
		assert.Equal(t, externalPorts == nil, true)
		assert.Equal(t, servicePorts == nil, true)
	case <-time.After(250 * time.Millisecond):
		worker.quitEvent.Set()
		<-done
		t.Fatal("assignDeployPorts waited inside a stale deployment target")
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

// conntrackRecorder captures quiet conntrack invocations and supplies the
// command's normally unlogged stdout/stderr.
type conntrackRecorder struct {
	mu        sync.Mutex
	commands  [][]string
	responder func(args []string) (commandOutput, error)
}

func (r *conntrackRecorder) getCommands() [][]string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([][]string, len(r.commands))
	for i, command := range r.commands {
		out[i] = slices.Clone(command)
	}
	return out
}

func installConntrackRecorder(t *testing.T, rec *conntrackRecorder) {
	t.Helper()

	origRunQuiet := runQuietFunc
	runQuietFunc = func(cmd *exec.Cmd) (commandOutput, error) {
		args := cmd.Args
		// skip "sudo" prefix
		if len(args) > 0 && args[0] == "sudo" {
			args = args[1:]
		}
		if len(args) == 0 || args[0] != "conntrack" {
			return commandOutput{}, nil
		}
		rec.mu.Lock()
		rec.commands = append(rec.commands, slices.Clone(args))
		responder := rec.responder
		rec.mu.Unlock()
		if responder != nil {
			return responder(args)
		}
		return commandOutput{}, nil
	}
	t.Cleanup(func() {
		runQuietFunc = origRunQuiet
	})
}

func conntrackSaveEntry(replySrc string, replyPort int, marker string) string {
	return fmt.Sprintf(
		"-A udp --orig-src 203.0.113.10 --orig-dst 198.51.100.20 --sport 31000 --dport 7163 --reply-src %s --reply-dst 203.0.113.10 --reply-port-src %d --reply-port-dst 31000 --state ASSURED %s\n",
		replySrc,
		replyPort,
		marker,
	)
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
	logOutput := captureErrOutput(t)
	const rawFlowMarker = "RAW_CONNTRACK_FLOW_MUST_NOT_BE_LOGGED"
	listOutput := "" +
		conntrackSaveEntry("172.19.0.1", 14098, rawFlowMarker) +
		conntrackSaveEntry("172.19.0.1", 14098, rawFlowMarker) +
		conntrackSaveEntry("172.19.0.1", 14099, rawFlowMarker) +
		conntrackSaveEntry("172.19.0.1", 14100, rawFlowMarker) +
		conntrackSaveEntry("172.19.0.1", 14101, rawFlowMarker) +
		conntrackSaveEntry("172.19.0.1", 65000, rawFlowMarker)
	rec := &conntrackRecorder{
		responder: func(args []string) (commandOutput, error) {
			switch args[1] {
			case "-L":
				return commandOutput{stdout: []byte(listOutput)}, nil
			case "-D":
				port := flagValue(args, "--reply-port-src")
				switch port {
				case "14098":
					return commandOutput{stdout: []byte(
						conntrackSaveEntry("172.19.0.1", 14098, rawFlowMarker) +
							conntrackSaveEntry("172.19.0.1", 14098, rawFlowMarker),
					)}, nil
				case "14101":
					return commandOutput{stdout: []byte(
						conntrackSaveEntry("172.19.0.1", 14101, rawFlowMarker),
					)}, nil
				}
			}
			return commandOutput{}, nil
		},
	}
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
	stats := worker.cleanupStaleConntrackForOccupiedPorts(map[int]bool{
		14099: true,
		14100: true,
	})

	commands := rec.getCommands()
	assert.Equal(t, len(commands), 3)
	assert.Equal(t, commands[0][1], "-L")

	deletedPorts := map[string]bool{}
	for _, args := range commands[1:] {
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
	// unrelated flows outside this configured pool are preserved too
	assert.Equal(t, deletedPorts["65000"], false)

	assert.Equal(t, len(stats), 1)
	assert.Equal(t, stats[0].scanned, 6)
	assert.Equal(t, stats[0].candidatePorts, 2)
	assert.Equal(t, stats[0].stalePorts, 2)
	assert.Equal(t, stats[0].deletedFlows, 3)
	assert.Equal(t, len(stats[0].errors), 0)
	assert.Equal(t, strings.Count(logOutput.String(), "Conntrack cleanup"), 1)
	assert.Equal(t, strings.Contains(logOutput.String(), "scanned=6"), true)
	assert.Equal(t, strings.Contains(logOutput.String(), "deleted_flows=3"), true)
	// Normal conntrack rows are captured for parsing, never copied to journald.
	assert.Equal(t, strings.Contains(logOutput.String(), rawFlowMarker), false)
}

// An empty 180-port allocation should cost one filtered table read, not 180
// blind conntrack deletes (and their command/PAM output).
func TestCleanupStaleConntrackEmptyLargePool(t *testing.T) {
	logOutput := captureErrOutput(t)
	rec := &conntrackRecorder{}
	installConntrackRecorder(t, rec)

	worker := &RunWorker{
		env:            "test",
		service:        "lb",
		block:          "edge-0-eth0",
		hostNetworking: true,
		portBlocks:     parsePortBlocks("443:443:14000-14179"),
		dockerNetwork: &DockerNetwork{
			networkName: "warpeth0",
			ipv4: &NetworkInterface{
				interfaceName: "warpeth0",
				interfaceIp:   "172.18.0.1",
			},
		},
	}

	stats := worker.cleanupStaleConntrackForOccupiedPorts(map[int]bool{})
	commands := rec.getCommands()
	assert.Equal(t, len(commands), 1)
	assert.Equal(t, commands[0][1], "-L")
	assert.Equal(t, stats[0].candidatePorts, 180)
	assert.Equal(t, stats[0].scanned, 0)
	assert.Equal(t, stats[0].stalePorts, 0)
	assert.Equal(t, stats[0].deletedFlows, 0)
	assert.Equal(t, strings.Count(logOutput.String(), "Conntrack cleanup"), 1)
	assert.Equal(t, strings.Contains(logOutput.String(), "candidate_ports=180"), true)
}

func TestCleanupStaleConntrackIpv6(t *testing.T) {
	rec := &conntrackRecorder{
		responder: func(args []string) (commandOutput, error) {
			family := flagValue(args, "-f")
			replySrc := flagValue(args, "--reply-src")
			return commandOutput{stdout: []byte(
				conntrackSaveEntry(replySrc, 14098, "family-"+family),
			)}, nil
		},
	}
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

	stats := worker.cleanupStaleConntrackForOccupiedPorts(map[int]bool{
		14099: true,
	})

	commands := rec.getCommands()
	// One filtered read and one real stale-port delete per address family.
	assert.Equal(t, len(commands), 4)

	replySrcsByFamily := map[string]string{}
	for _, args := range commands {
		if args[1] != "-D" {
			continue
		}
		assert.Equal(t, flagValue(args, "--reply-port-src"), "14098")
		replySrcsByFamily[flagValue(args, "-f")] = flagValue(args, "--reply-src")
	}
	assert.Equal(t, replySrcsByFamily["ipv4"], "172.19.0.1")
	assert.Equal(t, replySrcsByFamily["ipv6"], "fd00:f1a4:349b:bc6e::1")
	assert.Equal(t, len(stats), 2)
	for _, familyStats := range stats {
		assert.Equal(t, familyStats.scanned, 1)
		assert.Equal(t, familyStats.stalePorts, 1)
		assert.Equal(t, familyStats.deletedFlows, 1)
		assert.Equal(t, len(familyStats.errors), 0)
	}
}

func TestCleanupStaleConntrackAggregatesFailures(t *testing.T) {
	tests := []struct {
		name             string
		responder        func(args []string) (commandOutput, error)
		expectedCommands int
		expectedErrors   int
	}{
		{
			name: "list failure",
			responder: func(args []string) (commandOutput, error) {
				return commandOutput{
					stdout: []byte("RAW_LIST_STDOUT_MUST_NOT_BE_LOGGED"),
					stderr: []byte("RAW_LIST_STDERR_MUST_NOT_BE_LOGGED"),
				}, fmt.Errorf("exit status 1")
			},
			expectedCommands: 1,
			expectedErrors:   1,
		},
		{
			name: "delete failures",
			responder: func(args []string) (commandOutput, error) {
				if args[1] == "-L" {
					return commandOutput{stdout: []byte(
						conntrackSaveEntry("172.19.0.1", 14098, "RAW_FLOW_ONE") +
							conntrackSaveEntry("172.19.0.1", 14101, "RAW_FLOW_TWO"),
					)}, nil
				}
				return commandOutput{
					stdout: []byte("RAW_DELETE_STDOUT_MUST_NOT_BE_LOGGED"),
					stderr: []byte("RAW_DELETE_STDERR_MUST_NOT_BE_LOGGED"),
				}, fmt.Errorf("exit status 1")
			},
			expectedCommands: 3,
			expectedErrors:   2,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			logOutput := captureErrOutput(t)
			rec := &conntrackRecorder{responder: test.responder}
			installConntrackRecorder(t, rec)
			worker := &RunWorker{
				env:            "test",
				service:        "proxy",
				block:          "g8",
				hostNetworking: true,
				portBlocks:     parsePortBlocks("8084:7163:14098-14101"),
				dockerNetwork: &DockerNetwork{
					networkName: "warpeno1np0",
					ipv4: &NetworkInterface{
						interfaceName: "warpeno1np0",
						interfaceIp:   "172.19.0.1",
					},
				},
			}

			stats := worker.cleanupStaleConntrackForOccupiedPorts(map[int]bool{})
			assert.Equal(t, len(rec.getCommands()), test.expectedCommands)
			assert.Equal(t, len(stats), 1)
			assert.Equal(t, len(stats[0].errors), test.expectedErrors)
			assert.Equal(t, strings.Count(logOutput.String(), "Conntrack cleanup"), 1)
			assert.Equal(t, strings.Contains(
				logOutput.String(),
				fmt.Sprintf("errors=%d", test.expectedErrors),
			), true)
			assert.Equal(t, strings.Contains(logOutput.String(), "RAW_"), false)
		})
	}
}

func TestConntrackCommandUsesDirectInvocationForRoot(t *testing.T) {
	rootCommand := conntrackCommandForEuid(0, "-L", "-f", "ipv4")
	assert.Equal(t, rootCommand.Args[0], "conntrack")
	assert.Equal(t, slices.Contains(rootCommand.Args, "sudo"), false)

	nonRootCommand := conntrackCommandForEuid(1000, "-L", "-f", "ipv4")
	assert.Equal(t, nonRootCommand.Args[0], "sudo")
	assert.Equal(t, nonRootCommand.Args[1], "conntrack")
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
