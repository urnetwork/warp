package main

// Tests of the lb_alt worker paths through w-route's and w-split's real
// functions, as defaultLbAltWorkerOps wires them (server/LBALT-IMPL.md
// §2.2-§2.5): a connect generation's route file, the deploy's readiness poll
// against a private status with the §2.4 headers and then the block chains,
// the lb unit's routing-only split reconcile and its nginx retirement, the
// rollback, the chains' refresh, the route file's removal, and a candidate's
// ports around the chains of a dead generation. Only commands are fakes:
// docker in the command hooks and PATH fixture of lbalt_worker_test.go, and
// iptables, iptables-restore and ss in the in-memory host of
// lbalt_split_test.go, which the split writer reaches through runQuiet and,
// for the nat listings the worker reads, a test reaches through sudo2
// (installLbAltWiringNatListings).

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// Routes the quiet commands the worker and the split writer run to host:
// iptables, ip6tables, their restores and ss, as the split writer runs them
// (under sudo when not root), and conntrack to an empty listing. record gets
// "restore <family> <table>" for each transaction and "conntrack" for each
// conntrack command.
func installLbAltWiringCommands(t *testing.T, host *fakeLbAltHost, record func(event string)) {
	t.Helper()
	previousRunQuiet := runQuietFunc
	t.Cleanup(func() {
		runQuietFunc = previousRunQuiet
	})
	runQuietFunc = func(cmd *exec.Cmd) (commandOutput, error) {
		args := slices.Clone(cmd.Args)
		if 0 < len(args) && args[0] == "sudo" {
			args = args[1:]
		}
		if len(args) == 0 {
			return commandOutput{}, errors.New("empty command")
		}
		switch args[0] {
		case "iptables", "ip6tables", "iptables-restore", "ip6tables-restore", "ss":
			stdin := ""
			if cmd.Stdin != nil {
				data, err := io.ReadAll(cmd.Stdin)
				if err != nil {
					return commandOutput{}, err
				}
				stdin = string(data)
			}
			if strings.HasSuffix(args[0], "-restore") {
				family := "ipv4"
				if strings.HasPrefix(args[0], "ip6") {
					family = "ipv6"
				}
				table, _, _ := strings.Cut(strings.TrimPrefix(stdin, "*"), "\n")
				record(fmt.Sprintf("restore %s %s", family, table))
			}
			return host.run(context.Background(), lbAltCommand{
				name:       args[0],
				args:       args[1:],
				stdin:      stdin,
				privileged: args[0] != "ss",
			})
		case "conntrack":
			record("conntrack")
			return commandOutput{}, nil
		}
		return commandOutput{}, fmt.Errorf("unexpected quiet command %v", args)
	}
}

// Answers the nat listings the worker reads through sudo2 (`iptables -t nat
// -L -n`, with or without -w) from host, in the command's family, as far as
// the worker's readers of them look: each chain's header, and each rule's
// target, with a DNAT's protocol, port and destination. Every other command
// runs under the fixture's sudo, as without the hook.
func installLbAltWiringNatListings(t *testing.T, host *fakeLbAltHost) {
	t.Helper()
	natListing := func(family string) string {
		host.stateLock.Lock()
		defer host.stateLock.Unlock()
		table := host.tables[family+"/nat"]
		anywhere := "0.0.0.0/0"
		if family == "ipv6" {
			anywhere = "::/0"
		}
		lines := []string{}
		for _, chain := range append(slices.Clone(table.builtinChains), table.userChains()...) {
			if slices.Contains(table.builtinChains, chain) {
				lines = append(lines, fmt.Sprintf("Chain %s (policy ACCEPT)", chain))
			} else {
				lines = append(lines, fmt.Sprintf("Chain %s (1 references)", chain))
			}
			lines = append(lines, "target     prot opt source               destination")
			for _, rule := range table.chainRules[chain] {
				ruleArgs := map[string]string{}
				for i := 0; i+1 < len(rule.listedSpec); i += 1 {
					ruleArgs[rule.listedSpec[i]] = rule.listedSpec[i+1]
				}
				if ruleArgs["-j"] != "DNAT" {
					lines = append(lines, fmt.Sprintf("%s  all  --  %s %s", ruleArgs["-j"], anywhere, anywhere))
					continue
				}
				lines = append(lines, fmt.Sprintf(
					"DNAT       %s  --  %s %s %s dpt:%s to:%s",
					ruleArgs["-p"],
					anywhere,
					anywhere,
					ruleArgs["-p"],
					ruleArgs["--dport"],
					ruleArgs["--to-destination"],
				))
			}
			lines = append(lines, "")
		}
		return strings.Join(lines, "\n")
	}
	previousSudo2 := sudo2Func
	t.Cleanup(func() {
		sudo2Func = previousSudo2
	})
	sudo2Func = func(name []string, args ...string) *exec.Cmd {
		commandArgs := append(slices.Clone(name), args...)
		if len(name) == 1 && (name[0] == "iptables" || name[0] == "ip6tables") && strings.HasSuffix(" "+strings.Join(args, " "), " -t nat -L -n") {
			family := "ipv4"
			if name[0] == "ip6tables" {
				family = "ipv6"
			}
			return exec.Command("/bin/sh", "-c", `printf '%s' "$1"`, "sh", natListing(family))
		}
		return exec.Command("sudo", commandArgs...)
	}
}

// The route file of the one generation under warpHome, its name and its
// revision.
func readLbAltWiringRouteFile(warpHome string) (*LbAltRouteTable, string, string, error) {
	entries, err := os.ReadDir(filepath.Join(warpHome, lbAltRouteHostDirName))
	if err != nil {
		return nil, "", "", err
	}
	if len(entries) != 1 {
		return nil, "", "", fmt.Errorf("%d generations have route files", len(entries))
	}
	generation := entries[0].Name()
	data, err := os.ReadFile(filepath.Join(warpHome, lbAltRouteHostDirName, generation, lbAltRouteFileName))
	if err != nil {
		return nil, "", "", err
	}
	table := &LbAltRouteTable{}
	if err := json.Unmarshal(data, table); err != nil {
		return nil, "", "", err
	}
	digest := sha256.Sum256(data)
	return table, generation, hex.EncodeToString(digest[:]), nil
}

// The §2.4 headers of a connect generation that loaded the one route file
// under warpHome: its generation and revision, and each socket the file has it
// bind, every bridge address times the four listen sockets, at the counts
// socketCounts gives the socket's name; ready only when all are 4/4.
func lbAltWiringFrontHeaders(warpHome string, socketCounts func(socketName string) string) (map[string]string, error) {
	table, generation, revision, err := readLbAltWiringRouteFile(warpHome)
	if err != nil {
		return nil, err
	}
	socketEntries := []string{}
	ready := "1"
	for _, routeInterface := range table.Interfaces {
		for _, address := range []string{routeInterface.Ipv4, routeInterface.Ipv6} {
			if address == "" {
				continue
			}
			for _, socketName := range []string{
				fmt.Sprintf("tcp/%s/%d", address, table.Listen.HttpPort),
				fmt.Sprintf("tcp/%s/%d", address, table.Listen.HttpsPort),
				fmt.Sprintf("udp/%s/%d", address, table.Listen.QuicPort),
				fmt.Sprintf("udp/%s/%d", address, table.Listen.WhodisPort),
			} {
				counts := socketCounts(socketName)
				if counts != "4/4" {
					ready = "0"
				}
				socketEntries = append(socketEntries, socketName+"="+counts)
			}
		}
	}
	slices.Sort(socketEntries)
	return map[string]string{
		lbAltFrontGenerationHeader:    generation,
		lbAltFrontRouteRevisionHeader: revision,
		lbAltFrontReadyHeader:         ready,
		lbAltFrontSocketsHeader:       strings.Join(socketEntries, ","),
		lbAltFrontCertExpiryHeader:    "2030-01-01T00:00:00Z",
	}, nil
}

// Answers the fixture's private status as the candidate's front: the
// readiness poll, which names no Host, gets the §2.4 headers and is
// recorded, with the Host it named; the ordinary status poll, which names the
// service, gets none. Returns the Hosts the readiness polls named so far.
func (self *lbAltWorkerFixture) answerLbAltReadiness(socketCounts func(socketName string) string) func() []string {
	readinessHosts := []string{}
	self.setFrontStatus(func(header http.Header, request *http.Request) {
		if strings.HasPrefix(request.Host, "test-connect.") {
			return
		}
		headers, err := lbAltWiringFrontHeaders(self.home, socketCounts)
		if err != nil {
			self.t.Errorf("front status: %v", err)
			return
		}
		for name, value := range headers {
			header.Set(name, value)
		}
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.events = append(self.events, "readiness")
		readinessHosts = append(readinessHosts, request.Host)
	})
	return func() []string {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return slices.Clone(readinessHosts)
	}
}

// A connect generation on an lb_alt host starts with its own route file, as
// the real render and write leave it: mode 0444 under the warp home, the
// table of that generation, with warpctl's whodis tld, mounted read-only at
// the contract's path, named by WARP_LBALT_ROUTE_FILE, and WARP_GENERATION is
// the container name, which is the file's generation. The worker keeps the
// file's revision.
func TestLbAltWiringStartsAGenerationWithItsRouteFile(t *testing.T) {
	f := newLbAltWorkerFixture(t)
	f.worker.lbAltOps = defaultLbAltWorkerOps()
	if _, err := f.worker.startContainer(map[int]int{80: f.statusPort, 443: 7301, 4053: 7302}); err != nil {
		t.Fatal(err)
	}
	runArgs := f.dockerRunArgs[0]
	containerName := lbAltDockerRunValues(runArgs, "--name")[0]

	table, generation, revision, err := readLbAltWiringRouteFile(f.home)
	if err != nil {
		t.Fatal(err)
	}
	hostPath := filepath.Join(f.home, lbAltRouteHostDirName, containerName, lbAltRouteFileName)
	info, err := os.Stat(hostPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o444 {
		t.Fatalf("route file mode %v, want 0444", info.Mode().Perm())
	}
	if generation != containerName || table.Generation != containerName || table.Host != "edge-a.example" || table.Env != "test" {
		t.Fatalf("route file of %s holds generation %q of %s %s", generation, table.Generation, table.Env, table.Host)
	}
	if listen := table.Listen; listen.HttpPort != f.statusPort || listen.HttpsPort != 7301 || listen.QuicPort != 7301 || listen.WhodisPort != 7302 {
		t.Fatalf("route file listens on %+v", listen)
	}
	// warpctl's constant is the one source of the whodis tlds (§7)
	if !slices.Equal(table.Front.WhodisTlds, []string{lbAltDefaultWhodisTld}) {
		t.Fatalf("route file whodis tlds %v, want %s", table.Front.WhodisTlds, lbAltDefaultWhodisTld)
	}
	wantMount := fmt.Sprintf("type=bind,source=%s,target=/srv/warp/lbalt/route.json,readonly", hostPath)
	if !slices.Contains(lbAltDockerRunValues(runArgs, "--mount"), wantMount) {
		t.Fatalf("docker run mounts %v, want %s", lbAltDockerRunValues(runArgs, "--mount"), wantMount)
	}
	env := lbAltDockerRunValues(runArgs, "-e")
	for _, want := range []string{
		"WARP_LBALT_ROUTE_FILE=/srv/warp/lbalt/route.json",
		"WARP_GENERATION=" + containerName,
	} {
		if !slices.Contains(env, want) {
			t.Fatalf("docker run env %v lacks %s", env, want)
		}
	}
	if f.worker.lbAltState.candidateRevision != revision {
		t.Fatalf("kept revision %q, want the file's %q", f.worker.lbAltState.candidateRevision, revision)
	}
}

// A connect block's deploy on an lb_alt host: the candidate starts, the real
// readiness poll asks its private status, which answers with the §2.4 headers
// of the file the candidate loaded, and only then does the real chain writer
// point the block's chain on both interfaces, in both families, at the
// candidate's listen ports, before the pool cutover. The poll names no Host.
func TestLbAltWiringDeployPollsReadinessThenWritesTheBlockChains(t *testing.T) {
	f := newLbAltWorkerFixture(t)
	f.worker.lbAltOps = defaultLbAltWorkerOps()
	host := newFakeLbAltHost()
	installLbAltWiringCommands(t, host, f.record)
	readinessHosts := f.answerLbAltReadiness(func(socketName string) string { return "4/4" })

	if err := f.worker.deployContainerOverlap(true, nil); err != nil {
		t.Fatal(err)
	}
	events := f.recorded()
	startIndex := slices.Index(events, "start")
	readinessIndex := slices.Index(events, "readiness")
	chainsIndex := slices.Index(events, "restore ipv4 nat")
	cutoverIndex := slices.Index(events, "cutover")
	if startIndex < 0 || readinessIndex < startIndex || chainsIndex < readinessIndex || cutoverIndex < chainsIndex {
		t.Fatalf("deploy events %v, want start, readiness, the chains' restore, then the cutover", events)
	}
	if want := []string{fmt.Sprintf("127.0.0.1:%d", f.statusPort)}; !slices.Equal(readinessHosts(), want) {
		t.Fatalf("the readiness poll named the Hosts %v, want only the private listener's address %v", readinessHosts(), want)
	}

	generation := lbAltTestGeneration{block: "g1", httpPort: f.statusPort, tlsPort: 7301, whodisPort: 7302}
	for _, bridge := range []struct {
		chain   string
		family  string
		address string
	}{
		{chain: "WARP-TEST-LBA-ETH1-G1", family: "ipv4", address: "192.0.2.1"},
		{chain: "WARP-TEST-LBA-ETH1-G1", family: "ipv6", address: "2001:db8:f1::1"},
		{chain: "WARP-TEST-LBA-ETH2-G1", family: "ipv4", address: "192.0.2.65"},
		{chain: "WARP-TEST-LBA-ETH2-G1", family: "ipv6", address: "2001:db8:f2::1"},
	} {
		requireLbAltRules(t, bridge.family+" "+bridge.chain, host.chainRules(bridge.family, "nat", bridge.chain), generation.blockRules(bridge.address))
	}
}

// A candidate whose private status reports one of its sockets short (3/4),
// and so itself not ready, is refused by the real readiness poll at its
// timeout. It gets no block chain, and it is stopped.
func TestLbAltWiringDeployWritesNoChainForAnUnreadyCandidate(t *testing.T) {
	f := newLbAltWorkerFixture(t)
	f.worker.lbAltOps = defaultLbAltWorkerOps()
	// one poll, refused, and the timeout has passed
	f.worker.lbAltSettings.readinessTimeout = time.Nanosecond
	host := newFakeLbAltHost()
	installLbAltWiringCommands(t, host, f.record)
	f.answerLbAltReadiness(func(socketName string) string {
		if strings.HasPrefix(socketName, "udp/2001:db8:f2::1/") {
			return "3/4"
		}
		return "4/4"
	})

	// the front reports itself not ready while a socket is short
	err := f.worker.deployContainerOverlap(true, nil)
	if err == nil || !strings.Contains(err.Error(), `X-UR-Front-Ready is "0", not 1`) {
		t.Fatalf("deploy error = %v, want the candidate not ready", err)
	}
	events := f.recorded()
	for _, event := range events {
		if strings.HasPrefix(event, "restore ") || event == "cutover" {
			t.Fatalf("an unready candidate got %q: %v", event, events)
		}
	}
	if !slices.Contains(events, "readiness") || !slices.Contains(events, "stop") {
		t.Fatalf("deploy events %v, want the readiness poll and the candidate's stop", events)
	}
	if chains := host.chainsWithPrefix("ipv4", "nat", "WARP-TEST-LBA-"); len(chains) != 0 {
		t.Fatalf("chains written for an unready candidate: %v", chains)
	}
}

// A connect block whose committed generation died: nothing listens on its
// ports, its chains on the host still DNAT to them, and the worker restarted,
// so iptables is all it knows of them. The next deploy's candidate never gets
// one of those ports, though the 443 and 4053 pools list them first:
// listening there, it would have the split's reconcile count the block ready,
// and send it the block's buckets, before its readiness poll. (The 80 pool
// lists the fixture's private status port first, since only it answers.) The
// candidate gets the pools' other ports, the chains still point at the dead
// generation while its readiness is polled, and they move to the candidate
// only once the poll accepts it.
func TestLbAltWiringCandidateNeverTakesAPortTheChainsTarget(t *testing.T) {
	f := newLbAltWorkerFixture(t)
	f.worker.lbAltOps = defaultLbAltWorkerOps()
	host := newFakeLbAltHost()
	installLbAltWiringCommands(t, host, f.record)
	installLbAltWiringNatListings(t, host)
	f.worker.portBlocks = parsePortBlocks(fmt.Sprintf("80:7000:%d,7310;443:7001:7311,7301;4053:7002:7312,7302", f.statusPort))
	deadGeneration := lbAltTestGeneration{block: "g1", httpPort: 7310, tlsPort: 7311, whodisPort: 7312}
	if err := f.worker.writeLbAltWorkerBlockChains(map[int]int{80: deadGeneration.httpPort, 443: deadGeneration.tlsPort, 4053: deadGeneration.whodisPort}); err != nil {
		t.Fatal(err)
	}
	bridges := []struct {
		chain   string
		family  string
		address string
	}{
		{chain: "WARP-TEST-LBA-ETH1-G1", family: "ipv4", address: "192.0.2.1"},
		{chain: "WARP-TEST-LBA-ETH1-G1", family: "ipv6", address: "2001:db8:f1::1"},
		{chain: "WARP-TEST-LBA-ETH2-G1", family: "ipv4", address: "192.0.2.65"},
		{chain: "WARP-TEST-LBA-ETH2-G1", family: "ipv6", address: "2001:db8:f2::1"},
	}
	chainRules := func() map[string][]string {
		rules := map[string][]string{}
		for _, bridge := range bridges {
			rules[bridge.family+" "+bridge.chain] = host.chainRules(bridge.family, "nat", bridge.chain)
		}
		return rules
	}
	generationRules := func(generation lbAltTestGeneration) map[string][]string {
		rules := map[string][]string{}
		for _, bridge := range bridges {
			rules[bridge.family+" "+bridge.chain] = generation.blockRules(bridge.address)
		}
		return rules
	}
	if !reflect.DeepEqual(chainRules(), generationRules(deadGeneration)) {
		t.Fatalf("the dead generation's chains are not in place:\n%v", chainRules())
	}

	// the candidate's private status answers the readiness poll, and notes
	// the chains and the candidate's listen ports at that moment
	var readinessChainRules map[string][]string
	var readinessListen LbAltRouteListen
	f.setFrontStatus(func(header http.Header, request *http.Request) {
		if strings.HasPrefix(request.Host, "test-connect.") {
			return
		}
		headers, err := lbAltWiringFrontHeaders(f.home, func(socketName string) string { return "4/4" })
		if err != nil {
			t.Errorf("front status: %v", err)
			return
		}
		for name, value := range headers {
			header.Set(name, value)
		}
		table, _, _, err := readLbAltWiringRouteFile(f.home)
		if err != nil {
			t.Errorf("front status: %v", err)
			return
		}
		rules := chainRules()
		f.stateLock.Lock()
		defer f.stateLock.Unlock()
		f.events = append(f.events, "readiness")
		readinessChainRules = rules
		readinessListen = table.Listen
	})

	if err := f.worker.deployContainerOverlap(true, nil); err != nil {
		t.Fatal(err)
	}
	f.stateLock.Lock()
	atReadiness, listen := readinessChainRules, readinessListen
	f.stateLock.Unlock()
	if atReadiness == nil {
		t.Fatal("the candidate's readiness was never polled")
	}
	deadPorts := map[int]bool{deadGeneration.httpPort: true, deadGeneration.tlsPort: true, deadGeneration.whodisPort: true}
	for _, port := range []int{listen.HttpPort, listen.HttpsPort, listen.QuicPort, listen.WhodisPort} {
		if deadPorts[port] {
			t.Fatalf("the candidate listens on %+v, sharing port %d with the chains' dead targets", listen, port)
		}
	}
	if listen.HttpPort != f.statusPort || listen.HttpsPort != 7301 || listen.WhodisPort != 7302 {
		t.Fatalf("the candidate listens on %+v, want the pool's other ports", listen)
	}
	if !reflect.DeepEqual(atReadiness, generationRules(deadGeneration)) {
		t.Fatalf("the chains moved before the readiness poll accepted the candidate:\n%v", atReadiness)
	}
	candidateGeneration := lbAltTestGeneration{block: "g1", httpPort: f.statusPort, tlsPort: 7301, whodisPort: 7302}
	if !reflect.DeepEqual(chainRules(), generationRules(candidateGeneration)) {
		t.Fatalf("the chains do not point at the accepted candidate:\n%v", chainRules())
	}
}

// The chains of a connect block between deploys: the first refresh writes
// them, a refresh while they match writes nothing, only lists, and a chain
// lost some other way than a rollback is written again at the next refresh.
func TestLbAltWiringChainRefreshWritesNothingWhileTheChainsMatch(t *testing.T) {
	f := newLbAltWorkerFixture(t)
	f.worker.lbAltOps = defaultLbAltWorkerOps()
	host := newFakeLbAltHost()
	installLbAltWiringCommands(t, host, f.record)
	restores := func() int {
		count := 0
		for _, event := range f.recorded() {
			if strings.HasPrefix(event, "restore ") {
				count += 1
			}
		}
		return count
	}
	f.worker.assignLbAltWorkerChains(map[int]int{80: f.statusPort, 443: 7301, 4053: 7302})
	chainRefreshTimeout := f.worker.lbAltSettings.chainRefreshTimeout
	due := f.worker.lbAltState.nextChainRefresh

	f.worker.refreshLbAltWorkerChainsIfDue(due)
	if count := restores(); count != 2 {
		t.Fatalf("the first refresh wrote %d transactions, want one per family", count)
	}
	listings := len(host.commandsNamed("iptables", "ip6tables"))
	f.worker.refreshLbAltWorkerChainsIfDue(due.Add(chainRefreshTimeout))
	if count := restores(); count != 2 {
		t.Fatalf("a refresh of matching chains wrote %d transactions", count-2)
	}
	if len(host.commandsNamed("iptables", "ip6tables")) == listings {
		t.Fatal("the refresh did not look at the chains")
	}

	// eth1's IPv4 chain is lost
	func() {
		host.stateLock.Lock()
		defer host.stateLock.Unlock()
		host.tables["ipv4/nat"].chainRules["WARP-TEST-LBA-ETH1-G1"] = nil
	}()
	f.worker.refreshLbAltWorkerChainsIfDue(due.Add(2 * chainRefreshTimeout))
	if count := restores(); count != 3 {
		t.Fatalf("the refresh after a loss wrote %d transactions, want one", count-2)
	}
	generation := lbAltTestGeneration{block: "g1", httpPort: f.statusPort, tlsPort: 7301, whodisPort: 7302}
	requireLbAltRules(t, "ipv4 WARP-TEST-LBA-ETH1-G1", host.chainRules("ipv4", "nat", "WARP-TEST-LBA-ETH1-G1"), generation.blockRules("192.0.2.1"))
}

// A host as the lb units' initBlockRedirect leaves it for env test: the lb
// chain of each interface, jumped from nat PREROUTING and OUTPUT, holding the
// DNAT nginx served the interface's public address with.
func newLbAltWiringHost(t *testing.T, splitInterface lbAltSplitInterface) *fakeLbAltHost {
	t.Helper()
	host := newFakeLbAltHost()
	names, err := newLbAltChainNames("test", splitInterface.name)
	if err != nil {
		t.Fatal(err)
	}
	for _, family := range []string{"ipv4", "ipv6"} {
		host.addChain(family, "nat", names.lbChain)
		host.addRule(t, family, "nat", "PREROUTING", "-m addrtype --dst-type LOCAL -j "+names.lbChain)
	}
	host.addRule(t, "ipv4", "nat", names.lbChain, lbAltTestNginxDnat(splitInterface.publicIpv4, splitInterface.bridgeIpv4))
	host.addRule(t, "ipv6", "nat", names.lbChain, lbAltTestNginxDnat(splitInterface.publicIpv6, splitInterface.bridgeIpv6))
	return host
}

// edge-a eth1 of lbAltUnitsServicesYaml as the split takes it: its public
// addresses, its bridge's, and the lb_alt public ports.
func lbAltWiringEdgeAEth1() lbAltSplitInterface {
	return lbAltSplitInterface{
		name:        "eth1",
		publicIpv4:  "198.51.100.1",
		publicIpv6:  "2001:db8:1::1",
		bridgeIpv4:  "192.0.2.1",
		bridgeIpv6:  "2001:db8:f1::1",
		publicPorts: lbAltTablePublicPorts(),
	}
}

// Writes every block's chain on the interface with the real writer and has
// their generations listen, so each block is ready.
func readyLbAltWiringBlocks(t *testing.T, host *fakeLbAltHost, splitInterface lbAltSplitInterface) {
	t.Helper()
	generations := lbAltTestGenerations()
	for _, generation := range generations {
		if err := writeLbAltBlockChains(context.Background(), "test", generation.block, []lbAltSplitInterface{splitInterface}, generation.targets()); err != nil {
			t.Fatal(err)
		}
	}
	host.setListenRows(lbAltTestListenRows(generations, splitInterface))
}

// The routing-only loop of an lb_alt interface's unit reconciles the split at
// its start and on every reconcile, one routing interval (30 s) apart. While
// the interface is still on nginx, the real reconcile waits for every block
// (errLbAltSplitAwaitsEveryBlock): with no block ready, and then with beta
// alone ready, it writes no split, so new flows stay on nginx instead of all
// going to beta, and the interface's nginx is kept and not even listed. The
// reconcile once every block is ready puts the base split in and retires
// nginx.
func TestLbAltWiringRoutingOnlyLoopRetiresNginxOnceTheSplitIsReady(t *testing.T) {
	setupTestVault(t, lbAltUnitsYaml(lbAltUnitsSettings{connect: "true"}))
	errOutput := captureErrOutput(t)
	splitInterface := lbAltWiringEdgeAEth1()
	host := newLbAltWiringHost(t, splitInterface)
	installLbAltWiringCommands(t, host, func(event string) {})
	routingCommands := lbAltFakeRoutingCommands(t)

	// docker ps lists the interface's nginx, and logs each listing
	bin := filepath.Join(os.Getenv("WARP_HOME"), "bin")
	if err := os.MkdirAll(bin, 0o700); err != nil {
		t.Fatal(err)
	}
	listingLog := filepath.Join(os.Getenv("WARP_HOME"), "docker-ps.log")
	t.Setenv("FIXTURE_LISTING_LOG", listingLog)
	writeSudoFixture(t, bin, `#!/bin/sh
case "$*" in
  "docker ps "*) printf 'listed\n' >> "$FIXTURE_LISTING_LOG"; printf '0ea7c0000001\n' ;;
  *) printf 'unexpected fixture command\n' >&2; exit 97 ;;
esac
`)
	t.Setenv("PATH", bin)
	listings := func() int {
		data, err := os.ReadFile(listingLog)
		if errors.Is(err, os.ErrNotExist) {
			return 0
		} else if err != nil {
			t.Fatal(err)
		}
		return strings.Count(string(data), "listed\n")
	}
	var stopOnce sync.Once
	stopped := make(chan struct{})
	previousRun := runAndLogFunc
	runAndLogFunc = func(cmd *exec.Cmd) error {
		err := previousRun(cmd)
		if strings.Contains(strings.Join(cmd.Args, " "), "docker container stop ") {
			stopOnce.Do(func() { close(stopped) })
		}
		return err
	}

	worker := newLbAltSplitWorker(defaultLbAltWorkerOps())
	worker.dockerNetwork.ipv6 = &NetworkInterface{
		interfaceName:   "warpeth1",
		interfaceIp:     "2001:db8:f1::1",
		interfaceSubnet: "2001:db8:f1::/64",
	}
	splitNames, err := newLbAltChainNames("test", "eth1")
	if err != nil {
		t.Fatal(err)
	}

	// as Run does: the split at the loop's start, then the loop
	worker.reconcileLbAltWorkerInterface()
	waits := 0
	reconcileRoutingTableUntilQuit(func(timeout time.Duration) bool {
		// §2.5: the lb unit reconciles the split every 30 s
		if timeout != 30*time.Second {
			t.Fatalf("the loop waits %s between reconciles, want 30s", timeout)
		}
		waits += 1
		switch waits {
		case 1:
			// the start's reconcile found no ready block
			if count := listings(); count != 0 {
				t.Fatalf("nginx was listed %d times with no ready block", count)
			}
			// beta comes up alone
			beta := lbAltTestGenerations()[0]
			if err := writeLbAltBlockChains(context.Background(), "test", beta.block, []lbAltSplitInterface{splitInterface}, beta.targets()); err != nil {
				t.Fatal(err)
			}
			host.setListenRows(lbAltTestListenRows([]lbAltTestGeneration{beta}, splitInterface))
		case 2:
			if count := listings(); count != 0 {
				t.Fatalf("nginx was listed %d times with beta alone ready", count)
			}
			for _, family := range []string{"ipv4", "ipv6"} {
				if host.hasChain(family, "nat", splitNames.splitChain) || 0 < len(host.rulesMentioning(family, "nat", splitNames.ruleComment)) || 0 < len(host.rulesMentioning(family, "mangle", splitNames.ruleComment)) {
					t.Fatalf("%s holds the split with beta alone ready", family)
				}
			}
			// every connect block comes up
			readyLbAltWiringBlocks(t, host, splitInterface)
		case 3:
			select {
			case <-stopped:
			case <-time.After(30 * time.Second):
				t.Fatal("the reconcile with a ready split did not stop nginx")
			}
			return true
		}
		return false
	}, worker.routingOnlyReconcile())
	if worker.orphanDrain == nil {
		t.Fatal("no nginx retirement is running")
	}
	if err := <-worker.orphanDrain; err != nil {
		t.Fatalf("nginx retirement: %v", err)
	}

	if count := listings(); count != 1 {
		t.Fatalf("nginx was listed %d times, want once, after the ready reconcile", count)
	}
	// one line per reconcile, which names each family the split waited in
	if count := strings.Count(errOutput.String(), "lb_alt split of edge-a.example-eth1 keeps nginx until every block is ready: "+errLbAltSplitAwaitsEveryBlock.Error()); count != 2 {
		t.Fatalf("the split waited for every block %d times, want at the start and the first reconcile:\n%s", count, errOutput.String())
	}
	for _, family := range []string{"ipv4", "ipv6"} {
		if runs := lbAltTestSplitRuns(t, splitNames, host.chainRules(family, "nat", splitNames.splitChain)); runs != lbAltTestBaseRuns {
			t.Fatalf("%s split runs %s", family, runs)
		}
	}
	stopCommands := 0
	for _, command := range *routingCommands {
		if strings.Contains(command, "docker container stop -t 3600 0ea7c0000001") {
			stopCommands += 1
		}
	}
	if stopCommands != 1 {
		t.Fatalf("nginx was stopped %d times:\n%s", stopCommands, strings.Join(*routingCommands, "\n"))
	}
}

// Rolling an interface back to nginx (D18), through the real removal: the
// nginx lb's cutover puts its public DNAT back first, and only then is the
// recorded split removed, its HMARK rules, entry jumps and split chains, in
// both families. The connect blocks' chains stay.
func TestLbAltWiringRollbackRemovesTheSplitOnceNginxDnatIsBack(t *testing.T) {
	f := newLbAltLbFixture(t, false)
	f.worker.lbAltOps = defaultLbAltWorkerOps()
	splitInterface := lbAltWiringEdgeAEth1()
	host := newLbAltWiringHost(t, splitInterface)
	installLbAltWiringCommands(t, host, func(event string) {
		f.events = append(f.events, event)
	})
	readyLbAltWiringBlocks(t, host, splitInterface)
	if err := reconcileLbAltSplit(context.Background(), &lbAltSplitConfig{
		env:            "test",
		splitInterface: splitInterface,
		blockWeights:   lbAltTestBlockWeights(),
	}); err != nil {
		t.Fatal(err)
	}
	names, err := newLbAltChainNames("test", "eth1")
	if err != nil {
		t.Fatal(err)
	}
	blockChains := func() []string {
		state := []string{}
		for _, family := range []string{"ipv4", "ipv6"} {
			for _, chain := range host.chainsWithPrefix(family, "nat", names.blockChainPrefix) {
				state = append(state, family+" "+chain)
				state = append(state, host.chainRules(family, "nat", chain)...)
			}
		}
		return state
	}
	blockChainsBefore := blockChains()
	if len(host.rulesMentioning("ipv4", "mangle", names.ruleComment)) == 0 || !host.hasChain("ipv6", "nat", names.splitChain) {
		t.Fatal("the split is not in place before the rollback")
	}
	recordPath := lbAltWriteSplitRecord(t, "test", "eth1")
	f.events = nil

	if err := f.worker.deployContainerOverlap(true, nil); err != nil {
		t.Fatal(err)
	}
	dnatIndex := slices.Index(f.events, "public dnat")
	removalIndex := slices.Index(f.events, "restore ipv4 nat")
	if dnatIndex < 0 || removalIndex < dnatIndex {
		t.Fatalf("rollback events %v, want nginx's public dnat before the split's removal", f.events)
	}
	for _, family := range []string{"ipv4", "ipv6"} {
		for _, table := range []string{"mangle", "nat"} {
			requireLbAltRules(t, family+" "+table+" split rules", host.rulesMentioning(family, table, names.ruleComment), []string{})
		}
		for _, chain := range []string{names.splitChain, names.temporarySplitChain} {
			if host.hasChain(family, "nat", chain) {
				t.Fatalf("%s %s is left", family, chain)
			}
		}
	}
	requireLbAltRules(t, "block chains", blockChains(), blockChainsBefore)
	if _, err := os.Stat(recordPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the split record stayed: %v", err)
	}
}

// A generation's route file goes with its container: the real removal takes
// its directory once docker no longer lists the container, and not before.
func TestLbAltWiringPruneRemovesTheRouteFileWithItsContainer(t *testing.T) {
	f := newLbAltWorkerFixture(t)
	f.worker.lbAltOps = defaultLbAltWorkerOps()
	if _, err := f.worker.startContainer(map[int]int{80: f.statusPort, 443: 7301, 4053: 7302}); err != nil {
		t.Fatal(err)
	}
	containerName := lbAltDockerRunValues(f.dockerRunArgs[0], "--name")[0]
	routeDir := filepath.Join(f.home, lbAltRouteHostDirName, containerName)

	// docker ps lists the names in the state file
	namesFile := filepath.Join(f.home, "container-names")
	t.Setenv("FIXTURE_NAMES", namesFile)
	writeSudoFixture(t, filepath.Join(f.home, "bin"), `#!/bin/sh
case "$*" in
  "docker ps "*) while IFS= read -r line; do printf '%s\n' "$line"; done < "$FIXTURE_NAMES" ;;
  *) printf 'unexpected fixture command\n' >&2; exit 97 ;;
esac
`)

	if err := os.WriteFile(namesFile, []byte(containerName+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	f.worker.prune()
	if _, err := os.Stat(filepath.Join(routeDir, lbAltRouteFileName)); err != nil {
		t.Fatalf("the route file of a listed container went: %v", err)
	}

	if err := os.WriteFile(namesFile, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	f.worker.prune()
	if _, err := os.Stat(routeDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the route file of a removed container stayed: %v", err)
	}
}
