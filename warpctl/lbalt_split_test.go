package main

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/urnetwork/warp/services"
)

// An in-memory iptables and ss for the split writers. Both families' mangle
// and nat tables apply iptables-restore transactions as the kernel does: whole
// or not at all, refusing a jump to a missing chain and the deletion of a
// chain that is used or not empty. Rules are listed in the form iptables -S
// prints for the forms the writers use (newFakeIptablesRule), so the writers'
// comparisons are checked against the listed form, not against their own
// arguments, and a rule is deleted only by arguments that reproduce what the
// kernel stored for it.
type fakeLbAltHost struct {
	stateLock sync.Mutex
	// "<family>/<table>" -> table
	tables map[string]*fakeIptablesTable
	// the ss -Htuln output
	listenRows string
	commands   []lbAltCommand
	// runs before each command, without the state lock; an error fails the
	// command
	beforeCommand func(command lbAltCommand) error
	// runs after each committed transaction, with the state lock held
	afterCommitWithLock func(family string, table string)
}

// One table of one family.
type fakeIptablesTable struct {
	builtinChains []string
	userChainSet  map[string]bool
	// chain -> its rules in order
	chainRules map[string][]fakeIptablesRule
}

// One rule as the kernel holds it.
type fakeIptablesRule struct {
	// the arguments as iptables -S prints them
	listedSpec []string
	// what a deletion's arguments must reproduce: the listed arguments, with
	// HMARK's whole stored source mask in place of the prefix iptables prints
	storedSpec string
}

// A rule from the arguments that add it, as iptables lists and stores it.
// iptables -S prints -d with its prefix length, and HMARK's source mask as a
// prefix length over the family's address bits, its seed as eight hex digits
// and its offset in decimal (M7's listing on edge-4). libxt_HMARK stores the
// source mask as 16 bytes: --hmark-tuple src sets all 128 bits,
// --hmark-src-prefix N the first N. iptables compares a target's whole stored
// data on a delete, so an IPv4 rule added with the tuple lists as prefix 32
// but is not deleted by that listed form.
func newFakeIptablesRule(spec []string, family string) fakeIptablesRule {
	addressBits := 32
	if family == "ipv6" {
		addressBits = 128
	}
	listedSpec := []string{}
	isHmark := false
	// the leading one bits of HMARK's 128-bit source mask; -1 for none
	hmarkSourceBits := -1
	hmarkRnd := ""
	hmarkMod := ""
	hmarkOffset := ""
	for i := 0; i < len(spec); i++ {
		value := ""
		if i+1 < len(spec) {
			value = spec[i+1]
		}
		switch spec[i] {
		case "-d":
			if !strings.Contains(value, "/") {
				value += "/" + strconv.Itoa(addressBits)
			}
			listedSpec = append(listedSpec, "-d", value)
			i += 1
		case "--hmark-tuple":
			isHmark = true
			if slices.Contains(strings.Split(value, ","), "src") {
				hmarkSourceBits = 128
			}
			i += 1
		case "--hmark-src-prefix":
			isHmark = true
			hmarkSourceBits, _ = strconv.Atoi(value)
			i += 1
		case "--hmark-rnd":
			isHmark = true
			number, _ := strconv.ParseUint(value, 0, 32)
			hmarkRnd = fmt.Sprintf("0x%08x", number)
			i += 1
		case "--hmark-mod":
			isHmark = true
			hmarkMod = value
			i += 1
		case "--hmark-offset":
			isHmark = true
			number, _ := strconv.ParseUint(value, 0, 32)
			hmarkOffset = strconv.FormatUint(number, 10)
			i += 1
		default:
			listedSpec = append(listedSpec, spec[i])
		}
	}
	storedSpec := strings.Join(listedSpec, " ")
	if isHmark {
		if 0 <= hmarkSourceBits {
			listedSpec = append(listedSpec, "--hmark-src-prefix", strconv.Itoa(min(hmarkSourceBits, addressBits)))
			storedSpec += fmt.Sprintf(" hmark-src-mask-bits=%d", hmarkSourceBits)
		}
		hmarkValues := []string{"--hmark-rnd", hmarkRnd, "--hmark-mod", hmarkMod, "--hmark-offset", hmarkOffset}
		listedSpec = append(listedSpec, hmarkValues...)
		storedSpec += " " + strings.Join(hmarkValues, " ")
	}
	return fakeIptablesRule{
		listedSpec: listedSpec,
		storedSpec: storedSpec,
	}
}

func newFakeLbAltHost() *fakeLbAltHost {
	host := &fakeLbAltHost{
		tables:     map[string]*fakeIptablesTable{},
		listenRows: "",
		commands:   []lbAltCommand{},
	}
	for _, family := range []string{"ipv4", "ipv6"} {
		host.tables[family+"/nat"] = newFakeIptablesTable("PREROUTING", "INPUT", "OUTPUT", "POSTROUTING")
		host.tables[family+"/mangle"] = newFakeIptablesTable("PREROUTING", "INPUT", "FORWARD", "OUTPUT", "POSTROUTING")
	}
	return host
}

func newFakeIptablesTable(builtinChains ...string) *fakeIptablesTable {
	table := &fakeIptablesTable{
		builtinChains: builtinChains,
		userChainSet:  map[string]bool{},
		chainRules:    map[string][]fakeIptablesRule{},
	}
	return table
}

func (self *fakeIptablesTable) clone() *fakeIptablesTable {
	chainRules := map[string][]fakeIptablesRule{}
	for chain, rules := range self.chainRules {
		chainRules[chain] = slices.Clone(rules)
	}
	return &fakeIptablesTable{
		builtinChains: self.builtinChains,
		userChainSet:  maps.Clone(self.userChainSet),
		chainRules:    chainRules,
	}
}

func (self *fakeIptablesTable) hasChain(chain string) bool {
	return slices.Contains(self.builtinChains, chain) || self.userChainSet[chain]
}

// The user chains, sorted.
func (self *fakeIptablesTable) userChains() []string {
	return slices.Sorted(maps.Keys(self.userChainSet))
}

// Whether any rule jumps to the chain.
func (self *fakeIptablesTable) referenced(chain string) bool {
	for _, rules := range self.chainRules {
		for _, rule := range rules {
			spec := rule.listedSpec
			for i := 0; i+1 < len(spec); i++ {
				if (spec[i] == "-j" || spec[i] == "-g") && spec[i+1] == chain {
					return true
				}
			}
		}
	}
	return false
}

// The table as iptables -S lists it.
func (self *fakeIptablesTable) listing() string {
	lines := []string{}
	for _, chain := range self.builtinChains {
		lines = append(lines, "-P "+chain+" ACCEPT")
	}
	for _, chain := range self.userChains() {
		lines = append(lines, "-N "+chain)
	}
	for _, chain := range append(slices.Clone(self.builtinChains), self.userChains()...) {
		for _, rule := range self.chainRules[chain] {
			lines = append(lines, "-A "+chain+" "+joinIptablesArgs(rule.listedSpec))
		}
	}
	return strings.Join(lines, "\n") + "\n"
}

func (self *fakeLbAltHost) run(ctx context.Context, command lbAltCommand) (commandOutput, error) {
	if self.beforeCommand != nil {
		if err := self.beforeCommand(command); err != nil {
			return commandOutput{}, err
		}
	}
	var output commandOutput
	var err error
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.commands = append(self.commands, command)
		output, err = self.executeWithLock(command)
	}()
	return output, err
}

func (self *fakeLbAltHost) executeWithLock(command lbAltCommand) (commandOutput, error) {
	family := "ipv4"
	if strings.HasPrefix(command.name, "ip6tables") {
		family = "ipv6"
	}
	switch command.name {
	case "ss":
		if command.privileged || !slices.Equal(command.args, []string{"-Htuln"}) {
			return commandOutput{}, fmt.Errorf("unexpected ss call %v", command)
		}
		return commandOutput{stdout: []byte(self.listenRows)}, nil
	case "iptables", "ip6tables":
		if !command.privileged || len(command.args) != 4 || command.args[0] != "-w" || command.args[1] != "-t" || command.args[3] != "-S" {
			return commandOutput{}, fmt.Errorf("unexpected iptables call %v", command)
		}
		table, ok := self.tables[family+"/"+command.args[2]]
		if !ok {
			return commandOutput{}, fmt.Errorf("no table %s", command.args[2])
		}
		return commandOutput{stdout: []byte(table.listing())}, nil
	case "iptables-restore", "ip6tables-restore":
		if !command.privileged || !slices.Equal(command.args, []string{"-w", "--noflush"}) {
			return commandOutput{}, fmt.Errorf("unexpected restore call %v", command)
		}
		return commandOutput{}, self.applyRestoreWithLock(family, command.stdin)
	}
	return commandOutput{}, fmt.Errorf("unexpected command %s", command.name)
}

// Applies one restore input: each table section is checked on a copy and
// replaces the table only at its COMMIT.
func (self *fakeLbAltHost) applyRestoreWithLock(family string, input string) error {
	tableName := ""
	var working *fakeIptablesTable
	for lineIndex, line := range strings.Split(input, "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		fail := func(format string, args ...any) error {
			return fmt.Errorf("restore line %d failed: %s", lineIndex+1, fmt.Sprintf(format, args...))
		}
		if strings.HasPrefix(line, "*") {
			tableName = line[1:]
			table, ok := self.tables[family+"/"+tableName]
			if !ok {
				return fail("no table %s", tableName)
			}
			working = table.clone()
			continue
		}
		if working == nil {
			return fail("no table")
		}
		if line == "COMMIT" {
			self.tables[family+"/"+tableName] = working
			working = nil
			if self.afterCommitWithLock != nil {
				self.afterCommitWithLock(family, tableName)
			}
			continue
		}
		if strings.HasPrefix(line, ":") {
			chain := strings.Fields(line[1:])[0]
			if !slices.Contains(working.builtinChains, chain) {
				working.userChainSet[chain] = true
				working.chainRules[chain] = nil
			}
			continue
		}
		args, err := splitIptablesArgs(line)
		if err != nil || len(args) < 2 {
			return fail("unreadable")
		}
		operation := args[0]
		chain := args[1]
		rest := args[2:]
		if !working.hasChain(chain) && operation != "-N" {
			return fail("no chain %s", chain)
		}
		checkJump := func(spec []string) error {
			for i := 0; i+1 < len(spec); i++ {
				if spec[i] != "-j" && spec[i] != "-g" {
					continue
				}
				switch spec[i+1] {
				case "ACCEPT", "DROP", "RETURN", "DNAT", "SNAT", "MASQUERADE", "HMARK", "MARK":
				default:
					if !working.hasChain(spec[i+1]) {
						return fail("no target %s", spec[i+1])
					}
				}
			}
			return nil
		}
		switch operation {
		case "-A":
			if err := checkJump(rest); err != nil {
				return err
			}
			working.chainRules[chain] = append(working.chainRules[chain], newFakeIptablesRule(rest, family))
		case "-I":
			position := 1
			if 0 < len(rest) {
				if number, err := strconv.Atoi(rest[0]); err == nil {
					position = number
					rest = rest[1:]
				}
			}
			if position < 1 || len(working.chainRules[chain])+1 < position {
				return fail("index of insertion too big")
			}
			if err := checkJump(rest); err != nil {
				return err
			}
			working.chainRules[chain] = slices.Insert(working.chainRules[chain], position-1, newFakeIptablesRule(rest, family))
		case "-D":
			// as iptables does, the arguments must reproduce the stored rule
			storedSpec := newFakeIptablesRule(rest, family).storedSpec
			index := slices.IndexFunc(working.chainRules[chain], func(rule fakeIptablesRule) bool {
				return rule.storedSpec == storedSpec
			})
			if index < 0 {
				return fail("bad rule (does a matching rule exist in that chain?)")
			}
			working.chainRules[chain] = slices.Delete(working.chainRules[chain], index, index+1)
		case "-F":
			working.chainRules[chain] = nil
		case "-X":
			if !working.userChainSet[chain] {
				return fail("%s is not a user chain", chain)
			}
			if 0 < len(working.chainRules[chain]) {
				return fail("%s is not empty", chain)
			}
			if working.referenced(chain) {
				return fail("%s is in use", chain)
			}
			delete(working.userChainSet, chain)
			delete(working.chainRules, chain)
		case "-N":
			if working.hasChain(chain) {
				return fail("chain %s exists", chain)
			}
			working.userChainSet[chain] = true
		default:
			return fail("unknown operation %s", operation)
		}
	}
	if working != nil {
		return errors.New("restore input has no COMMIT")
	}
	return nil
}

func (self *fakeLbAltHost) addChain(family string, table string, chain string) {
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.tables[family+"/"+table].userChainSet[chain] = true
	}()
}

// Adds a rule at the chain's position, from 0, from the arguments that add it.
func (self *fakeLbAltHost) insertRule(t *testing.T, family string, table string, chain string, position int, specText string) {
	spec, err := splitIptablesArgs(specText)
	if err != nil {
		t.Fatal(err)
	}
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		iptablesTable := self.tables[family+"/"+table]
		iptablesTable.chainRules[chain] = slices.Insert(iptablesTable.chainRules[chain], position, newFakeIptablesRule(spec, family))
	}()
}

// Appends a rule from the arguments that add it.
func (self *fakeLbAltHost) addRule(t *testing.T, family string, table string, chain string, specText string) {
	position := 0
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		position = len(self.tables[family+"/"+table].chainRules[chain])
	}()
	self.insertRule(t, family, table, chain, position, specText)
}

// The chain's rules, each as its listed arguments.
func (self *fakeLbAltHost) chainRulesWithLock(family string, table string, chain string) []string {
	rules := []string{}
	for _, rule := range self.tables[family+"/"+table].chainRules[chain] {
		rules = append(rules, strings.Join(rule.listedSpec, " "))
	}
	return rules
}

func (self *fakeLbAltHost) chainRules(family string, table string, chain string) []string {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.chainRulesWithLock(family, table, chain)
}

func (self *fakeLbAltHost) hasChainWithLock(family string, table string, chain string) bool {
	return self.tables[family+"/"+table].hasChain(chain)
}

func (self *fakeLbAltHost) hasChain(family string, table string, chain string) bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.hasChainWithLock(family, table, chain)
}

// Every rule of the table that mentions the text, as "<chain> <arguments>".
func (self *fakeLbAltHost) rulesMentioning(family string, table string, text string) []string {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	iptablesTable := self.tables[family+"/"+table]
	rules := []string{}
	for _, chain := range append(slices.Clone(iptablesTable.builtinChains), iptablesTable.userChains()...) {
		for _, tableRule := range iptablesTable.chainRules[chain] {
			rule := chain + " " + strings.Join(tableRule.listedSpec, " ")
			if strings.Contains(rule, text) {
				rules = append(rules, rule)
			}
		}
	}
	return rules
}

// The user chains of the table whose names start with the prefix.
func (self *fakeLbAltHost) chainsWithPrefix(family string, table string, prefix string) []string {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	chains := []string{}
	for _, chain := range self.tables[family+"/"+table].userChains() {
		if strings.HasPrefix(chain, prefix) {
			chains = append(chains, chain)
		}
	}
	return chains
}

// The listing of one table.
func (self *fakeLbAltHost) listing(family string, table string) string {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.tables[family+"/"+table].listing()
}

// The commands run so far named one of the names.
func (self *fakeLbAltHost) commandsNamed(names ...string) []lbAltCommand {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	commands := []lbAltCommand{}
	for _, command := range self.commands {
		if slices.Contains(names, command.name) {
			commands = append(commands, command)
		}
	}
	return commands
}

func (self *fakeLbAltHost) clearCommands() {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.commands = []lbAltCommand{}
}

func (self *fakeLbAltHost) setListenRows(listenRows string) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.listenRows = listenRows
}

// A host in main's shape (LBALT.md §3.1) on documentation addresses: env main
// and connect's five blocks with main's weights.
const lbAltTestEnv = "main"

func lbAltTestBlockWeights() []services.BlockWeight {
	return []services.BlockWeight{
		{Block: "beta", Weight: 1},
		{Block: "g1", Weight: 24},
		{Block: "g2", Weight: 25},
		{Block: "g3", Weight: 25},
		{Block: "g4", Weight: 25},
	}
}

// main's lb_alt public ports (services.LbAltPublicPorts).
func lbAltTestPublicPorts() map[string][]int {
	return map[string][]int{
		"tcp": {80, 443},
		"udp": {53, 443, 4053},
	}
}

// eno4np3 has both families.
func lbAltTestDualStackInterface() lbAltSplitInterface {
	return lbAltSplitInterface{
		name:        "eno4np3",
		publicIpv4:  "203.0.113.4",
		publicIpv6:  "2001:db8:ff04::1",
		bridgeIpv4:  "198.51.100.4",
		bridgeIpv6:  "2001:db8:4::1",
		publicPorts: lbAltTestPublicPorts(),
	}
}

// eno4 has no public IPv6, though its bridge has IPv6, as every lb interface
// network does. Its name is a prefix of eno4np3's, so its chain prefix must
// never take in eno4np3's chains.
func lbAltTestIpv4OnlyInterface() lbAltSplitInterface {
	return lbAltSplitInterface{
		name:        "eno4",
		publicIpv4:  "203.0.113.5",
		publicIpv6:  "",
		bridgeIpv4:  "198.51.100.5",
		bridgeIpv6:  "2001:db8:5::1",
		publicPorts: lbAltTestPublicPorts(),
	}
}

func lbAltTestConfig(splitInterface lbAltSplitInterface) *lbAltSplitConfig {
	return &lbAltSplitConfig{
		env:            lbAltTestEnv,
		splitInterface: splitInterface,
		blockWeights:   lbAltTestBlockWeights(),
	}
}

func lbAltTestNames(t *testing.T, splitInterface lbAltSplitInterface) *lbAltChainNames {
	names, err := newLbAltChainNames(lbAltTestEnv, splitInterface.name)
	if err != nil {
		t.Fatal(err)
	}
	return names
}

// The internal ports of one block generation.
type lbAltTestGeneration struct {
	block string
	// service port 80: the front's port-80 handler
	httpPort int
	// service port 443: tls on tcp, quic on udp
	tlsPort int
	// service port 4053: whodis, for public udp 4053 and 53
	whodisPort int
}

func (self lbAltTestGeneration) targets() []lbAltBlockTarget {
	return []lbAltBlockTarget{
		{protocol: "tcp", publicPort: 80, internalPort: self.httpPort},
		{protocol: "tcp", publicPort: 443, internalPort: self.tlsPort},
		{protocol: "udp", publicPort: 53, internalPort: self.whodisPort},
		{protocol: "udp", publicPort: 443, internalPort: self.tlsPort},
		{protocol: "udp", publicPort: 4053, internalPort: self.whodisPort},
	}
}

// The ss rows of the generation's public sockets on the bridge addresses.
func (self lbAltTestGeneration) listenRows(bridgeAddresses ...string) string {
	rows := []string{}
	for _, bridgeAddress := range bridgeAddresses {
		host := bridgeAddress
		peer := "0.0.0.0:*"
		if strings.Contains(host, ":") {
			host = "[" + host + "]"
			peer = "[::]:*"
		}
		rows = append(rows,
			fmt.Sprintf("tcp   LISTEN 0      4096   %s:%d   %s", host, self.httpPort, peer),
			fmt.Sprintf("tcp   LISTEN 0      4096   %s:%d   %s", host, self.tlsPort, peer),
			fmt.Sprintf("udp   UNCONN 0      0      %s:%d   %s", host, self.tlsPort, peer),
			fmt.Sprintf("udp   UNCONN 0      0      %s:%d   %s", host, self.whodisPort, peer),
		)
	}
	return strings.Join(rows, "\n") + "\n"
}

// A block chain's listed DNATs for the generation on the bridge address.
func (self lbAltTestGeneration) blockRules(bridgeAddress string) []string {
	destination := func(port int) string {
		return netip.AddrPortFrom(netip.MustParseAddr(bridgeAddress), uint16(port)).String()
	}
	return []string{
		"-p tcp -m tcp --dport 80 -j DNAT --to-destination " + destination(self.httpPort),
		"-p tcp -m tcp --dport 443 -j DNAT --to-destination " + destination(self.tlsPort),
		"-p udp -m udp --dport 53 -j DNAT --to-destination " + destination(self.whodisPort),
		"-p udp -m udp --dport 443 -j DNAT --to-destination " + destination(self.tlsPort),
		"-p udp -m udp --dport 4053 -j DNAT --to-destination " + destination(self.whodisPort),
	}
}

// Each block's first generation.
func lbAltTestGenerations() []lbAltTestGeneration {
	generations := []lbAltTestGeneration{}
	for i, blockWeight := range lbAltTestBlockWeights() {
		generations = append(generations, lbAltTestGeneration{
			block:      blockWeight.Block,
			httpPort:   7201 + i,
			tlsPort:    7231 + i,
			whodisPort: 7261 + i,
		})
	}
	return generations
}

// The ss rows of the generations on every bridge address of the interfaces.
func lbAltTestListenRows(generations []lbAltTestGeneration, splitInterfaces ...lbAltSplitInterface) string {
	bridgeAddresses := []string{}
	for _, splitInterface := range splitInterfaces {
		bridgeAddresses = append(bridgeAddresses, splitInterface.bridgeIpv4)
		if splitInterface.bridgeIpv6 != "" {
			bridgeAddresses = append(bridgeAddresses, splitInterface.bridgeIpv6)
		}
	}
	rows := ""
	for _, generation := range generations {
		rows += generation.listenRows(bridgeAddresses...)
	}
	return rows
}

// A host whose lb chains are as the lb workers' initBlockRedirect leaves them,
// each still holding the DNAT nginx served its interface with.
func newLbAltTestHost(t *testing.T, splitInterfaces ...lbAltSplitInterface) *fakeLbAltHost {
	host := newFakeLbAltHost()
	for _, splitInterface := range splitInterfaces {
		names := lbAltTestNames(t, splitInterface)
		for _, family := range []string{"ipv4", "ipv6"} {
			loopbackSubnet := "127.0.0.0/8"
			if family == "ipv6" {
				loopbackSubnet = "::1/128"
			}
			host.addChain(family, "nat", names.lbChain)
			host.addRule(t, family, "nat", "PREROUTING", "-m addrtype --dst-type LOCAL -j "+names.lbChain)
			host.addRule(t, family, "nat", "OUTPUT", "-m addrtype --dst-type LOCAL ! -d "+loopbackSubnet+" -j "+names.lbChain)
		}
		host.addRule(t, "ipv4", "nat", names.lbChain, lbAltTestNginxDnat(splitInterface.publicIpv4, splitInterface.bridgeIpv4))
		if splitInterface.publicIpv6 != "" {
			host.addRule(t, "ipv6", "nat", names.lbChain, lbAltTestNginxDnat(splitInterface.publicIpv6, splitInterface.bridgeIpv6))
		}
	}
	return host
}

// nginx's tcp 443 DNAT, as the lb worker's redirect wrote it.
func lbAltTestNginxDnat(publicAddress string, bridgeAddress string) string {
	public := netip.MustParseAddr(publicAddress)
	return fmt.Sprintf(
		"-d %s -p tcp -m tcp --dport 443 -j DNAT --to-destination %s",
		netip.PrefixFrom(public, public.BitLen()),
		netip.AddrPortFrom(netip.MustParseAddr(bridgeAddress), 7301),
	)
}

func newLbAltTestWriter(t *testing.T, host *fakeLbAltHost, lockDirectory string) *lbAltSplitWriter {
	settings := DefaultLbAltSplitSettings()
	settings.LockDirectory = lockDirectory
	settings.LockPollInterval = time.Millisecond
	return &lbAltSplitWriter{
		settings: settings,
		run:      host.run,
		lockBusy: nil,
	}
}

// Writes every generation's block chains on the interfaces.
func writeLbAltTestBlockChains(t *testing.T, writer *lbAltSplitWriter, generations []lbAltTestGeneration, splitInterfaces ...lbAltSplitInterface) {
	for _, generation := range generations {
		if err := writer.writeBlockChains(context.Background(), lbAltTestEnv, generation.block, splitInterfaces, generation.targets()); err != nil {
			t.Fatal(err)
		}
	}
}

// The split chain's rules as runs of buckets: "beta 0-0, g1 1-24, ...".
func lbAltTestSplitRuns(t *testing.T, names *lbAltChainNames, rules []string) string {
	runs := []string{}
	runBlock := ""
	runFirst := 0
	runLast := 0
	flush := func() {
		if runBlock != "" {
			runs = append(runs, fmt.Sprintf("%s %d-%d", runBlock, runFirst, runLast))
		}
	}
	for _, rule := range rules {
		fields := strings.Fields(rule)
		if len(fields) != 6 || fields[0] != "-m" || fields[1] != "mark" || fields[2] != "--mark" || fields[4] != "-j" {
			t.Fatalf("split rule %q is not a bucket jump", rule)
		}
		mark, err := strconv.ParseUint(fields[3], 0, 32)
		if err != nil {
			t.Fatalf("split rule %q has no mark", rule)
		}
		bucket := int(mark) - lbAltHmarkOffset
		block := strings.ToLower(strings.TrimPrefix(fields[5], names.blockChainPrefix))
		if block == runBlock && bucket == runLast+1 {
			runLast = bucket
			continue
		}
		flush()
		runBlock = block
		runFirst = bucket
		runLast = bucket
	}
	flush()
	return strings.Join(runs, ", ")
}

// The listed split rules of bucket runs written as "<block> <first>-<last>".
func lbAltTestSplitRules(t *testing.T, names *lbAltChainNames, runs ...string) []string {
	rules := []string{}
	for _, run := range runs {
		block, bucketRange, _ := strings.Cut(run, " ")
		firstText, lastText, _ := strings.Cut(bucketRange, "-")
		first, firstErr := strconv.Atoi(firstText)
		last, lastErr := strconv.Atoi(lastText)
		if firstErr != nil || lastErr != nil {
			t.Fatalf("bad run %q", run)
		}
		for bucket := first; bucket <= last; bucket += 1 {
			rules = append(rules, fmt.Sprintf("-m mark --mark %#x -j %s%s", lbAltHmarkOffset+bucket, names.blockChainPrefix, strings.ToUpper(block)))
		}
	}
	return rules
}

// main's weights over 100 buckets, as LBALT-IMPL §2.5 assigns them.
const lbAltTestBaseRuns = "beta 0-0, g1 1-24, g2 25-49, g3 50-74, g4 75-99"

func requireLbAltRules(t *testing.T, what string, got []string, want []string) {
	t.Helper()
	if !slices.Equal(got, want) {
		t.Fatalf("%s:\n got %d rules:\n  %s\nwant %d rules:\n  %s", what, len(got), strings.Join(got, "\n  "), len(want), strings.Join(want, "\n  "))
	}
}

func TestLbAltSplitChainNamesFitTheIptablesLimit(t *testing.T) {
	// main's lb interfaces (LBALT.md §3.1) and connect blocks
	for _, interfaceName := range []string{"eno1np0", "eno2np1", "eno3np2", "eno4np3", "eno3", "eno4"} {
		names, err := newLbAltChainNames("main", interfaceName)
		if err != nil {
			t.Fatal(err)
		}
		for _, chain := range []string{names.lbChain, names.splitChain, names.temporarySplitChain} {
			if lbAltChainNameLimit < len(chain) {
				t.Errorf("chain %s is %d characters", chain, len(chain))
			}
		}
		if len(names.temporarySplitChain) != len(names.splitChain) {
			t.Errorf("temporary chain %s is not as long as %s", names.temporarySplitChain, names.splitChain)
		}
		for _, blockWeight := range lbAltTestBlockWeights() {
			chain, err := names.blockChain(blockWeight.Block)
			if err != nil || lbAltChainNameLimit < len(chain) {
				t.Errorf("block chain %s: %v", chain, err)
			}
		}
		// the lb chain is the lb worker's own
		lbWorker := &RunWorker{
			env:     "main",
			service: "lb",
			block:   "edge-a.example-" + interfaceName,
		}
		if names.lbChain != lbWorker.iptablesChainName() {
			t.Errorf("lb chain %s, lb worker chain %s", names.lbChain, lbWorker.iptablesChainName())
		}
	}

	names, err := newLbAltChainNames("main", "eno2np1")
	if err != nil {
		t.Fatal(err)
	}
	longestChain, err := names.blockChain("beta")
	if err != nil {
		t.Fatal(err)
	}
	if longestChain != "WARP-MAIN-LBA-ENO2NP1-BETA" || names.splitChain != "WARP-MAIN-LBA-ENO2NP1" || names.temporarySplitChain != "WARP-MAIN-LBT-ENO2NP1" {
		t.Fatalf("chains %s %s %s", names.splitChain, names.temporarySplitChain, longestChain)
	}

	// a name past the limit is an error, never a truncated name
	if _, err := newLbAltChainNames("community", "enp129s0f1np1"); err == nil {
		t.Fatal("a split chain over 28 characters was accepted")
	}
	longNames, err := newLbAltChainNames("main", "enp129s0f1")
	if err != nil {
		t.Fatal(err)
	}
	if chain, err := longNames.blockChain("beta"); err == nil {
		t.Fatalf("block chain %s over 28 characters was accepted", chain)
	}
	// a dash would let eno4's block chain prefix take in an interface eno4-x's
	if _, err := newLbAltChainNames("main", "eno4-x"); err == nil {
		t.Fatal("an interface name with a dash was accepted")
	}
}

func TestLbAltSplitBucketsFollowMainWeights(t *testing.T) {
	plan, err := newLbAltInterfacePlan(lbAltTestConfig(lbAltTestDualStackInterface()))
	if err != nil {
		t.Fatal(err)
	}
	allReady := map[string]bool{"beta": true, "g1": true, "g2": true, "g3": true, "g4": true}
	specs := plan.splitRuleSpecs(assignLbAltBuckets(plan.baseBucketBlocks, plan.blockWeights, allReady))
	rules := []string{}
	for _, spec := range specs {
		rules = append(rules, strings.Join(spec, " "))
	}
	if runs := lbAltTestSplitRuns(t, plan.names, rules); runs != lbAltTestBaseRuns {
		t.Fatalf("runs %s", runs)
	}
	// one rule per bucket, the mark 0x10000 + bucket, in bucket order
	if len(rules) != 100 {
		t.Fatalf("%d split rules", len(rules))
	}
	for bucket, want := range map[int]string{
		0:  "-m mark --mark 0x10000 -j WARP-MAIN-LBA-ENO4NP3-BETA",
		1:  "-m mark --mark 0x10001 -j WARP-MAIN-LBA-ENO4NP3-G1",
		24: "-m mark --mark 0x10018 -j WARP-MAIN-LBA-ENO4NP3-G1",
		25: "-m mark --mark 0x10019 -j WARP-MAIN-LBA-ENO4NP3-G2",
		99: "-m mark --mark 0x10063 -j WARP-MAIN-LBA-ENO4NP3-G4",
	} {
		if rules[bucket] != want {
			t.Errorf("bucket %d rule %q, want %q", bucket, rules[bucket], want)
		}
	}
}

func TestLbAltSplitMovesOnlyOrphanedBucketsToReadyBlocksByWeight(t *testing.T) {
	plan, err := newLbAltInterfacePlan(lbAltTestConfig(lbAltTestDualStackInterface()))
	if err != nil {
		t.Fatal(err)
	}
	runsOf := func(readyBlocks ...string) string {
		readySet := map[string]bool{}
		for _, block := range readyBlocks {
			readySet[block] = true
		}
		rules := []string{}
		for _, spec := range plan.splitRuleSpecs(assignLbAltBuckets(plan.baseBucketBlocks, plan.blockWeights, readySet)) {
			rules = append(rules, strings.Join(spec, " "))
		}
		return lbAltTestSplitRuns(t, plan.names, rules)
	}
	cases := []struct {
		readyBlocks []string
		runs        string
	}{
		{
			readyBlocks: []string{"beta", "g1", "g2", "g3", "g4"},
			runs:        lbAltTestBaseRuns,
		},
		// g2's 25 buckets go to beta 1, g1 8, g3 8 and g4 8 (weights 1, 24,
		// 25, 25 of 75), the leftover bucket to the earliest of the tied
		// remainders; no other bucket moves
		{
			readyBlocks: []string{"beta", "g1", "g3", "g4"},
			runs:        "beta 0-0, g1 1-24, beta 25-25, g1 26-33, g3 34-41, g4 42-49, g3 50-74, g4 75-99",
		},
		// beta's one bucket goes to the largest remainder of 24, 25, 25, 25
		// of 99, the earliest of the tie
		{
			readyBlocks: []string{"g1", "g2", "g3", "g4"},
			runs:        "g2 0-0, g1 1-24, g2 25-49, g3 50-74, g4 75-99",
		},
		{
			readyBlocks: []string{"beta"},
			runs:        "beta 0-99",
		},
		// every block down: the split sends nothing
		{
			readyBlocks: []string{},
			runs:        "",
		},
	}
	for _, c := range cases {
		if runs := runsOf(c.readyBlocks...); runs != c.runs {
			t.Errorf("ready %v: runs %q, want %q", c.readyBlocks, runs, c.runs)
		}
	}
}

func TestLbAltSplitReconcileWritesTheExactRulesOfADualStackInterface(t *testing.T) {
	splitInterface := lbAltTestDualStackInterface()
	names := lbAltTestNames(t, splitInterface)
	host := newLbAltTestHost(t, splitInterface)
	writer := newLbAltTestWriter(t, host, t.TempDir())
	generations := lbAltTestGenerations()
	writeLbAltTestBlockChains(t, writer, generations, splitInterface)
	host.setListenRows(lbAltTestListenRows(generations, splitInterface))
	host.clearCommands()

	if err := writer.reconcile(context.Background(), lbAltTestConfig(splitInterface)); err != nil {
		t.Fatal(err)
	}

	// the HMARK rule as iptables-restore receives it, with §2.5's parameters:
	// the hash of the whole source address, spelled as the family's full
	// source prefix, the form iptables lists it in
	for _, family := range []struct {
		restoreName string
		hmarkRule   string
	}{
		{
			restoreName: "iptables-restore",
			hmarkRule:   "-I PREROUTING 1 -d 203.0.113.4/32 -p tcp -m multiport --dports 80,443 -m conntrack --ctstate NEW -m comment --comment warp-main-lba-eno4np3 -j HMARK --hmark-src-prefix 32 --hmark-mod 100 --hmark-offset 0x10000 --hmark-rnd 0x4c42414c\n",
		},
		{
			restoreName: "ip6tables-restore",
			hmarkRule:   "-I PREROUTING 1 -d 2001:db8:ff04::1/128 -p tcp -m multiport --dports 80,443 -m conntrack --ctstate NEW -m comment --comment warp-main-lba-eno4np3 -j HMARK --hmark-src-prefix 128 --hmark-mod 100 --hmark-offset 0x10000 --hmark-rnd 0x4c42414c\n",
		},
	} {
		restores := host.commandsNamed(family.restoreName)
		if len(restores) == 0 || !strings.Contains(restores[0].stdin, family.hmarkRule) {
			t.Fatalf("first %s transaction:\n%v", family.restoreName, restores)
		}
	}

	for _, family := range []struct {
		name          string
		destination   string
		addressBits   string
		bridgeAddress string
	}{
		{name: "ipv4", destination: "203.0.113.4/32", addressBits: "32", bridgeAddress: "198.51.100.4"},
		{name: "ipv6", destination: "2001:db8:ff04::1/128", addressBits: "128", bridgeAddress: "2001:db8:4::1"},
	} {
		hmark := "-m conntrack --ctstate NEW -m comment --comment warp-main-lba-eno4np3 -j HMARK --hmark-src-prefix " + family.addressBits + " --hmark-rnd 0x4c42414c --hmark-mod 100 --hmark-offset 65536"
		wantHmark := []string{
			"-d " + family.destination + " -p tcp -m multiport --dports 80,443 " + hmark,
			"-d " + family.destination + " -p udp -m multiport --dports 53,443,4053 " + hmark,
		}
		requireLbAltRules(t, family.name+" mangle PREROUTING", host.chainRules(family.name, "mangle", "PREROUTING"), wantHmark)
		requireLbAltRules(t, family.name+" mangle OUTPUT", host.chainRules(family.name, "mangle", "OUTPUT"), wantHmark)

		// the entry jumps lead the lb chain, ahead of nginx's DNAT
		requireLbAltRules(t, family.name+" lb chain", host.chainRules(family.name, "nat", names.lbChain), []string{
			"-d " + family.destination + " -p tcp -m multiport --dports 80,443 -m comment --comment warp-main-lba-eno4np3 -j WARP-MAIN-LBA-ENO4NP3",
			"-d " + family.destination + " -p udp -m multiport --dports 53,443,4053 -m comment --comment warp-main-lba-eno4np3 -j WARP-MAIN-LBA-ENO4NP3",
			lbAltTestNginxDnat(strings.TrimSuffix(family.destination, "/"+family.addressBits), family.bridgeAddress),
		})

		requireLbAltRules(t, family.name+" split chain", host.chainRules(family.name, "nat", names.splitChain), lbAltTestSplitRules(t, names, strings.Split(lbAltTestBaseRuns, ", ")...))
		for _, generation := range generations {
			chain, err := names.blockChain(generation.block)
			if err != nil {
				t.Fatal(err)
			}
			requireLbAltRules(t, family.name+" "+chain, host.chainRules(family.name, "nat", chain), generation.blockRules(family.bridgeAddress))
		}
		if host.hasChain(family.name, "nat", names.temporarySplitChain) {
			t.Fatalf("%s temporary split chain left behind", family.name)
		}
	}
}

func TestLbAltSplitReconcileWritesTheExactRulesOfTwoInterfacesOneIpv4Only(t *testing.T) {
	dualStackInterface := lbAltTestDualStackInterface()
	ipv4OnlyInterface := lbAltTestIpv4OnlyInterface()
	host := newLbAltTestHost(t, dualStackInterface, ipv4OnlyInterface)
	writer := newLbAltTestWriter(t, host, t.TempDir())
	generations := lbAltTestGenerations()
	writeLbAltTestBlockChains(t, writer, generations, dualStackInterface, ipv4OnlyInterface)
	host.setListenRows(lbAltTestListenRows(generations, dualStackInterface, ipv4OnlyInterface))

	for _, splitInterface := range []lbAltSplitInterface{dualStackInterface, ipv4OnlyInterface} {
		if err := writer.reconcile(context.Background(), lbAltTestConfig(splitInterface)); err != nil {
			t.Fatal(err)
		}
	}

	dualStackNames := lbAltTestNames(t, dualStackInterface)
	ipv4OnlyNames := lbAltTestNames(t, ipv4OnlyInterface)
	// eno4 in ipv4: its own HMARK rules beside eno4np3's
	hmark := func(comment string) string {
		return "-m conntrack --ctstate NEW -m comment --comment " + comment + " -j HMARK --hmark-src-prefix 32 --hmark-rnd 0x4c42414c --hmark-mod 100 --hmark-offset 65536"
	}
	requireLbAltRules(t, "ipv4 mangle PREROUTING", host.chainRules("ipv4", "mangle", "PREROUTING"), []string{
		// the later reconcile's rules go in at the head
		"-d 203.0.113.5/32 -p tcp -m multiport --dports 80,443 " + hmark("warp-main-lba-eno4"),
		"-d 203.0.113.5/32 -p udp -m multiport --dports 53,443,4053 " + hmark("warp-main-lba-eno4"),
		"-d 203.0.113.4/32 -p tcp -m multiport --dports 80,443 " + hmark("warp-main-lba-eno4np3"),
		"-d 203.0.113.4/32 -p udp -m multiport --dports 53,443,4053 " + hmark("warp-main-lba-eno4np3"),
	})
	requireLbAltRules(t, "ipv4 eno4 lb chain", host.chainRules("ipv4", "nat", ipv4OnlyNames.lbChain), []string{
		"-d 203.0.113.5/32 -p tcp -m multiport --dports 80,443 -m comment --comment warp-main-lba-eno4 -j WARP-MAIN-LBA-ENO4",
		"-d 203.0.113.5/32 -p udp -m multiport --dports 53,443,4053 -m comment --comment warp-main-lba-eno4 -j WARP-MAIN-LBA-ENO4",
		lbAltTestNginxDnat("203.0.113.5", "198.51.100.5"),
	})
	requireLbAltRules(t, "ipv4 eno4 split chain", host.chainRules("ipv4", "nat", ipv4OnlyNames.splitChain), lbAltTestSplitRules(t, ipv4OnlyNames, strings.Split(lbAltTestBaseRuns, ", ")...))
	requireLbAltRules(t, "ipv4 eno4np3 split chain", host.chainRules("ipv4", "nat", dualStackNames.splitChain), lbAltTestSplitRules(t, dualStackNames, strings.Split(lbAltTestBaseRuns, ", ")...))

	// eno4 in ipv6: no split, though its block chains are ready for a public
	// IPv6 address that comes later
	requireLbAltRules(t, "ipv6 eno4 rules", host.rulesMentioning("ipv6", "mangle", "warp-main-lba-eno4 "), []string{})
	requireLbAltRules(t, "ipv6 eno4 entry jumps", host.rulesMentioning("ipv6", "nat", "warp-main-lba-eno4 "), []string{})
	if host.hasChain("ipv6", "nat", ipv4OnlyNames.splitChain) {
		t.Fatal("ipv6 split chain written for an interface with no public IPv6")
	}
	g1Chain, err := ipv4OnlyNames.blockChain("g1")
	if err != nil {
		t.Fatal(err)
	}
	requireLbAltRules(t, "ipv6 eno4 g1 chain", host.chainRules("ipv6", "nat", g1Chain), generations[1].blockRules("2001:db8:5::1"))

	// eno4np3 in ipv6 is complete, and eno4's rules never reach its chains
	requireLbAltRules(t, "ipv6 eno4np3 split chain", host.chainRules("ipv6", "nat", dualStackNames.splitChain), lbAltTestSplitRules(t, dualStackNames, strings.Split(lbAltTestBaseRuns, ", ")...))
	requireLbAltRules(t, "ipv6 eno4np3 lb chain", host.chainRules("ipv6", "nat", dualStackNames.lbChain), []string{
		"-d 2001:db8:ff04::1/128 -p tcp -m multiport --dports 80,443 -m comment --comment warp-main-lba-eno4np3 -j WARP-MAIN-LBA-ENO4NP3",
		"-d 2001:db8:ff04::1/128 -p udp -m multiport --dports 53,443,4053 -m comment --comment warp-main-lba-eno4np3 -j WARP-MAIN-LBA-ENO4NP3",
		lbAltTestNginxDnat("2001:db8:ff04::1", "2001:db8:4::1"),
	})
}

// Reconciled state is listed back in iptables' own form, which the reconcile
// must read as equal to what it wants, or it rewrites on every pass.
func TestLbAltSplitReconcileWritesNothingWhenUnchanged(t *testing.T) {
	dualStackInterface := lbAltTestDualStackInterface()
	ipv4OnlyInterface := lbAltTestIpv4OnlyInterface()
	host := newLbAltTestHost(t, dualStackInterface, ipv4OnlyInterface)
	writer := newLbAltTestWriter(t, host, t.TempDir())
	generations := lbAltTestGenerations()
	writeLbAltTestBlockChains(t, writer, generations, dualStackInterface, ipv4OnlyInterface)
	host.setListenRows(lbAltTestListenRows(generations, dualStackInterface, ipv4OnlyInterface))
	for _, splitInterface := range []lbAltSplitInterface{dualStackInterface, ipv4OnlyInterface} {
		if err := writer.reconcile(context.Background(), lbAltTestConfig(splitInterface)); err != nil {
			t.Fatal(err)
		}
	}
	before := host.listing("ipv4", "nat") + host.listing("ipv4", "mangle") + host.listing("ipv6", "nat") + host.listing("ipv6", "mangle")
	host.clearCommands()

	for _, splitInterface := range []lbAltSplitInterface{dualStackInterface, ipv4OnlyInterface} {
		if err := writer.reconcile(context.Background(), lbAltTestConfig(splitInterface)); err != nil {
			t.Fatal(err)
		}
	}
	writeLbAltTestBlockChains(t, writer, generations, dualStackInterface, ipv4OnlyInterface)

	if restores := host.commandsNamed("iptables-restore", "ip6tables-restore"); len(restores) != 0 {
		t.Fatalf("an unchanged host was written:\n%v", restores)
	}
	after := host.listing("ipv4", "nat") + host.listing("ipv4", "mangle") + host.listing("ipv6", "nat") + host.listing("ipv6", "mangle")
	if before != after {
		t.Fatal("an unchanged reconcile changed the tables")
	}
}

func TestLbAltSplitReconcileMovesALostBlocksRangeAndReturnsIt(t *testing.T) {
	splitInterface := lbAltTestDualStackInterface()
	names := lbAltTestNames(t, splitInterface)
	host := newLbAltTestHost(t, splitInterface)
	writer := newLbAltTestWriter(t, host, t.TempDir())
	generations := lbAltTestGenerations()
	writeLbAltTestBlockChains(t, writer, generations, splitInterface)
	reconcile := func() {
		t.Helper()
		if err := writer.reconcile(context.Background(), lbAltTestConfig(splitInterface)); err != nil {
			t.Fatal(err)
		}
	}
	requireRuns := func(what string, want string) {
		t.Helper()
		for _, family := range []string{"ipv4", "ipv6"} {
			if runs := lbAltTestSplitRuns(t, names, host.chainRules(family, "nat", names.splitChain)); runs != want {
				t.Fatalf("%s %s: runs %s, want %s", what, family, runs, want)
			}
		}
	}

	host.setListenRows(lbAltTestListenRows(generations, splitInterface))
	reconcile()
	requireRuns("every block up", lbAltTestBaseRuns)

	// g2's targets lose their listeners: only its range moves
	movedRuns := "beta 0-0, g1 1-24, beta 25-25, g1 26-33, g3 34-41, g4 42-49, g3 50-74, g4 75-99"
	withoutG2 := slices.DeleteFunc(slices.Clone(generations), func(generation lbAltTestGeneration) bool {
		return generation.block == "g2"
	})
	host.setListenRows(lbAltTestListenRows(withoutG2, splitInterface))
	reconcile()
	requireRuns("g2 without listeners", movedRuns)

	// g2 listens again: its range goes back
	host.setListenRows(lbAltTestListenRows(generations, splitInterface))
	reconcile()
	requireRuns("g2 back", lbAltTestBaseRuns)

	// a block with no chain at all is lost the same way
	g3Chain, err := names.blockChain("g3")
	if err != nil {
		t.Fatal(err)
	}
	freshHost := newLbAltTestHost(t, splitInterface)
	freshWriter := newLbAltTestWriter(t, freshHost, t.TempDir())
	withoutG3 := slices.DeleteFunc(slices.Clone(generations), func(generation lbAltTestGeneration) bool {
		return generation.block == "g3"
	})
	writeLbAltTestBlockChains(t, freshWriter, withoutG3, splitInterface)
	freshHost.setListenRows(lbAltTestListenRows(generations, splitInterface))
	if err := freshWriter.reconcile(context.Background(), lbAltTestConfig(splitInterface)); err != nil {
		t.Fatal(err)
	}
	if freshHost.hasChain("ipv4", "nat", g3Chain) {
		t.Fatal("g3's chain exists")
	}
	// g3's 50-74 go to beta 1, g1 8, g2 8 and g4 8; g4's run joins its own
	if runs := lbAltTestSplitRuns(t, names, freshHost.chainRules("ipv4", "nat", names.splitChain)); runs != "beta 0-0, g1 1-24, g2 25-49, beta 50-50, g1 51-58, g2 59-66, g4 67-99" {
		t.Fatalf("runs without g3's chain: %s", runs)
	}
}

func TestLbAltSplitReconcileSendsNothingWhenEveryBlockIsDown(t *testing.T) {
	splitInterface := lbAltTestDualStackInterface()
	names := lbAltTestNames(t, splitInterface)
	host := newLbAltTestHost(t, splitInterface)
	writer := newLbAltTestWriter(t, host, t.TempDir())
	generations := lbAltTestGenerations()
	writeLbAltTestBlockChains(t, writer, generations, splitInterface)
	host.setListenRows(lbAltTestListenRows(generations, splitInterface))
	if err := writer.reconcile(context.Background(), lbAltTestConfig(splitInterface)); err != nil {
		t.Fatal(err)
	}

	host.setListenRows("")
	err := writer.reconcile(context.Background(), lbAltTestConfig(splitInterface))
	if !errors.Is(err, errLbAltSplitNoReadyBlock) {
		t.Fatalf("reconcile with every block down: %v", err)
	}
	for _, family := range []string{"ipv4", "ipv6"} {
		if !host.hasChain(family, "nat", names.splitChain) {
			t.Fatalf("%s split chain removed", family)
		}
		requireLbAltRules(t, family+" split chain", host.chainRules(family, "nat", names.splitChain), []string{})
		// the entry jumps still lead to the empty split, so no flow falls
		// through to a stale target
		if rules := host.chainRules(family, "nat", names.lbChain); !strings.HasSuffix(rules[0], "-j WARP-MAIN-LBA-ENO4NP3") {
			t.Fatalf("%s lb chain %v", family, rules)
		}
	}
}

// A block of weight 0 takes no bucket, so its being ready does not make the
// split send anywhere.
func TestLbAltSplitReconcileCountsOnlyBlocksThatTakeBuckets(t *testing.T) {
	splitInterface := lbAltTestDualStackInterface()
	names := lbAltTestNames(t, splitInterface)
	host := newLbAltTestHost(t, splitInterface)
	writer := newLbAltTestWriter(t, host, t.TempDir())
	idleBlock := lbAltTestGeneration{
		block:      "g5",
		httpPort:   7206,
		tlsPort:    7236,
		whodisPort: 7266,
	}
	writeLbAltTestBlockChains(t, writer, append(lbAltTestGenerations(), idleBlock), splitInterface)
	// only the weight-0 block listens
	host.setListenRows(lbAltTestListenRows([]lbAltTestGeneration{idleBlock}, splitInterface))
	config := lbAltTestConfig(splitInterface)
	config.blockWeights = append(config.blockWeights, services.BlockWeight{Block: "g5", Weight: 0})

	err := writer.reconcile(context.Background(), config)
	if !errors.Is(err, errLbAltSplitNoReadyBlock) {
		t.Fatalf("reconcile with only a weight-0 block ready: %v", err)
	}
	requireLbAltRules(t, "ipv4 split chain", host.chainRules("ipv4", "nat", names.splitChain), []string{})
}

// A block chain left pointing at an address that is not the interface's bridge
// address, as after its docker network was recreated, is not ready, even when
// the block listens there.
func TestLbAltSplitReconcileNeedsTargetsOnTheInterfacesOwnBridge(t *testing.T) {
	dualStackInterface := lbAltTestDualStackInterface()
	ipv4OnlyInterface := lbAltTestIpv4OnlyInterface()
	names := lbAltTestNames(t, dualStackInterface)
	host := newLbAltTestHost(t, dualStackInterface, ipv4OnlyInterface)
	writer := newLbAltTestWriter(t, host, t.TempDir())
	generations := lbAltTestGenerations()
	withoutG2 := slices.DeleteFunc(slices.Clone(generations), func(generation lbAltTestGeneration) bool {
		return generation.block == "g2"
	})
	writeLbAltTestBlockChains(t, writer, withoutG2, dualStackInterface)
	// g2's eno4np3 chain targets eno4's bridge, where g2 listens too
	otherBridgeInterface := dualStackInterface
	otherBridgeInterface.bridgeIpv4 = ipv4OnlyInterface.bridgeIpv4
	otherBridgeInterface.bridgeIpv6 = ipv4OnlyInterface.bridgeIpv6
	writeLbAltTestBlockChains(t, writer, generations[2:3], otherBridgeInterface)
	host.setListenRows(lbAltTestListenRows(generations, dualStackInterface, ipv4OnlyInterface))

	if err := writer.reconcile(context.Background(), lbAltTestConfig(dualStackInterface)); err != nil {
		t.Fatal(err)
	}
	for _, family := range []string{"ipv4", "ipv6"} {
		if runs := lbAltTestSplitRuns(t, names, host.chainRules(family, "nat", names.splitChain)); runs != "beta 0-0, g1 1-24, beta 25-25, g1 26-33, g3 34-41, g4 42-49, g3 50-74, g4 75-99" {
			t.Fatalf("%s runs %s", family, runs)
		}
	}
}

// The jumps never reach a chain that is not complete: after every committed
// transaction, the chain they use holds the old split or the new one.
func TestLbAltSplitReplacementIsBuiltCompleteUnderTheTemporaryName(t *testing.T) {
	splitInterface := lbAltTestDualStackInterface()
	names := lbAltTestNames(t, splitInterface)
	host := newLbAltTestHost(t, splitInterface)
	writer := newLbAltTestWriter(t, host, t.TempDir())
	generations := lbAltTestGenerations()
	writeLbAltTestBlockChains(t, writer, generations, splitInterface)
	host.setListenRows(lbAltTestListenRows(generations, splitInterface))
	if err := writer.reconcile(context.Background(), lbAltTestConfig(splitInterface)); err != nil {
		t.Fatal(err)
	}

	oldRules := lbAltTestSplitRules(t, names, strings.Split(lbAltTestBaseRuns, ", ")...)
	newRules := lbAltTestSplitRules(t, names, "beta 0-0", "g1 1-24", "beta 25-25", "g1 26-33", "g3 34-41", "g4 42-49", "g3 50-74", "g4 75-99")
	// per committed ipv4 nat transaction: the chain the jumps use, whether it
	// holds "old" or "new", and the temporary chain's content
	steps := []string{}
	describe := func(rules []string) string {
		switch {
		case slices.Equal(rules, oldRules):
			return "old"
		case slices.Equal(rules, newRules):
			return "new"
		}
		return fmt.Sprintf("partial(%d)", len(rules))
	}
	host.afterCommitWithLock = func(family string, table string) {
		if family != "ipv4" || table != "nat" {
			return
		}
		lbRules := host.chainRulesWithLock(family, table, names.lbChain)
		jumpTarget := lbRules[0][strings.LastIndex(lbRules[0], " ")+1:]
		temporary := "absent"
		if host.hasChainWithLock(family, table, names.temporarySplitChain) {
			temporary = describe(host.chainRulesWithLock(family, table, names.temporarySplitChain))
		}
		steps = append(steps, fmt.Sprintf("jumps to %s holding %s, temporary %s", jumpTarget, describe(host.chainRulesWithLock(family, table, jumpTarget)), temporary))
	}

	withoutG2 := slices.DeleteFunc(slices.Clone(generations), func(generation lbAltTestGeneration) bool {
		return generation.block == "g2"
	})
	host.setListenRows(lbAltTestListenRows(withoutG2, splitInterface))
	if err := writer.reconcile(context.Background(), lbAltTestConfig(splitInterface)); err != nil {
		t.Fatal(err)
	}
	requireLbAltRules(t, "replacement steps", steps, []string{
		// built complete while the jumps keep the old split
		"jumps to WARP-MAIN-LBA-ENO4NP3 holding old, temporary new",
		// the jumps move to the complete replacement
		"jumps to WARP-MAIN-LBT-ENO4NP3 holding new, temporary new",
		// the stable chain is rebuilt, the jumps move back, the temporary
		// chain is gone
		"jumps to WARP-MAIN-LBA-ENO4NP3 holding new, temporary absent",
	})
}

func TestLbAltSplitReconcileRecoversAnInterruptionBetweenFamilies(t *testing.T) {
	splitInterface := lbAltTestDualStackInterface()
	names := lbAltTestNames(t, splitInterface)
	host := newLbAltTestHost(t, splitInterface)
	writer := newLbAltTestWriter(t, host, t.TempDir())
	generations := lbAltTestGenerations()
	writeLbAltTestBlockChains(t, writer, generations, splitInterface)
	host.setListenRows(lbAltTestListenRows(generations, splitInterface))

	// the worker stops after ipv4 is written: ipv6's first transaction fails
	host.beforeCommand = func(command lbAltCommand) error {
		if command.name == "ip6tables-restore" {
			return errors.New("interrupted")
		}
		return nil
	}
	if err := writer.reconcile(context.Background(), lbAltTestConfig(splitInterface)); err == nil {
		t.Fatal("an interrupted reconcile reported success")
	}
	requireLbAltRules(t, "ipv4 split chain", host.chainRules("ipv4", "nat", names.splitChain), lbAltTestSplitRules(t, names, strings.Split(lbAltTestBaseRuns, ", ")...))
	requireLbAltRules(t, "ipv6 rules after the interruption", host.rulesMentioning("ipv6", "mangle", names.ruleComment), []string{})
	if host.hasChain("ipv6", "nat", names.splitChain) {
		t.Fatal("ipv6 split chain written by the failed transaction")
	}

	// the next run finishes ipv6 and leaves ipv4 alone
	host.beforeCommand = nil
	host.clearCommands()
	if err := writer.reconcile(context.Background(), lbAltTestConfig(splitInterface)); err != nil {
		t.Fatal(err)
	}
	if restores := host.commandsNamed("iptables-restore"); len(restores) != 0 {
		t.Fatalf("the converged ipv4 family was written again: %v", restores)
	}
	requireLbAltRules(t, "ipv6 split chain", host.chainRules("ipv6", "nat", names.splitChain), lbAltTestSplitRules(t, names, strings.Split(lbAltTestBaseRuns, ", ")...))
	if len(host.rulesMentioning("ipv6", "mangle", names.ruleComment)) != 4 {
		t.Fatal("ipv6 HMARK rules missing")
	}
}

// A worker that stops after the jumps moved to the temporary chain leaves the
// flows on a complete replacement; its next run rebuilds the stable chain and
// moves them back.
func TestLbAltSplitReconcileRecoversAReplacementInterruptedAfterItsSwitch(t *testing.T) {
	splitInterface := lbAltTestDualStackInterface()
	names := lbAltTestNames(t, splitInterface)
	host := newLbAltTestHost(t, splitInterface)
	writer := newLbAltTestWriter(t, host, t.TempDir())
	generations := lbAltTestGenerations()
	writeLbAltTestBlockChains(t, writer, generations, splitInterface)
	host.setListenRows(lbAltTestListenRows(generations, splitInterface))
	if err := writer.reconcile(context.Background(), lbAltTestConfig(splitInterface)); err != nil {
		t.Fatal(err)
	}

	natTransactions := 0
	host.beforeCommand = func(command lbAltCommand) error {
		if command.name == "iptables-restore" && strings.HasPrefix(command.stdin, "*nat") {
			natTransactions += 1
			// the third: rebuilding the stable chain after the switch
			if natTransactions == 3 {
				return errors.New("interrupted")
			}
		}
		return nil
	}
	withoutG2 := slices.DeleteFunc(slices.Clone(generations), func(generation lbAltTestGeneration) bool {
		return generation.block == "g2"
	})
	host.setListenRows(lbAltTestListenRows(withoutG2, splitInterface))
	if err := writer.reconcile(context.Background(), lbAltTestConfig(splitInterface)); err == nil {
		t.Fatal("an interrupted reconcile reported success")
	}
	newRuns := "beta 0-0, g1 1-24, beta 25-25, g1 26-33, g3 34-41, g4 42-49, g3 50-74, g4 75-99"
	lbRules := host.chainRules("ipv4", "nat", names.lbChain)
	if !strings.HasSuffix(lbRules[0], "-j "+names.temporarySplitChain) {
		t.Fatalf("after the interruption the jumps go to %s", lbRules[0])
	}
	if runs := lbAltTestSplitRuns(t, names, host.chainRules("ipv4", "nat", names.temporarySplitChain)); runs != newRuns {
		t.Fatalf("temporary chain %s", runs)
	}

	host.beforeCommand = nil
	if err := writer.reconcile(context.Background(), lbAltTestConfig(splitInterface)); err != nil {
		t.Fatal(err)
	}
	lbRules = host.chainRules("ipv4", "nat", names.lbChain)
	if !strings.HasSuffix(lbRules[0], "-j "+names.splitChain) || !strings.HasSuffix(lbRules[1], "-j "+names.splitChain) {
		t.Fatalf("after recovery the jumps go to %v", lbRules[:2])
	}
	if runs := lbAltTestSplitRuns(t, names, host.chainRules("ipv4", "nat", names.splitChain)); runs != newRuns {
		t.Fatalf("split chain %s", runs)
	}
	if host.hasChain("ipv4", "nat", names.temporarySplitChain) {
		t.Fatal("temporary chain left behind")
	}
}

// A worker that stops between building a replacement and moving the jumps to
// it leaves a complete temporary chain nothing uses. When the split chain
// already holds the wanted split at the next run, as when the lost block came
// back in between, that run drops the temporary chain, and the run after it
// writes nothing.
func TestLbAltSplitReconcileDropsAnUnusedReplacementChain(t *testing.T) {
	splitInterface := lbAltTestDualStackInterface()
	names := lbAltTestNames(t, splitInterface)
	host := newLbAltTestHost(t, splitInterface)
	writer := newLbAltTestWriter(t, host, t.TempDir())
	generations := lbAltTestGenerations()
	writeLbAltTestBlockChains(t, writer, generations, splitInterface)
	host.setListenRows(lbAltTestListenRows(generations, splitInterface))
	if err := writer.reconcile(context.Background(), lbAltTestConfig(splitInterface)); err != nil {
		t.Fatal(err)
	}
	baseRules := lbAltTestSplitRules(t, names, strings.Split(lbAltTestBaseRuns, ", ")...)

	natTransactions := 0
	host.beforeCommand = func(command lbAltCommand) error {
		if command.name == "iptables-restore" && strings.HasPrefix(command.stdin, "*nat") {
			natTransactions += 1
			// the second: moving the jumps to the built replacement
			if natTransactions == 2 {
				return errors.New("interrupted")
			}
		}
		return nil
	}
	withoutG2 := slices.DeleteFunc(slices.Clone(generations), func(generation lbAltTestGeneration) bool {
		return generation.block == "g2"
	})
	host.setListenRows(lbAltTestListenRows(withoutG2, splitInterface))
	if err := writer.reconcile(context.Background(), lbAltTestConfig(splitInterface)); err == nil {
		t.Fatal("an interrupted reconcile reported success")
	}
	if !host.hasChain("ipv4", "nat", names.temporarySplitChain) {
		t.Fatal("the interruption left no temporary chain")
	}
	if lbRules := host.chainRules("ipv4", "nat", names.lbChain); !strings.HasSuffix(lbRules[0], "-j "+names.splitChain) {
		t.Fatalf("after the interruption the jumps go to %s", lbRules[0])
	}
	requireLbAltRules(t, "ipv4 split chain after the interruption", host.chainRules("ipv4", "nat", names.splitChain), baseRules)

	host.beforeCommand = nil
	host.setListenRows(lbAltTestListenRows(generations, splitInterface))
	if err := writer.reconcile(context.Background(), lbAltTestConfig(splitInterface)); err != nil {
		t.Fatal(err)
	}
	if host.hasChain("ipv4", "nat", names.temporarySplitChain) {
		t.Fatal("the unused temporary chain was kept")
	}
	requireLbAltRules(t, "ipv4 split chain", host.chainRules("ipv4", "nat", names.splitChain), baseRules)
	lbRules := host.chainRules("ipv4", "nat", names.lbChain)
	if !strings.HasSuffix(lbRules[0], "-j "+names.splitChain) || !strings.HasSuffix(lbRules[1], "-j "+names.splitChain) {
		t.Fatalf("the jumps go to %v", lbRules[:2])
	}

	host.clearCommands()
	if err := writer.reconcile(context.Background(), lbAltTestConfig(splitInterface)); err != nil {
		t.Fatal(err)
	}
	if restores := host.commandsNamed("iptables-restore", "ip6tables-restore"); len(restores) != 0 {
		t.Fatalf("a converged split was written again: %v", restores)
	}
}

// A block worker that writes its chain while the lb unit reconciles waits for
// the host lock: it lists nothing until the reconcile is done, and so never
// acts on a listing the reconcile then changes.
func TestLbAltSplitWritersTakeTurnsOnTheHostLock(t *testing.T) {
	splitInterface := lbAltTestDualStackInterface()
	names := lbAltTestNames(t, splitInterface)
	host := newLbAltTestHost(t, splitInterface)
	lockDirectory := t.TempDir()
	setupWriter := newLbAltTestWriter(t, host, lockDirectory)
	generations := lbAltTestGenerations()
	withoutG2 := slices.DeleteFunc(slices.Clone(generations), func(generation lbAltTestGeneration) bool {
		return generation.block == "g2"
	})
	// g2 has no chain yet
	writeLbAltTestBlockChains(t, setupWriter, withoutG2, splitInterface)
	host.setListenRows(lbAltTestListenRows(generations, splitInterface))

	var commandLogLock sync.Mutex
	commandLog := []string{}
	loggingWriter := func(writerName string) *lbAltSplitWriter {
		writer := newLbAltTestWriter(t, host, lockDirectory)
		writer.run = func(ctx context.Context, command lbAltCommand) (commandOutput, error) {
			func() {
				commandLogLock.Lock()
				defer commandLogLock.Unlock()
				commandLog = append(commandLog, writerName)
			}()
			return host.run(ctx, command)
		}
		return writer
	}
	lbWriter := loggingWriter("lb")
	blockWriter := loggingWriter("g2")
	blockWriterWaiting := make(chan struct{})
	blockWriter.lockBusy = func() {
		close(blockWriterWaiting)
	}

	lbWriterWriting := make(chan struct{})
	releaseLbWriter := make(chan struct{})
	var holdOnce sync.Once
	host.beforeCommand = func(command lbAltCommand) error {
		if command.name == "iptables-restore" {
			holdOnce.Do(func() {
				close(lbWriterWriting)
				<-releaseLbWriter
			})
		}
		return nil
	}

	lbDone := make(chan error, 1)
	go func() {
		lbDone <- lbWriter.reconcile(context.Background(), lbAltTestConfig(splitInterface))
	}()
	<-lbWriterWriting
	blockDone := make(chan error, 1)
	go func() {
		blockDone <- blockWriter.writeBlockChains(context.Background(), lbAltTestEnv, "g2", []lbAltSplitInterface{splitInterface}, generations[2].targets())
	}()
	select {
	case <-blockWriterWaiting:
	case err := <-blockDone:
		close(releaseLbWriter)
		<-lbDone
		t.Fatalf("the block writer finished while the lb unit held the lock: %v", err)
	}
	func() {
		commandLogLock.Lock()
		defer commandLogLock.Unlock()
		if slices.Contains(commandLog, "g2") {
			t.Errorf("the block writer ran a command while the lb unit held the lock: %v", commandLog)
		}
	}()

	close(releaseLbWriter)
	if err := <-lbDone; err != nil {
		t.Fatal(err)
	}
	if err := <-blockDone; err != nil {
		t.Fatal(err)
	}
	lastLbCommand := slices.Index(commandLog, "g2") - 1
	if lastLbCommand < 0 || slices.Contains(commandLog[lastLbCommand+1:], "lb") {
		t.Fatalf("the writers' commands interleaved: %v", commandLog)
	}

	// the reconcile ran without g2; the next one, after g2's chain, gives its
	// range back
	if err := lbWriter.reconcile(context.Background(), lbAltTestConfig(splitInterface)); err != nil {
		t.Fatal(err)
	}
	if runs := lbAltTestSplitRuns(t, names, host.chainRules("ipv4", "nat", names.splitChain)); runs != lbAltTestBaseRuns {
		t.Fatalf("runs %s", runs)
	}
}

func TestLbAltSplitRemovalLeavesNothingForTheInterface(t *testing.T) {
	dualStackInterface := lbAltTestDualStackInterface()
	ipv4OnlyInterface := lbAltTestIpv4OnlyInterface()
	host := newLbAltTestHost(t, dualStackInterface, ipv4OnlyInterface)
	writer := newLbAltTestWriter(t, host, t.TempDir())
	generations := lbAltTestGenerations()
	writeLbAltTestBlockChains(t, writer, generations, dualStackInterface, ipv4OnlyInterface)
	host.setListenRows(lbAltTestListenRows(generations, dualStackInterface, ipv4OnlyInterface))
	for _, splitInterface := range []lbAltSplitInterface{dualStackInterface, ipv4OnlyInterface} {
		if err := writer.reconcile(context.Background(), lbAltTestConfig(splitInterface)); err != nil {
			t.Fatal(err)
		}
	}
	dualStackNames := lbAltTestNames(t, dualStackInterface)
	ipv4OnlyNames := lbAltTestNames(t, ipv4OnlyInterface)
	// leave a temporary chain behind too, as an interrupted replacement does
	host.addChain("ipv4", "nat", ipv4OnlyNames.temporarySplitChain)
	host.addChain("ipv6", "nat", dualStackNames.temporarySplitChain)
	eno4np3State := func() []string {
		state := []string{}
		for _, family := range []string{"ipv4", "ipv6"} {
			for _, table := range []string{"mangle", "nat"} {
				state = append(state, host.rulesMentioning(family, table, dualStackNames.ruleComment+" ")...)
			}
			for _, chain := range host.chainsWithPrefix(family, "nat", dualStackNames.splitChain) {
				state = append(state, chain)
				state = append(state, host.chainRules(family, "nat", chain)...)
			}
			state = append(state, fmt.Sprintf("%s temporary chain %t", family, host.hasChain(family, "nat", dualStackNames.temporarySplitChain)))
		}
		return state
	}
	eno4np3Before := eno4np3State()
	// eno4's chains: its split chain, its temporary chain and its block chains
	eno4Chains := func(family string) []string {
		chains := []string{}
		for _, prefix := range []string{ipv4OnlyNames.splitChain, ipv4OnlyNames.temporarySplitChain} {
			for _, chain := range host.chainsWithPrefix(family, "nat", prefix) {
				if chain == prefix || strings.HasPrefix(chain, prefix+"-") {
					chains = append(chains, chain)
				}
			}
		}
		return chains
	}
	if len(eno4Chains("ipv4")) != 7 || len(eno4Chains("ipv6")) != 5 {
		t.Fatalf("eno4 chains before the removal: %v %v", eno4Chains("ipv4"), eno4Chains("ipv6"))
	}

	// nginx's DNAT is back in eno4's lb chain; the rollback removes the rest
	if err := writer.remove(context.Background(), lbAltTestEnv, ipv4OnlyInterface.name); err != nil {
		t.Fatal(err)
	}
	for _, family := range []string{"ipv4", "ipv6"} {
		for _, table := range []string{"mangle", "nat"} {
			requireLbAltRules(t, family+" "+table+" rules of eno4", host.rulesMentioning(family, table, ipv4OnlyNames.ruleComment+" "), []string{})
		}
		requireLbAltRules(t, family+" chains of eno4", eno4Chains(family), []string{})
	}
	// the lb chain is the lb worker's, and keeps nginx's DNAT
	requireLbAltRules(t, "ipv4 eno4 lb chain", host.chainRules("ipv4", "nat", ipv4OnlyNames.lbChain), []string{
		lbAltTestNginxDnat("203.0.113.5", "198.51.100.5"),
	})
	// eno4np3, whose name eno4's is a prefix of, is untouched
	if eno4np3After := eno4np3State(); !slices.Equal(eno4np3Before, eno4np3After) {
		t.Fatalf("eno4np3 changed:\n%v\n%v", eno4np3Before, eno4np3After)
	}

	host.clearCommands()
	if err := writer.remove(context.Background(), lbAltTestEnv, ipv4OnlyInterface.name); err != nil {
		t.Fatal(err)
	}
	if restores := host.commandsNamed("iptables-restore", "ip6tables-restore"); len(restores) != 0 {
		t.Fatalf("a second removal wrote: %v", restores)
	}
}

func TestLbAltSplitRemovalCompletesAfterAnInterruption(t *testing.T) {
	splitInterface := lbAltTestDualStackInterface()
	names := lbAltTestNames(t, splitInterface)
	host := newLbAltTestHost(t, splitInterface)
	writer := newLbAltTestWriter(t, host, t.TempDir())
	generations := lbAltTestGenerations()
	writeLbAltTestBlockChains(t, writer, generations, splitInterface)
	host.setListenRows(lbAltTestListenRows(generations, splitInterface))
	if err := writer.reconcile(context.Background(), lbAltTestConfig(splitInterface)); err != nil {
		t.Fatal(err)
	}

	// the worker stops after ipv4's nat transaction
	host.beforeCommand = func(command lbAltCommand) error {
		if command.name == "iptables-restore" && strings.HasPrefix(command.stdin, "*mangle") {
			return errors.New("interrupted")
		}
		return nil
	}
	if err := writer.remove(context.Background(), lbAltTestEnv, splitInterface.name); err == nil {
		t.Fatal("an interrupted removal reported success")
	}
	if host.hasChain("ipv4", "nat", names.splitChain) || len(host.rulesMentioning("ipv4", "mangle", names.ruleComment)) != 4 {
		t.Fatal("the interruption did not leave ipv4's HMARK rules behind its nat removal")
	}

	host.beforeCommand = nil
	if err := writer.remove(context.Background(), lbAltTestEnv, splitInterface.name); err != nil {
		t.Fatal(err)
	}
	for _, family := range []string{"ipv4", "ipv6"} {
		for _, table := range []string{"mangle", "nat"} {
			requireLbAltRules(t, family+" "+table, host.rulesMentioning(family, table, names.ruleComment), []string{})
		}
		if chains := host.chainsWithPrefix(family, "nat", names.splitChain); len(chains) != 0 {
			t.Fatalf("%s chains left: %v", family, chains)
		}
	}
}

// A block chain is never seen half written or mixing generations: after every
// committed transaction, each chain the split uses holds a complete target
// set of one generation, and a failed write leaves the last one.
func TestLbAltBlockChainsAreCompleteWhenTheyReplaceThePreviousGeneration(t *testing.T) {
	dualStackInterface := lbAltTestDualStackInterface()
	ipv4OnlyInterface := lbAltTestIpv4OnlyInterface()
	host := newLbAltTestHost(t, dualStackInterface, ipv4OnlyInterface)
	writer := newLbAltTestWriter(t, host, t.TempDir())
	generations := lbAltTestGenerations()
	writeLbAltTestBlockChains(t, writer, generations, dualStackInterface, ipv4OnlyInterface)
	nextG1 := lbAltTestGeneration{
		block:      "g1",
		httpPort:   7212,
		tlsPort:    7242,
		whodisPort: 7272,
	}
	host.setListenRows(lbAltTestListenRows(append(slices.Clone(generations), nextG1), dualStackInterface, ipv4OnlyInterface))
	for _, splitInterface := range []lbAltSplitInterface{dualStackInterface, ipv4OnlyInterface} {
		if err := writer.reconcile(context.Background(), lbAltTestConfig(splitInterface)); err != nil {
			t.Fatal(err)
		}
	}

	// per committed nat transaction and chain the split uses: which g1
	// generation it holds, or "incomplete"
	seen := map[string][]string{}
	g1Chains := map[string]string{}
	for _, splitInterface := range []lbAltSplitInterface{dualStackInterface, ipv4OnlyInterface} {
		chain, err := lbAltTestNames(t, splitInterface).blockChain("g1")
		if err != nil {
			t.Fatal(err)
		}
		g1Chains[chain] = splitInterface.bridgeIpv4
	}
	host.afterCommitWithLock = func(family string, table string) {
		if family != "ipv4" || table != "nat" {
			return
		}
		for chain, bridgeAddress := range g1Chains {
			rules := host.chainRulesWithLock(family, table, chain)
			state := "incomplete"
			switch {
			case slices.Equal(rules, generations[1].blockRules(bridgeAddress)):
				state = "first"
			case slices.Equal(rules, nextG1.blockRules(bridgeAddress)):
				state = "next"
			}
			seen[chain] = append(seen[chain], state)
		}
	}

	// a failed write leaves the first generation's targets
	host.beforeCommand = func(command lbAltCommand) error {
		if strings.HasSuffix(command.name, "-restore") {
			return errors.New("refused")
		}
		return nil
	}
	if err := writer.writeBlockChains(context.Background(), lbAltTestEnv, "g1", []lbAltSplitInterface{dualStackInterface, ipv4OnlyInterface}, nextG1.targets()); err == nil {
		t.Fatal("a refused write reported success")
	}
	for chain, bridgeAddress := range g1Chains {
		requireLbAltRules(t, chain+" after a refused write", host.chainRules("ipv4", "nat", chain), generations[1].blockRules(bridgeAddress))
	}

	host.beforeCommand = nil
	if err := writer.writeBlockChains(context.Background(), lbAltTestEnv, "g1", []lbAltSplitInterface{dualStackInterface, ipv4OnlyInterface}, nextG1.targets()); err != nil {
		t.Fatal(err)
	}
	for chain, bridgeAddress := range g1Chains {
		if !slices.Equal(seen[chain], []string{"next"}) {
			t.Fatalf("%s states %v, want the next generation in one step", chain, seen[chain])
		}
		requireLbAltRules(t, chain, host.chainRules("ipv4", "nat", chain), nextG1.blockRules(bridgeAddress))
	}
	dualStackG1Chain, err := lbAltTestNames(t, dualStackInterface).blockChain("g1")
	if err != nil {
		t.Fatal(err)
	}
	requireLbAltRules(t, "ipv6 "+dualStackG1Chain, host.chainRules("ipv6", "nat", dualStackG1Chain), nextG1.blockRules("2001:db8:4::1"))

	// g1's next generation is ready, so the split keeps its range: the
	// reconcile after the switch writes nothing
	host.afterCommitWithLock = nil
	host.clearCommands()
	for _, splitInterface := range []lbAltSplitInterface{dualStackInterface, ipv4OnlyInterface} {
		if err := writer.reconcile(context.Background(), lbAltTestConfig(splitInterface)); err != nil {
			t.Fatal(err)
		}
		names := lbAltTestNames(t, splitInterface)
		if runs := lbAltTestSplitRuns(t, names, host.chainRules("ipv4", "nat", names.splitChain)); runs != lbAltTestBaseRuns {
			t.Fatalf("%s runs %s", splitInterface.name, runs)
		}
	}
	if restores := host.commandsNamed("iptables-restore", "ip6tables-restore"); len(restores) != 0 {
		t.Fatalf("the split moved after a block chain switch: %v", restores)
	}
}

func TestLbAltBlockChainsRefuseTargetsThatLeaveAPublicPortOut(t *testing.T) {
	splitInterface := lbAltTestDualStackInterface()
	host := newLbAltTestHost(t, splitInterface)
	writer := newLbAltTestWriter(t, host, t.TempDir())
	targets := lbAltTestGenerations()[1].targets()
	withoutUdp53 := slices.DeleteFunc(slices.Clone(targets), func(target lbAltBlockTarget) bool {
		return target.protocol == "udp" && target.publicPort == 53
	})
	err := writer.writeBlockChains(context.Background(), lbAltTestEnv, "g1", []lbAltSplitInterface{splitInterface}, withoutUdp53)
	if err == nil || !strings.Contains(err.Error(), "udp port 53 has no target") {
		t.Fatalf("incomplete targets: %v", err)
	}
	repeated := append(slices.Clone(targets), lbAltBlockTarget{protocol: "udp", publicPort: 53, internalPort: 7999})
	if err := writer.writeBlockChains(context.Background(), lbAltTestEnv, "g1", []lbAltSplitInterface{splitInterface}, repeated); err == nil {
		t.Fatal("a public port with two targets was accepted")
	}
	if commands := host.commandsNamed("iptables", "ip6tables", "iptables-restore", "ip6tables-restore"); len(commands) != 0 {
		t.Fatalf("a refused write ran %v", commands)
	}
}

// A family the interface loses keeps no split, but its block chains stay, so
// the split comes back whole with the address.
func TestLbAltSplitReconcileDropsTheSplitOfAFamilyTheInterfaceLost(t *testing.T) {
	splitInterface := lbAltTestDualStackInterface()
	names := lbAltTestNames(t, splitInterface)
	host := newLbAltTestHost(t, splitInterface)
	writer := newLbAltTestWriter(t, host, t.TempDir())
	generations := lbAltTestGenerations()
	writeLbAltTestBlockChains(t, writer, generations, splitInterface)
	host.setListenRows(lbAltTestListenRows(generations, splitInterface))
	if err := writer.reconcile(context.Background(), lbAltTestConfig(splitInterface)); err != nil {
		t.Fatal(err)
	}
	ipv4Before := host.listing("ipv4", "nat") + host.listing("ipv4", "mangle")

	withoutIpv6 := splitInterface
	withoutIpv6.publicIpv6 = ""
	if err := writer.reconcile(context.Background(), lbAltTestConfig(withoutIpv6)); err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"mangle", "nat"} {
		requireLbAltRules(t, "ipv6 "+table, host.rulesMentioning("ipv6", table, names.ruleComment), []string{})
	}
	if host.hasChain("ipv6", "nat", names.splitChain) {
		t.Fatal("ipv6 split chain kept")
	}
	if blockChains := host.chainsWithPrefix("ipv6", "nat", names.blockChainPrefix); len(blockChains) != 5 {
		t.Fatalf("ipv6 block chains %v", blockChains)
	}
	if ipv4After := host.listing("ipv4", "nat") + host.listing("ipv4", "mangle"); ipv4After != ipv4Before {
		t.Fatal("ipv4 changed")
	}

	if err := writer.reconcile(context.Background(), lbAltTestConfig(splitInterface)); err != nil {
		t.Fatal(err)
	}
	if runs := lbAltTestSplitRuns(t, names, host.chainRules("ipv6", "nat", names.splitChain)); runs != lbAltTestBaseRuns {
		t.Fatalf("ipv6 runs %s", runs)
	}
}

// An nginx deploy inserts its DNAT at the head of the lb chain. While the
// interface is lb_alt, the reconcile puts the entry jumps back in front of it.
func TestLbAltSplitReconcileKeepsTheEntryJumpsAheadOfNginx(t *testing.T) {
	splitInterface := lbAltTestDualStackInterface()
	names := lbAltTestNames(t, splitInterface)
	host := newLbAltTestHost(t, splitInterface)
	writer := newLbAltTestWriter(t, host, t.TempDir())
	generations := lbAltTestGenerations()
	writeLbAltTestBlockChains(t, writer, generations, splitInterface)
	host.setListenRows(lbAltTestListenRows(generations, splitInterface))
	if err := writer.reconcile(context.Background(), lbAltTestConfig(splitInterface)); err != nil {
		t.Fatal(err)
	}
	nginxDnat := lbAltTestNginxDnat(splitInterface.publicIpv4, splitInterface.bridgeIpv4)
	host.insertRule(t, "ipv4", "nat", names.lbChain, 0, nginxDnat)

	if err := writer.reconcile(context.Background(), lbAltTestConfig(splitInterface)); err != nil {
		t.Fatal(err)
	}
	requireLbAltRules(t, "ipv4 lb chain", host.chainRules("ipv4", "nat", names.lbChain), []string{
		"-d 203.0.113.4/32 -p tcp -m multiport --dports 80,443 -m comment --comment warp-main-lba-eno4np3 -j WARP-MAIN-LBA-ENO4NP3",
		"-d 203.0.113.4/32 -p udp -m multiport --dports 53,443,4053 -m comment --comment warp-main-lba-eno4np3 -j WARP-MAIN-LBA-ENO4NP3",
		nginxDnat,
		nginxDnat,
	})
}

// A new public address or port list rewrites the HMARK rules, deleting the old
// ones by the form iptables lists them in. In IPv4 that form deletes only a
// rule added as the full source prefix, never one added as the tuple, which
// stores another mask: the fake host compares what each rule stored, as
// iptables does.
func TestLbAltSplitReconcileRewritesTheHmarkRulesForANewAddressAndPorts(t *testing.T) {
	splitInterface := lbAltTestDualStackInterface()
	names := lbAltTestNames(t, splitInterface)
	host := newLbAltTestHost(t, splitInterface)
	writer := newLbAltTestWriter(t, host, t.TempDir())
	generations := lbAltTestGenerations()
	writeLbAltTestBlockChains(t, writer, generations, splitInterface)
	host.setListenRows(lbAltTestListenRows(generations, splitInterface))
	if err := writer.reconcile(context.Background(), lbAltTestConfig(splitInterface)); err != nil {
		t.Fatal(err)
	}

	// the public IPv4 address moves, and udp 53 is no longer public
	moved := splitInterface
	moved.publicIpv4 = "203.0.113.14"
	moved.publicPorts = map[string][]int{
		"tcp": {80, 443},
		"udp": {443, 4053},
	}
	if err := writer.reconcile(context.Background(), lbAltTestConfig(moved)); err != nil {
		t.Fatal(err)
	}
	for _, family := range []struct {
		name        string
		destination string
		addressBits string
	}{
		{name: "ipv4", destination: "203.0.113.14/32", addressBits: "32"},
		{name: "ipv6", destination: "2001:db8:ff04::1/128", addressBits: "128"},
	} {
		hmark := "-m conntrack --ctstate NEW -m comment --comment warp-main-lba-eno4np3 -j HMARK --hmark-src-prefix " + family.addressBits + " --hmark-rnd 0x4c42414c --hmark-mod 100 --hmark-offset 65536"
		wantHmark := []string{
			"-d " + family.destination + " -p tcp -m multiport --dports 80,443 " + hmark,
			"-d " + family.destination + " -p udp -m multiport --dports 443,4053 " + hmark,
		}
		requireLbAltRules(t, family.name+" mangle PREROUTING", host.chainRules(family.name, "mangle", "PREROUTING"), wantHmark)
		requireLbAltRules(t, family.name+" mangle OUTPUT", host.chainRules(family.name, "mangle", "OUTPUT"), wantHmark)
		// the entry jumps follow the marks
		requireLbAltRules(t, family.name+" entry jumps", host.rulesMentioning(family.name, "nat", names.ruleComment), []string{
			names.lbChain + " -d " + family.destination + " -p tcp -m multiport --dports 80,443 -m comment --comment warp-main-lba-eno4np3 -j WARP-MAIN-LBA-ENO4NP3",
			names.lbChain + " -d " + family.destination + " -p udp -m multiport --dports 443,4053 -m comment --comment warp-main-lba-eno4np3 -j WARP-MAIN-LBA-ENO4NP3",
		})
	}

	host.clearCommands()
	if err := writer.reconcile(context.Background(), lbAltTestConfig(moved)); err != nil {
		t.Fatal(err)
	}
	if restores := host.commandsNamed("iptables-restore", "ip6tables-restore"); len(restores) != 0 {
		t.Fatalf("rewritten rules were written again: %v", restores)
	}
}

// A host's DHCP clients bind sockets to a device, which ss prints with the
// device after the address. The reconcile reads those rows with the rest.
func TestLbAltSplitReconcileReadsDeviceBoundSockets(t *testing.T) {
	splitInterface := lbAltTestDualStackInterface()
	names := lbAltTestNames(t, splitInterface)
	host := newLbAltTestHost(t, splitInterface)
	writer := newLbAltTestWriter(t, host, t.TempDir())
	generations := lbAltTestGenerations()
	writeLbAltTestBlockChains(t, writer, generations, splitInterface)
	host.setListenRows(lbAltTestListenRows(generations, splitInterface) + strings.Join([]string{
		"udp   UNCONN 0      0      [2001:db8:fe::1]%eth0:546      [::]:*",
		"udp   UNCONN 0      0                  *%eth0:68            *:*",
	}, "\n") + "\n")

	if err := writer.reconcile(context.Background(), lbAltTestConfig(splitInterface)); err != nil {
		t.Fatal(err)
	}
	for _, family := range []string{"ipv4", "ipv6"} {
		if runs := lbAltTestSplitRuns(t, names, host.chainRules(family, "nat", names.splitChain)); runs != lbAltTestBaseRuns {
			t.Fatalf("%s runs %s", family, runs)
		}
	}
}

func TestLbAltSplitReconcileRefusesAnInterfaceWithoutItsLbChain(t *testing.T) {
	splitInterface := lbAltTestDualStackInterface()
	host := newFakeLbAltHost()
	writer := newLbAltTestWriter(t, host, t.TempDir())
	err := writer.reconcile(context.Background(), lbAltTestConfig(splitInterface))
	if err == nil || !strings.Contains(err.Error(), "the lb chain WARP-MAIN-LB-ENO4NP3 is missing") {
		t.Fatalf("reconcile without the lb chain: %v", err)
	}
	if restores := host.commandsNamed("iptables-restore", "ip6tables-restore"); len(restores) != 0 {
		t.Fatalf("wrote without the lb chain: %v", restores)
	}
}

// The forms iptables lists rules in compare equal to the forms the writers
// add them in.
func TestLbAltSplitRuleKeysMatchTheListedForms(t *testing.T) {
	cases := []struct {
		added  string
		listed string
	}{
		// the HMARK rule as iptables 1.8.10 lists it (M7 on edge-4)
		{
			added:  "-d 203.0.113.4/32 -p tcp -m multiport --dports 80,443 -m conntrack --ctstate NEW -m comment --comment warp-main-lba-eno4np3 -j HMARK --hmark-src-prefix 32 --hmark-mod 100 --hmark-offset 0x10000 --hmark-rnd 0x4c42414c",
			listed: `-d 203.0.113.4/32 -p tcp -m multiport --dports 80,443 -m conntrack --ctstate NEW -m comment --comment "warp-main-lba-eno4np3" -j HMARK --hmark-src-prefix 32 --hmark-rnd 0x4c42414c --hmark-mod 100 --hmark-offset 65536`,
		},
		{
			added:  "-d 2001:db8:ff04::1/128 -p udp -m multiport --dports 53,443,4053 -m conntrack --ctstate NEW -m comment --comment warp-main-lba-eno4np3 -j HMARK --hmark-src-prefix 128 --hmark-mod 100 --hmark-offset 0x10000 --hmark-rnd 0x4c42414c",
			listed: `-d 2001:db8:ff04::1/128 -p udp -m multiport --dports 53,443,4053 -m state --state NEW -m comment --comment "warp-main-lba-eno4np3" -j HMARK --hmark-src-prefix 128 --hmark-rnd 0x4c42414c --hmark-mod 100 --hmark-offset 65536`,
		},
		{
			added:  "-m mark --mark 0x10005 -j WARP-MAIN-LBA-ENO4NP3-G1",
			listed: "-m mark --mark 0x10005/0xffffffff -j WARP-MAIN-LBA-ENO4NP3-G1",
		},
		{
			added:  "-d 2001:db8:ff04::1 -p udp -m multiport --dports 4053,53,443 -m comment --comment warp-main-lba-eno4np3 -j WARP-MAIN-LBA-ENO4NP3",
			listed: "-d 2001:db8:ff04::1/128 -p 17 -m multiport --dports 53,443,4053 -m comment --comment warp-main-lba-eno4np3 -j WARP-MAIN-LBA-ENO4NP3",
		},
		{
			added:  "-p udp -m udp --dport 443 -j DNAT --to-destination [2001:db8:4::1]:7231",
			listed: "-p udp -m udp --dport 443 -j DNAT --to-destination [2001:db8:4:0::1]:7231",
		},
	}
	for _, c := range cases {
		addedArgs, err := splitIptablesArgs(c.added)
		if err != nil {
			t.Fatal(err)
		}
		listedArgs, err := splitIptablesArgs(c.listed)
		if err != nil {
			t.Fatal(err)
		}
		if parseIptablesRuleKey(addedArgs) != parseIptablesRuleKey(listedArgs) {
			t.Errorf("keys differ:\n%+v\n%+v", parseIptablesRuleKey(addedArgs), parseIptablesRuleKey(listedArgs))
		}
	}
	// a different seed, hash input, mark, target or extra match is a different
	// rule
	for _, pair := range [][2]string{
		{"-j HMARK --hmark-src-prefix 32 --hmark-mod 100 --hmark-offset 0x10000 --hmark-rnd 0x4c42414c", "-j HMARK --hmark-src-prefix 32 --hmark-mod 100 --hmark-offset 0x10000 --hmark-rnd 0x1"},
		{"-j HMARK --hmark-src-prefix 32 --hmark-mod 100 --hmark-offset 0x10000 --hmark-rnd 0x4c42414c", "-j HMARK --hmark-src-prefix 24 --hmark-mod 100 --hmark-offset 0x10000 --hmark-rnd 0x4c42414c"},
		{"-j HMARK --hmark-src-prefix 32 --hmark-mod 100 --hmark-offset 0x10000 --hmark-rnd 0x4c42414c", "-j HMARK --hmark-src-prefix 32 --hmark-dst-prefix 32 --hmark-mod 100 --hmark-offset 0x10000 --hmark-rnd 0x4c42414c"},
		// iptables never lists the tuple, which in IPv4 stores another mask
		{"-j HMARK --hmark-src-prefix 32 --hmark-mod 100 --hmark-offset 0x10000 --hmark-rnd 0x4c42414c", "-j HMARK --hmark-tuple src --hmark-mod 100 --hmark-offset 0x10000 --hmark-rnd 0x4c42414c"},
		{"-m mark --mark 0x10005 -j WARP-MAIN-LBA-ENO4NP3-G1", "-m mark --mark 0x10005/0xff -j WARP-MAIN-LBA-ENO4NP3-G1"},
		{"-m mark --mark 0x10005 -j WARP-MAIN-LBA-ENO4NP3-G1", "-m mark --mark 0x10005 -j WARP-MAIN-LBA-ENO4NP3-G2"},
		{"-d 203.0.113.4/32 -p tcp -j X", "! -d 203.0.113.4/32 -p tcp -j X"},
		{"-p tcp -j X", "-p tcp -m addrtype --dst-type LOCAL -j X"},
	} {
		a, _ := splitIptablesArgs(pair[0])
		b, _ := splitIptablesArgs(pair[1])
		if parseIptablesRuleKey(a) == parseIptablesRuleKey(b) {
			t.Errorf("keys equal: %q and %q", pair[0], pair[1])
		}
	}
}

// A synthetic generation id and route revision.
const (
	lbAltTestGenerationId = "main-connect-g1-2026.11.18-1-1795000000000"
	lbAltTestRevision     = "4c1a7e9fd2b6a0c3e5f7182930a4b5c6d7e8f90112233445566778899aabbccd"
)

func lbAltTestExpectedSockets() []lbAltExpectedSocket {
	expected := []lbAltExpectedSocket{}
	for _, address := range []string{"198.51.100.4", "2001:db8:4::1"} {
		expected = append(expected,
			lbAltExpectedSocket{protocol: "tcp", address: address, port: 7202},
			lbAltExpectedSocket{protocol: "tcp", address: address, port: 7232},
			lbAltExpectedSocket{protocol: "udp", address: address, port: 7232},
			lbAltExpectedSocket{protocol: "udp", address: address, port: 7262},
		)
	}
	return expected
}

// X-UR-Front-Sockets for the expected sockets, sorted, with one socket's counts
// replaced when replaceSocket is set.
func lbAltTestSocketsHeader(replaceSocket string, replaceCounts string) string {
	entries := []string{}
	for _, socket := range lbAltTestExpectedSockets() {
		name := fmt.Sprintf("%s/%s/%d", socket.protocol, socket.address, socket.port)
		counts := "4/4"
		if name == replaceSocket {
			if replaceCounts == "" {
				continue
			}
			counts = replaceCounts
		}
		entries = append(entries, name+"="+counts)
	}
	slices.Sort(entries)
	return strings.Join(entries, ",")
}

func lbAltTestReadyHeader() http.Header {
	header := http.Header{}
	header.Set(lbAltFrontGenerationHeader, lbAltTestGenerationId)
	header.Set(lbAltFrontRouteRevisionHeader, lbAltTestRevision)
	header.Set(lbAltFrontReadyHeader, "1")
	header.Set(lbAltFrontSocketsHeader, lbAltTestSocketsHeader("", ""))
	header.Set(lbAltFrontCertExpiryHeader, "2027-01-15T00:00:00Z")
	return header
}

func TestLbAltReadinessAcceptsOnlyAnExactlyReadyGeneration(t *testing.T) {
	expectedSockets := []lbAltFrontSocket{}
	for _, socket := range lbAltTestExpectedSockets() {
		expectedSockets = append(expectedSockets, lbAltFrontSocket{
			protocol: socket.protocol,
			address:  netip.MustParseAddr(socket.address),
			port:     socket.port,
		})
	}
	withHeader := func(name string, value string) http.Header {
		header := lbAltTestReadyHeader()
		if value == "" {
			header.Del(name)
		} else {
			header.Set(name, value)
		}
		return header
	}
	okBody := `{"version":"2026.11.18-1","config_version":"2026.11.18-2","status":"ok"}`
	cases := []struct {
		what       string
		statusCode int
		body       string
		header     http.Header
		// "" accepts; otherwise the refusal names this
		refusal    string
		definitive bool
	}{
		{what: "ready", statusCode: 200, body: okBody, header: lbAltTestReadyHeader()},
		{what: "draining", statusCode: 200, body: `{"status":"draining"}`, header: lbAltTestReadyHeader(), refusal: "draining", definitive: true},
		{what: "not ready yet", statusCode: 200, body: `{"status":"error not ready: startup"}`, header: lbAltTestReadyHeader(), refusal: "error not ready"},
		{what: "a listener down", statusCode: 503, body: "not ready: QUIC listener down", header: http.Header{}, refusal: "status code 503"},
		{what: "a 2xx that is not 200", statusCode: 204, body: okBody, header: lbAltTestReadyHeader(), refusal: "status code 204"},
		{what: "another generation", statusCode: 200, body: okBody, header: withHeader(lbAltFrontGenerationHeader, "main-connect-g1-2026.11.18-1-1794999999999"), refusal: lbAltFrontGenerationHeader, definitive: true},
		{what: "no generation", statusCode: 200, body: okBody, header: withHeader(lbAltFrontGenerationHeader, ""), refusal: lbAltFrontGenerationHeader},
		{what: "another revision", statusCode: 200, body: okBody, header: withHeader(lbAltFrontRouteRevisionHeader, strings.Repeat("0", 64)), refusal: lbAltFrontRouteRevisionHeader, definitive: true},
		{what: "not ready", statusCode: 200, body: okBody, header: withHeader(lbAltFrontReadyHeader, "0"), refusal: lbAltFrontReadyHeader},
		{what: "a missing socket", statusCode: 200, body: okBody, header: withHeader(lbAltFrontSocketsHeader, lbAltTestSocketsHeader("udp/2001:db8:4::1/7262", "")), refusal: "does not list udp/2001:db8:4::1/7262"},
		{what: "3/4", statusCode: 200, body: okBody, header: withHeader(lbAltFrontSocketsHeader, lbAltTestSocketsHeader("tcp/198.51.100.4/7232", "3/4")), refusal: "tcp/198.51.100.4/7232 is 3/4"},
		{what: "1/1", statusCode: 200, body: okBody, header: withHeader(lbAltFrontSocketsHeader, lbAltTestSocketsHeader("udp/198.51.100.4/7232", "1/1")), refusal: "udp/198.51.100.4/7232 is 1/1"},
		{what: "unreadable sockets", statusCode: 200, body: okBody, header: withHeader(lbAltFrontSocketsHeader, "tcp:198.51.100.4:7202=4/4"), refusal: lbAltFrontSocketsHeader, definitive: true},
		{what: "an extra socket", statusCode: 200, body: okBody, header: withHeader(lbAltFrontSocketsHeader, lbAltTestSocketsHeader("", "")+",tcp/198.51.100.9/7202=4/4")},
		{what: "another text form of an address", statusCode: 200, body: okBody, header: withHeader(lbAltFrontSocketsHeader, strings.ReplaceAll(lbAltTestSocketsHeader("", ""), "2001:db8:4::1", "2001:db8:4:0::1"))},
	}
	for _, c := range cases {
		err := acceptLbAltStatus(c.statusCode, c.header, []byte(c.body), lbAltTestGenerationId, lbAltTestRevision, expectedSockets, 4)
		if c.refusal == "" {
			if err != nil {
				t.Errorf("%s: refused: %v", c.what, err)
			}
			continue
		}
		var refusal *lbAltReadinessRefusal
		if !errors.As(err, &refusal) || !strings.Contains(refusal.reason, c.refusal) {
			t.Errorf("%s: %v, want a refusal naming %q", c.what, err, c.refusal)
			continue
		}
		if refusal.definitive != c.definitive {
			t.Errorf("%s: definitive %t, want %t", c.what, refusal.definitive, c.definitive)
		}
	}
}

// A status server whose answers the test scripts, counting requests.
type lbAltTestStatusServer struct {
	requestCount atomic.Int32
	// answers request n (from 1)
	answer func(n int32, w http.ResponseWriter)
}

func newLbAltTestStatusServer(t *testing.T, answer func(n int32, w http.ResponseWriter)) (*lbAltTestStatusServer, string) {
	statusServer := &lbAltTestStatusServer{answer: answer}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/status" {
			http.NotFound(w, r)
			return
		}
		statusServer.answer(statusServer.requestCount.Add(1), w)
	}))
	t.Cleanup(server.Close)
	return statusServer, server.URL + "/status"
}

func writeLbAltTestStatus(w http.ResponseWriter, header http.Header, status string) {
	for name, values := range header {
		w.Header()[name] = values
	}
	fmt.Fprintf(w, `{"version":"2026.11.18-1","config_version":"2026.11.18-2","status":%q}`, status)
}

func newLbAltTestReadinessPoll() *lbAltReadinessPoll {
	settings := DefaultLbAltSplitSettings()
	settings.ReadinessPollInterval = time.Millisecond
	return newLbAltReadinessPoll(settings)
}

func TestPollLbAltReadinessWaitsForTheGenerationToBeReady(t *testing.T) {
	statusServer, statusUrl := newLbAltTestStatusServer(t, func(n int32, w http.ResponseWriter) {
		header := lbAltTestReadyHeader()
		if n < 3 {
			header.Set(lbAltFrontReadyHeader, "0")
			header.Set(lbAltFrontSocketsHeader, lbAltTestSocketsHeader("udp/198.51.100.4/7232", "3/4"))
		}
		writeLbAltTestStatus(w, header, "ok")
	})
	err := newLbAltTestReadinessPoll().poll(context.Background(), statusUrl, lbAltTestGenerationId, lbAltTestRevision, lbAltTestExpectedSockets(), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if n := statusServer.requestCount.Load(); n != 3 {
		t.Fatalf("%d requests, want 3", n)
	}
}

func TestPollLbAltReadinessRefusesADrainingGenerationAtOnce(t *testing.T) {
	statusServer, statusUrl := newLbAltTestStatusServer(t, func(n int32, w http.ResponseWriter) {
		writeLbAltTestStatus(w, lbAltTestReadyHeader(), "draining")
	})
	err := newLbAltTestReadinessPoll().poll(context.Background(), statusUrl, lbAltTestGenerationId, lbAltTestRevision, lbAltTestExpectedSockets(), time.Minute)
	if err == nil || !strings.Contains(err.Error(), "draining") {
		t.Fatalf("draining candidate: %v", err)
	}
	if n := statusServer.requestCount.Load(); n != 1 {
		t.Fatalf("%d requests, want the first answer to end the poll", n)
	}
}

func TestPollLbAltReadinessReturnsTheLastRefusalAtItsTimeout(t *testing.T) {
	_, statusUrl := newLbAltTestStatusServer(t, func(n int32, w http.ResponseWriter) {
		header := lbAltTestReadyHeader()
		header.Set(lbAltFrontSocketsHeader, lbAltTestSocketsHeader("tcp/2001:db8:4::1/7202", "3/4"))
		writeLbAltTestStatus(w, header, "ok")
	})
	err := newLbAltTestReadinessPoll().poll(context.Background(), statusUrl, lbAltTestGenerationId, lbAltTestRevision, lbAltTestExpectedSockets(), 0)
	if err == nil || !strings.Contains(err.Error(), "not ready within") || !strings.Contains(err.Error(), "tcp/2001:db8:4::1/7202 is 3/4") {
		t.Fatalf("never-ready candidate: %v", err)
	}
}

func TestPollLbAltReadinessStopsWhenItsContextEnds(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	statusServer, statusUrl := newLbAltTestStatusServer(t, func(n int32, w http.ResponseWriter) {
		cancel()
		header := lbAltTestReadyHeader()
		header.Set(lbAltFrontReadyHeader, "0")
		writeLbAltTestStatus(w, header, "ok")
	})
	err := newLbAltTestReadinessPoll().poll(ctx, statusUrl, lbAltTestGenerationId, lbAltTestRevision, lbAltTestExpectedSockets(), time.Hour)
	if err == nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled poll: %v", err)
	}
	if n := statusServer.requestCount.Load(); n != 1 {
		t.Fatalf("%d requests after the cancel", n)
	}
}
