package main

// The lb_alt split (server/LBALT-IMPL.md §2.4, §2.5; LBALT.md D10, D13, D22,
// §4.7). New flows to an lb_alt interface's public address are hashed by
// source address into buckets, and each bucket is DNATed to one connect block
// of the host. Per interface, in each family it has (IPv6 only with a public
// IPv6 address):
//   - mangle PREROUTING, and OUTPUT for local dials, hold one HMARK rule per
//     protocol for the public address and ports, on new flows only, marking
//     0x10000 + bucket. The seed is fixed, so a restart keeps every address in
//     its bucket.
//   - the interface's lb chain, WARP-<ENV>-LB-<IFACE>, starts with one jump
//     per protocol to the split chain, ahead of any DNAT nginx left there.
//   - the split chain, WARP-<ENV>-LBA-<IFACE>, holds one rule per bucket,
//     -m mark --mark 0x100XX -j <block chain>.
//   - each block chain, WARP-<ENV>-LBA-<IFACE>-<BLOCK>, holds only the block's
//     DNATs to <bridge address>:<internal port>.
//
// The rules the split adds to chains it does not own, the HMARK rules and the
// entry jumps, carry a comment naming the env and interface, so a reconcile or
// a rollback finds them again even after an address changed.
//
// Writers. The interface's lb unit writes the HMARK rules, the entry jumps and
// the split chain (reconcileLbAltSplit at start and every 30 s,
// removeLbAltSplit on rollback). A connect block's worker writes only its own
// block chains, once its candidate generation is ready (writeLbAltBlockChains).
// The writers of one env on a host, its lb units and its block workers, take
// one host lock file under WARP_HOME for a whole operation, from listing to
// last write, so none acts on a listing another has since changed. Every
// iptables call waits for the xtables lock (-w).
//
// Transactions. Each change is one iptables-restore --noflush transaction on
// one table of one family, which the kernel applies whole or not at all, so a
// packet never meets half a chain:
//   - a replacement split chain is built complete under its temporary name,
//     WARP-<ENV>-LBT-<IFACE>, before the entry jumps move to it, and the old
//     chain keeps the flows until then. The stable chain is then rebuilt while
//     nothing uses it and the jumps move back, so the steady state always has
//     the stable names;
//   - a block chain is flushed and refilled in one transaction, so the split's
//     jumps keep the previous generation's targets until the new set is
//     complete. The block's worker never edits the split chain, the lb unit's;
//   - the HMARK rules go in before the split is reached, so no flow reaches the
//     split unmarked.
//
// Recovery. Every operation computes the whole wanted state from a fresh
// listing and writes only the difference, so it is idempotent, and a worker
// interrupted between two transactions, or between the IPv4 and IPv6
// families, converges on its next run: a temporary split chain the jumps use
// is rebuilt into the stable one, and one they do not use is dropped.
//
// Buckets. Buckets go to blocks as services.LbAltBucketBlocks assigns them. A
// block is ready in a family when its chain exists, holds a DNAT for every
// public (protocol, port) of the interface to the family's bridge address, and
// each target has a listener. Only an orphaned bucket, one whose block is not
// ready, moves, to the ready blocks by weight, and it goes back once its block
// is ready again. With no ready block the split chain is empty and sends
// nothing anywhere, so the interface fails its Route53 health check.
//
// The first switch. A family whose lb chain still holds nginx's DNAT and no
// entry jump switches only once every block of positive weight is ready
// there; until then the reconcile writes nothing in the family and nginx
// keeps its new flows (errLbAltSplitAwaitsEveryBlock). So the switch sends
// new flows to every block at once (LBALT.md §4.6, D16), never all of them to
// the first block ready, and the lb unit retires nginx only after it. The
// orphan moves above apply once the jumps are in, and to an interface nginx
// never served, as after a reboot.

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode"

	"github.com/urnetwork/warp/services"
)

// iptables target names, so chain names, are at most 28 characters (xtables'
// 29-byte name with its terminating NUL).
const lbAltChainNameLimit = 28

// The ports one multiport match takes (xt_multiport's XT_MULTI_PORTS).
const lbAltMultiportLimit = 15

// The token after the env in the split and block chain names, and the one a
// replacement split chain is built under. Both are three characters, so the
// temporary name fits wherever the stable one does.
const (
	lbAltChainMarker          = "LBA"
	lbAltTemporaryChainMarker = "LBT"
)

// The lock file the lb_alt writers of one env share on a host.
const lbAltHostLockFileFormat = "warpctl-lbalt-%s.lock"

// The service whose blocks write block chains: the lb_alt service, which only
// connect may be (services.LbAltService; LBALT.md D2).
const lbAltBlockService = "connect"

// The comment on the rules the split adds to chains it does not own.
const lbAltRuleCommentFormat = "warp-%s-lba-%s"

// The protocols of the public ports, in rule order.
var lbAltProtocols = [2]string{"tcp", "udp"}

// Env and block names: letters, digits, '_', '.' and '-'.
var lbAltNamePattern = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)

// Interface names: as env and block names, without '-', which would make the
// prefix of the interface's block chains ambiguous.
var lbAltInterfaceNamePattern = regexp.MustCompile(`^[A-Za-z0-9_.]+$`)

// Returned by reconcileLbAltSplit, after it has converged the rules, when a
// family of the interface has no ready block, so its split sends nothing
// anywhere. The lb unit can keep nginx's DNAT behind the entry jumps until a
// block is ready.
var errLbAltSplitNoReadyBlock = errors.New("lb_alt split has no ready block")

// Returned by reconcileLbAltSplit when a family of the interface is still on
// nginx, with nginx's DNAT and no entry jumps in its lb chain, and some block
// of positive weight is not ready there. The split writes nothing in that
// family, so its new flows keep reaching nginx, until every block is ready
// and the switch sends them to all of the blocks at once. The lb unit keeps
// nginx meanwhile.
var errLbAltSplitAwaitsEveryBlock = errors.New("lb_alt split waits for every block before it takes the interface from nginx")

// Tunables of the split writers and of the readiness poll.
type LbAltSplitSettings struct {
	// The directory of the host lock file the lb_alt writers of an env share,
	// warpctl-lbalt-<env>.lock. Empty means WARP_HOME, which the lb units and
	// the connect workers of an env have in common on a host.
	LockDirectory string
	// How long a writer waits for the host lock. Another writer holds it for
	// one listing and a few transactions, about a second. Non-positive waits
	// until the context ends.
	LockTimeout time.Duration
	// How often a waiting writer tries the host lock again. Must be positive.
	LockPollInterval time.Duration
	// Bound on each iptables, iptables-restore and ss process, which also
	// bounds iptables -w's wait for the xtables lock. Non-positive leaves only
	// the context's bound.
	CommandTimeout time.Duration
	// Bound on one readiness request, as for the connect transport poll.
	ReadinessRequestTimeout time.Duration
	// Pause between readiness polls, the worker's version poll interval. Must
	// be positive.
	ReadinessPollInterval time.Duration
	// The most status body bytes read.
	ReadinessBodyByteLimit int64
	// The sockets connect opens per public (address, protocol, port), D10's N.
	// A candidate is accepted only when every expected socket shows this many
	// up of this many expected.
	SocketsPerPort int
}

// The lock and command bounds are generous next to the second an operation
// takes, the readiness values follow the existing candidate polls, and
// SocketsPerPort is the owner's N = 4 (LBALT.md D10).
func DefaultLbAltSplitSettings() *LbAltSplitSettings {
	return &LbAltSplitSettings{
		LockDirectory:           "",
		LockTimeout:             60 * time.Second,
		LockPollInterval:        100 * time.Millisecond,
		CommandTimeout:          60 * time.Second,
		ReadinessRequestTimeout: 5 * time.Second,
		ReadinessPollInterval:   5 * time.Second,
		ReadinessBodyByteLimit:  1024 * 1024,
		SocketsPerPort:          4,
	}
}

// One lb_alt interface as the split sees it. An empty address means the family
// is absent.
type lbAltSplitInterface struct {
	name       string
	publicIpv4 string
	publicIpv6 string
	bridgeIpv4 string
	bridgeIpv6 string
	// services.LbAltPublicPorts: protocol -> public ports
	publicPorts map[string][]int
}

// The lb unit's view of its interface's split.
type lbAltSplitConfig struct {
	env            string
	splitInterface lbAltSplitInterface
	// the lb_alt service's blocks in services.ServiceBlockWeights order
	blockWeights []services.BlockWeight
}

// Reconciles the HMARK rules, the lb chain's entry jumps and the split chain of
// one lb_alt interface, in both families. Run by the lb unit at start and every
// 30 s. Orphaned bucket ranges move to ready blocks by weight; when every block
// of a family is down the split sends nothing, and the error wraps
// errLbAltSplitNoReadyBlock once the rules have converged. A family still on
// nginx switches only with every block ready, and until then the error wraps
// errLbAltSplitAwaitsEveryBlock. A family the interface lacks keeps no split,
// and its block chains stay for when it returns.
func reconcileLbAltSplit(ctx context.Context, config *lbAltSplitConfig) error {
	return newLbAltSplitWriter(DefaultLbAltSplitSettings()).reconcile(ctx, config)
}

// Removes the HMARK rules, entry jumps and split chains of an interface that
// is no longer lb_alt, in both families (rollback, D18). The block chains
// stay: they belong to the connect blocks' workers, and nothing reaches them
// without the split's jumps, so an interface turned lb_alt again finds every
// ready block's chain in place. The caller restores nginx's DNAT first: once
// the entry jumps are gone, new flows take the next rule of the lb chain.
func removeLbAltSplit(ctx context.Context, env string, interfaceName string) error {
	return newLbAltSplitWriter(DefaultLbAltSplitSettings()).remove(ctx, env, interfaceName)
}

// One DNAT a block chain holds: public (protocol, port) to the block's internal
// port on the interface's bridge address.
type lbAltBlockTarget struct {
	protocol     string
	publicPort   int
	internalPort int
}

// Writes the block's chain on every given interface, in each family its bridge
// has, complete before it replaces the previous generation's targets. Called by
// the block worker after pollLbAltReadiness accepts the candidate. Every public
// (protocol, port) of an interface needs a target; an interface with no public
// ports is skipped. A family whose interface has no public address still gets
// its chain, so a public address that comes later finds the block ready.
func writeLbAltBlockChains(ctx context.Context, env string, block string, splitInterfaces []lbAltSplitInterface, targets []lbAltBlockTarget) error {
	return newLbAltSplitWriter(DefaultLbAltSplitSettings()).writeBlockChains(ctx, env, block, splitInterfaces, targets)
}

// One socket a candidate generation must report in X-UR-Front-Sockets.
type lbAltExpectedSocket struct {
	protocol string
	address  string
	port     int
}

// Polls the candidate's private status until it is accepted under §2.4 or the
// timeout passes: 200 with status exactly "ok", X-UR-Front-Ready 1, the
// expected generation and revision, and every expected socket at up == expected
// == SocketsPerPort. A draining candidate, or one that reports another
// generation or revision, is refused at once.
func pollLbAltReadiness(ctx context.Context, statusUrl string, generation string, revision string, expected []lbAltExpectedSocket, timeout time.Duration) error {
	return newLbAltReadinessPoll(DefaultLbAltSplitSettings()).poll(ctx, statusUrl, generation, revision, expected, timeout)
}

// One command a writer runs.
type lbAltCommand struct {
	name string
	args []string
	// the standard input, an iptables-restore transaction
	stdin string
	// whether it needs root
	privileged bool
}

// Runs the lb_alt writers of a host: each operation takes the host lock, lists
// the tables it changes and writes the difference with iptables-restore. A
// writer holds no state between operations, so one is safe to use from
// several goroutines; the host lock serializes them.
type lbAltSplitWriter struct {
	settings *LbAltSplitSettings
	// runs one command and returns its output
	run func(ctx context.Context, command lbAltCommand) (commandOutput, error)
	// called once when another writer holds the host lock, before waiting;
	// tests order a second writer with it
	lockBusy func()
}

// A writer that runs real commands: under sudo when a command needs root and
// warpctl does not run as root. A failed command's error carries its bounded
// stderr, such as the line iptables-restore refused. The commands run through
// runQuiet, which keeps both outputs out of the log and is the hook the
// worker tests fake commands with.
func newLbAltSplitWriter(settings *LbAltSplitSettings) *lbAltSplitWriter {
	run := func(ctx context.Context, command lbAltCommand) (commandOutput, error) {
		name := command.name
		args := command.args
		if command.privileged && os.Geteuid() != 0 {
			args = append([]string{name}, args...)
			name = "sudo"
		}
		cmd := exec.CommandContext(ctx, name, args...)
		if command.stdin != "" {
			cmd.Stdin = strings.NewReader(command.stdin)
		}
		output, err := runQuiet(cmd)
		if err != nil {
			if detail := boundedCommandStderr(output.stderr); detail != "" {
				return output, fmt.Errorf("%s: %w: %s", command.name, err, detail)
			}
			return output, fmt.Errorf("%s: %w", command.name, err)
		}
		return output, nil
	}
	return &lbAltSplitWriter{
		settings: settings,
		run:      run,
		lockBusy: nil,
	}
}

// Takes the env's host lock, waiting while another writer holds it. The
// returned func releases it. An advisory flock belongs to its open file, so
// the lock is released when the file closes, also when the process dies.
func (self *lbAltSplitWriter) lockHost(ctx context.Context, env string) (func(), error) {
	if self.settings.LockPollInterval <= 0 {
		return nil, errors.New("lb_alt host lock: the poll interval must be positive")
	}
	lockDirectory := self.settings.LockDirectory
	if lockDirectory == "" {
		lockDirectory = os.Getenv("WARP_HOME")
		if lockDirectory == "" {
			return nil, errors.New("lb_alt host lock: WARP_HOME is not set")
		}
	}
	lockPath := filepath.Join(lockDirectory, fmt.Sprintf(lbAltHostLockFileFormat, sanitizeHostDrainLockNamePart(env)))
	file, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		return nil, fmt.Errorf("lb_alt host lock: %w", err)
	}

	var deadline time.Time
	if 0 < self.settings.LockTimeout {
		deadline = time.Now().Add(self.settings.LockTimeout)
	}
	busyReported := false
	for {
		err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			return func() {
				file.Close()
			}, nil
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) {
			file.Close()
			return nil, fmt.Errorf("lb_alt host lock: %w", err)
		}
		if !busyReported && self.lockBusy != nil {
			self.lockBusy()
		}
		busyReported = true
		if !deadline.IsZero() && !time.Now().Before(deadline) {
			file.Close()
			return nil, fmt.Errorf("lb_alt host lock not acquired within %s", self.settings.LockTimeout)
		}
		select {
		case <-ctx.Done():
			file.Close()
			return nil, fmt.Errorf("lb_alt host lock: %w", ctx.Err())
		case <-time.After(self.settings.LockPollInterval):
		}
	}
}

// Runs one command within the command timeout.
func (self *lbAltSplitWriter) runCommand(ctx context.Context, command lbAltCommand) (commandOutput, error) {
	if 0 < self.settings.CommandTimeout {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, self.settings.CommandTimeout)
		defer cancel()
	}
	return self.run(ctx, command)
}

// Lists the host's listening sockets (readListenSockets).
func (self *lbAltSplitWriter) listSockets(ctx context.Context) (*listenSockets, error) {
	return readListenSockets(func(name string, args []string) (commandOutput, error) {
		return self.runCommand(ctx, lbAltCommand{
			name:       name,
			args:       args,
			stdin:      "",
			privileged: false,
		})
	})
}

// Lists one table of one family with `iptables -S`: its -P and -N lines name
// the table's chains, and its -A lines are the rules.
func (self *lbAltSplitWriter) listTable(ctx context.Context, family *lbAltFamily, table string) (*iptablesListing, error) {
	output, err := self.runCommand(ctx, lbAltCommand{
		name:       family.iptables,
		args:       []string{"-w", "-t", table, "-S"},
		stdin:      "",
		privileged: true,
	})
	if err != nil {
		return nil, fmt.Errorf("list %s %s: %w", family.name, table, err)
	}
	listing := &iptablesListing{
		listedChains: map[string]bool{},
		listedRules:  []*iptablesListedRule{},
	}
	for lineIndex, line := range strings.Split(string(output.stdout), "\n") {
		args, err := splitIptablesArgs(line)
		if err != nil {
			return nil, fmt.Errorf("list %s %s: listing line %d: %w", family.name, table, lineIndex+1, err)
		}
		if len(args) < 2 {
			continue
		}
		switch args[0] {
		case "-P", "-N":
			listing.listedChains[args[1]] = true
		case "-A":
			listing.listedRules = append(listing.listedRules, &iptablesListedRule{
				chain: args[1],
				spec:  args[2:],
				key:   parseIptablesRuleKey(args[2:]),
			})
		}
	}
	return listing, nil
}

// Applies one transaction to one family, and logs what it did.
func (self *lbAltSplitWriter) apply(ctx context.Context, family *lbAltFamily, restore *iptablesRestore, subject string, what string) error {
	if restore.empty() {
		return nil
	}
	_, err := self.runCommand(ctx, lbAltCommand{
		name:       family.iptablesRestore,
		args:       []string{"-w", "--noflush"},
		stdin:      restore.input(),
		privileged: true,
	})
	if err != nil {
		return fmt.Errorf("lb_alt %s %s: %s: %w", subject, family.name, what, err)
	}
	Err.Printf("lb_alt %s %s: %s (%d lines)\n", subject, family.name, what, len(restore.lines))
	return nil
}

// One address family of an interface.
type lbAltFamily struct {
	name            string
	iptables        string
	iptablesRestore string
	// the prefix length of one address
	addressBits int
	// the interface's public address; invalid when the family has none
	publicAddress netip.Addr
	// the interface bridge's address; invalid when the family has none
	bridgeAddress netip.Addr
}

// Whether the interface splits this family's flows: it needs a public address
// to match and a bridge address to DNAT to.
func (self *lbAltFamily) splits() bool {
	return self.publicAddress.IsValid() && self.bridgeAddress.IsValid()
}

// IPv4 and IPv6, with their commands and no addresses.
func newLbAltFamilyPair() []*lbAltFamily {
	return []*lbAltFamily{
		&lbAltFamily{
			name:            "ipv4",
			iptables:        "iptables",
			iptablesRestore: "iptables-restore",
			addressBits:     32,
			publicAddress:   netip.Addr{},
			bridgeAddress:   netip.Addr{},
		},
		&lbAltFamily{
			name:            "ipv6",
			iptables:        "ip6tables",
			iptablesRestore: "ip6tables-restore",
			addressBits:     128,
			publicAddress:   netip.Addr{},
			bridgeAddress:   netip.Addr{},
		},
	}
}

// IPv4 and IPv6 with the interface's addresses. An address must be a plain
// address of its family.
func newLbAltFamilies(splitInterface *lbAltSplitInterface) ([]*lbAltFamily, error) {
	families := newLbAltFamilyPair()
	parse := func(family *lbAltFamily, text string, what string) (netip.Addr, error) {
		if text == "" {
			return netip.Addr{}, nil
		}
		address, err := netip.ParseAddr(text)
		if err != nil || address.Zone() != "" || address.BitLen() != family.addressBits || address.Is4In6() {
			return netip.Addr{}, fmt.Errorf("interface %s: the %s %s address is not a plain %s address", splitInterface.name, what, family.name, family.name)
		}
		return address, nil
	}
	var err error
	if families[0].publicAddress, err = parse(families[0], splitInterface.publicIpv4, "public"); err != nil {
		return nil, err
	}
	if families[0].bridgeAddress, err = parse(families[0], splitInterface.bridgeIpv4, "bridge"); err != nil {
		return nil, err
	}
	if families[1].publicAddress, err = parse(families[1], splitInterface.publicIpv6, "public"); err != nil {
		return nil, err
	}
	if families[1].bridgeAddress, err = parse(families[1], splitInterface.bridgeIpv6, "bridge"); err != nil {
		return nil, err
	}
	return families, nil
}

// Checks the public ports, tcp and udp each in 1..65535, and returns them sorted
// without repeats. A protocol with no ports is left out.
func normalizeLbAltPublicPorts(interfaceName string, publicPorts map[string][]int) (map[string][]int, error) {
	normalizedPorts := map[string][]int{}
	for protocol, ports := range publicPorts {
		if protocol != "tcp" && protocol != "udp" {
			return nil, fmt.Errorf("interface %s: public port protocol %q is not tcp or udp", interfaceName, protocol)
		}
		sortedPorts := slices.Clone(ports)
		slices.Sort(sortedPorts)
		for _, port := range sortedPorts {
			if port < 1 || 65535 < port {
				return nil, fmt.Errorf("interface %s: public %s port %d is not in 1..65535", interfaceName, protocol, port)
			}
		}
		sortedPorts = slices.Compact(sortedPorts)
		if 0 < len(sortedPorts) {
			normalizedPorts[protocol] = sortedPorts
		}
	}
	return normalizedPorts, nil
}

// The ports as multiport lists of at most lbAltMultiportLimit ports each.
func chunkLbAltPorts(ports []int) []string {
	portLists := []string{}
	for chunk := range slices.Chunk(ports, lbAltMultiportLimit) {
		portTexts := make([]string, len(chunk))
		for i, port := range chunk {
			portTexts[i] = strconv.Itoa(port)
		}
		portLists = append(portLists, strings.Join(portTexts, ","))
	}
	return portLists
}

// The chain names and rule comment of one lb_alt interface.
type lbAltChainNames struct {
	interfaceName string
	// the interface's lb chain, the lb worker's own (initBlockRedirect)
	lbChain    string
	splitChain string
	// where a replacement split chain is built
	temporarySplitChain string
	// every block chain of the interface starts with this
	blockChainPrefix string
	// the comment on the rules the split adds to chains it does not own
	ruleComment string
}

// The names of an interface's chains, each within the iptables limit. The lb
// chain's is iptablesChainName's for the interface's lb block.
func newLbAltChainNames(env string, interfaceName string) (*lbAltChainNames, error) {
	if !lbAltNamePattern.MatchString(env) {
		return nil, fmt.Errorf("env %q is not letters, digits, '_', '.' or '-'", env)
	}
	if !lbAltInterfaceNamePattern.MatchString(interfaceName) {
		return nil, fmt.Errorf("interface name %q is not letters, digits, '_' or '.'", interfaceName)
	}
	upperEnv := strings.ToUpper(env)
	upperInterfaceName := strings.ToUpper(interfaceName)
	splitChain := fmt.Sprintf("WARP-%s-%s-%s", upperEnv, lbAltChainMarker, upperInterfaceName)
	names := &lbAltChainNames{
		interfaceName:       interfaceName,
		lbChain:             fmt.Sprintf("WARP-%s-LB-%s", upperEnv, upperInterfaceName),
		splitChain:          splitChain,
		temporarySplitChain: fmt.Sprintf("WARP-%s-%s-%s", upperEnv, lbAltTemporaryChainMarker, upperInterfaceName),
		blockChainPrefix:    splitChain + "-",
		ruleComment:         fmt.Sprintf(lbAltRuleCommentFormat, strings.ToLower(env), strings.ToLower(interfaceName)),
	}
	for _, chain := range []string{names.lbChain, names.splitChain, names.temporarySplitChain} {
		if lbAltChainNameLimit < len(chain) {
			return nil, fmt.Errorf("chain %s is over %d characters", chain, lbAltChainNameLimit)
		}
	}
	return names, nil
}

// The block's chain on the interface.
func (self *lbAltChainNames) blockChain(block string) (string, error) {
	if !lbAltNamePattern.MatchString(block) {
		return "", fmt.Errorf("block %q is not letters, digits, '_', '.' or '-'", block)
	}
	chain := self.blockChainPrefix + strings.ToUpper(block)
	if lbAltChainNameLimit < len(chain) {
		return "", fmt.Errorf("chain %s is over %d characters", chain, lbAltChainNameLimit)
	}
	return chain, nil
}

// Whether the chain is one of the worker's own lb_alt chains: for a connect
// block, its block chain on any interface; for an lb unit, its interface's
// split chain, temporary split chain and block chains. The lb unit's interface
// is the last part of its block, as in iptablesChainName. No other service
// owns one, though its blocks may share connect's block names.
func lbAltChainOwnedBy(chain string, env string, service string, block string) bool {
	upperEnv := strings.ToUpper(env)
	rest := ""
	found := false
	for _, marker := range []string{lbAltChainMarker, lbAltTemporaryChainMarker} {
		if rest, found = strings.CutPrefix(chain, fmt.Sprintf("WARP-%s-%s-", upperEnv, marker)); found {
			break
		}
	}
	if !found {
		return false
	}
	interfacePart, blockPart, hasBlock := strings.Cut(rest, "-")
	switch service {
	case "lb":
		blockParts := strings.Split(block, "-")
		return interfacePart == strings.ToUpper(blockParts[len(blockParts)-1])
	case lbAltBlockService:
		return hasBlock && blockPart == strings.ToUpper(block)
	}
	return false
}

// The configured internal ports the worker's own lb_alt chains DNAT to, in both
// families. IPv6 is read only when IPv4 shows the worker has lb_alt chains, so
// a host without lb_alt never depends on ip6tables here.
func (self *RunWorker) lbAltChainTargetPorts(configuredInternalPorts map[int]bool) (map[int]bool, error) {
	targetPorts := map[int]bool{}
	chainHeader := regexp.MustCompile(`^Chain\s+(\S+)\s+`)
	dnatDestination := regexp.MustCompile(`^\s*DNAT\s+.*\bto:(\S+)\s*$`)
	for _, iptablesCommand := range [][]string{{"iptables"}, {"ip6tables"}} {
		out, err := sudo2(iptablesCommand, "-w", "-t", "nat", "-L", "-n").Output()
		if err != nil {
			return nil, fmt.Errorf("inspect %s lb_alt chains: %w", iptablesCommand[0], err)
		}
		ownedChainCount := 0
		owned := false
		for _, line := range strings.Split(string(out), "\n") {
			if groups := chainHeader.FindStringSubmatch(line); groups != nil {
				owned = lbAltChainOwnedBy(groups[1], self.env, self.service, self.block)
				if owned {
					ownedChainCount += 1
				}
				continue
			}
			if !owned {
				continue
			}
			groups := dnatDestination.FindStringSubmatch(line)
			if groups == nil {
				continue
			}
			destination, err := netip.ParseAddrPort(groups[1])
			if err != nil {
				continue
			}
			internalPort := int(destination.Port())
			if configuredInternalPorts[internalPort] {
				targetPorts[internalPort] = true
			}
		}
		if ownedChainCount == 0 {
			break
		}
	}
	return targetPorts, nil
}

// One interface's split, resolved from its config.
type lbAltInterfacePlan struct {
	names *lbAltChainNames
	// ipv4, then ipv6
	families    []*lbAltFamily
	publicPorts map[string][]int
	// in services.ServiceBlockWeights order
	blockWeights []services.BlockWeight
	// block -> its chain on the interface
	blockChains map[string]string
	// each bucket's block when every block is ready
	baseBucketBlocks []string
}

// Resolves and checks the config before anything is listed or written: the
// chain names fit, the addresses are plain addresses of their families, a
// public address has a bridge address to DNAT to, and the blocks split.
func newLbAltInterfacePlan(config *lbAltSplitConfig) (*lbAltInterfacePlan, error) {
	if config == nil {
		return nil, errors.New("the split config is missing")
	}
	splitInterface := &config.splitInterface
	names, err := newLbAltChainNames(config.env, splitInterface.name)
	if err != nil {
		return nil, err
	}
	families, err := newLbAltFamilies(splitInterface)
	if err != nil {
		return nil, err
	}
	splitFamilyCount := 0
	for _, family := range families {
		if family.publicAddress.IsValid() && !family.bridgeAddress.IsValid() {
			return nil, fmt.Errorf("interface %s has a public %s address but its bridge has none", splitInterface.name, family.name)
		}
		if family.splits() {
			splitFamilyCount += 1
		}
	}
	if splitFamilyCount == 0 {
		return nil, fmt.Errorf("interface %s has no family with a public and a bridge address", splitInterface.name)
	}
	publicPorts, err := normalizeLbAltPublicPorts(splitInterface.name, splitInterface.publicPorts)
	if err != nil {
		return nil, err
	}
	if len(publicPorts) == 0 {
		return nil, fmt.Errorf("interface %s has no public ports", splitInterface.name)
	}
	// the marks and the entry jumps take only ports a front socket serves
	if err := lbAltCheckPublicPorts(publicPorts); err != nil {
		return nil, fmt.Errorf("interface %s: %w", splitInterface.name, err)
	}
	baseBucketBlocks, err := services.LbAltBucketBlocks(config.blockWeights, services.LbAltBucketCount)
	if err != nil {
		return nil, fmt.Errorf("interface %s: %w", splitInterface.name, err)
	}
	blockChains := map[string]string{}
	chainBlocks := map[string]string{}
	for _, blockWeight := range config.blockWeights {
		chain, err := names.blockChain(blockWeight.Block)
		if err != nil {
			return nil, err
		}
		if otherBlock, ok := chainBlocks[chain]; ok {
			return nil, fmt.Errorf("blocks %q and %q share the chain %s", otherBlock, blockWeight.Block, chain)
		}
		chainBlocks[chain] = blockWeight.Block
		blockChains[blockWeight.Block] = chain
	}
	return &lbAltInterfacePlan{
		names:            names,
		families:         families,
		publicPorts:      publicPorts,
		blockWeights:     config.blockWeights,
		blockChains:      blockChains,
		baseBucketBlocks: baseBucketBlocks,
	}, nil
}

// A rule the split wants, in a chain and with its arguments.
type lbAltRule struct {
	chain string
	spec  []string
}

// The family's HMARK rules: for PREROUTING and OUTPUT, one rule per protocol,
// more past lbAltMultiportLimit ports, for the public address and ports, on
// new flows.
//
// The hash takes the whole source address and nothing else, which §2.5 writes
// as --hmark-tuple src. The rules spell it as the family's full source prefix,
// --hmark-src-prefix 32 or 128, the form iptables lists them in (M7 on
// edge-4), because a rule is deleted by its listed form. libxt_HMARK stores
// the tuple as a 16-byte mask of ones and the prefix as only its leading
// bits, and iptables compares the whole stored mask on a delete, so an IPv4
// rule added with the tuple, listed as prefix 32, is never found again. Both
// spellings hash the same: IPv4 masks only the address's 32 bits.
func (self *lbAltInterfacePlan) hmarkRules(family *lbAltFamily) []lbAltRule {
	destination := netip.PrefixFrom(family.publicAddress, family.addressBits).String()
	rules := []lbAltRule{}
	for _, chain := range []string{"PREROUTING", "OUTPUT"} {
		for _, protocol := range lbAltProtocols {
			for _, ports := range chunkLbAltPorts(self.publicPorts[protocol]) {
				rules = append(rules, lbAltRule{
					chain: chain,
					spec: []string{
						"-d", destination,
						"-p", protocol,
						"-m", "multiport", "--dports", ports,
						"-m", "conntrack", "--ctstate", "NEW",
						"-m", "comment", "--comment", self.names.ruleComment,
						"-j", "HMARK",
						"--hmark-src-prefix", strconv.Itoa(family.addressBits),
						"--hmark-mod", strconv.Itoa(lbAltHmarkMod),
						"--hmark-offset", fmt.Sprintf("%#x", lbAltHmarkOffset),
						"--hmark-rnd", fmt.Sprintf("%#x", lbAltHmarkRnd),
					},
				})
			}
		}
	}
	return rules
}

// The family's entry jumps from the lb chain to a split chain, one per protocol,
// more past lbAltMultiportLimit ports.
func (self *lbAltInterfacePlan) entryRules(family *lbAltFamily, splitChain string) []lbAltRule {
	destination := netip.PrefixFrom(family.publicAddress, family.addressBits).String()
	rules := []lbAltRule{}
	for _, protocol := range lbAltProtocols {
		for _, ports := range chunkLbAltPorts(self.publicPorts[protocol]) {
			rules = append(rules, lbAltRule{
				chain: self.names.lbChain,
				spec: []string{
					"-d", destination,
					"-p", protocol,
					"-m", "multiport", "--dports", ports,
					"-m", "comment", "--comment", self.names.ruleComment,
					"-j", splitChain,
				},
			})
		}
	}
	return rules
}

// The split chain's rules, one per bucket that has a block, in bucket order.
func (self *lbAltInterfacePlan) splitRuleSpecs(bucketBlocks []string) [][]string {
	specs := [][]string{}
	for bucket, block := range bucketBlocks {
		if block == "" {
			continue
		}
		specs = append(specs, []string{
			"-m", "mark", "--mark", fmt.Sprintf("%#x", lbAltHmarkOffset+bucket),
			"-j", self.blockChains[block],
		})
	}
	return specs
}

// One public socket of an interface: a protocol and a public port.
type lbAltPublicSocket struct {
	protocol string
	port     int
}

// The blocks ready in the family: each one's chain exists, its first DNAT for
// every public (protocol, port), the one a packet takes, goes to the family's
// bridge address, and a socket listens on each target.
func (self *lbAltInterfacePlan) readyBlocks(family *lbAltFamily, nat *iptablesListing, sockets *listenSockets) map[string]bool {
	readyBlocks := map[string]bool{}
	for _, blockWeight := range self.blockWeights {
		chain := self.blockChains[blockWeight.Block]
		if !nat.hasChain(chain) {
			continue
		}
		blockTargets := map[lbAltPublicSocket]netip.AddrPort{}
		for _, rule := range nat.chainRules(chain) {
			if rule.key.jump != "DNAT" {
				continue
			}
			port, err := strconv.Atoi(rule.key.ports)
			if err != nil {
				continue
			}
			target, err := netip.ParseAddrPort(rule.key.toDestination)
			if err != nil {
				continue
			}
			publicSocket := lbAltPublicSocket{protocol: rule.key.protocol, port: port}
			if _, ok := blockTargets[publicSocket]; !ok {
				blockTargets[publicSocket] = target
			}
		}
		ready := true
		for _, protocol := range lbAltProtocols {
			for _, port := range self.publicPorts[protocol] {
				target, ok := blockTargets[lbAltPublicSocket{protocol: protocol, port: port}]
				if !ok || target.Addr() != family.bridgeAddress || !sockets.holds(protocol, target.Addr(), int(target.Port())) {
					ready = false
				}
			}
		}
		if ready {
			readyBlocks[blockWeight.Block] = true
		}
	}
	return readyBlocks
}

// Whether the lb chain starts with exactly the wanted entry jumps to the split
// chain, and no other rule carries the interface's comment.
func (self *lbAltInterfacePlan) entriesLead(family *lbAltFamily, nat *iptablesListing, taggedRules []*iptablesListedRule, splitChain string) bool {
	wantedRules := self.entryRules(family, splitChain)
	if len(taggedRules) != len(wantedRules) {
		return false
	}
	lbRules := nat.chainRules(self.names.lbChain)
	if len(lbRules) < len(wantedRules) {
		return false
	}
	for i, wantedRule := range wantedRules {
		if lbRules[i].key != parseIptablesRuleKey(wantedRule.spec) {
			return false
		}
	}
	return true
}

// The block each bucket sends to: the base split, with each orphaned bucket,
// one whose block is not ready, moved to a ready block. A ready block keeps its
// whole base range, and a range goes back to its block once the block is ready
// again. Orphaned buckets are shared out in bucket order, as one run per block,
// among the ready blocks of positive weight in blockWeights order, by largest
// remainder of weight × orphaned / ready total, ties to the earlier block. With
// no ready block every bucket is "", and the split sends nothing.
func assignLbAltBuckets(baseBucketBlocks []string, blockWeights []services.BlockWeight, readyBlocks map[string]bool) []string {
	bucketBlocks := slices.Clone(baseBucketBlocks)
	orphanedBuckets := []int{}
	for bucket, block := range bucketBlocks {
		if !readyBlocks[block] {
			orphanedBuckets = append(orphanedBuckets, bucket)
			bucketBlocks[bucket] = ""
		}
	}
	readyBlockWeights := []services.BlockWeight{}
	readyTotal := 0
	for _, blockWeight := range blockWeights {
		if 0 < blockWeight.Weight && readyBlocks[blockWeight.Block] {
			readyBlockWeights = append(readyBlockWeights, blockWeight)
			readyTotal += blockWeight.Weight
		}
	}
	if len(orphanedBuckets) == 0 || len(readyBlockWeights) == 0 {
		return bucketBlocks
	}

	// each ready block gets the floor of weight × orphaned / ready total, and
	// the rest go one each to the largest remainders, ties to the earlier
	// block, so a block may get none. Remainders are scaled by the total, so
	// the comparisons are exact.
	bucketCounts := make([]int, len(readyBlockWeights))
	remainders := make([]int, len(readyBlockWeights))
	assignedCount := 0
	for i, blockWeight := range readyBlockWeights {
		bucketCounts[i] = blockWeight.Weight * len(orphanedBuckets) / readyTotal
		remainders[i] = blockWeight.Weight * len(orphanedBuckets) % readyTotal
		assignedCount += bucketCounts[i]
	}
	// fewer buckets are left than there are blocks, since each remainder is
	// under one bucket
	remainderOrder := make([]int, len(readyBlockWeights))
	for i := range remainderOrder {
		remainderOrder[i] = i
	}
	slices.SortStableFunc(remainderOrder, func(a int, b int) int {
		return cmp.Compare(remainders[b], remainders[a])
	})
	for _, i := range remainderOrder[:len(orphanedBuckets)-assignedCount] {
		bucketCounts[i] += 1
	}

	nextOrphanedBucket := 0
	for i, blockWeight := range readyBlockWeights {
		for range bucketCounts[i] {
			bucketBlocks[orphanedBuckets[nextOrphanedBucket]] = blockWeight.Block
			nextOrphanedBucket += 1
		}
	}
	return bucketBlocks
}

// reconcileLbAltSplit's work: under the host lock, one socket snapshot, then
// each family in turn, so a failure in one family leaves the other converged.
func (self *lbAltSplitWriter) reconcile(ctx context.Context, config *lbAltSplitConfig) error {
	plan, err := newLbAltInterfacePlan(config)
	if err != nil {
		return fmt.Errorf("lb_alt split: %w", err)
	}
	unlock, err := self.lockHost(ctx, config.env)
	if err != nil {
		return err
	}
	defer unlock()

	sockets, err := self.listSockets(ctx)
	if err != nil {
		// keep the last working rules: readiness is unknown
		return fmt.Errorf("lb_alt split %s: %w", plan.names.interfaceName, err)
	}

	familyErrors := []error{}
	noReadyFamilyNames := []string{}
	for _, family := range plan.families {
		if !family.splits() {
			// a family the interface lacks keeps no split; its block chains
			// stay, so a public address that comes back finds them ready
			if err := self.removeFamily(ctx, plan.names, family); err != nil {
				familyErrors = append(familyErrors, err)
			}
			continue
		}
		sends, err := self.reconcileFamily(ctx, plan, family, sockets)
		if err != nil {
			familyErrors = append(familyErrors, err)
			continue
		}
		if !sends {
			noReadyFamilyNames = append(noReadyFamilyNames, family.name)
		}
	}
	if 0 < len(noReadyFamilyNames) {
		familyErrors = append(familyErrors, fmt.Errorf(
			"%w: interface %s %s",
			errLbAltSplitNoReadyBlock,
			plan.names.interfaceName,
			strings.Join(noReadyFamilyNames, ", "),
		))
	}
	return errors.Join(familyErrors...)
}

// Reconciles one family, and returns whether its split sends anywhere: false
// when no block of positive weight is ready. Before the family's first switch
// from nginx it may instead write nothing and return an error wrapping
// errLbAltSplitAwaitsEveryBlock.
func (self *lbAltSplitWriter) reconcileFamily(ctx context.Context, plan *lbAltInterfacePlan, family *lbAltFamily, sockets *listenSockets) (bool, error) {
	mangle, err := self.listTable(ctx, family, "mangle")
	if err != nil {
		return false, fmt.Errorf("lb_alt split %s: %w", plan.names.interfaceName, err)
	}
	nat, err := self.listTable(ctx, family, "nat")
	if err != nil {
		return false, fmt.Errorf("lb_alt split %s: %w", plan.names.interfaceName, err)
	}
	if !nat.hasChain(plan.names.lbChain) {
		// the lb worker creates its chain and the jumps to it (initBlockRedirect)
		return false, fmt.Errorf("lb_alt split %s %s: the lb chain %s is missing", plan.names.interfaceName, family.name, plan.names.lbChain)
	}

	readyBlocks := plan.readyBlocks(family, nat, sockets)

	// The first switch from nginx (LBALT.md §4.6, D16): while the family has
	// no entry jumps and the lb chain still holds nginx's DNAT, a rule the
	// split did not tag, nginx keeps the new flows, and the split takes them
	// only once every block of positive weight is ready, so that the switch
	// sends them to every block at once, never all to whichever block was
	// ready first. Once the jumps are in, a block lost later has its range
	// moved, and an interface where nginx never ran, as after a reboot,
	// switches with the blocks that are ready.
	if len(nat.taggedRules(plan.names.ruleComment)) == 0 {
		nginxDnat := slices.ContainsFunc(nat.chainRules(plan.names.lbChain), func(rule *iptablesListedRule) bool {
			return rule.key.jump == "DNAT" && rule.key.comment != plan.names.ruleComment
		})
		unreadyBlocks := []string{}
		for _, blockWeight := range plan.blockWeights {
			if 0 < blockWeight.Weight && !readyBlocks[blockWeight.Block] {
				unreadyBlocks = append(unreadyBlocks, blockWeight.Block)
			}
		}
		if nginxDnat && 0 < len(unreadyBlocks) {
			return false, fmt.Errorf(
				"%w: interface %s %s: %s not ready",
				errLbAltSplitAwaitsEveryBlock,
				plan.names.interfaceName,
				family.name,
				strings.Join(unreadyBlocks, ", "),
			)
		}
	}

	// marks first, so no flow reaches the split unmarked
	if err := self.convergeHmark(ctx, plan, family, mangle); err != nil {
		return false, err
	}

	bucketBlocks := assignLbAltBuckets(plan.baseBucketBlocks, plan.blockWeights, readyBlocks)
	if err := self.convergeSplit(ctx, plan, family, nat, plan.splitRuleSpecs(bucketBlocks)); err != nil {
		return false, err
	}
	sends := slices.ContainsFunc(bucketBlocks, func(block string) bool {
		return block != ""
	})
	return sends, nil
}

// Brings the rules carrying the interface's comment in mangle to exactly the
// family's HMARK rules, in one transaction.
func (self *lbAltSplitWriter) convergeHmark(ctx context.Context, plan *lbAltInterfacePlan, family *lbAltFamily, mangle *iptablesListing) error {
	wantedRules := plan.hmarkRules(family)
	taggedRules := mangle.taggedRules(plan.names.ruleComment)
	// whether the tagged rules are, chain by chain and in order, the wanted ones
	converged := func() bool {
		listedKeys := map[string][]iptablesRuleKey{}
		for _, rule := range taggedRules {
			listedKeys[rule.chain] = append(listedKeys[rule.chain], rule.key)
		}
		wantedKeys := map[string][]iptablesRuleKey{}
		for _, rule := range wantedRules {
			wantedKeys[rule.chain] = append(wantedKeys[rule.chain], parseIptablesRuleKey(rule.spec))
		}
		if len(listedKeys) != len(wantedKeys) {
			return false
		}
		for chain, keys := range wantedKeys {
			if !slices.Equal(listedKeys[chain], keys) {
				return false
			}
		}
		return true
	}
	if converged() {
		return nil
	}
	restore := newIptablesRestore("mangle")
	for _, rule := range taggedRules {
		restore.deleteRule(rule.chain, rule.spec)
	}
	chainPositions := map[string]int{}
	for _, rule := range wantedRules {
		chainPositions[rule.chain] += 1
		restore.insertRule(rule.chain, chainPositions[rule.chain], rule.spec)
	}
	return self.apply(ctx, family, restore, "split "+plan.names.interfaceName, "wrote the HMARK rules")
}

// Brings the split chain to the wanted rules, with the entry jumps leading the
// lb chain. The state the listing shows decides the steps:
//   - no entry jumps: build the split chain, then add the jumps;
//   - jumps to the split chain: when it holds the wanted rules, only the jumps
//     and a leftover temporary chain are repaired. Otherwise the replacement
//     is built under the temporary name, the jumps move to it, the split
//     chain is rebuilt while nothing uses it and the jumps move back;
//   - jumps to the temporary chain, a replacement interrupted after its
//     switch: the split chain is rebuilt and the jumps move back;
//   - anything else, a state no writer leaves: one transaction rewrites the
//     split chain and the jumps.
//
// Each step is its own transaction, so the jumps only ever reach a complete
// chain, and the old one keeps the flows until the switch.
func (self *lbAltSplitWriter) convergeSplit(ctx context.Context, plan *lbAltInterfacePlan, family *lbAltFamily, nat *iptablesListing, splitSpecs [][]string) error {
	names := plan.names
	subject := "split " + names.interfaceName
	taggedRules := nat.taggedRules(names.ruleComment)
	entryTargets := map[string]bool{}
	listedEntries := []lbAltRule{}
	for _, rule := range taggedRules {
		entryTargets[rule.key.jump] = true
		listedEntries = append(listedEntries, lbAltRule{chain: rule.chain, spec: rule.spec})
	}
	hasTemporaryChain := nat.hasChain(names.temporarySplitChain)

	buildChain := func(restore *iptablesRestore, chain string) {
		restore.createOrFlushChain(chain)
		for _, spec := range splitSpecs {
			restore.appendRule(chain, spec)
		}
	}
	deleteEntries := func(restore *iptablesRestore, entries []lbAltRule) {
		for _, entry := range entries {
			restore.deleteRule(entry.chain, entry.spec)
		}
	}
	insertEntries := func(restore *iptablesRestore, splitChain string) {
		for i, entry := range plan.entryRules(family, splitChain) {
			restore.insertRule(entry.chain, i+1, entry.spec)
		}
	}
	dropTemporaryChain := func(restore *iptablesRestore) {
		if hasTemporaryChain {
			restore.flushChain(names.temporarySplitChain)
			restore.deleteChain(names.temporarySplitChain)
		}
	}
	// rebuilds the unused split chain and moves the jumps back from the
	// temporary chain
	rebuildSplitChain := func(entries []lbAltRule) error {
		restore := newIptablesRestore("nat")
		buildChain(restore, names.splitChain)
		deleteEntries(restore, entries)
		insertEntries(restore, names.splitChain)
		dropTemporaryChain(restore)
		return self.apply(ctx, family, restore, subject, "rebuilt the split chain and moved the entry jumps back to it")
	}

	switch {
	case len(taggedRules) == 0:
		build := newIptablesRestore("nat")
		buildChain(build, names.splitChain)
		dropTemporaryChain(build)
		if err := self.apply(ctx, family, build, subject, "built the split chain"); err != nil {
			return err
		}
		entries := newIptablesRestore("nat")
		insertEntries(entries, names.splitChain)
		return self.apply(ctx, family, entries, subject, "added the entry jumps")

	case len(entryTargets) == 1 && entryTargets[names.splitChain]:
		if sameIptablesRuleSpecs(nat.chainRules(names.splitChain), splitSpecs) {
			if !hasTemporaryChain && plan.entriesLead(family, nat, taggedRules, names.splitChain) {
				return nil
			}
			repair := newIptablesRestore("nat")
			deleteEntries(repair, listedEntries)
			insertEntries(repair, names.splitChain)
			dropTemporaryChain(repair)
			return self.apply(ctx, family, repair, subject, "repaired the entry jumps")
		}
		// nothing uses the temporary chain while the jumps go to the split
		// chain, so it can be built (or flushed and rebuilt) in place
		build := newIptablesRestore("nat")
		buildChain(build, names.temporarySplitChain)
		if err := self.apply(ctx, family, build, subject, "built the replacement split chain"); err != nil {
			return err
		}
		switchover := newIptablesRestore("nat")
		deleteEntries(switchover, listedEntries)
		insertEntries(switchover, names.temporarySplitChain)
		if err := self.apply(ctx, family, switchover, subject, "moved the entry jumps to the replacement"); err != nil {
			return err
		}
		hasTemporaryChain = true
		return rebuildSplitChain(plan.entryRules(family, names.temporarySplitChain))

	case len(entryTargets) == 1 && entryTargets[names.temporarySplitChain]:
		return rebuildSplitChain(listedEntries)

	default:
		repair := newIptablesRestore("nat")
		buildChain(repair, names.splitChain)
		deleteEntries(repair, listedEntries)
		insertEntries(repair, names.splitChain)
		dropTemporaryChain(repair)
		return self.apply(ctx, family, repair, subject, "rewrote the split chain and the entry jumps")
	}
}

// Whether a chain's listed rules are the wanted ones, in order.
func sameIptablesRuleSpecs(listedRules []*iptablesListedRule, wantedSpecs [][]string) bool {
	if len(listedRules) != len(wantedSpecs) {
		return false
	}
	for i, spec := range wantedSpecs {
		if listedRules[i].key != parseIptablesRuleKey(spec) {
			return false
		}
	}
	return true
}

// removeLbAltSplit's work: under the host lock, both families, whatever
// addresses the interface had.
func (self *lbAltSplitWriter) remove(ctx context.Context, env string, interfaceName string) error {
	names, err := newLbAltChainNames(env, interfaceName)
	if err != nil {
		return fmt.Errorf("lb_alt split: %w", err)
	}
	unlock, err := self.lockHost(ctx, env)
	if err != nil {
		return err
	}
	defer unlock()

	familyErrors := []error{}
	for _, family := range newLbAltFamilyPair() {
		if err := self.removeFamily(ctx, names, family); err != nil {
			familyErrors = append(familyErrors, err)
		}
	}
	return errors.Join(familyErrors...)
}

// Removes the interface's split from one family: in nat, the entry jumps and
// the split chains in one transaction; then the HMARK rules in mangle. The
// block chains stay, the block workers'. A family with nothing to remove is
// not written.
func (self *lbAltSplitWriter) removeFamily(ctx context.Context, names *lbAltChainNames, family *lbAltFamily) error {
	subject := "split " + names.interfaceName
	nat, err := self.listTable(ctx, family, "nat")
	if err != nil {
		return fmt.Errorf("lb_alt %s: %w", subject, err)
	}
	natRestore := newIptablesRestore("nat")
	for _, rule := range nat.taggedRules(names.ruleComment) {
		natRestore.deleteRule(rule.chain, rule.spec)
	}
	removedChains := []string{}
	for _, chain := range []string{names.splitChain, names.temporarySplitChain} {
		if nat.hasChain(chain) {
			removedChains = append(removedChains, chain)
		}
	}
	// a chain is deleted only once it is empty and no rule jumps to it; the
	// entry jumps go first, and the block chains the split chains jump to stay
	for _, chain := range removedChains {
		natRestore.flushChain(chain)
	}
	for _, chain := range removedChains {
		natRestore.deleteChain(chain)
	}
	if err := self.apply(ctx, family, natRestore, subject, "removed the entry jumps and chains"); err != nil {
		return err
	}

	mangle, err := self.listTable(ctx, family, "mangle")
	if err != nil {
		return fmt.Errorf("lb_alt %s: %w", subject, err)
	}
	mangleRestore := newIptablesRestore("mangle")
	for _, rule := range mangle.taggedRules(names.ruleComment) {
		mangleRestore.deleteRule(rule.chain, rule.spec)
	}
	return self.apply(ctx, family, mangleRestore, subject, "removed the HMARK rules")
}

// One interface's block chain, resolved.
type lbAltBlockChainPlan struct {
	chain string
	// the DNATs of each family the interface's bridge has, by family name
	familySpecs map[string][][]string
}

// writeLbAltBlockChains' work: every chain is resolved and checked first, then,
// under the host lock, each family's changed chains are written in one
// transaction. A chain that already holds its targets is not written.
func (self *lbAltSplitWriter) writeBlockChains(ctx context.Context, env string, block string, splitInterfaces []lbAltSplitInterface, targets []lbAltBlockTarget) error {
	internalPorts := map[lbAltPublicSocket]int{}
	for _, target := range targets {
		if target.protocol != "tcp" && target.protocol != "udp" {
			return fmt.Errorf("lb_alt block %s: target protocol %q is not tcp or udp", block, target.protocol)
		}
		if target.publicPort < 1 || 65535 < target.publicPort || target.internalPort < 1 || 65535 < target.internalPort {
			return fmt.Errorf("lb_alt block %s: target %s %d->%d is not in 1..65535", block, target.protocol, target.publicPort, target.internalPort)
		}
		publicSocket := lbAltPublicSocket{protocol: target.protocol, port: target.publicPort}
		if _, ok := internalPorts[publicSocket]; ok {
			return fmt.Errorf("lb_alt block %s: public %s port %d has two targets", block, target.protocol, target.publicPort)
		}
		internalPorts[publicSocket] = target.internalPort
	}

	// resolve every chain before taking the lock, so a bad input writes nothing
	chainPlans := []*lbAltBlockChainPlan{}
	for i := range splitInterfaces {
		splitInterface := &splitInterfaces[i]
		names, err := newLbAltChainNames(env, splitInterface.name)
		if err != nil {
			return fmt.Errorf("lb_alt block %s: %w", block, err)
		}
		chain, err := names.blockChain(block)
		if err != nil {
			return fmt.Errorf("lb_alt block %s: %w", block, err)
		}
		families, err := newLbAltFamilies(splitInterface)
		if err != nil {
			return fmt.Errorf("lb_alt block %s: %w", block, err)
		}
		publicPorts, err := normalizeLbAltPublicPorts(splitInterface.name, splitInterface.publicPorts)
		if err != nil {
			return fmt.Errorf("lb_alt block %s: %w", block, err)
		}
		if len(publicPorts) == 0 {
			Err.Printf("lb_alt block %s: interface %s has no public ports; no chain written\n", block, splitInterface.name)
			continue
		}
		chainPlan := &lbAltBlockChainPlan{
			chain:       chain,
			familySpecs: map[string][][]string{},
		}
		for _, family := range families {
			if !family.bridgeAddress.IsValid() {
				continue
			}
			specs := [][]string{}
			for _, protocol := range lbAltProtocols {
				for _, port := range publicPorts[protocol] {
					internalPort, ok := internalPorts[lbAltPublicSocket{protocol: protocol, port: port}]
					if !ok {
						return fmt.Errorf("lb_alt block %s: interface %s public %s port %d has no target", block, splitInterface.name, protocol, port)
					}
					destination := netip.AddrPortFrom(family.bridgeAddress, uint16(internalPort)).String()
					specs = append(specs, []string{
						"-p", protocol,
						"-m", protocol, "--dport", strconv.Itoa(port),
						"-j", "DNAT", "--to-destination", destination,
					})
				}
			}
			chainPlan.familySpecs[family.name] = specs
		}
		chainPlans = append(chainPlans, chainPlan)
	}

	unlock, err := self.lockHost(ctx, env)
	if err != nil {
		return err
	}
	defer unlock()

	familyErrors := []error{}
	for _, family := range newLbAltFamilyPair() {
		hasFamily := false
		for _, chainPlan := range chainPlans {
			if _, ok := chainPlan.familySpecs[family.name]; ok {
				hasFamily = true
			}
		}
		if !hasFamily {
			continue
		}
		nat, err := self.listTable(ctx, family, "nat")
		if err != nil {
			familyErrors = append(familyErrors, fmt.Errorf("lb_alt block %s: %w", block, err))
			continue
		}
		// each chain is flushed and refilled in the same transaction, so the
		// split's jumps go from the old complete set to the new one
		restore := newIptablesRestore("nat")
		for _, chainPlan := range chainPlans {
			specs, ok := chainPlan.familySpecs[family.name]
			if !ok {
				continue
			}
			if nat.hasChain(chainPlan.chain) && sameIptablesRuleSpecs(nat.chainRules(chainPlan.chain), specs) {
				continue
			}
			restore.createOrFlushChain(chainPlan.chain)
			for _, spec := range specs {
				restore.appendRule(chainPlan.chain, spec)
			}
		}
		if err := self.apply(ctx, family, restore, "block "+block, "wrote the block chains"); err != nil {
			familyErrors = append(familyErrors, err)
		}
	}
	return errors.Join(familyErrors...)
}

// What a rule matches and does, in canonical form, so a rule as `iptables -S`
// lists it compares equal to the arguments that added it: an address gets its
// prefix length, a protocol number its name, ports, marks and HMARK values
// their numeric value, and the match modules their options imply drop out.
// HMARK's options are compared by value. Its tuple is not one of them, since
// iptables lists the tuple as prefixes and masks (hmarkRules), so a rule spelled
// with it never compares equal to a listed one. Every other argument is kept,
// in order, in otherArgs, so an unexpected rule never compares equal to one of
// ours.
type iptablesRuleKey struct {
	destination   string
	protocol      string
	ports         string
	ctStateNew    bool
	mark          string
	comment       string
	jump          string
	toDestination string
	hmark         string
	otherArgs     string
}

// The key of a rule's arguments, as added or as listed. A value that does not
// read as its kind is kept as written.
func parseIptablesRuleKey(spec []string) iptablesRuleKey {
	key := iptablesRuleKey{}
	otherArgs := []string{}
	// HMARK option name, without its "--hmark-", -> canonical value
	hmarkValues := map[string]string{}
	value := func(i int) string {
		if i+1 < len(spec) {
			return spec[i+1]
		}
		return ""
	}
	// a number in decimal, whether written in hex or decimal
	canonicalNumber := func(text string) string {
		if number, err := strconv.ParseUint(text, 0, 64); err == nil {
			return strconv.FormatUint(number, 10)
		}
		return text
	}
	// an address or prefix as a masked prefix, 203.0.113.4/32 for 203.0.113.4
	canonicalPrefix := func(text string) string {
		if strings.Contains(text, "/") {
			if prefix, err := netip.ParsePrefix(text); err == nil {
				return prefix.Masked().String()
			}
			return text
		}
		if address, err := netip.ParseAddr(text); err == nil {
			return netip.PrefixFrom(address, address.BitLen()).String()
		}
		return text
	}
	// a protocol by name
	canonicalProtocol := func(text string) string {
		switch strings.ToLower(text) {
		case "6", "tcp":
			return "tcp"
		case "17", "udp":
			return "udp"
		}
		return strings.ToLower(text)
	}
	// a port list, sorted by number; a range keeps its a:b form
	canonicalPorts := func(text string) string {
		portTexts := strings.Split(text, ",")
		firstPorts := make([]int, len(portTexts))
		for i, portText := range portTexts {
			first, last, isRange := strings.Cut(portText, ":")
			firstPort, err := strconv.Atoi(first)
			if err != nil {
				return text
			}
			firstPorts[i] = firstPort
			if isRange {
				lastPort, err := strconv.Atoi(last)
				if err != nil {
					return text
				}
				portTexts[i] = fmt.Sprintf("%d:%d", firstPort, lastPort)
			} else {
				portTexts[i] = strconv.Itoa(firstPort)
			}
		}
		order := make([]int, len(portTexts))
		for i := range order {
			order[i] = i
		}
		slices.SortStableFunc(order, func(a int, b int) int {
			return cmp.Compare(firstPorts[a], firstPorts[b])
		})
		sortedTexts := make([]string, len(order))
		for i, j := range order {
			sortedTexts[i] = portTexts[j]
		}
		return strings.Join(sortedTexts, ",")
	}
	// a mark in hex, with its mask only when it is not the full one
	canonicalMark := func(text string) string {
		valueText, maskText, hasMask := strings.Cut(text, "/")
		markValue, err := strconv.ParseUint(valueText, 0, 32)
		if err != nil {
			return text
		}
		if hasMask {
			mask, err := strconv.ParseUint(maskText, 0, 32)
			if err != nil {
				return text
			}
			if mask != 0xffffffff {
				return fmt.Sprintf("%#x/%#x", markValue, mask)
			}
		}
		return fmt.Sprintf("%#x", markValue)
	}
	// a DNAT destination, [2001:db8::1]:7231 for IPv6
	canonicalAddrPort := func(text string) string {
		if addrPort, err := netip.ParseAddrPort(text); err == nil {
			return addrPort.String()
		}
		return text
	}

	for i := 0; i < len(spec); i++ {
		arg := spec[i]
		switch arg {
		case "-d", "--destination":
			key.destination = canonicalPrefix(value(i))
			i += 1
		case "-p", "--protocol":
			key.protocol = canonicalProtocol(value(i))
			i += 1
		case "-m", "--match":
			switch value(i) {
			case "tcp", "udp", "multiport", "conntrack", "state", "comment", "mark":
			default:
				otherArgs = append(otherArgs, arg, value(i))
			}
			i += 1
		case "--dport", "--dports", "--destination-port", "--destination-ports":
			key.ports = canonicalPorts(value(i))
			i += 1
		case "--ctstate", "--state":
			if value(i) == "NEW" {
				key.ctStateNew = true
			} else {
				otherArgs = append(otherArgs, arg, value(i))
			}
			i += 1
		case "--mark":
			key.mark = canonicalMark(value(i))
			i += 1
		case "--comment":
			key.comment = value(i)
			i += 1
		case "-j", "--jump":
			key.jump = value(i)
			i += 1
		case "-g", "--goto":
			key.jump = "goto " + value(i)
			i += 1
		case "--to-destination":
			key.toDestination = canonicalAddrPort(value(i))
			i += 1
		case "--hmark-src-prefix", "--hmark-dst-prefix", "--hmark-sport-mask", "--hmark-dport-mask", "--hmark-spi-mask", "--hmark-proto-mask", "--hmark-rnd", "--hmark-mod", "--hmark-offset":
			hmarkValues[strings.TrimPrefix(arg, "--hmark-")] = canonicalNumber(value(i))
			i += 1
		default:
			otherArgs = append(otherArgs, arg)
		}
	}
	hmarkTexts := []string{}
	for _, name := range slices.Sorted(maps.Keys(hmarkValues)) {
		hmarkTexts = append(hmarkTexts, name+"="+hmarkValues[name])
	}
	key.hmark = strings.Join(hmarkTexts, " ")
	key.otherArgs = strings.Join(otherArgs, " ")
	return key
}

// A rule as `iptables -S` lists it.
type iptablesListedRule struct {
	chain string
	// the arguments after "-A <chain>" as listed, which delete it again
	spec []string
	key  iptablesRuleKey
}

// One table of one family as `iptables -S` lists it.
type iptablesListing struct {
	listedChains map[string]bool
	// every rule in listing order, so each chain's rules are in rule order
	listedRules []*iptablesListedRule
}

// Whether the table has the chain, built in or user.
func (self *iptablesListing) hasChain(chain string) bool {
	return self.listedChains[chain]
}

// The chain's rules in order.
func (self *iptablesListing) chainRules(chain string) []*iptablesListedRule {
	rules := []*iptablesListedRule{}
	for _, rule := range self.listedRules {
		if rule.chain == chain {
			rules = append(rules, rule)
		}
	}
	return rules
}

// The rules carrying the comment, in listing order.
func (self *iptablesListing) taggedRules(comment string) []*iptablesListedRule {
	rules := []*iptablesListedRule{}
	for _, rule := range self.listedRules {
		if rule.key.comment == comment {
			rules = append(rules, rule)
		}
	}
	return rules
}

// Splits one `iptables -S` line into its arguments, undoing iptables'
// double-quoting of values such as comments.
func splitIptablesArgs(line string) ([]string, error) {
	args := []string{}
	var arg strings.Builder
	inArg := false
	quoted := false
	escaped := false
	for _, r := range line {
		switch {
		case escaped:
			arg.WriteRune(r)
			escaped = false
		case quoted && r == '\\':
			escaped = true
		case r == '"':
			quoted = !quoted
			inArg = true
		case !quoted && unicode.IsSpace(r):
			if inArg {
				args = append(args, arg.String())
				arg.Reset()
				inArg = false
			}
		default:
			arg.WriteRune(r)
			inArg = true
		}
	}
	if quoted || escaped {
		return nil, errors.New("unterminated quote")
	}
	if inArg {
		args = append(args, arg.String())
	}
	return args, nil
}

// Joins arguments into an iptables-restore line, double-quoting any that
// iptables would split.
func joinIptablesArgs(args []string) string {
	quotedArgs := make([]string, len(args))
	escaper := strings.NewReplacer(`\`, `\\`, `"`, `\"`)
	for i, arg := range args {
		if arg != "" && !strings.ContainsFunc(arg, func(r rune) bool {
			return unicode.IsSpace(r) || r == '"' || r == '\'' || r == '\\'
		}) {
			quotedArgs[i] = arg
			continue
		}
		quotedArgs[i] = `"` + escaper.Replace(arg) + `"`
	}
	return strings.Join(quotedArgs, " ")
}

// One iptables-restore --noflush transaction on one table. It touches only the
// chains and rules it names, and the kernel applies it whole or not at all.
type iptablesRestore struct {
	table string
	lines []string
}

// An empty transaction on the table.
func newIptablesRestore(table string) *iptablesRestore {
	return &iptablesRestore{
		table: table,
		lines: []string{},
	}
}

// Creates the user chain, or flushes it when it exists.
func (self *iptablesRestore) createOrFlushChain(chain string) {
	self.lines = append(self.lines, fmt.Sprintf(":%s - [0:0]", chain))
}

// Appends at the end of the chain.
func (self *iptablesRestore) appendRule(chain string, spec []string) {
	self.lines = append(self.lines, fmt.Sprintf("-A %s %s", chain, joinIptablesArgs(spec)))
}

// Inserts at a 1-based position.
func (self *iptablesRestore) insertRule(chain string, position int, spec []string) {
	self.lines = append(self.lines, fmt.Sprintf("-I %s %d %s", chain, position, joinIptablesArgs(spec)))
}

// Deletes the first rule that matches the arguments.
func (self *iptablesRestore) deleteRule(chain string, spec []string) {
	self.lines = append(self.lines, fmt.Sprintf("-D %s %s", chain, joinIptablesArgs(spec)))
}

// Removes every rule of the chain.
func (self *iptablesRestore) flushChain(chain string) {
	self.lines = append(self.lines, fmt.Sprintf("-F %s", chain))
}

// Deletes an empty user chain nothing jumps to.
func (self *iptablesRestore) deleteChain(chain string) {
	self.lines = append(self.lines, fmt.Sprintf("-X %s", chain))
}

// Whether the transaction changes nothing, so it need not run.
func (self *iptablesRestore) empty() bool {
	return len(self.lines) == 0
}

// The transaction as iptables-restore reads it.
func (self *iptablesRestore) input() string {
	return fmt.Sprintf("*%s\n%s\nCOMMIT\n", self.table, strings.Join(self.lines, "\n"))
}

// Why a candidate's status is not accepted (§2.4), and whether waiting could
// change that.
type lbAltReadinessRefusal struct {
	reason string
	// the candidate can never be accepted: it is draining, it is another
	// generation or route revision, or it reports sockets in another format
	definitive bool
}

// The reason alone, so a refusal logs as what is missing.
func (self *lbAltReadinessRefusal) Error() string {
	return self.reason
}

// A refusal with a formatted reason.
func refuseLbAltReadiness(definitive bool, format string, args ...any) *lbAltReadinessRefusal {
	return &lbAltReadinessRefusal{
		reason:     fmt.Sprintf(format, args...),
		definitive: definitive,
	}
}

// One socket X-UR-Front-Sockets reports.
type lbAltFrontSocket struct {
	protocol string
	address  netip.Addr
	port     int
}

// A socket's count of sockets up and expected.
type lbAltFrontSocketCounts struct {
	up       int
	expected int
}

// Checks one status response on §2.4's terms: 200 with status exactly "ok",
// the expected generation and route revision, X-UR-Front-Ready 1, and every
// expected socket at socketsPerPort up of socketsPerPort expected. Sockets the
// candidate reports beyond the expected ones are allowed. Draining is never
// ready. A refusal says whether waiting could change it.
//
// X-UR-Front-Sockets is "<protocol>/<address>/<port>=<up>/<expected>",
// comma-separated. Addresses compare as addresses, so any text form of one
// matches. A socket listed twice, or an entry in another form, is a definitive
// refusal.
func acceptLbAltStatus(statusCode int, header http.Header, body []byte, generation string, revision string, expectedSockets []lbAltFrontSocket, socketsPerPort int) error {
	if statusCode != http.StatusOK {
		return refuseLbAltReadiness(false, "status code %d", statusCode)
	}
	var warpStatusResponse WarpStatusResponse
	if err := json.Unmarshal(body, &warpStatusResponse); err != nil {
		return refuseLbAltReadiness(false, "status body is not status json")
	}
	switch warpStatusResponse.Status {
	case "ok":
	case "draining":
		return refuseLbAltReadiness(true, "status is draining")
	default:
		return refuseLbAltReadiness(false, "status is %q, not ok", warpStatusResponse.Status)
	}

	switch reportedGeneration := header.Get(lbAltFrontGenerationHeader); reportedGeneration {
	case generation:
	case "":
		return refuseLbAltReadiness(false, "no %s", lbAltFrontGenerationHeader)
	default:
		return refuseLbAltReadiness(true, "%s is %q, not %q", lbAltFrontGenerationHeader, reportedGeneration, generation)
	}
	switch reportedRevision := header.Get(lbAltFrontRouteRevisionHeader); reportedRevision {
	case revision:
	case "":
		return refuseLbAltReadiness(false, "no %s", lbAltFrontRouteRevisionHeader)
	default:
		return refuseLbAltReadiness(true, "%s is %q, not %q", lbAltFrontRouteRevisionHeader, reportedRevision, revision)
	}
	if ready := header.Get(lbAltFrontReadyHeader); ready != "1" {
		return refuseLbAltReadiness(false, "%s is %q, not 1", lbAltFrontReadyHeader, ready)
	}

	parseSockets := func(value string) (map[lbAltFrontSocket]lbAltFrontSocketCounts, error) {
		socketCounts := map[lbAltFrontSocket]lbAltFrontSocketCounts{}
		if strings.TrimSpace(value) == "" {
			return socketCounts, nil
		}
		for _, entry := range strings.Split(value, ",") {
			entry = strings.TrimSpace(entry)
			name, countsText, ok := strings.Cut(entry, "=")
			protocolEnd := strings.Index(name, "/")
			portStart := strings.LastIndex(name, "/")
			if !ok || protocolEnd <= 0 || portStart <= protocolEnd {
				return nil, fmt.Errorf("entry %q is not <protocol>/<address>/<port>=<up>/<expected>", entry)
			}
			address, err := netip.ParseAddr(name[protocolEnd+1 : portStart])
			if err != nil {
				return nil, fmt.Errorf("entry %q has no address", entry)
			}
			port, err := strconv.Atoi(name[portStart+1:])
			if err != nil || port < 1 || 65535 < port {
				return nil, fmt.Errorf("entry %q has no port", entry)
			}
			upText, expectedText, ok := strings.Cut(countsText, "/")
			up, upErr := strconv.Atoi(upText)
			expected, expectedErr := strconv.Atoi(expectedText)
			if !ok || upErr != nil || expectedErr != nil || up < 0 || expected < 0 {
				return nil, fmt.Errorf("entry %q has no <up>/<expected> counts", entry)
			}
			socket := lbAltFrontSocket{
				protocol: name[:protocolEnd],
				address:  address.Unmap(),
				port:     port,
			}
			if _, ok := socketCounts[socket]; ok {
				return nil, fmt.Errorf("entry %q repeats a socket", entry)
			}
			socketCounts[socket] = lbAltFrontSocketCounts{up: up, expected: expected}
		}
		return socketCounts, nil
	}
	socketCounts, err := parseSockets(header.Get(lbAltFrontSocketsHeader))
	if err != nil {
		return refuseLbAltReadiness(true, "%s: %s", lbAltFrontSocketsHeader, err)
	}
	for _, expectedSocket := range expectedSockets {
		counts, ok := socketCounts[expectedSocket]
		socketName := fmt.Sprintf("%s/%s/%d", expectedSocket.protocol, expectedSocket.address, expectedSocket.port)
		if !ok {
			return refuseLbAltReadiness(false, "%s does not list %s", lbAltFrontSocketsHeader, socketName)
		}
		if counts.up != socketsPerPort || counts.expected != socketsPerPort {
			return refuseLbAltReadiness(false, "socket %s is %d/%d, not %d/%d", socketName, counts.up, counts.expected, socketsPerPort, socketsPerPort)
		}
	}
	return nil
}

// Polls one candidate generation's private status until §2.4 accepts it.
type lbAltReadinessPoll struct {
	settings *LbAltSplitSettings
}

// A poll with the settings' bounds and intervals.
func newLbAltReadinessPoll(settings *LbAltSplitSettings) *lbAltReadinessPoll {
	return &lbAltReadinessPoll{
		settings: settings,
	}
}

// Polls every ReadinessPollInterval until the candidate is accepted, a
// refusal is definitive, the timeout passes or the context ends. A
// non-positive timeout polls once.
func (self *lbAltReadinessPoll) poll(ctx context.Context, statusUrl string, generation string, revision string, expected []lbAltExpectedSocket, timeout time.Duration) error {
	if generation == "" || revision == "" {
		return errors.New("lb_alt readiness needs the generation and the route revision")
	}
	if len(expected) == 0 {
		return errors.New("lb_alt readiness needs the expected sockets")
	}
	if self.settings.ReadinessPollInterval <= 0 {
		return errors.New("lb_alt readiness: the poll interval must be positive")
	}
	expectedSockets := make([]lbAltFrontSocket, 0, len(expected))
	for _, socket := range expected {
		address, err := netip.ParseAddr(socket.address)
		if err != nil || (socket.protocol != "tcp" && socket.protocol != "udp") || socket.port < 1 || 65535 < socket.port {
			return fmt.Errorf("lb_alt readiness: expected socket %s/%s/%d is not tcp or udp at an address and port", socket.protocol, socket.address, socket.port)
		}
		expectedSockets = append(expectedSockets, lbAltFrontSocket{
			protocol: socket.protocol,
			address:  address.Unmap(),
			port:     socket.port,
		})
	}

	client := &http.Client{
		Transport: &http.Transport{
			DialContext:       (&net.Dialer{Timeout: self.settings.ReadinessRequestTimeout}).DialContext,
			DisableKeepAlives: true,
		},
		Timeout: self.settings.ReadinessRequestTimeout,
	}
	deadline := time.Now().Add(timeout)
	for {
		err := self.check(ctx, client, statusUrl, generation, revision, expectedSockets)
		if err == nil {
			return nil
		}
		Err.Printf("Poll lb_alt readiness %s: %s\n", statusUrl, err)
		var refusal *lbAltReadinessRefusal
		if errors.As(err, &refusal) && refusal.definitive {
			return fmt.Errorf("lb_alt candidate %s refused: %w", generation, err)
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return fmt.Errorf("lb_alt candidate %s not ready within %s: %w", generation, timeout, err)
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("lb_alt candidate %s readiness poll stopped: %w", generation, ctx.Err())
		case <-time.After(min(self.settings.ReadinessPollInterval, remaining)):
		}
	}
}

// One status request and its acceptance.
func (self *lbAltReadinessPoll) check(ctx context.Context, client *http.Client, statusUrl string, generation string, revision string, expectedSockets []lbAltFrontSocket) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, statusUrl, nil)
	if err != nil {
		return err
	}
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, self.settings.ReadinessBodyByteLimit+1))
	if err != nil {
		return err
	}
	if self.settings.ReadinessBodyByteLimit < int64(len(body)) {
		return refuseLbAltReadiness(false, "status body is over %d bytes", self.settings.ReadinessBodyByteLimit)
	}
	return acceptLbAltStatus(response.StatusCode, response.Header, body, generation, revision, expectedSockets, self.settings.SocketsPerPort)
}
