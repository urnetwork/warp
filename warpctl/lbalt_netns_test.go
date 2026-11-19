package main

// The lb_alt network-namespace harness (server/LBALT.md §4.7 and §9:
// "Generations and chains", "Handover" and "Port contract";
// server/LBALT-IMPL.md §2.3-§2.5). It drives warpctl's real split writers
// (reconcileLbAltSplit, writeLbAltBlockChains, removeLbAltSplit), the lb
// unit's real routing, chain and nginx redirect code, and the socket and
// conntrack helpers, against the kernel's iptables and ip6tables (nf_tables,
// 1.8.10, as the edges run), iptables-restore, conntrack and ss, with real
// traffic both ways.
//
// Topology. Two Docker networks stand in for two public interfaces of an edge,
// each with an IPv4 and an IPv6 TEST-NET subnet (lbAltNetnsInterfaceSpecs):
//   - the edge container is the host. eth0 and eth1 carry the public
//     addresses. Bridges inside it stand in for the lb interface docker
//     networks (lbnet0, lbnet1) and warpservices, and fake connect blocks and
//     nginx lbs listen on the bridge addresses, as host-networked containers
//     do. The lb units' routing tables, policy rules and lb chains come from
//     warpctl's own initRoutingTable and initBlockRedirect, and the main table
//     has no default route, so a reply reaches a client only through its
//     interface's policy table, as on the edges.
//   - the client container dials from off-link source addresses, one in each
//     HMARK bucket in each family (lbAltNetnsSources), through both
//     interfaces. It runs the harness's client agent, which the edge tests
//     drive over a control connection.
//
// Both containers get only CAP_NET_ADMIN and CAP_NET_RAW. That allows no new
// network namespace inside a container, so the client is a container of its
// own. Each edge test (TestLbAltNetnsEdge*, lbalt_netns_linux_test.go) runs in
// a fresh edge container.
//
// The harness knows which block each source must reach: lbAltNetnsHmarkBucket
// is xt_HMARK's hash under the split's rule, and every flow checks it, so a
// change in what the kernel or iptables hashes fails the harness.
//
// Running it needs Docker with a Linux VM whose kernel has xt_HMARK (Docker
// Desktop's has), about 200 MB in the VM for the image, and free TEST-NET
// subnets (one run at a time):
//
//	cd warpctl
//	WARPCTL_LBALT_NETNS=1 GOFLAGS=-trimpath go test -count=1 -timeout 60m -run '^TestLbAltNetns$' -v .
//
// The test cross-compiles this package's test binary for the VM's Linux
// architecture with CGO off, builds the image from testdata/lbalt_netns once
// (tagged by a hash of its Dockerfile, and kept for the next run), and removes
// every container and network it made. WARPCTL_LBALT_NETNS_BINARY names a
// prebuilt linux test binary of this package, which skips the build, and
// WARPCTL_LBALT_NETNS_RUN a pattern that picks the edge tests to run. Without
// WARPCTL_LBALT_NETNS=1, or without a usable Docker, the test skips and says
// why.

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/rand/v2"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// The harness's environment variables: the opt-in, a prebuilt linux test
// binary, a pattern for the edge tests to run, and the role the test binary
// plays inside a harness container.
const (
	lbAltNetnsEnvName       = "WARPCTL_LBALT_NETNS"
	lbAltNetnsBinaryEnvName = "WARPCTL_LBALT_NETNS_BINARY"
	lbAltNetnsRunEnvName    = "WARPCTL_LBALT_NETNS_RUN"
	lbAltNetnsRoleEnvName   = "WARPCTL_LBALT_NETNS_ROLE"
)

// The edge test that runs with the sysctls that copy packet marks onto
// replies (lbAltNetnsMarkedReplySysctls).
const lbAltNetnsMarkedRepliesTestName = "TestLbAltNetnsEdgeRoutesRepliesThatCarryBucketMarks"

// The roles of the test binary inside the harness's containers.
const (
	lbAltNetnsEdgeRole   = "edge"
	lbAltNetnsClientRole = "client"
)

// The harness image's repository, its build context, and where the test
// binary goes in each container.
const (
	lbAltNetnsImageRepository = "warpctl-lbalt-netns"
	lbAltNetnsImageContext    = "testdata/lbalt_netns"
	lbAltNetnsBinaryPath      = "/usr/local/bin/warpctl-lbalt-netns.test"
)

// The line the client agent prints once it serves its control port, and the
// prefix of the lines edge tests log as facts for the harness's report.
const (
	lbAltNetnsClientReadyLine = "lbalt_netns client agent ready"
	lbAltNetnsFactPrefix      = "lbalt_netns fact"
)

// The client agent's control port, on its address on the first network.
const lbAltNetnsControlPort = 7900

// Tunables of the harness. Every bound only bounds a failure, so each is
// generous: the harness runs on a loaded workstation.
type lbAltNetnsSettings struct {
	// Bound on one docker command other than a build or an edge test.
	dockerCommandTimeout time.Duration
	// Bound on building the image, and on cross-compiling the test binary.
	buildTimeout time.Duration
	// Bound on one edge test in its container.
	edgeTestTimeout time.Duration
	// How long the harness waits for the client agent's ready line, and an edge
	// test for the agent's control connection.
	clientReadyTimeout time.Duration
	// Pause between an edge test's attempts to reach the client agent.
	clientRetryInterval time.Duration
	// Bound on one flow's dial, and on one exchange on it, in the client
	// agent. A flow that must not be answered waits this long.
	flowTimeout time.Duration
	// Flows the client agent dials or sends on at once.
	dialConcurrency int
	// The client agent's source ports, below the kernel's ephemeral range
	// (32768 on), handed out one per flow from each source address and never
	// again, so this many flows per source fit one harness run.
	firstSourcePort int
	lastSourcePort  int
	// Bound on a hook's wait for the step it holds a writer at.
	hookTimeout time.Duration
	// The most output of a failed edge test the harness reports, from its end.
	failureOutputByteLimit int
}

// The defaults, a new instance on every call.
func defaultLbAltNetnsSettings() *lbAltNetnsSettings {
	return &lbAltNetnsSettings{
		dockerCommandTimeout:   2 * time.Minute,
		buildTimeout:           20 * time.Minute,
		edgeTestTimeout:        15 * time.Minute,
		clientReadyTimeout:     2 * time.Minute,
		clientRetryInterval:    200 * time.Millisecond,
		flowTimeout:            3 * time.Second,
		dialConcurrency:        256,
		firstSourcePort:        20000,
		lastSourcePort:         32767,
		hookTimeout:            2 * time.Minute,
		failureOutputByteLimit: 64 * 1024,
	}
}

// The sysctls that copy a packet's mark onto replies: to the socket that
// accepts a tcp connection, and to the kernel's own resets and icmp errors.
// The kernel's defaults are off.
func lbAltNetnsMarkedReplySysctls() []string {
	return []string{
		"net.ipv4.tcp_fwmark_accept=1",
		"net.ipv4.fwmark_reflect=1",
		"net.ipv6.fwmark_reflect=1",
	}
}

// One public interface of the harness edge: the edge's interface on one Docker
// network, the lb interface bridge behind it, and the lb unit's routing table
// and mark (--rttable, --fwmark).
type lbAltNetnsInterfaceSpec struct {
	// the edge's interface, named by docker in connect order
	name string
	// the edge's public addresses, with the network's prefix
	publicIpv4 netip.Prefix
	publicIpv6 netip.Prefix
	// the client's addresses on the network: the edge's gateway towards the
	// client's sources
	clientIpv4 netip.Addr
	clientIpv6 netip.Addr
	// the interface's docker network bridge inside the edge, whose addresses
	// the blocks bind, with its prefix
	bridgeName  string
	bridgeIpv4  netip.Prefix
	bridgeIpv6  netip.Prefix
	tableNumber int
	fwMark      int
}

// The two public interfaces. Their marks are the edges' routing marks 0x65 and
// 0x66 (LBALT.md §7.1, M7).
func lbAltNetnsInterfaceSpecs() []*lbAltNetnsInterfaceSpec {
	return []*lbAltNetnsInterfaceSpec{
		&lbAltNetnsInterfaceSpec{
			name:        "eth0",
			publicIpv4:  netip.MustParsePrefix("198.51.100.2/28"),
			publicIpv6:  netip.MustParsePrefix("2001:db8:a::2/64"),
			clientIpv4:  netip.MustParseAddr("198.51.100.3"),
			clientIpv6:  netip.MustParseAddr("2001:db8:a::3"),
			bridgeName:  "lbnet0",
			bridgeIpv4:  netip.MustParsePrefix("192.0.2.1/28"),
			bridgeIpv6:  netip.MustParsePrefix("2001:db8:ba::1/64"),
			tableNumber: 101,
			fwMark:      0x65,
		},
		&lbAltNetnsInterfaceSpec{
			name:        "eth1",
			publicIpv4:  netip.MustParsePrefix("198.51.100.18/28"),
			publicIpv6:  netip.MustParsePrefix("2001:db8:b::2/64"),
			clientIpv4:  netip.MustParseAddr("198.51.100.19"),
			clientIpv6:  netip.MustParseAddr("2001:db8:b::3"),
			bridgeName:  "lbnet1",
			bridgeIpv4:  netip.MustParsePrefix("192.0.2.17/28"),
			bridgeIpv6:  netip.MustParsePrefix("2001:db8:bb::1/64"),
			tableNumber: 102,
			fwMark:      0x66,
		},
	}
}

// Drives the harness from the host: Docker, the image, the networks and the
// containers of one run.
type lbAltNetnsHarness struct {
	t        *testing.T
	settings *lbAltNetnsSettings
	// what every container and network of this run is named after
	namePrefix string
	image      string
	binaryPath string
	// the docker network of each interface spec, in spec order
	networkNames []string
	clientName   string
}

// Runs every edge test of lbalt_netns_linux_test.go, each in a fresh edge
// container, against one client container. Opt-in: see the file comment.
func TestLbAltNetns(t *testing.T) {
	if os.Getenv(lbAltNetnsEnvName) != "1" {
		t.Skipf("the lb_alt network-namespace harness runs only with %s=1 and Docker (lbalt_netns_test.go)", lbAltNetnsEnvName)
	}
	if os.Getenv(lbAltNetnsRoleEnvName) != "" {
		t.Skip("already inside a harness container")
	}
	harness := &lbAltNetnsHarness{
		t:            t,
		settings:     defaultLbAltNetnsSettings(),
		namePrefix:   fmt.Sprintf("warpctl-lbalt-netns-%08x", rand.Uint32()),
		image:        "",
		binaryPath:   "",
		networkNames: []string{},
		clientName:   "",
	}
	goArch := harness.dockerGoArch()
	harness.buildBinary(goArch)
	harness.ensureImage()
	harness.createNetworks()
	harness.startClient()
	edgeTestNames := harness.listEdgeTests()
	for i, edgeTestName := range edgeTestNames {
		harness.runEdgeTest(i, edgeTestName)
	}
	t.Logf("%d edge tests ran", len(edgeTestNames))
}

// Runs a command within the timeout, and returns its combined output.
func (self *lbAltNetnsHarness) command(timeout time.Duration, dir string, env []string, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = dir
	if env != nil {
		cmd.Env = env
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("%s %s: %w", name, strings.Join(args, " "), err)
	}
	return string(out), nil
}

// Runs docker within the docker command bound.
func (self *lbAltNetnsHarness) docker(args ...string) (string, error) {
	return self.command(self.settings.dockerCommandTimeout, "", nil, "docker", args...)
}

// The Go architecture of Docker's Linux VM. Skips the test when Docker is not
// usable or its VM is not Linux on arm64 or amd64.
func (self *lbAltNetnsHarness) dockerGoArch() string {
	out, err := self.docker("info", "--format", "{{.OSType}}/{{.Architecture}}")
	if err != nil {
		self.t.Skipf("Docker is not usable: %s: %s", err, strings.TrimSpace(out))
	}
	switch strings.TrimSpace(out) {
	case "linux/aarch64", "linux/arm64":
		return "arm64"
	case "linux/x86_64", "linux/amd64":
		return "amd64"
	}
	self.t.Skipf("Docker's VM is %s, not Linux on arm64 or amd64", strings.TrimSpace(out))
	return ""
}

// Cross-compiles this package's test binary for the VM, or takes the prebuilt
// one WARPCTL_LBALT_NETNS_BINARY names. The build inherits GOFLAGS and
// GOCACHE.
func (self *lbAltNetnsHarness) buildBinary(goArch string) {
	if binaryPath := os.Getenv(lbAltNetnsBinaryEnvName); binaryPath != "" {
		if _, err := os.Stat(binaryPath); err != nil {
			self.t.Fatalf("%s: %s", lbAltNetnsBinaryEnvName, err)
		}
		self.binaryPath = binaryPath
		return
	}
	goCommand, err := exec.LookPath("go")
	if err != nil {
		self.t.Fatalf("no go command to build the linux test binary: %s", err)
	}
	binaryPath := filepath.Join(self.t.TempDir(), "warpctl-lbalt-netns.test")
	env := append(os.Environ(), "GOOS=linux", "GOARCH="+goArch, "CGO_ENABLED=0")
	started := time.Now()
	if out, err := self.command(self.settings.buildTimeout, ".", env, goCommand, "test", "-c", "-o", binaryPath, "."); err != nil {
		self.t.Fatalf("build the linux test binary: %s\n%s", err, out)
	}
	self.t.Logf("built the linux/%s test binary in %s", goArch, time.Since(started).Round(time.Second))
	self.binaryPath = binaryPath
}

// The image, built from testdata/lbalt_netns when no image has its Dockerfile's
// hash as its tag.
func (self *lbAltNetnsHarness) ensureImage() {
	dockerfile, err := os.ReadFile(filepath.Join(lbAltNetnsImageContext, "Dockerfile"))
	if err != nil {
		self.t.Fatal(err)
	}
	dockerfileHash := sha256.Sum256(dockerfile)
	self.image = fmt.Sprintf("%s:%s", lbAltNetnsImageRepository, hex.EncodeToString(dockerfileHash[:])[:12])
	if _, err := self.docker("image", "inspect", self.image); err == nil {
		return
	}
	if out, err := self.command(self.settings.buildTimeout, "", nil, "docker", "build", "--pull=false", "-t", self.image, lbAltNetnsImageContext); err != nil {
		self.t.Fatalf("build the harness image: %s\n%s", err, out)
	}
}

// One docker network per interface spec, with its IPv4 and IPv6 subnets.
func (self *lbAltNetnsHarness) createNetworks() {
	for _, spec := range lbAltNetnsInterfaceSpecs() {
		networkName := fmt.Sprintf("%s-%s", self.namePrefix, spec.name)
		out, err := self.docker(
			"network", "create",
			"--ipv6",
			"--subnet", spec.publicIpv4.Masked().String(),
			"--subnet", spec.publicIpv6.Masked().String(),
			networkName,
		)
		if err != nil {
			self.t.Fatalf("create network %s: %s\n%s\nanother run of the harness, or a network a stopped run left (docker network ls --filter name=%s), may hold its TEST-NET subnets", networkName, err, out, lbAltNetnsImageRepository)
		}
		self.networkNames = append(self.networkNames, networkName)
		self.t.Cleanup(func() {
			if out, err := self.docker("network", "rm", networkName); err != nil {
				self.t.Errorf("remove network %s: %s\n%s", networkName, err, out)
			}
		})
	}
}

// Starts a container on every network, at the addresses given per spec, with
// only CAP_NET_ADMIN and CAP_NET_RAW and the extra sysctls, and copies the test
// binary into it. It is removed at the test's end if nothing removed it
// before.
func (self *lbAltNetnsHarness) startContainer(containerName string, addresses func(spec *lbAltNetnsInterfaceSpec) (netip.Addr, netip.Addr), extraSysctls []string) {
	specs := lbAltNetnsInterfaceSpecs()
	firstIpv4, firstIpv6 := addresses(specs[0])
	self.t.Cleanup(func() {
		self.docker("rm", "-f", containerName)
	})
	runArgs := []string{
		"run", "-d",
		"--name", containerName,
		"--cap-add", "NET_ADMIN",
		"--cap-add", "NET_RAW",
		"--network", self.networkNames[0],
		"--ip", firstIpv4.String(),
		"--ip6", firstIpv6.String(),
	}
	for _, sysctl := range append([]string{
		"net.ipv6.conf.all.disable_ipv6=0",
		"net.ipv6.conf.default.disable_ipv6=0",
		"net.ipv4.conf.all.rp_filter=0",
		"net.ipv4.conf.default.rp_filter=0",
	}, extraSysctls...) {
		runArgs = append(runArgs, "--sysctl", sysctl)
	}
	runArgs = append(runArgs, self.image, "sleep", "infinity")
	if out, err := self.docker(runArgs...); err != nil {
		self.t.Fatalf("start %s: %s\n%s", containerName, err, out)
	}
	for i, spec := range specs[1:] {
		ipv4, ipv6 := addresses(spec)
		if out, err := self.docker("network", "connect", "--ip", ipv4.String(), "--ip6", ipv6.String(), self.networkNames[i+1], containerName); err != nil {
			self.t.Fatalf("connect %s to %s: %s\n%s", containerName, self.networkNames[i+1], err, out)
		}
	}
	if out, err := self.docker("cp", self.binaryPath, containerName+":"+lbAltNetnsBinaryPath); err != nil {
		self.t.Fatalf("copy the test binary into %s: %s\n%s", containerName, err, out)
	}
}

// Starts the client container and its agent, and waits for the agent's ready
// line. The agent runs until its stdin closes at the test's end.
func (self *lbAltNetnsHarness) startClient() {
	self.clientName = self.namePrefix + "-client"
	self.startContainer(self.clientName, func(spec *lbAltNetnsInterfaceSpec) (netip.Addr, netip.Addr) {
		return spec.clientIpv4, spec.clientIpv6
	}, nil)

	ctx, cancel := context.WithCancel(context.Background())
	agent := exec.CommandContext(
		ctx,
		"docker", "exec", "-i",
		"-e", lbAltNetnsRoleEnvName+"="+lbAltNetnsClientRole,
		self.clientName,
		lbAltNetnsBinaryPath,
		"-test.run", "^TestLbAltNetnsClientAgent$",
		"-test.v",
		"-test.timeout", "0",
	)
	stdin, err := agent.StdinPipe()
	if err != nil {
		self.t.Fatal(err)
	}
	stdout, err := agent.StdoutPipe()
	if err != nil {
		self.t.Fatal(err)
	}
	agent.Stderr = agent.Stdout
	if err := agent.Start(); err != nil {
		self.t.Fatal(err)
	}

	outputLock := sync.Mutex{}
	output := &bytes.Buffer{}
	ready := make(chan struct{})
	scanned := make(chan struct{})
	go func() {
		defer close(scanned)
		readyOnce := sync.Once{}
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			line := scanner.Text()
			func() {
				outputLock.Lock()
				defer outputLock.Unlock()
				output.WriteString(line + "\n")
			}()
			if strings.Contains(line, lbAltNetnsClientReadyLine) {
				readyOnce.Do(func() {
					close(ready)
				})
			}
		}
	}()
	agentOutput := func() string {
		outputLock.Lock()
		defer outputLock.Unlock()
		return output.String()
	}
	self.t.Cleanup(func() {
		stdin.Close()
		select {
		case <-scanned:
		case <-time.After(self.settings.dockerCommandTimeout):
		}
		cancel()
		agent.Wait()
		if self.t.Failed() {
			self.t.Logf("client agent output:\n%s", lbAltNetnsTail(agentOutput(), self.settings.failureOutputByteLimit))
		}
	})

	select {
	case <-ready:
	case <-scanned:
		self.t.Fatalf("the client agent ended before it was ready:\n%s", agentOutput())
	case <-time.After(self.settings.clientReadyTimeout):
		self.t.Fatalf("the client agent was not ready within %s:\n%s", self.settings.clientReadyTimeout, agentOutput())
	}
}

// The edge tests the binary holds, listed by the binary itself in the client
// container: all of them, or those WARPCTL_LBALT_NETNS_RUN matches.
func (self *lbAltNetnsHarness) listEdgeTests() []string {
	pattern := os.Getenv(lbAltNetnsRunEnvName)
	if pattern == "" {
		pattern = "^TestLbAltNetnsEdge"
	}
	out, err := self.docker("exec", self.clientName, lbAltNetnsBinaryPath, "-test.list", pattern)
	if err != nil {
		self.t.Fatalf("list the edge tests: %s\n%s", err, out)
	}
	edgeTestNames := []string{}
	for _, line := range strings.Split(out, "\n") {
		if line = strings.TrimSpace(line); strings.HasPrefix(line, "TestLbAltNetnsEdge") {
			edgeTestNames = append(edgeTestNames, line)
		}
	}
	if len(edgeTestNames) == 0 {
		self.t.Fatalf("the test binary lists no edge tests:\n%s", out)
	}
	return edgeTestNames
}

// Runs one edge test in a fresh edge container, logs the facts it reported,
// and fails with the end of its output when it fails.
func (self *lbAltNetnsHarness) runEdgeTest(index int, edgeTestName string) {
	edgeName := fmt.Sprintf("%s-edge%d", self.namePrefix, index)
	extraSysctls := []string{}
	if edgeTestName == lbAltNetnsMarkedRepliesTestName {
		extraSysctls = lbAltNetnsMarkedReplySysctls()
	}
	self.startContainer(edgeName, func(spec *lbAltNetnsInterfaceSpec) (netip.Addr, netip.Addr) {
		return spec.publicIpv4.Addr(), spec.publicIpv6.Addr()
	}, extraSysctls)
	defer self.docker("rm", "-f", edgeName)

	started := time.Now()
	out, err := self.command(
		self.settings.edgeTestTimeout+self.settings.dockerCommandTimeout,
		"",
		nil,
		"docker", "exec",
		"-e", lbAltNetnsRoleEnvName+"="+lbAltNetnsEdgeRole,
		edgeName,
		lbAltNetnsBinaryPath,
		"-test.run", "^"+edgeTestName+"$",
		"-test.v",
		"-test.count", "1",
		"-test.timeout", self.settings.edgeTestTimeout.String(),
	)
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, lbAltNetnsFactPrefix) {
			self.t.Log(strings.TrimSpace(line))
		}
	}
	switch {
	case err != nil:
		self.t.Errorf("%s failed: %s\n%s", edgeTestName, err, lbAltNetnsTail(out, self.settings.failureOutputByteLimit))
	case !strings.Contains(out, "--- PASS: "+edgeTestName):
		self.t.Errorf("%s did not pass:\n%s", edgeTestName, lbAltNetnsTail(out, self.settings.failureOutputByteLimit))
	default:
		self.t.Logf("%s passed in %s", edgeTestName, time.Since(started).Round(time.Second))
	}
}

// The end of the text, at most byteLimit bytes.
func lbAltNetnsTail(text string, byteLimit int) string {
	if len(text) <= byteLimit {
		return text
	}
	return "...\n" + text[len(text)-byteLimit:]
}
