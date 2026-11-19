package main

// The two sides of the lb_alt network-namespace harness (lbalt_netns_test.go)
// that run inside its containers.
//
// The client agent (TestLbAltNetnsClientAgent) puts every source address on a
// dummy interface and serves control sessions: an edge test asks it to make
// flows, exchange again on kept flows, and close them. A tcp flow sends a line
// and reads the answer line; a udp flow sends a datagram from an unconnected
// socket and reads the answer datagram and its source, so a reply from any
// other address than the public one dialed shows.
//
// The edge (newLbAltNetnsEdge) builds the host an lb_alt interface runs on:
// the bridges, then the lb units' routing tables, policy rules, masquerade and
// lb chains from warpctl's own initRoutingTable and initBlockRedirect. Fake
// generations of connect blocks and nginx lbs listen on the bridges and answer
// with their name, generation and the local address that took the flow, so
// each answer shows which DNAT target a flow reached. Probes compare every
// answer with the generation the split, nginx or nothing must give it.

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/urnetwork/warp"
	"github.com/urnetwork/warp/services"
)

// The env the harness's chains and locks are named for.
const lbAltNetnsEnv = "test"

// The services bridge, IPv4 only as warpservices is, where a connect
// generation keeps its trusted sockets.
const (
	lbAltNetnsServicesBridgeName = "warpservices"
	lbAltNetnsServicesBridge     = "192.0.2.33/28"
)

// The dummy interface the client's source addresses are on.
const lbAltNetnsSourceInterfaceName = "src0"

// The control operations of a session.
const (
	lbAltNetnsDialOp  = "dial"
	lbAltNetnsSendOp  = "send"
	lbAltNetnsCloseOp = "close"
)

// The comments of the harness's own counting rules start with this. The split
// never matches them: its rules carry warp-<env>-lba-<iface>.
const lbAltNetnsCounterCommentPrefix = "lbalt-netns-"

// One flow the client agent makes: a dial from a source address to a public
// address and port, with one exchange, kept open for later exchanges when Keep
// is set.
type lbAltNetnsFlow struct {
	Id       string `json:"id"`
	Protocol string `json:"protocol"`
	Source   string `json:"source"`
	Target   string `json:"target"`
	Keep     bool   `json:"keep"`
}

// What one exchange on a flow got. Answer is empty when nothing answered.
type lbAltNetnsFlowResult struct {
	Id     string `json:"id"`
	Answer string `json:"answer"`
	// for udp the answer datagram's source, for tcp the connection's peer
	ReplyFrom string `json:"reply_from"`
	// the client's own address and port of the flow
	Local string `json:"local"`
	Error string `json:"error"`
}

// One request of a control session: dial flows, exchange again on kept flows
// (send), or close kept flows.
type lbAltNetnsRequest struct {
	Op    string           `json:"op"`
	Flows []lbAltNetnsFlow `json:"flows"`
	Ids   []string         `json:"ids"`
}

// The answer to a request: one result per flow or id, in request order.
type lbAltNetnsResponse struct {
	Results []lbAltNetnsFlowResult `json:"results"`
	Error   string                 `json:"error"`
}

// Runs each in its own goroutine, at most concurrency at once, and returns the
// results in order.
func lbAltNetnsParallel[T any](count int, concurrency int, each func(i int) T) []T {
	results := make([]T, count)
	slots := make(chan struct{}, max(concurrency, 1))
	group := sync.WaitGroup{}
	for i := range count {
		slots <- struct{}{}
		group.Add(1)
		go func() {
			defer group.Done()
			defer func() {
				<-slots
			}()
			results[i] = each(i)
		}()
	}
	group.Wait()
	return results
}

// Runs a command and returns its combined output, or an error that carries it.
func lbAltNetnsCommand(stdin string, name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}

// Runs `ip -batch -` with the lines.
func lbAltNetnsIpBatch(t *testing.T, lines []string) {
	t.Helper()
	if _, err := lbAltNetnsCommand(strings.Join(lines, "\n")+"\n", "ip", "-batch", "-"); err != nil {
		t.Fatal(err)
	}
}

// Removes every default route, so traffic leaves only towards the harness's
// other container, by a connected route or a policy table.
func lbAltNetnsDeleteDefaultRoutes() {
	for _, family := range []string{"-4", "-6"} {
		for {
			if _, err := lbAltNetnsCommand("", "ip", family, "route", "del", "default"); err != nil {
				break
			}
		}
	}
}

// A listen config whose sockets share their port with SO_REUSEPORT, as
// connect's public sockets do within a block (D10).
func lbAltNetnsReusePortConfig() *net.ListenConfig {
	return &net.ListenConfig{
		Control: func(network string, address string, rawConn syscall.RawConn) error {
			var socketErr error
			if err := rawConn.Control(func(fd uintptr) {
				socketErr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEPORT, 1)
			}); err != nil {
				return err
			}
			return socketErr
		},
	}
}

// "4" or "6", the family suffix of a network name such as tcp4.
func lbAltNetnsFamilySuffix(address netip.Addr) string {
	if address.Is4() {
		return "4"
	}
	return "6"
}

// The client agent of the harness: it puts every source address on a dummy
// interface, removes the default routes, and serves the edge tests' control
// sessions until its stdin closes. A session's kept flows close with it.
// Skips outside the harness's client container.
func TestLbAltNetnsClientAgent(t *testing.T) {
	if os.Getenv(lbAltNetnsRoleEnvName) != lbAltNetnsClientRole {
		t.Skip("the client agent runs only in the harness's client container (TestLbAltNetns)")
	}
	settings := defaultLbAltNetnsSettings()

	batchLines := []string{
		fmt.Sprintf("link add %s type dummy", lbAltNetnsSourceInterfaceName),
		fmt.Sprintf("link set %s up", lbAltNetnsSourceInterfaceName),
	}
	for _, ipv6 := range []bool{false, true} {
		sources, err := lbAltNetnsSources(ipv6)
		if err != nil {
			t.Fatal(err)
		}
		for _, source := range sources {
			if ipv6 {
				batchLines = append(batchLines, fmt.Sprintf("addr add %s/128 dev %s nodad", source, lbAltNetnsSourceInterfaceName))
			} else {
				batchLines = append(batchLines, fmt.Sprintf("addr add %s/32 dev %s", source, lbAltNetnsSourceInterfaceName))
			}
		}
	}
	lbAltNetnsIpBatch(t, batchLines)
	lbAltNetnsDeleteDefaultRoutes()

	controlAddress := netip.AddrPortFrom(lbAltNetnsInterfaceSpecs()[0].clientIpv4, lbAltNetnsControlPort)
	listener, err := net.Listen("tcp4", controlAddress.String())
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		io.Copy(io.Discard, os.Stdin)
		listener.Close()
	}()
	fmt.Println(lbAltNetnsClientReadyLine)
	sourcePorts := newLbAltNetnsSourcePorts(settings)
	for {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		go func() {
			session := &lbAltNetnsAgentSession{
				settings:    settings,
				sourcePorts: sourcePorts,
				idKeptFlows: map[string]*lbAltNetnsKeptFlow{},
			}
			if err := session.serve(conn); err != nil {
				fmt.Printf("lbalt_netns client session: %s\n", err)
			}
		}()
	}
}

// One control session of the client agent.
type lbAltNetnsAgentSession struct {
	settings *lbAltNetnsSettings
	// nil for ephemeral source ports
	sourcePorts *lbAltNetnsSourcePorts
	stateLock   sync.Mutex
	idKeptFlows map[string]*lbAltNetnsKeptFlow
}

// Hands out the client's source ports: a new one for every flow from a source
// address, never one the source used before. A new udp flow on an earlier
// flow's tuple would follow that flow's conntrack entry, and so its DNAT,
// while the entry lives; an ephemeral port can repeat within that time.
// Safe for concurrent use.
type lbAltNetnsSourcePorts struct {
	first           int
	last            int
	stateLock       sync.Mutex
	sourceNextPorts map[netip.Addr]int
}

// Source ports from the settings' range, below the kernel's ephemeral ports.
func newLbAltNetnsSourcePorts(settings *lbAltNetnsSettings) *lbAltNetnsSourcePorts {
	return &lbAltNetnsSourcePorts{
		first:           settings.firstSourcePort,
		last:            settings.lastSourcePort,
		sourceNextPorts: map[netip.Addr]int{},
	}
}

// The source's next unused port.
func (self *lbAltNetnsSourcePorts) next(source netip.Addr) (int, error) {
	port := 0
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		nextPort, ok := self.sourceNextPorts[source]
		if !ok {
			nextPort = self.first
		}
		if nextPort <= self.last {
			port = nextPort
			self.sourceNextPorts[source] = nextPort + 1
		}
	}()
	if port == 0 {
		return 0, fmt.Errorf("source %s has used every port up to %d", source, self.last)
	}
	return port, nil
}

// A flow the client has open: a tcp connection, or a udp socket and its target.
type lbAltNetnsKeptFlow struct {
	protocol  string
	tcpConn   net.Conn
	tcpReader *bufio.Reader
	udpConn   *net.UDPConn
	target    netip.AddrPort
	local     string
	// exchanges so far, which tell an answer apart from a late one
	exchangeCount int
}

// Serves the session's requests until the edge closes it. The neighbor caches
// are flushed first: each edge test brings a new edge container with the same
// addresses.
func (self *lbAltNetnsAgentSession) serve(conn net.Conn) error {
	defer conn.Close()
	defer func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		for _, keptFlow := range self.idKeptFlows {
			keptFlow.close()
		}
		self.idKeptFlows = map[string]*lbAltNetnsKeptFlow{}
	}()
	for _, family := range []string{"-4", "-6"} {
		// an empty cache is not an error to the session
		lbAltNetnsCommand("", "ip", family, "neigh", "flush", "all")
	}
	decoder := json.NewDecoder(bufio.NewReader(conn))
	encoder := json.NewEncoder(conn)
	for {
		request := &lbAltNetnsRequest{}
		if err := decoder.Decode(request); err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		response := &lbAltNetnsResponse{
			Results: []lbAltNetnsFlowResult{},
			Error:   "",
		}
		switch request.Op {
		case lbAltNetnsDialOp:
			response.Results = lbAltNetnsParallel(len(request.Flows), self.settings.dialConcurrency, func(i int) lbAltNetnsFlowResult {
				return self.dial(request.Flows[i])
			})
		case lbAltNetnsSendOp:
			response.Results = lbAltNetnsParallel(len(request.Ids), self.settings.dialConcurrency, func(i int) lbAltNetnsFlowResult {
				return self.send(request.Ids[i])
			})
		case lbAltNetnsCloseOp:
			func() {
				self.stateLock.Lock()
				defer self.stateLock.Unlock()
				for _, id := range request.Ids {
					if keptFlow, ok := self.idKeptFlows[id]; ok {
						keptFlow.close()
						delete(self.idKeptFlows, id)
					}
				}
			}()
		default:
			response.Error = fmt.Sprintf("unknown op %q", request.Op)
		}
		if err := encoder.Encode(response); err != nil {
			return err
		}
	}
}

// Makes the flow and its first exchange, and keeps it when asked to and the
// exchange got an answer.
func (self *lbAltNetnsAgentSession) dial(flow lbAltNetnsFlow) lbAltNetnsFlowResult {
	failure := func(err error) lbAltNetnsFlowResult {
		return lbAltNetnsFlowResult{
			Id:        flow.Id,
			Answer:    "",
			ReplyFrom: "",
			Local:     "",
			Error:     err.Error(),
		}
	}
	source, err := netip.ParseAddr(flow.Source)
	if err != nil {
		return failure(err)
	}
	target, err := netip.ParseAddrPort(flow.Target)
	if err != nil {
		return failure(err)
	}
	sourcePort := 0
	if self.sourcePorts != nil {
		if sourcePort, err = self.sourcePorts.next(source); err != nil {
			return failure(err)
		}
	}
	local := netip.AddrPortFrom(source, uint16(sourcePort))
	keptFlow := &lbAltNetnsKeptFlow{
		protocol: flow.Protocol,
		target:   target,
	}
	switch flow.Protocol {
	case "tcp":
		dialer := &net.Dialer{
			LocalAddr: net.TCPAddrFromAddrPort(local),
			Timeout:   self.settings.flowTimeout,
		}
		conn, err := dialer.Dial("tcp"+lbAltNetnsFamilySuffix(source), target.String())
		if err != nil {
			return failure(err)
		}
		keptFlow.tcpConn = conn
		keptFlow.tcpReader = bufio.NewReader(conn)
		keptFlow.local = conn.LocalAddr().String()
	case "udp":
		conn, err := net.ListenUDP("udp"+lbAltNetnsFamilySuffix(source), net.UDPAddrFromAddrPort(local))
		if err != nil {
			return failure(err)
		}
		keptFlow.udpConn = conn
		keptFlow.local = conn.LocalAddr().String()
	default:
		return failure(fmt.Errorf("unknown protocol %q", flow.Protocol))
	}
	result := keptFlow.exchange(flow.Id, self.settings.flowTimeout)
	if !flow.Keep || result.Answer == "" {
		keptFlow.close()
		return result
	}
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.idKeptFlows[flow.Id] = keptFlow
	}()
	return result
}

// Exchanges again on a kept flow. The flow stays kept whatever the exchange
// gets, so a later exchange on the same tuple can follow.
func (self *lbAltNetnsAgentSession) send(id string) lbAltNetnsFlowResult {
	var keptFlow *lbAltNetnsKeptFlow
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		keptFlow = self.idKeptFlows[id]
	}()
	if keptFlow == nil {
		return lbAltNetnsFlowResult{
			Id:        id,
			Answer:    "",
			ReplyFrom: "",
			Local:     "",
			Error:     "no kept flow",
		}
	}
	return keptFlow.exchange(id, self.settings.flowTimeout)
}

// Sends "<id>#<exchange>" and reads the answer to it: the answering
// generation's line, which ends with the request it answers. A udp answer to
// an earlier exchange is skipped.
func (self *lbAltNetnsKeptFlow) exchange(id string, timeout time.Duration) lbAltNetnsFlowResult {
	self.exchangeCount += 1
	request := fmt.Sprintf("%s#%d", id, self.exchangeCount)
	result := lbAltNetnsFlowResult{
		Id:        id,
		Answer:    "",
		ReplyFrom: "",
		Local:     self.local,
		Error:     "",
	}
	deadline := time.Now().Add(timeout)
	switch self.protocol {
	case "tcp":
		self.tcpConn.SetDeadline(deadline)
		if _, err := self.tcpConn.Write([]byte(request + "\n")); err != nil {
			result.Error = err.Error()
			return result
		}
		line, err := self.tcpReader.ReadString('\n')
		if err != nil {
			result.Error = err.Error()
			return result
		}
		answer, answered, ok := strings.Cut(strings.TrimSpace(line), " | ")
		if !ok || answered != request {
			result.Error = fmt.Sprintf("answer %q is not to %q", line, request)
			return result
		}
		result.Answer = answer
		result.ReplyFrom = self.tcpConn.RemoteAddr().String()
	case "udp":
		self.udpConn.SetDeadline(deadline)
		if _, err := self.udpConn.WriteToUDPAddrPort([]byte(request), self.target); err != nil {
			result.Error = err.Error()
			return result
		}
		buffer := make([]byte, 64*1024)
		for {
			n, from, err := self.udpConn.ReadFromUDPAddrPort(buffer)
			if err != nil {
				result.Error = err.Error()
				return result
			}
			answer, answered, ok := strings.Cut(string(buffer[:n]), " | ")
			if !ok || answered != request {
				continue
			}
			result.Answer = answer
			result.ReplyFrom = netip.AddrPortFrom(from.Addr().Unmap(), from.Port()).String()
			return result
		}
	}
	return result
}

// Closes the flow's socket.
func (self *lbAltNetnsKeptFlow) close() {
	if self.tcpConn != nil {
		self.tcpConn.Close()
	}
	if self.udpConn != nil {
		self.udpConn.Close()
	}
}

// The edge's control session with the client agent. Requests run one at a
// time, on the test's goroutine.
type lbAltNetnsClient struct {
	conn    net.Conn
	decoder *json.Decoder
	encoder *json.Encoder
}

// Sends one request and reads its response.
func (self *lbAltNetnsClient) do(request *lbAltNetnsRequest) (*lbAltNetnsResponse, error) {
	if err := self.encoder.Encode(request); err != nil {
		return nil, err
	}
	response := &lbAltNetnsResponse{}
	if err := self.decoder.Decode(response); err != nil {
		return nil, err
	}
	if response.Error != "" {
		return nil, errors.New(response.Error)
	}
	return response, nil
}

// The block weights of the harness: main's connect blocks (LBALT.md §3.1), so
// beta holds one bucket.
func lbAltNetnsBlockWeights() []services.BlockWeight {
	return []services.BlockWeight{
		services.BlockWeight{Block: "beta", Weight: 1},
		services.BlockWeight{Block: "g1", Weight: 24},
		services.BlockWeight{Block: "g2", Weight: 25},
		services.BlockWeight{Block: "g3", Weight: 25},
		services.BlockWeight{Block: "g4", Weight: 25},
	}
}

// One public (protocol, port) of an lb_alt interface.
type lbAltNetnsPublicPort struct {
	protocol string
	port     int
}

// The public ports of an lb_alt interface, from the §2.3 table the block
// workers write their chains from (lbAltWorkerPublicTargets).
func lbAltNetnsPublicPorts() []lbAltNetnsPublicPort {
	publicPorts := []lbAltNetnsPublicPort{}
	for _, publicTarget := range lbAltWorkerPublicTargets() {
		publicPorts = append(publicPorts, lbAltNetnsPublicPort{
			protocol: publicTarget.protocol,
			port:     publicTarget.publicPort,
		})
	}
	return publicPorts
}

// The ports a generation listens on: its internal ports for service ports 80
// (http), 443 (tls on tcp, quic on udp) and 4053 (whodis), as WARP_PORTS
// gives them.
type lbAltNetnsPorts struct {
	http   int
	tls    int
	whodis int
}

// The generation's port for a public (protocol, port), by the §2.3 table: tcp
// 80 to http, tcp and udp 443 to tls, udp 4053 and 53 to whodis; 0 for none.
func (self lbAltNetnsPorts) forPublic(protocol string, publicPort int) int {
	switch {
	case protocol == "tcp" && publicPort == 80:
		return self.http
	case publicPort == 443:
		return self.tls
	case protocol == "udp" && (publicPort == 4053 || publicPort == 53):
		return self.whodis
	}
	return 0
}

// The internal ports by service port, as WARP_PORTS gives them.
func (self lbAltNetnsPorts) serviceInternalPorts() map[int]int {
	return map[int]int{
		lbAltWorkerHttpServicePort:   self.http,
		lbAltWorkerHttpsServicePort:  self.tls,
		lbAltWorkerWhodisServicePort: self.whodis,
	}
}

// One generation of a fake connect block or nginx lb. It listens on its
// public addresses with socketsPerPort SO_REUSEPORT sockets for each of tcp
// http, tcp and udp tls, and udp whodis, as connect does (D10). A connect
// generation also keeps trusted sockets on the services bridge for its
// lifetime (§2.3: private H1, the PROXY-reading udp 443 and 4053), so its
// ports stay held while its public sockets are down. It answers each request
// line or datagram with "<name>/<generation> <protocol> <local address:port> |
// <request>": the local address shows the DNAT target the flow reached.
type lbAltNetnsGeneration struct {
	name            string
	generation      int
	ports           lbAltNetnsPorts
	publicAddresses []netip.Addr
	// invalid for an nginx generation
	trustedAddress netip.Addr
	socketsPerPort int

	stateLock      sync.Mutex
	publicSockets  []*lbAltNetnsSocket
	trustedClosers []io.Closer
	// accepted connections, closed when the generation retires
	acceptedConns map[net.Conn]bool
	retired       bool
}

// One listening socket of a generation.
type lbAltNetnsSocket struct {
	protocol string
	closer   io.Closer
}

// The generation's answer to a request taken on the local address.
func (self *lbAltNetnsGeneration) answer(protocol string, local netip.AddrPort) string {
	return fmt.Sprintf("%s/%d %s %s", self.name, self.generation, protocol, local)
}

// Listens on one (protocol, address, port) with count sockets, and serves
// them. Returns their closers.
func (self *lbAltNetnsGeneration) listen(protocol string, address netip.Addr, port int, count int) ([]io.Closer, error) {
	listenConfig := lbAltNetnsReusePortConfig()
	addressPort := netip.AddrPortFrom(address, uint16(port))
	network := protocol + lbAltNetnsFamilySuffix(address)
	closers := []io.Closer{}
	for range count {
		switch protocol {
		case "tcp":
			listener, err := listenConfig.Listen(context.Background(), network, addressPort.String())
			if err != nil {
				return closers, err
			}
			closers = append(closers, listener)
			go self.serveTcp(listener)
		case "udp":
			packetConn, err := listenConfig.ListenPacket(context.Background(), network, addressPort.String())
			if err != nil {
				return closers, err
			}
			closers = append(closers, packetConn)
			go self.serveUdp(packetConn.(*net.UDPConn))
		}
	}
	return closers, nil
}

// Answers every line on every connection the listener accepts.
func (self *lbAltNetnsGeneration) serveTcp(listener net.Listener) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		accepted := func() bool {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			if self.retired {
				return false
			}
			self.acceptedConns[conn] = true
			return true
		}()
		if !accepted {
			conn.Close()
			continue
		}
		go func() {
			defer func() {
				self.stateLock.Lock()
				defer self.stateLock.Unlock()
				delete(self.acceptedConns, conn)
			}()
			defer conn.Close()
			localAddress := conn.LocalAddr().(*net.TCPAddr).AddrPort()
			local := netip.AddrPortFrom(localAddress.Addr().Unmap(), localAddress.Port())
			reader := bufio.NewReader(conn)
			for {
				line, err := reader.ReadString('\n')
				if err != nil {
					return
				}
				if _, err := conn.Write([]byte(self.answer("tcp", local) + " | " + strings.TrimSpace(line) + "\n")); err != nil {
					return
				}
			}
		}()
	}
}

// Answers every datagram.
func (self *lbAltNetnsGeneration) serveUdp(conn *net.UDPConn) {
	localAddress := conn.LocalAddr().(*net.UDPAddr).AddrPort()
	local := netip.AddrPortFrom(localAddress.Addr().Unmap(), localAddress.Port())
	buffer := make([]byte, 64*1024)
	for {
		n, from, err := conn.ReadFromUDPAddrPort(buffer)
		if err != nil {
			return
		}
		conn.WriteToUDPAddrPort([]byte(self.answer("udp", local)+" | "+strings.TrimSpace(string(buffer[:n]))), from)
	}
}

// Opens public sockets: on every public address, those of tcp http, tcp and
// udp tls, and udp whodis whose protocol is the given one, or all for "".
func (self *lbAltNetnsGeneration) openPublic(protocol string) error {
	sockets := []*lbAltNetnsSocket{}
	closeAll := func() {
		for _, socket := range sockets {
			socket.closer.Close()
		}
	}
	for _, address := range self.publicAddresses {
		for _, publicSocket := range []lbAltNetnsPublicPort{
			lbAltNetnsPublicPort{protocol: "tcp", port: self.ports.http},
			lbAltNetnsPublicPort{protocol: "tcp", port: self.ports.tls},
			lbAltNetnsPublicPort{protocol: "udp", port: self.ports.tls},
			lbAltNetnsPublicPort{protocol: "udp", port: self.ports.whodis},
		} {
			if protocol != "" && publicSocket.protocol != protocol {
				continue
			}
			closers, err := self.listen(publicSocket.protocol, address, publicSocket.port, self.socketsPerPort)
			for _, closer := range closers {
				sockets = append(sockets, &lbAltNetnsSocket{
					protocol: publicSocket.protocol,
					closer:   closer,
				})
			}
			if err != nil {
				closeAll()
				return fmt.Errorf("%s/%d %s %s:%d: %w", self.name, self.generation, publicSocket.protocol, address, publicSocket.port, err)
			}
		}
	}
	retired := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.retired {
			return true
		}
		self.publicSockets = append(self.publicSockets, sockets...)
		return false
	}()
	if retired {
		closeAll()
		return fmt.Errorf("%s/%d is retired", self.name, self.generation)
	}
	return nil
}

// Opens count more public sockets on one (protocol, address, port).
func (self *lbAltNetnsGeneration) listenPublic(protocol string, address netip.Addr, port int, count int) error {
	closers, err := self.listen(protocol, address, port, count)
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		for _, closer := range closers {
			self.publicSockets = append(self.publicSockets, &lbAltNetnsSocket{
				protocol: protocol,
				closer:   closer,
			})
		}
	}()
	return err
}

// Closes the public sockets of the protocol, or all for "", as a block that
// lost them; the trusted sockets stay.
func (self *lbAltNetnsGeneration) closePublic(protocol string) {
	closing := func() []*lbAltNetnsSocket {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		closing := []*lbAltNetnsSocket{}
		kept := []*lbAltNetnsSocket{}
		for _, socket := range self.publicSockets {
			if protocol == "" || socket.protocol == protocol {
				closing = append(closing, socket)
			} else {
				kept = append(kept, socket)
			}
		}
		self.publicSockets = kept
		return closing
	}()
	for _, socket := range closing {
		socket.closer.Close()
	}
}

// Closes every socket and connection, as the generation's container ending.
func (self *lbAltNetnsGeneration) retire() {
	closers := func() []io.Closer {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.retired = true
		closers := []io.Closer{}
		for _, socket := range self.publicSockets {
			closers = append(closers, socket.closer)
		}
		closers = append(closers, self.trustedClosers...)
		for conn := range self.acceptedConns {
			closers = append(closers, conn)
		}
		self.publicSockets = nil
		self.trustedClosers = nil
		self.acceptedConns = map[net.Conn]bool{}
		return closers
	}()
	for _, closer := range closers {
		closer.Close()
	}
}

// The block chain targets of the generation, from the §2.3 table.
func (self *lbAltNetnsGeneration) targets() []lbAltBlockTarget {
	serviceInternalPorts := self.ports.serviceInternalPorts()
	blockTargets := []lbAltBlockTarget{}
	for _, publicTarget := range lbAltWorkerPublicTargets() {
		blockTargets = append(blockTargets, lbAltBlockTarget{
			protocol:     publicTarget.protocol,
			publicPort:   publicTarget.publicPort,
			internalPort: serviceInternalPorts[publicTarget.servicePort],
		})
	}
	return blockTargets
}

// One public interface of the edge, and the worker of its lb unit, which owns
// the interface's routing table, rules and lb chain.
type lbAltNetnsInterface struct {
	index    int
	spec     *lbAltNetnsInterfaceSpec
	lbWorker *RunWorker
}

// The public address of the family.
func (self *lbAltNetnsInterface) publicAddress(ipv6 bool) netip.Addr {
	if ipv6 {
		return self.spec.publicIpv6.Addr()
	}
	return self.spec.publicIpv4.Addr()
}

// The bridge address of the family.
func (self *lbAltNetnsInterface) bridgeAddress(ipv6 bool) netip.Addr {
	if ipv6 {
		return self.spec.bridgeIpv6.Addr()
	}
	return self.spec.bridgeIpv4.Addr()
}

// The interface as the split takes it, with the §2.3 public ports.
func (self *lbAltNetnsInterface) splitInterface() lbAltSplitInterface {
	publicPorts := map[string][]int{}
	for _, publicPort := range lbAltNetnsPublicPorts() {
		publicPorts[publicPort.protocol] = append(publicPorts[publicPort.protocol], publicPort.port)
	}
	return lbAltSplitInterface{
		name:        self.spec.name,
		publicIpv4:  self.spec.publicIpv4.Addr().String(),
		publicIpv6:  self.spec.publicIpv6.Addr().String(),
		bridgeIpv4:  self.spec.bridgeIpv4.Addr().String(),
		bridgeIpv6:  self.spec.bridgeIpv6.Addr().String(),
		publicPorts: publicPorts,
	}
}

// The interface's chain names.
func (self *lbAltNetnsInterface) chainNames(t *testing.T) *lbAltChainNames {
	t.Helper()
	names, err := newLbAltChainNames(lbAltNetnsEnv, self.spec.name)
	if err != nil {
		t.Fatal(err)
	}
	return names
}

// The nginx lb's ports of a generation on this interface, in its lb port
// blocks (lbPortBlocks).
func (self *lbAltNetnsInterface) nginxPorts(generation int) lbAltNetnsPorts {
	base := 7000 + 1000*self.index
	return lbAltNetnsPorts{
		http:   base + 200 + generation,
		tls:    base + 230 + generation,
		whodis: base + 260 + generation,
	}
}

// The lb unit's port blocks: three generations of nginx ports per service
// port, with this interface's external ports.
func (self *lbAltNetnsInterface) lbPortBlocks() string {
	base := 7000 + 1000*self.index
	externalBase := 17000 + 1000*self.index
	return fmt.Sprintf(
		"80:%d:%d-%d;443:%d:%d-%d;4053:%d:%d-%d",
		externalBase+80, base+201, base+203,
		externalBase+443, base+231, base+233,
		externalBase+453, base+261, base+263,
	)
}

// One flow an edge test asks for, and what decides its answer.
type lbAltNetnsProbe struct {
	flow       lbAltNetnsFlow
	source     netip.Addr
	iface      *lbAltNetnsInterface
	protocol   string
	publicPort int
}

// The probe's bucket under the split.
func (self *lbAltNetnsProbe) bucket() int {
	return lbAltNetnsHmarkBucket(self.source)
}

// The public address and port the probe dials.
func (self *lbAltNetnsProbe) target() netip.AddrPort {
	return netip.AddrPortFrom(self.iface.publicAddress(self.source.Is6()), uint16(self.publicPort))
}

// Which generation must answer a probe; nil when nothing must.
type lbAltNetnsAnswerer func(probe *lbAltNetnsProbe) *lbAltNetnsGeneration

// Each probe answered by the generation of the block its bucket goes to; no
// answer where the bucket goes nowhere.
func lbAltNetnsSplitAnswerer(bucketBlocks []string, blockGenerations map[string]*lbAltNetnsGeneration) lbAltNetnsAnswerer {
	return func(probe *lbAltNetnsProbe) *lbAltNetnsGeneration {
		block := bucketBlocks[probe.bucket()]
		if block == "" {
			return nil
		}
		return blockGenerations[block]
	}
}

// Each probe answered by an nginx generation on the ports nginx publishes:
// tcp 80 and 443, udp 443 and 53. nginx keeps udp 4053 private (§3.1), so a
// probe of it falls through to whatever follows nginx's DNAT: the split while
// its entry jumps are there, or nothing for a nil fallback.
func lbAltNetnsNginxAnswerer(generation *lbAltNetnsGeneration, privateFallback lbAltNetnsAnswerer) lbAltNetnsAnswerer {
	return func(probe *lbAltNetnsProbe) *lbAltNetnsGeneration {
		if probe.protocol == "udp" && probe.publicPort == 4053 {
			if privateFallback == nil {
				return nil
			}
			return privateFallback(probe)
		}
		return generation
	}
}

// The IPv4 answerer for IPv4 probes and the IPv6 one for IPv6 probes. A nil
// answerer answers nothing.
func lbAltNetnsFamiliesAnswerer(ipv4Answerer lbAltNetnsAnswerer, ipv6Answerer lbAltNetnsAnswerer) lbAltNetnsAnswerer {
	return func(probe *lbAltNetnsProbe) *lbAltNetnsGeneration {
		answerer := ipv4Answerer
		if probe.source.Is6() {
			answerer = ipv6Answerer
		}
		if answerer == nil {
			return nil
		}
		return answerer(probe)
	}
}

// Every probe answered on its own interface: the answerer of each interface,
// by index.
func lbAltNetnsInterfaceAnswerer(answerers ...lbAltNetnsAnswerer) lbAltNetnsAnswerer {
	return func(probe *lbAltNetnsProbe) *lbAltNetnsGeneration {
		return answerers[probe.iface.index](probe)
	}
}

// The edge side of the harness inside an edge container: the public
// interfaces with their lb units' routing and lb chains, the fake generations
// on the bridges, and the control session with the client agent. One edge
// test uses it, from its own goroutine.
type lbAltNetnsEdge struct {
	t        *testing.T
	settings *lbAltNetnsSettings
	ctx      context.Context
	// in spec order
	interfaces         []*lbAltNetnsInterface
	servicesNetwork    *DockerNetwork
	warpHome           string
	client             *lbAltNetnsClient
	nextFlowNumber     int
	startedGenerations []*lbAltNetnsGeneration
}

// The edge, set up: the bridges, the lb units' routing tables, policy rules,
// masquerade and lb chains (warpctl's initRoutingTable and initBlockRedirect),
// and the control session. Skips outside a harness edge container.
func newLbAltNetnsEdge(t *testing.T) *lbAltNetnsEdge {
	t.Helper()
	if os.Getenv(lbAltNetnsRoleEnvName) != lbAltNetnsEdgeRole {
		t.Skip("edge tests run only in the harness's edge containers (TestLbAltNetns)")
	}
	settings := defaultLbAltNetnsSettings()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	warpHome := t.TempDir()
	t.Setenv("WARP_HOME", warpHome)

	servicesBridge := netip.MustParsePrefix(lbAltNetnsServicesBridge)
	edge := &lbAltNetnsEdge{
		t:          t,
		settings:   settings,
		ctx:        ctx,
		interfaces: []*lbAltNetnsInterface{},
		servicesNetwork: &DockerNetwork{
			networkName: lbAltNetnsServicesBridgeName,
			ipv4: &NetworkInterface{
				interfaceName:    lbAltNetnsServicesBridgeName,
				interfaceIp:      servicesBridge.Addr().String(),
				interfaceSubnet:  servicesBridge.Masked().String(),
				interfaceGateway: servicesBridge.Addr().String(),
			},
			ipv6: nil,
		},
		warpHome:           warpHome,
		client:             nil,
		nextFlowNumber:     0,
		startedGenerations: []*lbAltNetnsGeneration{},
	}
	t.Cleanup(func() {
		for _, generation := range edge.startedGenerations {
			generation.retire()
		}
	})

	// the lb units' tables by name, as the edges' rt_tables have them
	rtTables := "255\tlocal\n254\tmain\n253\tdefault\n0\tunspec\n"
	for _, spec := range lbAltNetnsInterfaceSpecs() {
		rtTables += fmt.Sprintf("%d\twarp%d\n", spec.tableNumber, spec.tableNumber)
	}
	if err := os.MkdirAll("/etc/iproute2", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile("/etc/iproute2/rt_tables", []byte(rtTables), 0o644); err != nil {
		t.Fatal(err)
	}
	lbAltNetnsDeleteDefaultRoutes()

	// the bridges, each with a dummy port so it has a carrier, as a docker
	// bridge with containers on it has
	batchLines := []string{}
	addBridge := func(bridgeName string, prefixes ...netip.Prefix) {
		batchLines = append(batchLines,
			fmt.Sprintf("link add %s type bridge", bridgeName),
			fmt.Sprintf("link add %sp type dummy", bridgeName),
			fmt.Sprintf("link set %sp master %s", bridgeName, bridgeName),
			fmt.Sprintf("link set %sp up", bridgeName),
			fmt.Sprintf("link set %s up", bridgeName),
		)
		for _, prefix := range prefixes {
			if prefix.Addr().Is6() {
				batchLines = append(batchLines, fmt.Sprintf("addr add %s dev %s nodad", prefix, bridgeName))
			} else {
				batchLines = append(batchLines, fmt.Sprintf("addr add %s dev %s", prefix, bridgeName))
			}
		}
	}
	addBridge(lbAltNetnsServicesBridgeName, servicesBridge)
	for _, spec := range lbAltNetnsInterfaceSpecs() {
		addBridge(spec.bridgeName, spec.bridgeIpv4, spec.bridgeIpv6)
	}
	lbAltNetnsIpBatch(t, batchLines)

	for i, spec := range lbAltNetnsInterfaceSpecs() {
		iface := &lbAltNetnsInterface{
			index:    i,
			spec:     spec,
			lbWorker: nil,
		}
		networkInterface := func(name string, prefix netip.Prefix, gateway netip.Addr) *NetworkInterface {
			return &NetworkInterface{
				interfaceName:    name,
				interfaceIp:      prefix.Addr().String(),
				interfaceSubnet:  prefix.Masked().String(),
				interfaceGateway: gateway.String(),
			}
		}
		iface.lbWorker = &RunWorker{
			env:     lbAltNetnsEnv,
			service: "lb",
			block:   "edge-" + spec.name,
			// nginx's: 80 and 443 its own, 4053 its udp stream, kept private
			// behind udp 53
			portBlocks: parsePortBlocks(iface.lbPortBlocks()),
			forwardPorts: map[string]map[int]int{
				"tcp": map[int]int{},
				"udp": map[int]int{53: 4053},
			},
			privateServicePorts:   map[int]bool{},
			servicesDockerNetwork: edge.servicesNetwork,
			routingTable: &RoutingTable{
				interfaceName: spec.name,
				tableNumber:   spec.tableNumber,
				tableName:     fmt.Sprintf("warp%d", spec.tableNumber),
				// the client's address is the interface's gateway
				ipv4: networkInterface(spec.name, spec.publicIpv4, spec.clientIpv4),
				ipv6: networkInterface(spec.name, spec.publicIpv6, spec.clientIpv6),
			},
			dockerNetwork: &DockerNetwork{
				networkName: spec.bridgeName,
				ipv4:        networkInterface(spec.bridgeName, spec.bridgeIpv4, spec.bridgeIpv4.Addr()),
				ipv6:        networkInterface(spec.bridgeName, spec.bridgeIpv6, spec.bridgeIpv6.Addr()),
			},
			fwMark:         spec.fwMark,
			hostNetworking: true,
			quitEvent:      warp.NewEvent(),
		}
		iface.lbWorker.initRoutingTable()
		iface.lbWorker.initBlockRedirect()
		edge.interfaces = append(edge.interfaces, iface)
	}

	edge.client = edge.connectClient()
	return edge
}

// Opens the control session with the client agent, retrying until the
// agent's ready timeout.
func (self *lbAltNetnsEdge) connectClient() *lbAltNetnsClient {
	t := self.t
	t.Helper()
	controlAddress := netip.AddrPortFrom(self.interfaces[0].spec.clientIpv4, lbAltNetnsControlPort)
	deadline := time.Now().Add(self.settings.clientReadyTimeout)
	for {
		conn, err := net.DialTimeout("tcp4", controlAddress.String(), self.settings.flowTimeout)
		if err == nil {
			t.Cleanup(func() {
				conn.Close()
			})
			return &lbAltNetnsClient{
				conn:    conn,
				decoder: json.NewDecoder(bufio.NewReader(conn)),
				encoder: json.NewEncoder(conn),
			}
		}
		if !time.Now().Before(deadline) {
			t.Fatalf("the client agent is not reachable: %s", err)
		}
		select {
		case <-self.ctx.Done():
			t.Fatal(self.ctx.Err())
		case <-time.After(self.settings.clientRetryInterval):
		}
	}
}

// Starts a generation listening on its public addresses, and on the services
// bridge when it is a connect generation.
func (self *lbAltNetnsEdge) startGeneration(name string, generation int, ports lbAltNetnsPorts, publicAddresses []netip.Addr, trustedAddress netip.Addr) *lbAltNetnsGeneration {
	t := self.t
	t.Helper()
	started := &lbAltNetnsGeneration{
		name:            name,
		generation:      generation,
		ports:           ports,
		publicAddresses: publicAddresses,
		trustedAddress:  trustedAddress,
		socketsPerPort:  DefaultLbAltSplitSettings().SocketsPerPort,
		publicSockets:   []*lbAltNetnsSocket{},
		trustedClosers:  []io.Closer{},
		acceptedConns:   map[net.Conn]bool{},
		retired:         false,
	}
	self.startedGenerations = append(self.startedGenerations, started)
	if trustedAddress.IsValid() {
		for _, socket := range []lbAltNetnsPublicPort{
			lbAltNetnsPublicPort{protocol: "tcp", port: ports.http},
			lbAltNetnsPublicPort{protocol: "udp", port: ports.tls},
			lbAltNetnsPublicPort{protocol: "udp", port: ports.whodis},
		} {
			closers, err := started.listen(socket.protocol, trustedAddress, socket.port, 1)
			started.trustedClosers = append(started.trustedClosers, closers...)
			if err != nil {
				t.Fatalf("%s/%d trusted %s %d: %s", name, generation, socket.protocol, socket.port, err)
			}
		}
	}
	if err := started.openPublic(""); err != nil {
		t.Fatal(err)
	}
	return started
}

// The ports of a block's generation: 15000, plus 100 per block in weights
// order, plus 10 per generation, plus 0, 1 and 2 for http, tls and whodis.
func lbAltNetnsBlockPorts(block string, generation int) lbAltNetnsPorts {
	blockIndex := slices.IndexFunc(lbAltNetnsBlockWeights(), func(blockWeight services.BlockWeight) bool {
		return blockWeight.Block == block
	})
	base := 15000 + 100*blockIndex + 10*generation
	return lbAltNetnsPorts{
		http:   base,
		tls:    base + 1,
		whodis: base + 2,
	}
}

// Starts a generation of a connect block, on every lb bridge in both families
// and on the services bridge.
func (self *lbAltNetnsEdge) startBlock(block string, generation int) *lbAltNetnsGeneration {
	self.t.Helper()
	publicAddresses := []netip.Addr{}
	for _, iface := range self.interfaces {
		publicAddresses = append(publicAddresses, iface.bridgeAddress(false), iface.bridgeAddress(true))
	}
	return self.startGeneration(block, generation, lbAltNetnsBlockPorts(block, generation), publicAddresses, netip.MustParseAddr(self.servicesNetwork.ipv4.interfaceIp))
}

// Starts a generation of every block and writes its chains, so each block is
// ready. Returns the generations by block.
func (self *lbAltNetnsEdge) startBlocks(generation int) map[string]*lbAltNetnsGeneration {
	self.t.Helper()
	blockGenerations := map[string]*lbAltNetnsGeneration{}
	for _, blockWeight := range lbAltNetnsBlockWeights() {
		blockGenerations[blockWeight.Block] = self.startBlock(blockWeight.Block, generation)
		self.writeBlockChains(blockGenerations[blockWeight.Block])
	}
	return blockGenerations
}

// Points the block's chains on every interface at the generation, as its
// worker does after readiness (writeLbAltBlockChains).
func (self *lbAltNetnsEdge) writeBlockChains(generation *lbAltNetnsGeneration) {
	self.t.Helper()
	if err := writeLbAltBlockChains(self.ctx, lbAltNetnsEnv, generation.name, self.splitInterfaces(), generation.targets()); err != nil {
		self.t.Fatal(err)
	}
}

// Every interface as the split takes it.
func (self *lbAltNetnsEdge) splitInterfaces() []lbAltSplitInterface {
	splitInterfaces := []lbAltSplitInterface{}
	for _, iface := range self.interfaces {
		splitInterfaces = append(splitInterfaces, iface.splitInterface())
	}
	return splitInterfaces
}

// The lb unit's split config of the interface.
func (self *lbAltNetnsEdge) splitConfig(iface *lbAltNetnsInterface) *lbAltSplitConfig {
	return &lbAltSplitConfig{
		env:            lbAltNetnsEnv,
		splitInterface: iface.splitInterface(),
		blockWeights:   lbAltNetnsBlockWeights(),
	}
}

// Reconciles the interface's split (reconcileLbAltSplit), which must succeed.
func (self *lbAltNetnsEdge) reconcile(iface *lbAltNetnsInterface) {
	self.t.Helper()
	if err := reconcileLbAltSplit(self.ctx, self.splitConfig(iface)); err != nil {
		self.t.Fatalf("reconcile %s: %s", iface.spec.name, err)
	}
}

// Each bucket's block when every block is ready.
func (self *lbAltNetnsEdge) baseBucketBlocks() []string {
	self.t.Helper()
	baseBucketBlocks, err := services.LbAltBucketBlocks(lbAltNetnsBlockWeights(), services.LbAltBucketCount)
	if err != nil {
		self.t.Fatal(err)
	}
	return baseBucketBlocks
}

// Each bucket's block when only the given blocks are ready, as the reconcile
// moves orphaned buckets (assignLbAltBuckets).
func (self *lbAltNetnsEdge) bucketBlocksWithReady(readyBlocks ...string) []string {
	readyBlockSet := map[string]bool{}
	for _, block := range readyBlocks {
		readyBlockSet[block] = true
	}
	return assignLbAltBuckets(self.baseBucketBlocks(), lbAltNetnsBlockWeights(), readyBlockSet)
}

// Probes from every source of each family whose bucket the filter takes (all
// with a nil filter), to each interface, on each public port.
func (self *lbAltNetnsEdge) probes(ifaces []*lbAltNetnsInterface, publicPorts []lbAltNetnsPublicPort, bucketFilter func(bucket int) bool, keep bool) []*lbAltNetnsProbe {
	t := self.t
	t.Helper()
	probes := []*lbAltNetnsProbe{}
	for _, ipv6 := range []bool{false, true} {
		sources, err := lbAltNetnsSources(ipv6)
		if err != nil {
			t.Fatal(err)
		}
		for bucket, source := range sources {
			if bucketFilter != nil && !bucketFilter(bucket) {
				continue
			}
			for _, iface := range ifaces {
				for _, publicPort := range publicPorts {
					self.nextFlowNumber += 1
					probe := &lbAltNetnsProbe{
						source:     source,
						iface:      iface,
						protocol:   publicPort.protocol,
						publicPort: publicPort.port,
					}
					probe.flow = lbAltNetnsFlow{
						Id:       fmt.Sprintf("f%d", self.nextFlowNumber),
						Protocol: publicPort.protocol,
						Source:   source.String(),
						Target:   probe.target().String(),
						Keep:     keep,
					}
					probes = append(probes, probe)
				}
			}
		}
	}
	return probes
}

// The client makes the probes' flows.
func (self *lbAltNetnsEdge) dial(probes []*lbAltNetnsProbe) []lbAltNetnsFlowResult {
	t := self.t
	t.Helper()
	flows := []lbAltNetnsFlow{}
	for _, probe := range probes {
		flows = append(flows, probe.flow)
	}
	response, err := self.client.do(&lbAltNetnsRequest{
		Op:    lbAltNetnsDialOp,
		Flows: flows,
		Ids:   []string{},
	})
	if err != nil {
		t.Fatal(err)
	}
	return response.Results
}

// The client exchanges again on the probes' kept flows.
func (self *lbAltNetnsEdge) send(probes []*lbAltNetnsProbe) []lbAltNetnsFlowResult {
	t := self.t
	t.Helper()
	ids := []string{}
	for _, probe := range probes {
		ids = append(ids, probe.flow.Id)
	}
	response, err := self.client.do(&lbAltNetnsRequest{
		Op:    lbAltNetnsSendOp,
		Flows: []lbAltNetnsFlow{},
		Ids:   ids,
	})
	if err != nil {
		t.Fatal(err)
	}
	return response.Results
}

// Requires each probe's answer to be the one its answerer names: from that
// generation, taken on the interface bridge's address of the probe's family at
// the generation's port for the probe's protocol and public port, and coming
// back from the public address and port the client dialed. A probe nothing
// must answer gets no answer. Returns the answered flows by generation.
func (self *lbAltNetnsEdge) requireAnswers(what string, probes []*lbAltNetnsProbe, results []lbAltNetnsFlowResult, answerer lbAltNetnsAnswerer) map[string]int {
	t := self.t
	t.Helper()
	if len(results) != len(probes) {
		t.Fatalf("%s: %d results for %d probes", what, len(results), len(probes))
	}
	generationAnsweredCounts := map[string]int{}
	mismatches := []string{}
	for i, probe := range probes {
		result := results[i]
		generation := answerer(probe)
		wantAnswer := ""
		if generation != nil {
			port := generation.ports.forPublic(probe.protocol, probe.publicPort)
			wantAnswer = generation.answer(probe.protocol, netip.AddrPortFrom(probe.iface.bridgeAddress(probe.source.Is6()), uint16(port)))
		}
		describe := func() string {
			return fmt.Sprintf("%s %s %s from %s (bucket %d)", probe.iface.spec.name, probe.protocol, probe.target(), probe.source, probe.bucket())
		}
		switch {
		case result.Answer != wantAnswer:
			mismatches = append(mismatches, fmt.Sprintf("%s: got %q (%s), want %q", describe(), result.Answer, result.Error, wantAnswer))
		case generation != nil && result.ReplyFrom != probe.target().String():
			mismatches = append(mismatches, fmt.Sprintf("%s: reply from %s", describe(), result.ReplyFrom))
		case generation != nil:
			generationAnsweredCounts[fmt.Sprintf("%s/%d", generation.name, generation.generation)] += 1
		}
	}
	if 0 < len(mismatches) {
		t.Fatalf("%s: %d of %d flows wrong:\n%s", what, len(mismatches), len(probes), strings.Join(mismatches[:min(len(mismatches), 20)], "\n"))
	}
	return generationAnsweredCounts
}

// Dials the probes and requires their answers.
func (self *lbAltNetnsEdge) requireDialAnswers(what string, probes []*lbAltNetnsProbe, answerer lbAltNetnsAnswerer) map[string]int {
	self.t.Helper()
	return self.requireAnswers(what, probes, self.dial(probes), answerer)
}

// Exchanges again on the probes' kept flows and requires their answers.
func (self *lbAltNetnsEdge) requireSendAnswers(what string, probes []*lbAltNetnsProbe, answerer lbAltNetnsAnswerer) map[string]int {
	self.t.Helper()
	return self.requireAnswers(what, probes, self.send(probes), answerer)
}

// iptables or ip6tables.
func lbAltNetnsIptablesCommand(ipv6 bool) string {
	if ipv6 {
		return "ip6tables"
	}
	return "iptables"
}

// Runs iptables or ip6tables with -w and the arguments, which must succeed,
// and returns its output lines.
func (self *lbAltNetnsEdge) iptables(ipv6 bool, args ...string) []string {
	self.t.Helper()
	out, err := lbAltNetnsCommand("", lbAltNetnsIptablesCommand(ipv6), append([]string{"-w"}, args...)...)
	if err != nil {
		self.t.Fatal(err)
	}
	lines := []string{}
	for _, line := range strings.Split(out, "\n") {
		if line = strings.TrimSpace(line); line != "" {
			lines = append(lines, line)
		}
	}
	return lines
}

// The rules of a table, or of one chain, as `iptables -S` lists them.
func (self *lbAltNetnsEdge) listedRules(ipv6 bool, table string, chain string) []string {
	self.t.Helper()
	args := []string{"-t", table, "-S"}
	if chain != "" {
		args = append(args, chain)
	}
	rules := []string{}
	for _, line := range self.iptables(ipv6, args...) {
		if strings.HasPrefix(line, "-A ") {
			rules = append(rules, line)
		}
	}
	return rules
}

// Whether the table has the chain.
func (self *lbAltNetnsEdge) hasChain(ipv6 bool, table string, chain string) bool {
	self.t.Helper()
	return slices.Contains(self.iptables(ipv6, "-t", table, "-S"), "-N "+chain)
}

// The table's rules that carry the comment.
func (self *lbAltNetnsEdge) taggedRules(ipv6 bool, table string, comment string) []string {
	self.t.Helper()
	tagged := []string{}
	for _, rule := range self.listedRules(ipv6, table, "") {
		if strings.Contains(rule, "--comment "+comment) {
			tagged = append(tagged, rule)
		}
	}
	return tagged
}

// Requires a chain of the interface's split, in one family, to hold one rule
// per bucket that goes somewhere, in bucket order, each sending its mark to
// the block's chain.
func (self *lbAltNetnsEdge) requireBucketRules(iface *lbAltNetnsInterface, ipv6 bool, chain string, bucketBlocks []string) {
	t := self.t
	t.Helper()
	names := iface.chainNames(t)
	wantRules := []string{}
	for bucket, block := range bucketBlocks {
		if block == "" {
			continue
		}
		blockChain, err := names.blockChain(block)
		if err != nil {
			t.Fatal(err)
		}
		wantRules = append(wantRules, fmt.Sprintf("-A %s -m mark --mark %#x -j %s", chain, lbAltHmarkOffset+bucket, blockChain))
	}
	if rules := self.listedRules(ipv6, "nat", chain); !slices.Equal(rules, wantRules) {
		t.Fatalf("%s %s %s:\n%s\nwant:\n%s", iface.spec.name, lbAltNetnsIptablesCommand(ipv6), chain, strings.Join(rules, "\n"), strings.Join(wantRules, "\n"))
	}
}

// Requires the interface's converged split in both families: its split chain
// holds the buckets' rules, and no replacement chain is left.
func (self *lbAltNetnsEdge) requireSplitChain(iface *lbAltNetnsInterface, bucketBlocks []string) {
	t := self.t
	t.Helper()
	names := iface.chainNames(t)
	for _, ipv6 := range []bool{false, true} {
		self.requireBucketRules(iface, ipv6, names.splitChain, bucketBlocks)
		if self.hasChain(ipv6, "nat", names.temporarySplitChain) {
			t.Fatalf("%s %s keeps the replacement chain %s", iface.spec.name, lbAltNetnsIptablesCommand(ipv6), names.temporarySplitChain)
		}
	}
}

// Adds a counting rule, with no target, to a chain of mangle in the family.
// Its comment names it for the counters.
func (self *lbAltNetnsEdge) addCounter(ipv6 bool, chain string, name string, matchArgs ...string) {
	self.t.Helper()
	args := append([]string{"-t", "mangle", "-A", chain}, matchArgs...)
	args = append(args, "-m", "comment", "--comment", lbAltNetnsCounterCommentPrefix+name)
	self.iptables(ipv6, args...)
}

// The packets each counting rule of mangle in the family has seen, by name,
// from `iptables-save -c`.
func (self *lbAltNetnsEdge) counterPackets(ipv6 bool) map[string]int {
	t := self.t
	t.Helper()
	out, err := lbAltNetnsCommand("", lbAltNetnsIptablesCommand(ipv6)+"-save", "-c", "-t", "mangle")
	if err != nil {
		t.Fatal(err)
	}
	counterLine := regexp.MustCompile(`^\[(\d+):\d+\] -A \S+ .*--comment "?` + lbAltNetnsCounterCommentPrefix + `([^" ]+)"?`)
	packets := map[string]int{}
	for _, line := range strings.Split(out, "\n") {
		groups := counterLine.FindStringSubmatch(line)
		if groups == nil {
			continue
		}
		count, err := strconv.Atoi(groups[1])
		if err != nil {
			t.Fatal(err)
		}
		packets[groups[2]] += count
	}
	return packets
}

// The udp conntrack tuples whose replies come from the address, by the reply's
// source port, from conntrack's ordinary listing.
func (self *lbAltNetnsEdge) conntrackReplyPortCounts(replySource netip.Addr) map[int]int {
	t := self.t
	t.Helper()
	family := "ipv4"
	if replySource.Is6() {
		family = "ipv6"
	}
	cmd := exec.Command("conntrack", "-L", "-f", family, "-p", "udp", "--reply-src", replySource.String())
	stdout, err := cmd.Output()
	if err != nil {
		t.Fatalf("conntrack -L %s %s: %s", family, replySource, err)
	}
	sourcePort := regexp.MustCompile(`\bsport=(\d+)`)
	replyPortCounts := map[int]int{}
	for _, line := range strings.Split(string(stdout), "\n") {
		// the original tuple's port comes first, then the reply's
		groups := sourcePort.FindAllStringSubmatch(line, -1)
		if len(groups) < 2 {
			continue
		}
		port, err := strconv.Atoi(groups[1][1])
		if err != nil {
			t.Fatal(err)
		}
		replyPortCounts[port] += 1
	}
	return replyPortCounts
}

// A split writer as the package functions build one, sharing their host lock
// under WARP_HOME, whose commands are logged, and which the hooks can hold, or
// fail before a command runs, as a writer that died there.
func (self *lbAltNetnsEdge) newWriter(hooks lbAltNetnsWriterHooks) (*lbAltSplitWriter, *lbAltNetnsCommandLog) {
	settings := DefaultLbAltSplitSettings()
	settings.LockDirectory = self.warpHome
	writer := newLbAltSplitWriter(settings)
	commandLog := &lbAltNetnsCommandLog{
		commands: []lbAltCommand{},
	}
	run := writer.run
	writer.run = func(ctx context.Context, command lbAltCommand) (commandOutput, error) {
		if hooks.before != nil {
			if err := hooks.before(command); err != nil {
				return commandOutput{}, err
			}
		}
		output, err := run(ctx, command)
		func() {
			commandLog.stateLock.Lock()
			defer commandLog.stateLock.Unlock()
			commandLog.commands = append(commandLog.commands, command)
		}()
		if hooks.after != nil {
			hooks.after(command)
		}
		return output, err
	}
	writer.lockBusy = hooks.lockBusy
	return writer, commandLog
}

// Hooks of a harness writer. Each may be nil.
type lbAltNetnsWriterHooks struct {
	// before a command runs; an error fails the command unrun
	before func(command lbAltCommand) error
	// after a command ran
	after func(command lbAltCommand)
	// when another writer holds the host lock
	lockBusy func()
}

// The commands a harness writer ran.
type lbAltNetnsCommandLog struct {
	stateLock sync.Mutex
	commands  []lbAltCommand
}

// The iptables-restore and ip6tables-restore transactions among them: the
// writes.
func (self *lbAltNetnsCommandLog) restores() []lbAltCommand {
	restores := []lbAltCommand{}
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		for _, command := range self.commands {
			if strings.HasSuffix(command.name, "-restore") {
				restores = append(restores, command)
			}
		}
	}()
	return restores
}

// The transactions, for a failure message.
func lbAltNetnsDescribeRestores(restores []lbAltCommand) string {
	descriptions := []string{}
	for _, restore := range restores {
		descriptions = append(descriptions, restore.name+":\n"+restore.stdin)
	}
	return strings.Join(descriptions, "\n")
}

// Whether the command lists a family's nat table, as a writer does before it
// writes there.
func lbAltNetnsListsNat(command lbAltCommand, ipv6 bool) bool {
	return command.name == lbAltNetnsIptablesCommand(ipv6) && slices.Equal(command.args, []string{"-w", "-t", "nat", "-S"})
}

// Holds a writer's goroutine at a step until the test lets it go, so the test
// acts between two of the writer's steps. A hold that nobody takes or lets go
// within the hook timeout gives up, so a writer never hangs the test.
type lbAltNetnsHold struct {
	timeout time.Duration
	held    chan struct{}
	release chan struct{}
}

// A hold with the settings' hook timeout.
func newLbAltNetnsHold(settings *lbAltNetnsSettings) *lbAltNetnsHold {
	return &lbAltNetnsHold{
		timeout: settings.hookTimeout,
		held:    make(chan struct{}),
		release: make(chan struct{}),
	}
}

// Called by the writer's goroutine at the step: waits there until the test
// lets it go.
func (self *lbAltNetnsHold) at() {
	select {
	case self.held <- struct{}{}:
	case <-time.After(self.timeout):
		return
	}
	select {
	case <-self.release:
	case <-time.After(self.timeout):
	}
}

// Waits until the writer is held.
func (self *lbAltNetnsHold) wait(t *testing.T) {
	t.Helper()
	select {
	case <-self.held:
	case <-time.After(self.timeout):
		t.Fatal("the writer did not reach the held step")
	}
}

// Lets the held writer go on.
func (self *lbAltNetnsHold) resume(t *testing.T) {
	t.Helper()
	select {
	case self.release <- struct{}{}:
	case <-time.After(self.timeout):
		t.Fatal("the held writer was gone")
	}
}

// Logs a fact for the harness's report.
func (self *lbAltNetnsEdge) fact(format string, args ...any) {
	self.t.Helper()
	self.t.Logf("%s %s", lbAltNetnsFactPrefix, fmt.Sprintf(format, args...))
}
