package main

import (
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/urnetwork/warp"
)

// Three synthetic ring hosts, named by fqdn in the placement and by short name
// in settings.yml routes as in production, and a routed host outside the ring.
func alertmanagerTestHostSettings() (*HostSettings, []string) {
	hostSettings := &HostSettings{Routes: map[string]string{
		"edge-a": "192.0.2.10",
		"edge-b": "192.0.2.11",
		"edge-c": "192.0.2.12",
		"db-a":   "192.0.2.20",
	}}
	return hostSettings, []string{"edge-a.example", "edge-b.example", "edge-c.example"}
}

// grafana's http port as warp allocated it on Main on 2026-11-20 (WARP_PORTS
// 3000:14758): an internal port of the block, which warp DNATs.
const testGrafanaHttpPort = 14758

// warp's allocation, every block's external and internal ports (vault
// services.yml; xops main/ansible/tests/test_edge_ephemeral_ports.py
// WARP_EXTERNAL_PORTS and WARP_INTERNAL_PORTS).
const warpPortsFirst = 7000
const warpPortsLast = 20000

// Each Grafana ran its own Alertmanager with no ha_peers, so every host sent
// its own copy of every notification: six Slack messages for one alert on
// Main (2026-11-16, each of the six hosts counted the same sends). The
// rendered grafana.ini now clusters the Alertmanagers of the ring hosts, and
// only theirs.
func TestGrafanaAlertmanagersClusterAcrossTheRingHosts(t *testing.T) {
	hostSettings, ringHosts := alertmanagerTestHostSettings()
	section := renderUnifiedAlertingSection("test", "192.0.2.11", 6496, hostSettings, ringHosts)
	ini := parseIni(t, renderGrafanaIni(testGrafanaHttpPort, "test-grafana.example", "[database]\ntype = sqlite3", "", section, "password", ""))

	alerting := ini["unified_alerting"]
	wantPeers := "192.0.2.10:6495,192.0.2.11:6495,192.0.2.12:6495"
	if got := alerting["ha_peers"]; got != wantPeers {
		t.Fatalf("ha_peers = %q, want every ring host's route address at the alertmanager gossip port: %q", got, wantPeers)
	}
	for key, want := range map[string]string{
		"ha_advertise_address": "192.0.2.11:6495",
		"ha_listen_address":    "192.0.2.11:6496",
		"ha_label":             "test-grafana-alertmanager",
	} {
		if got := alerting[key]; got != want {
			t.Errorf("[unified_alerting] %s = %q, want %q", key, got, want)
		}
	}
}

// The alertmanagers never clustered on Main (2026-11-17 to 11-20): every
// refresh logged "failed to join <peer>:6495: ... connection reset by peer",
// six copies of every notification went out, and each Grafana counted one
// cluster member. The gossip listener took grafana's warp-allocated http port
// number on the route address. warpctl's run worker DNATs every warp port for
// every LOCAL destination but loopback (initBlockRedirect: nat OUTPUT and
// PREROUTING --dst-type LOCAL, OUTPUT ! -d 127.0.0.0/8, into the block chain's
// --dport <port> -j DNAT --to-destination <docker network ip>:<port>). The
// front's dial to that listener was DNATed to the docker network ip, where
// nothing listens, so the front closed each peer's connection unread. On
// edge-4 the rule for 14758 counted 10,817 dials in the 2.3 h after the 11-20
// deploy. The listener the front forwards to, and grafana's ha_listen_address,
// must be the route address at a port outside warp's allocation, for every
// port the front may pick.
func TestAlertmanagerGossipListenerIsNeverAWarpPort(t *testing.T) {
	hostSettings, ringHosts := alertmanagerTestHostSettings()
	if len(alertmanagerGossipListenPorts) < 2 {
		t.Fatalf("alertmanager gossip listen ports %v: a redeploy's old and new containers each hold one", alertmanagerGossipListenPorts)
	}
	for _, listenPort := range alertmanagerGossipListenPorts {
		section := renderUnifiedAlertingSection("test", "192.0.2.11", listenPort, hostSettings, ringHosts)
		ini := parseIni(t, renderGrafanaIni(testGrafanaHttpPort, "test-grafana.example", "[database]\ntype = sqlite3", "", section, "password", ""))
		haListenAddress := ini["unified_alerting"]["ha_listen_address"]

		listenHost, listenPortValue, err := net.SplitHostPort(haListenAddress)
		if err != nil {
			t.Fatal(err)
		}
		port, err := strconv.Atoi(listenPortValue)
		if err != nil {
			t.Fatal(err)
		}
		// memberlist sends its udp from this socket; a loopback source cannot
		// leave the host
		if listenHost != "192.0.2.11" {
			t.Errorf("ha_listen_address %q: want the route address", haListenAddress)
		}
		if warpPortsFirst <= port && port <= warpPortsLast {
			t.Errorf("ha_listen_address %q is a warp port: warp DNATs it for every local address but loopback, so the front's dial lands on the docker network ip", haListenAddress)
		}
		if listenPortValue == ini["server"]["http_port"] {
			t.Errorf("ha_listen_address %q takes grafana's warp-allocated http port", haListenAddress)
		}
		// the front forwards the advertised port to the listener grafana binds
		if frontBackend := alertmanagerGossipListenAddr("192.0.2.11", listenPort); frontBackend != haListenAddress {
			t.Errorf("front backend %q differs from ha_listen_address %q", frontBackend, haListenAddress)
		}
	}
}

// The front, not grafana, is the http server's only intended caller.
func TestGrafanaHttpServerBindsLoopback(t *testing.T) {
	ini := parseIni(t, renderGrafanaIni(testGrafanaHttpPort, "test-grafana.example", "[database]\ntype = sqlite3", "", "", "password", ""))
	if httpAddr := ini["server"]["http_addr"]; httpAddr != childListenAddress {
		t.Errorf("http_addr = %q, want loopback", httpAddr)
	}
}

// Holds a port as a memberlist would: a tcp listener and a udp socket on one
// loopback port. Returns the port.
func holdLoopbackPort(t *testing.T) int {
	t.Helper()
	for range 20 {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		port := listener.Addr().(*net.TCPAddr).Port
		packetConn, err := net.ListenPacket("udp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
		if err != nil {
			listener.Close()
			continue
		}
		t.Cleanup(func() {
			listener.Close()
			packetConn.Close()
		})
		return port
	}
	t.Fatal("no loopback port to hold for both tcp and udp")
	return 0
}

// A new container takes the first listen port free on the route address, as
// warp gives it the first free internal port; the old container's
// alertmanager still holds the other during the redeploy.
func TestPickAlertmanagerGossipListenPortSkipsAPortTheOldContainerHolds(t *testing.T) {
	freePort := freeLoopbackPort(t)
	if got, err := pickAlertmanagerGossipListenPort("127.0.0.1", []int{freePort}); err != nil || got != freePort {
		t.Fatalf("pick of free port %d = %d, %v", freePort, got, err)
	}

	heldPort := holdLoopbackPort(t)
	got, err := pickAlertmanagerGossipListenPort("127.0.0.1", []int{heldPort, freePort})
	if err != nil {
		t.Fatal(err)
	}
	if got != freePort {
		t.Errorf("picked %d, want %d: %d is held for tcp and udp", got, freePort, heldPort)
	}
}

// memberlist binds tcp and udp on one port, so a port held for either one is
// not free.
func TestPickAlertmanagerGossipListenPortNeedsTcpAndUdpFree(t *testing.T) {
	freePort := freeLoopbackPort(t)

	tcpHeld, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer tcpHeld.Close()
	tcpHeldPort := tcpHeld.Addr().(*net.TCPAddr).Port

	udpHeld, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer udpHeld.Close()
	udpHeldPort := udpHeld.LocalAddr().(*net.UDPAddr).Port

	for _, heldPort := range []int{tcpHeldPort, udpHeldPort} {
		got, err := pickAlertmanagerGossipListenPort("127.0.0.1", []int{heldPort, freePort})
		if err != nil {
			t.Fatal(err)
		}
		if got != freePort {
			t.Errorf("picked %d, want %d: %d is held for tcp or udp", got, freePort, heldPort)
		}
	}
}

// With every listen port held the front refuses to start, so warp's deploy
// poll fails and the running container stays.
func TestPickAlertmanagerGossipListenPortFailsWhenNoneIsFree(t *testing.T) {
	heldPorts := []int{holdLoopbackPort(t), holdLoopbackPort(t)}
	if got, err := pickAlertmanagerGossipListenPort("127.0.0.1", heldPorts); err == nil {
		t.Fatalf("picked %d of held ports %v, want an error", got, heldPorts)
	}
}

// An IPv6 route address is bracketed in every host:port setting.
func TestAlertmanagerClusterBracketsIpv6RouteAddresses(t *testing.T) {
	hostSettings := &HostSettings{Routes: map[string]string{"edge-a": "2001:db8::10", "edge-b": "2001:db8::11"}}
	section := renderUnifiedAlertingSection("test", "2001:db8::11", 6496, hostSettings, []string{"edge-a", "edge-b"})
	ini := parseIni(t, renderGrafanaIni(testGrafanaHttpPort, "test-grafana.example", "[database]\ntype = sqlite3", "", section, "password", ""))

	for key, want := range map[string]string{
		"ha_listen_address":    "[2001:db8::11]:6496",
		"ha_advertise_address": "[2001:db8::11]:6495",
		"ha_peers":             "[2001:db8::10]:6495,[2001:db8::11]:6495",
	} {
		if got := ini["unified_alerting"][key]; got != want {
			t.Errorf("[unified_alerting] %s = %q, want %q", key, got, want)
		}
	}
}

// Every memberlist seed is a valid host:port for an IPv6 route address too:
// the ring's join_members were formatted "%s:%d", which leaves an IPv6
// address unbracketed and unparseable.
func TestRingJoinMembersBracketIpv6Routes(t *testing.T) {
	hostSettings := &HostSettings{Routes: map[string]string{"edge-a": "2001:db8::10", "edge-b": "192.0.2.11"}}
	got := ringJoinMembers(hostSettings, []string{"edge-a", "edge-b"}, defaultGossipPort)
	want := []string{"192.0.2.11:6492", "[2001:db8::10]:6492"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("join members = %q, want %q", got, want)
	}
	for _, member := range got {
		if _, _, err := net.SplitHostPort(member); err != nil {
			t.Errorf("join member %q does not parse as host:port: %v", member, err)
		}
	}
}

// The fixed ports bound on the route net, the front's and the alertmanager's
// own gossip listeners, stay out of warp's 7000-20000 allocation and below the
// edges' local port range "20000 60999" (the proxy hosts reserve them in xops
// inventory.yml), and no two share a number.
func TestFrontRouteNetPortsAvoidWarpAndEphemeralRanges(t *testing.T) {
	ports := map[string]int{
		"local publish":       defaultLocalPort,
		"loki grpc":           defaultGrpcPort,
		"mimir grpc":          defaultMimirGrpcPort,
		"loki gossip":         defaultGossipPort,
		"mimir gossip":        defaultMimirGossipPort,
		"alertmanager gossip": defaultAlertmanagerGossipPort,
	}
	for i, port := range alertmanagerGossipListenPorts {
		ports[fmt.Sprintf("alertmanager gossip listener %d", i)] = port
	}
	seen := map[int]string{}
	for name, port := range ports {
		if warpPortsFirst <= port {
			t.Errorf("%s port %d is not below warp's allocation and the edges' local port range", name, port)
		}
		if other, ok := seen[port]; ok {
			t.Errorf("%s and %s share port %d", name, other, port)
		}
		seen[port] = name
	}
}

// A port free for both tcp and udp on loopback.
func freeLoopbackPort(t *testing.T) int {
	t.Helper()
	for range 20 {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		port := listener.Addr().(*net.TCPAddr).Port
		packetConn, err := net.ListenPacket("udp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
		listener.Close()
		if err == nil {
			packetConn.Close()
			return port
		}
	}
	t.Fatal("no loopback port free for both tcp and udp")
	return 0
}

// The ring proxy forwards to the backend address it is given, tcp and udp,
// and relays the backend's udp answer to the peer: the alertmanager's
// listener is not the loopback child port the ring proxies computed before.
func TestRingReusePortProxyForwardsToTheGivenBackend(t *testing.T) {
	backendTcp, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer backendTcp.Close()
	backendPort := backendTcp.Addr().(*net.TCPAddr).Port
	backendUdp, err := net.ListenPacket("udp", net.JoinHostPort("127.0.0.1", strconv.Itoa(backendPort)))
	if err != nil {
		t.Skipf("backend udp port %d is taken: %v", backendPort, err)
	}
	defer backendUdp.Close()
	go func() {
		for {
			connection, err := backendTcp.Accept()
			if err != nil {
				return
			}
			go func() {
				defer connection.Close()
				buffer := make([]byte, 64)
				n, err := connection.Read(buffer)
				if err == nil {
					connection.Write([]byte("tcp:" + string(buffer[:n])))
				}
			}()
		}
	}()
	go func() {
		buffer := make([]byte, 64)
		for {
			n, from, err := backendUdp.ReadFrom(buffer)
			if err != nil {
				return
			}
			backendUdp.WriteTo([]byte("udp:"+string(buffer[:n])), from)
		}
	}()

	event := warp.NewEvent()
	defer event.Set()
	externalPort := freeLoopbackPort(t)
	allowedIps := map[netip.Addr]bool{netip.MustParseAddr("127.0.0.1"): true}
	startRingReusePortProxy(event, "127.0.0.1", allowedIps, externalPort, backendTcp.Addr().String(), true)
	externalAddr := net.JoinHostPort("127.0.0.1", strconv.Itoa(externalPort))

	exchange := func(network string) (string, error) {
		connection, err := net.DialTimeout(network, externalAddr, time.Second)
		if err != nil {
			return "", err
		}
		defer connection.Close()
		connection.SetDeadline(time.Now().Add(time.Second))
		if _, err := connection.Write([]byte("gossip")); err != nil {
			return "", err
		}
		buffer := make([]byte, 64)
		n, err := connection.Read(buffer)
		if err != nil {
			return "", err
		}
		return string(buffer[:n]), nil
	}
	for _, network := range []string{"tcp", "udp"} {
		var answer string
		var lastErr error
		// the proxy binds from its own goroutines; give the bind a few tries
		for range 20 {
			answer, lastErr = exchange(network)
			if lastErr == nil {
				break
			}
		}
		if want := fmt.Sprintf("%s:gossip", network); answer != want {
			t.Errorf("%s through the proxy = %q (%v), want %q", network, answer, lastErr, want)
		}
	}
	if strings.Contains(backendTcp.Addr().String(), strconv.Itoa(externalPort)) {
		t.Fatal("the backend and the proxy share a port; the test proves nothing")
	}
}
