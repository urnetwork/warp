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

// Each Grafana ran its own Alertmanager with no ha_peers, so every host sent
// its own copy of every notification: six Slack messages for one alert on
// Main (2026-11-16, each of the six hosts counted the same sends). The
// rendered grafana.ini now clusters the Alertmanagers of the ring hosts, and
// only theirs.
func TestGrafanaAlertmanagersClusterAcrossTheRingHosts(t *testing.T) {
	hostSettings, ringHosts := alertmanagerTestHostSettings()
	section := renderUnifiedAlertingSection("test", "192.0.2.11", 14758, hostSettings, ringHosts)
	ini := parseIni(t, renderGrafanaIni(14758, "test-grafana.example", "[database]\ntype = sqlite3", "", section, "password", ""))

	alerting := ini["unified_alerting"]
	wantPeers := "192.0.2.10:6495,192.0.2.11:6495,192.0.2.12:6495"
	if got := alerting["ha_peers"]; got != wantPeers {
		t.Fatalf("ha_peers = %q, want every ring host's route address at the alertmanager gossip port: %q", got, wantPeers)
	}
	for key, want := range map[string]string{
		"ha_advertise_address": "192.0.2.11:6495",
		"ha_listen_address":    "192.0.2.11:14758",
		"ha_label":             "test-grafana-alertmanager",
	} {
		if got := alerting[key]; got != want {
			t.Errorf("[unified_alerting] %s = %q, want %q", key, got, want)
		}
	}
}

// Memberlist sends its udp packets from its listening socket, and a packet
// with a loopback source cannot leave the host, so the gossip listener binds
// the route address. It shares the number of grafana's http port, which is
// free there only while grafana's http server binds loopback.
func TestAlertmanagerGossipListenerSharesTheHttpPortOnTheRouteAddress(t *testing.T) {
	hostSettings, ringHosts := alertmanagerTestHostSettings()
	section := renderUnifiedAlertingSection("test", "192.0.2.11", 14758, hostSettings, ringHosts)
	ini := parseIni(t, renderGrafanaIni(14758, "test-grafana.example", "[database]\ntype = sqlite3", "", section, "password", ""))

	listenHost, listenPort, err := net.SplitHostPort(ini["unified_alerting"]["ha_listen_address"])
	if err != nil {
		t.Fatal(err)
	}
	if listenHost != "192.0.2.11" || listenHost == childListenAddress {
		t.Errorf("gossip listener host = %q, want the route address", listenHost)
	}
	if listenPort != ini["server"]["http_port"] {
		t.Errorf("gossip listener port = %s, want grafana's http port %s", listenPort, ini["server"]["http_port"])
	}
	if httpAddr := ini["server"]["http_addr"]; httpAddr != childListenAddress {
		t.Errorf("http_addr = %q: only a loopback http server leaves its port number free on the route address", httpAddr)
	}
	// the front forwards the advertised port to the same listener grafana binds
	if got := alertmanagerGossipListenAddr("192.0.2.11", 14758); got != ini["unified_alerting"]["ha_listen_address"] {
		t.Errorf("front backend %q differs from ha_listen_address %q", got, ini["unified_alerting"]["ha_listen_address"])
	}
}

// An IPv6 route address is bracketed in every host:port setting.
func TestAlertmanagerClusterBracketsIpv6RouteAddresses(t *testing.T) {
	hostSettings := &HostSettings{Routes: map[string]string{"edge-a": "2001:db8::10", "edge-b": "2001:db8::11"}}
	section := renderUnifiedAlertingSection("test", "2001:db8::11", 14758, hostSettings, []string{"edge-a", "edge-b"})
	ini := parseIni(t, renderGrafanaIni(14758, "test-grafana.example", "[database]\ntype = sqlite3", "", section, "password", ""))

	for key, want := range map[string]string{
		"ha_listen_address":    "[2001:db8::11]:14758",
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

// The front's fixed route-net ports stay out of warp's 7000-20000 allocation
// and below the edges' local port range "20000 60999" (the proxy hosts reserve
// them in xops inventory.yml), and no two share a number.
func TestFrontRouteNetPortsAvoidWarpAndEphemeralRanges(t *testing.T) {
	ports := map[string]int{
		"local publish":       defaultLocalPort,
		"loki grpc":           defaultGrpcPort,
		"mimir grpc":          defaultMimirGrpcPort,
		"loki gossip":         defaultGossipPort,
		"mimir gossip":        defaultMimirGossipPort,
		"alertmanager gossip": defaultAlertmanagerGossipPort,
	}
	seen := map[int]string{}
	for name, port := range ports {
		if 7000 <= port {
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
