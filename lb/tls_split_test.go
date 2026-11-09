//go:build linux || darwin

// §13.4's SNI split through a real nginx (TLS-M5-02): each kind of name reaches
// its branch, the tls edge's side gets PROXY v1 and the hello byte for byte,
// realip keys the http side per visitor, an upgraded connection lives through
// the hop, an oversized hello fails closed, the error log keeps no address,
// and a stale socket does not stop a restart. An external test package, so
// lb's main does not import its child splittest.
package main_test

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/urnetwork/warp"
	"github.com/urnetwork/warp/lb/splittest"
)

// How long a test waits on nginx or a backend before it fails: a bound on a
// failure, never a pause on success.
const splitTestTimeout = 10 * time.Second

// The repository's nginx_local first, then one on the path; a test skips when
// neither can run the split, and fails when NGINX_SPLIT_BINARY is set and
// wrong.
func splitBinary(t *testing.T) string {
	t.Helper()
	binary, err := splittest.FindBinary([]string{filepath.Join("build", "nginx-local", "sbin", "nginx"), "nginx"})
	if errors.Is(err, splittest.ErrNoBinary) {
		t.Skip(err)
	}
	if err != nil {
		t.Fatal(err)
	}
	return binary
}

// Starts the harness with settings, ending it with the test.
func startSplit(t *testing.T, settings *splittest.Settings) *splittest.Lb {
	t.Helper()
	lb, err := splittest.Start(settings)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { lb.Close() })
	return lb
}

// One GET on the http branch over conn, answering the status and body.
func splitGet(t *testing.T, conn net.Conn, host string, path string) (int, string) {
	t.Helper()
	conn.SetDeadline(time.Now().Add(splitTestTimeout))
	fmt.Fprintf(conn, "GET %s HTTP/1.1\r\nHost: %s\r\n\r\n", path, host)
	response, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("%s%s: %v", host, path, err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	return response.StatusCode, string(body)
}

// Records every byte written through it: what a visitor sent.
type recordingConn struct {
	net.Conn
	written bytes.Buffer
}

func (self *recordingConn) Write(b []byte) (int, error) {
	self.written.Write(b)
	return self.Conn.Write(b)
}

// Sends a crypto/tls ClientHello for serverName from network's loopback and
// answers the hello bytes written and the visitor's address: the handshake
// itself fails, since the edge stand-in answers unrecognized_name.
func sendEdgeHello(t *testing.T, lb *splittest.Lb, network string, serverName string) ([]byte, *net.TCPAddr) {
	t.Helper()
	conn, err := net.Dial(network, lb.Address(network))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	recording := &recordingConn{Conn: conn}
	client := tls.Client(recording, &tls.Config{ServerName: serverName, InsecureSkipVerify: true, NextProtos: []string{"h2", "http/1.1"}})
	client.SetDeadline(time.Now().Add(splitTestTimeout))
	if err := client.Handshake(); err == nil || !strings.Contains(err.Error(), "unrecognized name") {
		t.Fatalf("%s: the handshake answered %v, not the edge's unrecognized_name", serverName, err)
	}
	return recording.written.Bytes(), conn.LocalAddr().(*net.TCPAddr)
}

// The PROXY v1 line the split sends for a visitor at visitorAddr.
func splitProxyHeader(lb *splittest.Lb, network string, visitorAddr *net.TCPAddr) string {
	family, host := "TCP4", "127.0.0.1"
	if network == "tcp6" {
		family, host = "TCP6", "::1"
	}
	return fmt.Sprintf("PROXY %s %s %s %d %d\r\n", family, host, host, visitorAddr.Port, lb.Port)
}

// Each kind of name reaches its branch: platform names under the root, the
// apex, unknown names and a hello without SNI go to the http servers; a user's
// name under the root, one at any depth, and lbmap's custom host go to the
// edge, with PROXY v1 and the hello as sent.
func TestSplitRoutesEachKindOfNameToItsBranch(t *testing.T) {
	settings := splittest.DefaultSettings(splitBinary(t))
	settings.CustomHostLines = []string{"shop.customer.example " + splittest.EdgeUpstream + ";"}
	lb := startSplit(t, settings)

	for _, c := range []struct {
		name       string
		serverName string
		insecure   bool
	}{
		{name: "platform name under the root", serverName: "api.root.example"},
		{name: "the apex", serverName: "root.example"},
		{name: "unknown sni", serverName: "unknown.other.example", insecure: true},
		{name: "absent sni", serverName: ""},
	} {
		for _, network := range []string{"tcp4", "tcp6"} {
			before := len(lb.Http.Requests())
			conn, err := lb.DialHttps(network, c.serverName, c.insecure)
			if err != nil {
				t.Fatalf("%s over %s: %v", c.name, network, err)
			}
			host := c.serverName
			if host == "" {
				host = "absent.example"
			}
			status, body := splitGet(t, conn, host, "/branch")
			conn.Close()
			requests := lb.Http.Requests()
			if status != http.StatusOK || body != "/branch" || len(requests) != before+1 || requests[len(requests)-1].Host != host {
				t.Errorf("%s over %s: %d %q, %d requests", c.name, network, status, body, len(requests))
			}
		}
	}
	if count, errs := lb.Edge.Count(); count != 0 {
		t.Fatalf("http names reached the edge: %d, %v", count, errs)
	}

	edgeNames := []string{"a1b2c3d4e5.root.example", "web.a1b2c3d4e5.root.example", "shop.customer.example"}
	for _, serverName := range edgeNames {
		for _, network := range []string{"tcp4", "tcp6"} {
			hello, visitorAddr := sendEdgeHello(t, lb, network, serverName)
			open, err := lb.Edge.Next(splitTestTimeout)
			if err != nil {
				t.Fatalf("%s over %s: %v", serverName, network, err)
			}
			if want := splitProxyHeader(lb, network, visitorAddr); open.ProxyHeader != want {
				t.Errorf("%s over %s: proxy header %q, want %q", serverName, network, open.ProxyHeader, want)
			}
			if !bytes.Equal(open.Hello, hello) {
				t.Errorf("%s over %s: the edge got %d bytes of hello, the visitor sent %d", serverName, network, len(open.Hello), len(hello))
			}
		}
	}
	if count, errs := lb.Edge.Count(); count != 2*len(edgeNames) || 0 < len(errs) {
		t.Errorf("edge saw %d connections, %v", count, errs)
	}
	if requests := lb.Http.Requests(); len(requests) != 8 {
		t.Errorf("edge names reached the http branch: %d requests", len(requests))
	}
}

// realip gives the http server each visitor's own address from PROXY: a
// per-address limit keys per visitor, so one visitor's second request is
// refused while another's first passes, and X-UR-Forwarded-For carries the
// visitor's address and port exactly as it did before the split. The render's
// map brackets an IPv6 address only where nginx has PCRE, which nginx_local
// leaves out, so the IPv6 form follows the binary, and the split and the
// unsplit run must agree on it.
func TestSplitRealIpKeysPerVisitorAndKeepsXUrForwardedFor(t *testing.T) {
	binary := splitBinary(t)
	hasRegex, err := splittest.BinaryHasRegex(binary)
	if err != nil {
		t.Fatal(err)
	}
	// split -> network -> the header with the visitor's port written as PORT
	headers := map[bool]map[string]string{}
	for _, split := range []bool{true, false} {
		headers[split] = map[string]string{}
		settings := splittest.DefaultSettings(binary)
		settings.Split = split
		lb := startSplit(t, settings)
		visit := func(network string, wantStatus int) {
			t.Helper()
			conn, err := lb.DialHttps(network, "api.root.example", false)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			status, _ := splitGet(t, conn, "api.root.example", "/limited")
			if status != wantStatus {
				t.Fatalf("split %t: %s visitor got %d, want %d", split, network, status, wantStatus)
			}
			if status != http.StatusOK {
				return
			}
			requests := lb.Http.Requests()
			got := requests[len(requests)-1]
			if got.ForwardedForCount != 0 {
				t.Errorf("split %t: X-Forwarded-For passed through", split)
			}
			visitorPort := strconv.Itoa(conn.LocalAddr().(*net.TCPAddr).Port)
			if !strings.HasSuffix(got.UrForwardedFor, ":"+visitorPort) {
				t.Fatalf("split %t: X-UR-Forwarded-For %q does not end in the visitor's port %s", split, got.UrForwardedFor, visitorPort)
			}
			headers[split][network] = strings.TrimSuffix(got.UrForwardedFor, visitorPort) + "PORT"
		}
		visit("tcp4", http.StatusOK)
		// the same visitor again: its own zone entry is spent
		visit("tcp4", http.StatusTooManyRequests)
		// another visitor, whose key is its own address, not the socket's
		visit("tcp6", http.StatusOK)
	}
	wantIpv6 := "::1:PORT"
	if hasRegex {
		wantIpv6 = "[::1]:PORT"
	}
	for _, split := range []bool{true, false} {
		if headers[split]["tcp4"] != "127.0.0.1:PORT" || headers[split]["tcp6"] != wantIpv6 {
			t.Errorf("split %t: X-UR-Forwarded-For %v", split, headers[split])
		}
	}
}

// An upgraded H1 connection, as connect's H1 transport opens one, lives
// through the stream hop and the socket: the 101 arrives and bytes echo both
// ways, many times over.
func TestSplitCarriesAWebSocketThroughTheHop(t *testing.T) {
	lb := startSplit(t, splittest.DefaultSettings(splitBinary(t)))
	conn, err := lb.DialHttps("tcp4", "api.root.example", false)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(splitTestTimeout))
	fmt.Fprintf(conn, "GET /ws HTTP/1.1\r\nHost: api.root.example\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
	reader := bufio.NewReader(conn)
	response, err := http.ReadResponse(reader, nil)
	if err != nil || response.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("upgrade: %v, %v", response, err)
	}
	for i := range 64 {
		message := bytes.Repeat([]byte{byte(i)}, 1+i*97)
		if _, err := conn.Write(message); err != nil {
			t.Fatal(err)
		}
		echo := make([]byte, len(message))
		if _, err := io.ReadFull(reader, echo); err != nil || !bytes.Equal(echo, message) {
			t.Fatalf("message %d: %v", i, err)
		}
	}
}

// A hello past the preread buffer fails closed: nginx closes the connection,
// and neither branch sees a byte. One under the buffer, its positive twin,
// reaches the edge whole.
func TestSplitFailsClosedOnAHelloPastThePrereadBuffer(t *testing.T) {
	settings := splittest.DefaultSettings(splitBinary(t))
	settings.ClientHelloMaxBytes = 4096
	lb := startSplit(t, settings)

	fits := splittest.ClientHello("a1b2c3d4e5.root.example", 3000)
	if len(fits) <= 3000 || 4096 <= len(fits) {
		t.Fatalf("the fitting hello is %d bytes", len(fits))
	}
	conn, err := net.Dial("tcp4", lb.Address("tcp4"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write(fits); err != nil {
		t.Fatal(err)
	}
	open, err := lb.Edge.Next(splitTestTimeout)
	if err != nil || !bytes.Equal(open.Hello, fits) {
		t.Fatalf("a hello under the buffer: %v", err)
	}
	conn.Close()

	tooLong := splittest.ClientHello("a1b2c3d4e5.root.example", 5000)
	if len(tooLong) <= 4096 {
		t.Fatalf("the long hello is %d bytes", len(tooLong))
	}
	conn, err = net.Dial("tcp4", lb.Address("tcp4"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(splitTestTimeout))
	// nginx may close before taking it all, which the write then reports
	conn.Write(tooLong)
	if n, err := conn.Read(make([]byte, 1)); err == nil || errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("a hello past the buffer: read %d, %v, not a close", n, err)
	}
	if count, _ := lb.Edge.Count(); count != 1 {
		t.Errorf("the edge saw %d connections, only the fitting hello's", count)
	}
	if requests := lb.Http.Requests(); len(requests) != 0 {
		t.Errorf("the http branch saw %d requests", len(requests))
	}
	// stop nginx, so every entry has been read, then find why it closed
	lb.Close()
	if !strings.Contains(lb.ScrubbedErrorLog(), "preread buffer full") {
		t.Error("nginx did not log the full buffer")
	}
}

// Every address nginx writes into its error log, the visitor's and its own,
// is gone from what the lb process passes on, across http and stream errors,
// while the raw log, which never leaves memory, had them to take out.
func TestSplitErrorLogHoldsNoAddress(t *testing.T) {
	settings := splittest.DefaultSettings(splitBinary(t))
	settings.ClientHelloMaxBytes = 2048
	lb := startSplit(t, settings)

	// a stream error: a hello past the buffer, from both families
	for _, network := range []string{"tcp4", "tcp6"} {
		conn, err := net.Dial(network, lb.Address(network))
		if err != nil {
			t.Fatal(err)
		}
		conn.SetDeadline(time.Now().Add(splitTestTimeout))
		conn.Write(splittest.ClientHello("a1b2c3d4e5.root.example", 4000))
		conn.Read(make([]byte, 1))
		conn.Close()
	}
	// an http error: the upstream gone, so the http server logs its failure with the client
	lb.Http.Close()
	conn, err := lb.DialHttps("tcp6", "api.root.example", false)
	if err != nil {
		t.Fatal(err)
	}
	if status, _ := splitGet(t, conn, "api.root.example", "/gone?token=synthetic-secret"); status != http.StatusBadGateway {
		t.Errorf("status %d with the upstream gone", status)
	}
	conn.Close()
	// stop nginx, so every entry has been written
	lb.Close()

	ipv4 := regexp.MustCompile(`\b\d{1,3}(\.\d{1,3}){3}\b`)
	raw := lb.RawErrorLog()
	if !ipv4.MatchString(raw) || !strings.Contains(raw, "::1") {
		t.Fatal("the raw log holds no address, so the test proves nothing")
	}
	scrubbed := lb.ScrubbedErrorLog()
	if match := ipv4.FindString(scrubbed); match != "" {
		t.Errorf("the scrubbed log holds %s", match)
	}
	if strings.Contains(scrubbed, "::1") || strings.Contains(scrubbed, "synthetic-secret") {
		t.Error("the scrubbed log holds an ipv6 address or a query string")
	}
	if !strings.Contains(scrubbed, "preread buffer full") {
		t.Error("the stream error is missing from the scrubbed log")
	}
}

// A killed nginx leaves its socket, which the next nginx cannot bind; the lb
// process prepares the run directory first, so the restart serves.
func TestSplitRestartsOverAStaleSocket(t *testing.T) {
	lb := startSplit(t, splittest.DefaultSettings(splitBinary(t)))
	if err := lb.Kill(); err != nil {
		t.Fatal(err)
	}
	socketPath := filepath.Join(lb.RunDir, filepath.Base(warp.LbHttpsSocketPath))
	if info, err := os.Lstat(socketPath); err != nil || info.Mode().Type() != os.ModeSocket {
		t.Fatalf("the kill left no socket to test: %v", err)
	}
	if err := lb.Restart(); err != nil {
		t.Fatal(err)
	}
	conn, err := lb.DialHttps("tcp4", "api.root.example", false)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if status, _ := splitGet(t, conn, "api.root.example", "/after-restart"); status != http.StatusOK {
		t.Errorf("status %d after the restart", status)
	}
}

// The harness's config carries the directives warpctl's render writes for the
// split, held through the render's golden file, so the tests here prove what
// the lb runs and not a config of their own.
func TestSplitHarnessCarriesTheRendersDirectives(t *testing.T) {
	golden, err := os.ReadFile(filepath.Join("..", "warpctl", "testdata", "tls_split", "split.conf"))
	if err != nil {
		t.Fatal(err)
	}
	lb := startSplit(t, splittest.DefaultSettings(splitBinary(t)))
	config, err := lb.Config()
	if err != nil {
		t.Fatal(err)
	}
	for _, directive := range []string{
		"set_real_ip_from unix:;",
		"real_ip_header proxy_protocol;",
		"ssl proxy_protocol backlog=65535;",
		"map_hash_bucket_size 512;",
		"server_names_hash_bucket_size 512;",
		"map $ssl_preread_server_name $tls_split_upstream {",
		"hostnames;",
		"api.root.example lb-https;",
		"*.root.example stream-service-block-tlsedge-443;",
		"default lb-https;",
		"upstream lb-https {",
		"reuseport backlog=65535;",
		"ssl_preread on;",
		"preread_timeout 10s;",
		"preread_buffer_size 16384;",
		"proxy_protocol on;",
		"proxy_pass $tls_split_upstream;",
		"proxy_set_header X-UR-Forwarded-For $warp_client_addr:$remote_port;",
	} {
		if !bytes.Contains(golden, []byte(directive)) {
			t.Errorf("the render does not write %q", directive)
		}
		if !strings.Contains(config, directive) {
			t.Errorf("the harness does not write %q", directive)
		}
	}
	for _, directive := range []string{"listen unix:", "server unix:", "include "} {
		if !bytes.Contains(golden, []byte(directive)) || !strings.Contains(config, directive) {
			t.Errorf("%q is not in both", directive)
		}
	}
}

// The image and nginx_local build the split's modules: ssl, realip, stream
// ssl and ssl_preread, each kept to the pinned source.
func TestNginxBuildsCarryTheSplitsModules(t *testing.T) {
	for _, path := range []string{"Dockerfile", "Makefile"} {
		content, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		for _, option := range []string{"--with-http_ssl_module", "--with-http_realip_module", "--with-stream_ssl_module", "--with-stream_ssl_preread_module"} {
			if !bytes.Contains(content, []byte(option)) {
				t.Errorf("%s does not build %s", path, option)
			}
		}
	}
}

// NGINX_SPLIT_BINARY set and wrong is an error, never a skip; unset with no
// capable candidate is ErrNoBinary, which callers skip on.
func TestSplitBinaryFailsWhenSetAndWrong(t *testing.T) {
	t.Setenv(splittest.BinaryEnv, filepath.Join(t.TempDir(), "no-such-nginx"))
	if _, err := splittest.FindBinary(nil); err == nil || errors.Is(err, splittest.ErrNoBinary) {
		t.Errorf("a missing binary: %v", err)
	}
	notNginx := filepath.Join(t.TempDir(), "not-nginx")
	if err := os.WriteFile(notNginx, []byte("#!/bin/sh\necho 'nginx version: nginx/1.0.0'\necho 'configure arguments: --with-stream'\n"), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv(splittest.BinaryEnv, notNginx)
	if _, err := splittest.FindBinary(nil); err == nil || errors.Is(err, splittest.ErrNoBinary) || !strings.Contains(err.Error(), "--with-stream_ssl_preread_module") {
		t.Errorf("a binary without the split's modules: %v", err)
	}
	t.Setenv(splittest.BinaryEnv, "")
	if _, err := splittest.FindBinary([]string{notNginx}); !errors.Is(err, splittest.ErrNoBinary) {
		t.Errorf("no capable candidate: %v", err)
	}
}
