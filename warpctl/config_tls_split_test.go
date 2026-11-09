package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/urnetwork/warp"
)

// Set to rewrite the split's golden render from the code: only after reading
// the diff it makes.
const tlsSplitUpdateGoldenEnv = "WARP_UPDATE_TLS_SPLIT_GOLDEN"

// The split's root in the fixtures: a zone apart from the services domain, as
// <root> is apart from the platform's, with two platform names left under it.
const tlsSplitTestRoot = "root.example"

// The base fixture's latest version with a tls edge service and the split:
// tlsedge declares stream ports 443 and 8443, the lb gives 8443 to it, svc-a
// serves the root's apex and api.root.example, and mutate edits the result.
func tlsSplitServicesYaml(t *testing.T, mutate func(string) string) string {
	t.Helper()
	baseYaml, err := testServicesFS.ReadFile("testdata/services.yml")
	if err != nil {
		t.Fatal(err)
	}
	servicesYaml := string(baseYaml)
	replace := func(old string, new string) {
		t.Helper()
		// the latest version is the first in the file, so the first match
		replaced := strings.Replace(servicesYaml, old, new, 1)
		if replaced == servicesYaml {
			t.Fatalf("the fixture lacks %q", old)
		}
		servicesYaml = replaced
	}
	replace(
		"        tcp_stream_port_services:\n            444: svc-c\n",
		"        tcp_stream_port_services:\n            444: svc-c\n            8443: tlsedge\n",
	)
	replace(
		"        udp_forward_ports:\n            53: 5353\n",
		"        udp_forward_ports:\n            53: 5353\n"+
			"        tls_split:\n"+
			"            roots:\n"+
			"                - "+tlsSplitTestRoot+"\n"+
			"            service: tlsedge\n"+
			"            proxy_buffer_size: 32kib\n"+
			"            client_hello:\n"+
			"                timeout_s: 10\n"+
			"                max_bytes: 16384\n",
	)
	replace(
		"        svc-a:\n            cors_origins:\n",
		"        svc-a:\n            expose_aliases:\n                - "+tlsSplitTestRoot+"\n                - api."+tlsSplitTestRoot+"\n            cors_origins:\n",
	)
	replace(
		"        taskworker:\n            exposed: false\n",
		"        tlsedge:\n"+
			"            ports:\n"+
			"                - 80\n"+
			"            tcp_stream_ports:\n"+
			"                - 443\n"+
			"                - 8443\n"+
			"            blocks:\n"+
			"                - beta: 1\n"+
			"                - g1: 99\n"+
			"        taskworker:\n            exposed: false\n",
	)
	if mutate != nil {
		servicesYaml = mutate(servicesYaml)
	}
	return servicesYaml
}

// The same document with its tls_split block renamed to a key the loader
// ignores, so a split and an unsplit render share everything else.
func withoutTlsSplit(servicesYaml string) string {
	return strings.Replace(servicesYaml, "        tls_split:\n            roots:\n", "        tls_split_off:\n            roots:\n", 1)
}

// A test vault for servicesYaml with certificates for the services domain, the
// split's root and each of moreNames, `*.x` a wildcard over x, and its env.
func setupTlsSplitTestVault(t *testing.T, servicesYaml string, moreNames ...string) (env string, vaultDir string) {
	t.Helper()
	env, vaultDir = setupTestVaultWithTLS(t, []byte(servicesYaml))
	tlsDir := filepath.Join(vaultDir, "tls", "1.0.0")
	generateTestTLSFiles(t, tlsDir, tlsSplitTestRoot, true)
	generateTestTLSFiles(t, tlsDir, tlsSplitTestRoot, false)
	for _, name := range moreNames {
		zone, wildcard := strings.CutPrefix(name, "*.")
		generateTestTLSFiles(t, tlsDir, zone, wildcard)
	}
	return env, vaultDir
}

// Every lb block's render of servicesYaml, with certificates for moreNames.
func renderTlsSplitTest(t *testing.T, servicesYaml string, moreNames ...string) map[string]string {
	t.Helper()
	env, _ := setupTlsSplitTestVault(t, servicesYaml, moreNames...)
	nginxConfig, err := NewNginxConfig(env, nil)
	if err != nil {
		t.Fatal(err)
	}
	blockConfigs := nginxConfig.Generate()
	if len(blockConfigs) == 0 {
		t.Fatal("no lb blocks")
	}
	return blockConfigs
}

// Compares every block's render with the golden file, which all blocks of the
// fixture share, or rewrites it when asked.
func requireTlsSplitGolden(t *testing.T, blockConfigs map[string]string, goldenName string) {
	t.Helper()
	goldenPath := filepath.Join("testdata", "tls_split", goldenName)
	if os.Getenv(tlsSplitUpdateGoldenEnv) == "1" {
		for _, config := range blockConfigs {
			if err := os.WriteFile(goldenPath, []byte(config), 0644); err != nil {
				t.Fatal(err)
			}
			break
		}
	}
	golden, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatal(err)
	}
	for block, config := range blockConfigs {
		if config != string(golden) {
			t.Errorf("block %s differs from %s; the first differing line is %s", block, goldenPath, firstDifferingLine(config, string(golden)))
		}
	}
}

// The first line two texts differ at, both sides, for a failure message.
func firstDifferingLine(got string, want string) string {
	gotLines := strings.Split(got, "\n")
	wantLines := strings.Split(want, "\n")
	for i := 0; i < len(gotLines) || i < len(wantLines); i += 1 {
		gotLine, wantLine := "<end>", "<end>"
		if i < len(gotLines) {
			gotLine = gotLines[i]
		}
		if i < len(wantLines) {
			wantLine = wantLines[i]
		}
		if gotLine != wantLine {
			return fmt.Sprintf("%d: got %q, want %q", i+1, gotLine, wantLine)
		}
	}
	return "none"
}

// The text of the first top level block of config opening with header, through
// its closing brace at the same indent.
func nginxBlockText(t *testing.T, config string, header string) string {
	t.Helper()
	lines := strings.Split(config, "\n")
	for i, line := range lines {
		if strings.TrimSpace(line) != header+" {" {
			continue
		}
		indent := line[:len(line)-len(strings.TrimLeft(line, " "))]
		for j := i + 1; j < len(lines); j += 1 {
			if lines[j] == indent+"}" {
				return strings.Join(lines[i:j+1], "\n")
			}
		}
	}
	t.Fatalf("no %q block", header)
	return ""
}

// The server blocks of a block's text, each whole.
func nginxServerTexts(text string) []string {
	servers := []string{}
	lines := strings.Split(text, "\n")
	for i, line := range lines {
		if strings.TrimSpace(line) != "server {" {
			continue
		}
		indent := line[:len(line)-len(strings.TrimLeft(line, " "))]
		for j := i + 1; j < len(lines); j += 1 {
			if lines[j] == indent+"}" {
				servers = append(servers, strings.Join(lines[i:j+1], "\n"))
				break
			}
		}
	}
	return servers
}

// Without tls_split nothing changes: the render of the base fixture is today's
// byte for byte, the order of the stream blocks included, which map iteration
// set before and tcp before udp sets now.
func TestUnsplitRenderIsByteIdenticalToToday(t *testing.T) {
	baseYaml, err := testServicesFS.ReadFile("testdata/services.yml")
	if err != nil {
		t.Fatal(err)
	}
	env, _ := setupTestVaultWithTLS(t, baseYaml)
	nginxConfig, err := NewNginxConfig(env, nil)
	if err != nil {
		t.Fatal(err)
	}
	blockConfigs := nginxConfig.Generate()
	goldenPath := filepath.Join("testdata", "tls_split", "unsplit.conf")
	golden, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatal(err)
	}
	for block, config := range blockConfigs {
		if config != string(golden) {
			t.Errorf("block %s differs from today's render; first differing line %s", block, firstDifferingLine(config, string(golden)))
		}
		for _, absent := range []string{"ssl_preread", "warp-lb", "set_real_ip_from", "tls_split"} {
			if strings.Contains(config, absent) {
				t.Errorf("block %s renders %q without a split", block, absent)
			}
		}
	}
}

// The split's render, pinned whole.
func TestTlsSplitRenderMatchesGolden(t *testing.T) {
	requireTlsSplitGolden(t, renderTlsSplitTest(t, tlsSplitServicesYaml(t, nil)), "split.conf")
}

// §13.4's stream block on every interface: the map with hostnames, the root and
// its platform names to lb-https, `*.<root>` to the edge's upstream, the
// custom-host include, default lb-https; the socket's upstream; the 443
// server on both families with preread, PROXY and the variable proxy_pass;
// and the edge's 443 upstream with its blocks, which a variable proxy_pass
// needs defined.
func TestTlsSplitEveryInterfaceRendersTheStreamSplit(t *testing.T) {
	blockConfigs := renderTlsSplitTest(t, tlsSplitServicesYaml(t, nil))
	if len(blockConfigs) != 4 {
		t.Fatalf("%d blocks", len(blockConfigs))
	}
	for block, config := range blockConfigs {
		stream := nginxBlockText(t, config, "stream")
		mapText := nginxBlockText(t, stream, "map $ssl_preread_server_name $tls_split_upstream")
		wantMapLines := []string{
			"hostnames;",
			tlsSplitTestRoot + " lb-https;",
			"api." + tlsSplitTestRoot + " lb-https;",
			"*." + tlsSplitTestRoot + " stream-service-block-tlsedge-443;",
			"include " + warp.LbTlsCustomHostsMapPath + ";",
			"default lb-https;",
		}
		gotMapLines := []string{}
		for _, line := range strings.Split(mapText, "\n")[1:] {
			if trimmed := strings.TrimSpace(line); trimmed != "}" && trimmed != "" {
				gotMapLines = append(gotMapLines, trimmed)
			}
		}
		if !slices.Equal(gotMapLines, wantMapLines) {
			t.Errorf("block %s map:\n%s\nwant %v", block, strings.Join(gotMapLines, "\n"), wantMapLines)
		}

		upstream := nginxBlockText(t, stream, "upstream lb-https")
		if !strings.Contains(upstream, "server unix:"+warp.LbHttpsSocketPath+";") {
			t.Errorf("block %s lb-https:\n%s", block, upstream)
		}
		edgeUpstream := nginxBlockText(t, stream, "upstream stream-service-block-tlsedge-443")
		if strings.Count(edgeUpstream, "server testservices:") != 2 {
			t.Errorf("block %s edge upstream does not list tlsedge's two blocks:\n%s", block, edgeUpstream)
		}

		var splitServer string
		for _, server := range nginxServerTexts(stream) {
			if strings.Contains(server, "ssl_preread on;") {
				if splitServer != "" {
					t.Fatalf("block %s renders two split servers", block)
				}
				splitServer = server
			}
		}
		for _, want := range []string{
			"listen 443 reuseport backlog=65535;",
			"listen [::]:443 reuseport backlog=65535;",
			"ssl_preread on;",
			"preread_timeout 10s;",
			"preread_buffer_size 16384;",
			"proxy_protocol on;",
			"proxy_pass $tls_split_upstream;",
			"proxy_buffer_size 32768;",
		} {
			if !strings.Contains(splitServer, want) {
				t.Errorf("block %s split server lacks %q:\n%s", block, want, splitServer)
			}
		}
		// the stream block writes no access log, so no name a visitor sends is kept
		if strings.Contains(stream, "access_log") {
			t.Errorf("block %s stream block logs", block)
		}
		// the split owns tcp 443: no other stream server listens there
		for _, server := range nginxServerTexts(stream) {
			if server != splitServer && regexp.MustCompile(`listen (\[::\]:)?443;`).MatchString(server) {
				t.Errorf("block %s renders a second tcp 443 server:\n%s", block, server)
			}
		}
	}
}

// Every 443 listen of the http servers moves to the socket with PROXY, the
// first carrying the backlog and none reuseport; realip restores the visitor;
// and nothing in http listens on tcp 443 any more.
func TestTlsSplitMovesEveryHttpsListenToTheSocket(t *testing.T) {
	unsplitConfigs := renderTlsSplitTest(t, tlsSplitServicesYaml(t, withoutTlsSplit))
	splitConfigs := renderTlsSplitTest(t, tlsSplitServicesYaml(t, nil))
	for block, config := range splitConfigs {
		http := nginxBlockText(t, config, "http")
		unsplitHttp := nginxBlockText(t, unsplitConfigs[block], "http")
		httpsServerCount := strings.Count(unsplitHttp, "listen 443 ssl")
		if httpsServerCount < 2 {
			t.Fatalf("block %s: the unsplit fixture has %d https servers", block, httpsServerCount)
		}
		socketListen := "listen unix:" + warp.LbHttpsSocketPath + " ssl proxy_protocol"
		if count := strings.Count(http, socketListen); count != httpsServerCount {
			t.Errorf("block %s: %d socket listens for %d https servers", block, count, httpsServerCount)
		}
		if count := strings.Count(http, socketListen+" backlog=65535;"); count != 1 {
			t.Errorf("block %s: %d socket listens carry the backlog", block, count)
		}
		if regexp.MustCompile(`listen (\[::\]:)?443 ssl`).MatchString(http) {
			t.Errorf("block %s: an http server still listens on tcp 443", block)
		}
		if regexp.MustCompile(`listen unix:[^;]*reuseport`).MatchString(http) {
			t.Errorf("block %s: reuseport on a unix listen", block)
		}
		for _, want := range []string{"set_real_ip_from unix:;", "real_ip_header proxy_protocol;"} {
			if strings.Count(http, want) != 1 {
				t.Errorf("block %s: %q %d times", block, want, strings.Count(http, want))
			}
		}
		// X-UR-Forwarded-For keeps its form, which realip now fills with the visitor
		if !strings.Contains(http, "proxy_set_header X-UR-Forwarded-For $warp_client_addr:$remote_port;") {
			t.Errorf("block %s: X-UR-Forwarded-For changed", block)
		}
	}
}

// H3 keeps UDP 443 (D-TLS-10): with no udp 443 stream service, the http
// servers keep `listen 443 quic` and Alt-Svc behind the split as before it.
func TestSplitRenderLeavesQuic(t *testing.T) {
	withoutUdp443 := func(servicesYaml string) string {
		servicesYaml = strings.Replace(servicesYaml, "        udp_stream_port_services:\n            443: svc-c\n", "        udp_stream_port_services:\n", 1)
		return strings.Replace(servicesYaml, "            udp_stream_ports:\n                - 443\n                - 5353\n", "            udp_stream_ports:\n                - 5353\n", 1)
	}
	unsplitConfigs := renderTlsSplitTest(t, tlsSplitServicesYaml(t, func(servicesYaml string) string {
		return withoutTlsSplit(withoutUdp443(servicesYaml))
	}))
	splitConfigs := renderTlsSplitTest(t, tlsSplitServicesYaml(t, withoutUdp443))
	for block, config := range splitConfigs {
		http := nginxBlockText(t, config, "http")
		unsplitHttp := nginxBlockText(t, unsplitConfigs[block], "http")
		for _, want := range []string{"listen 443 quic;", "listen [::]:443 quic;", `add_header 'Alt-Svc' 'h3=":443"; ma=86400';`} {
			count := strings.Count(http, want)
			if count == 0 || count != strings.Count(unsplitHttp, want) {
				t.Errorf("block %s: %q %d times split, %d unsplit", block, want, count, strings.Count(unsplitHttp, want))
			}
		}
		// the quic listens are udp, which the stream split does not touch
		if strings.Contains(nginxBlockText(t, config, "stream"), "443 udp") {
			t.Errorf("block %s: a udp 443 stream server with no udp 443 service", block)
		}
	}
}

// Port 80 for the root's names redirects to https and logs nothing (I-13);
// lbmap's custom hosts follow through the include.
func TestTlsSplitPort80RedirectLogsNothing(t *testing.T) {
	for block, config := range renderTlsSplitTest(t, tlsSplitServicesYaml(t, nil)) {
		http := nginxBlockText(t, config, "http")
		var redirect string
		for _, server := range nginxServerTexts(http) {
			if strings.Contains(server, "server_name *."+tlsSplitTestRoot+";") {
				redirect = server
			}
		}
		for _, want := range []string{"listen 80;", "listen [::]:80;", "access_log off;", "return 301 https://$host$request_uri;"} {
			if !strings.Contains(redirect, want) {
				t.Errorf("block %s: the redirect lacks %q:\n%s", block, want, redirect)
			}
		}
		if !strings.Contains(http, "include "+warp.LbTlsCustomHosts80Path+";") {
			t.Errorf("block %s: no custom hosts include for port 80", block)
		}
	}
}

// A platform name under a root whose label is not reserved refuses the render,
// since a network could hold that label and get the name's traffic (§12.5).
func TestTlsSplitRefusesAnUnreservedPlatformName(t *testing.T) {
	servicesYaml := tlsSplitServicesYaml(t, func(servicesYaml string) string {
		return strings.Replace(servicesYaml, "                - api."+tlsSplitTestRoot+"\n", "                - api."+tlsSplitTestRoot+"\n                - shop."+tlsSplitTestRoot+"\n", 1)
	})
	env, _ := setupTlsSplitTestVault(t, servicesYaml)
	_, err := NewNginxConfig(env, nil)
	if err == nil || !strings.Contains(err.Error(), "shop."+tlsSplitTestRoot) || !strings.Contains(err.Error(), "not a reserved label") {
		t.Fatalf("err %v", err)
	}

	// a deeper platform name is judged by its label under the root
	servicesYaml = tlsSplitServicesYaml(t, func(servicesYaml string) string {
		return strings.Replace(servicesYaml, "                - api."+tlsSplitTestRoot+"\n", "                - api."+tlsSplitTestRoot+"\n                - www.shop."+tlsSplitTestRoot+"\n", 1)
	})
	env, _ = setupTlsSplitTestVault(t, servicesYaml, "shop."+tlsSplitTestRoot)
	if _, err := NewNginxConfig(env, nil); err == nil || !strings.Contains(err.Error(), `"shop"`) {
		t.Fatalf("deeper name: %v", err)
	}

	// a platform wildcard over the root would take every name the split sends
	servicesYaml = tlsSplitServicesYaml(t, func(servicesYaml string) string {
		return strings.Replace(servicesYaml, "                - api."+tlsSplitTestRoot+"\n", "                - api."+tlsSplitTestRoot+"\n                - \"*."+tlsSplitTestRoot+"\"\n", 1)
	})
	env, _ = setupTlsSplitTestVault(t, servicesYaml)
	if _, err := NewNginxConfig(env, nil); err == nil || !strings.Contains(err.Error(), "would take every name") {
		t.Fatalf("root wildcard: %v", err)
	}
}

// A name under a root is in the map only while its label is reserved: every
// lb-https line under the root, the root itself aside, has a reserved label,
// and a reserved pattern counts, as main-* and *-lb do.
func TestTlsSplitMapHoldsARootNameOnlyWhileReserved(t *testing.T) {
	servicesYaml := tlsSplitServicesYaml(t, func(servicesYaml string) string {
		aliases := "                - api." + tlsSplitTestRoot + "\n"
		for _, name := range []string{"main-web", "edge-7-lb", "*.connect"} {
			aliases += "                - \"" + name + "." + tlsSplitTestRoot + "\"\n"
		}
		return strings.Replace(servicesYaml, "                - api."+tlsSplitTestRoot+"\n", aliases, 1)
	})
	reserved, err := tlsSplitReserved()
	if err != nil {
		t.Fatal(err)
	}
	for block, config := range renderTlsSplitTest(t, servicesYaml, "*.connect."+tlsSplitTestRoot) {
		mapText := nginxBlockText(t, nginxBlockText(t, config, "stream"), "map $ssl_preread_server_name $tls_split_upstream")
		platformNames := []string{}
		for _, line := range strings.Split(mapText, "\n") {
			fields := strings.Fields(strings.TrimSuffix(strings.TrimSpace(line), ";"))
			if len(fields) != 2 || fields[1] != "lb-https" || fields[0] == "default" {
				continue
			}
			name := fields[0]
			if name == tlsSplitTestRoot {
				continue
			}
			below, under := strings.CutSuffix(name, "."+tlsSplitTestRoot)
			if !under {
				t.Errorf("block %s maps %s, which is under no root", block, name)
				continue
			}
			labels := strings.Split(below, ".")
			if !reserved.reserved(labels[len(labels)-1]) {
				t.Errorf("block %s maps %s with an unreserved label", block, name)
			}
			platformNames = append(platformNames, name)
		}
		want := []string{"*.connect." + tlsSplitTestRoot, "api." + tlsSplitTestRoot, "edge-7-lb." + tlsSplitTestRoot, "main-web." + tlsSplitTestRoot}
		if !slices.Equal(platformNames, want) {
			t.Errorf("block %s platform names %v, want %v", block, platformNames, want)
		}
	}
}

// The reserved list's patterns and labels, as the sidecar's parser reads them.
func TestTlsSplitReservedLabels(t *testing.T) {
	reserved, err := tlsSplitReserved()
	if err != nil {
		t.Fatal(err)
	}
	for _, label := range []string{"www", "api", "tlsedge", "main-api", "main-lb", "beta-web", "edge-lb", "probe-v4", "ur"} {
		if !reserved.reserved(label) {
			t.Errorf("%s is not reserved", label)
		}
	}
	for _, label := range []string{"shop", "a1b2c3d4e5", "main", "lb-x", "mainapi", "-lb", "v4"} {
		if reserved.reserved(label) {
			t.Errorf("%s is reserved", label)
		}
	}
	for _, broken := range []string{"Upper", "a*b", "**", "x_y", "*"} {
		if _, err := parseTlsSplitReservedLabels(broken + "\n"); err == nil {
			t.Errorf("%q parsed", broken)
		}
	}
}

// warpctl's copy of the reserved list is byte for byte the sidecar's
// (DNS-M0-01's file), so the render refuses exactly what §12.5 reserves.
func TestTlsSplitEmbeddedReservedListEqualsTheSidecars(t *testing.T) {
	siblingDir := filepath.Join("..", "..", "sidecar")
	if _, err := os.Stat(filepath.Join(siblingDir, "go.mod")); err != nil {
		t.Skipf("no sibling sidecar checkout beside warp: %v", err)
	}
	sibling, err := os.ReadFile(filepath.Join(siblingDir, "dns_reserved_labels.txt"))
	if err != nil {
		t.Fatalf("the sibling sidecar checkout has no reserved list: %v", err)
	}
	if !bytes.Equal(sibling, []byte(tlsSplitReservedLabelsText)) {
		t.Fatal("warpctl/dns_reserved_labels.txt differs from sidecar/dns_reserved_labels.txt: change both in one landing")
	}
}

// Each visitor connection on 443 now holds three worker connections, so the
// events block counts them where the fd cap does not bind.
func TestTlsSplitCountsItsWorkerConnections(t *testing.T) {
	small := func(servicesYaml string) string {
		return strings.ReplaceAll(servicesYaml, "concurrent_clients: 786432", "concurrent_clients: 2400")
	}
	unsplitConfigs := renderTlsSplitTest(t, tlsSplitServicesYaml(t, func(servicesYaml string) string {
		return withoutTlsSplit(small(servicesYaml))
	}))
	splitConfigs := renderTlsSplitTest(t, tlsSplitServicesYaml(t, small))
	workerConnections := regexp.MustCompile(`worker_connections (\d+);`)
	for block, config := range splitConfigs {
		unsplit := workerConnections.FindStringSubmatch(unsplitConfigs[block])
		split := workerConnections.FindStringSubmatch(config)
		// 32 connections per client, 2,400 clients over 24 cores, rounded up: 3,230, then three times the connections
		if unsplit == nil || split == nil || unsplit[1] != fmt.Sprint(32*(2400+23)/24) || split[1] != fmt.Sprint(3*32*(2400+23)/24) {
			t.Errorf("block %s: worker_connections %v unsplit, %v split", block, unsplit, split)
		}
	}
}

// Were a tcp_stream_port_services entry to give 443 to a service, which the
// loader refuses beside a split, the render still writes no second server on
// tcp 443.
func TestTlsSplitSkipsAStreamServerOn443(t *testing.T) {
	env, _ := setupTlsSplitTestVault(t, tlsSplitServicesYaml(t, nil))
	nginxConfig, err := NewNginxConfig(env, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, blockInfo := range nginxConfig.blockInfos["lb"] {
		blockInfo.lbBlock.TcpStreamPortServices[443] = "tlsedge"
	}
	for block, config := range nginxConfig.Generate() {
		for _, server := range nginxServerTexts(nginxBlockText(t, config, "stream")) {
			if !strings.Contains(server, "ssl_preread on;") && regexp.MustCompile(`listen (\[::\]:)?443;`).MatchString(server) {
				t.Errorf("block %s renders a second tcp 443 server:\n%s", block, server)
			}
		}
	}
}

// Rewrites the split's run paths into runDir, so nginx -t reads includes there.
func localTlsSplitConfig(config string, vaultDir string, runDir string) string {
	return strings.ReplaceAll(localNginxConfig(config, vaultDir), warp.LbRunDir+"/", runDir+"/")
}

// A run directory short enough for a unix socket path on every platform, with
// the two includes the lb writes before nginx starts.
func tlsSplitTestRunDir(t *testing.T, customHosts string, customHosts80 string) string {
	t.Helper()
	runDir, err := os.MkdirTemp("", "warp-lb")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(runDir) })
	for name, content := range map[string]string{
		filepath.Base(warp.LbTlsCustomHostsMapPath): customHosts,
		filepath.Base(warp.LbTlsCustomHosts80Path):  customHosts80,
	} {
		if err := os.WriteFile(filepath.Join(runDir, name), []byte(content), 0644); err != nil {
			t.Fatal(err)
		}
	}
	return runDir
}

// The split's render passes `nginx -t` through a production-capable nginx,
// with the includes empty, as at M5, and with lbmap's longest custom host.
func TestTlsSplitRenderPassesNginxTest(t *testing.T) {
	nginxBinary := nginxConfigValidationBinary(t)
	env, vaultDir := setupTlsSplitTestVault(t, tlsSplitServicesYaml(t, nil))
	nginxConfig, err := NewNginxConfig(env, nil)
	if err != nil {
		t.Fatal(err)
	}
	// one host of 253 bytes, the longest DNS name, as lbmap may write one
	longLabel := strings.Repeat("a", 63)
	longHost := strings.Join([]string{longLabel, longLabel, longLabel, strings.Repeat("b", 53), "example"}, ".")
	if len(longHost) != 253 {
		t.Fatalf("long host is %d bytes", len(longHost))
	}
	for _, includes := range []struct {
		name          string
		customHosts   string
		customHosts80 string
	}{
		{name: "empty"},
		{
			name:          "custom hosts",
			customHosts:   longHost + " stream-service-block-tlsedge-443;\nshop.customer.example stream-service-block-tlsedge-443;\n",
			customHosts80: "server {\n    listen 80;\n    server_name shop.customer.example;\n    access_log off;\n    return 301 https://$host$request_uri;\n}\n",
		},
	} {
		runDir := tlsSplitTestRunDir(t, includes.customHosts, includes.customHosts80)
		for block, config := range nginxConfig.Generate() {
			prefixDir := t.TempDir()
			for _, dir := range []string{"logs", "run"} {
				if err := os.MkdirAll(filepath.Join(prefixDir, dir), 0755); err != nil {
					t.Fatal(err)
				}
			}
			confPath := filepath.Join(prefixDir, "nginx.conf")
			if err := os.WriteFile(confPath, []byte(localTlsSplitConfig(config, vaultDir, runDir)), 0644); err != nil {
				t.Fatal(err)
			}
			if output, err := runNginxConfigTest(nginxBinary, confPath, prefixDir); err != nil {
				t.Errorf("%s: nginx -t refused block %s:\n%s", includes.name, block, output)
			}
		}
	}

	// and an include that is missing fails nginx -t, which is why the lb writes both before nginx starts
	runDir := tlsSplitTestRunDir(t, "", "")
	if err := os.Remove(filepath.Join(runDir, filepath.Base(warp.LbTlsCustomHostsMapPath))); err != nil {
		t.Fatal(err)
	}
	for _, config := range nginxConfig.Generate() {
		prefixDir := t.TempDir()
		confPath := filepath.Join(prefixDir, "nginx.conf")
		if err := os.WriteFile(confPath, []byte(localTlsSplitConfig(config, vaultDir, runDir)), 0644); err != nil {
			t.Fatal(err)
		}
		if _, err := runNginxConfigTest(nginxBinary, confPath, prefixDir); err == nil {
			t.Error("nginx -t passed with the custom hosts map missing")
		}
		break
	}
}
