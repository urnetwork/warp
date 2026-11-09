package warp

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// The render config the tests guard with: one root, a platform domain, a
// platform name elsewhere and a wildcard alias written as its zone, and
// tlsedge's 443.
func lbMapTestRenderConfig() *LbMapRenderConfig {
	return &LbMapRenderConfig{
		Format:          LbMapFormat,
		Roots:           []string{"root.example"},
		PlatformDomains: []string{"platform.example", "api.other-platform.example", "alias-platform.example"},
		EdgeUpstream:    "stream-service-block-tlsedge-443",
	}
}

// A version of hosts with its own digest.
func lbMapTestVersion(version uint64, hosts ...string) *LbCustomHostMap {
	return &LbCustomHostMap{
		Format:  LbMapFormat,
		Version: version,
		Digest:  LbCustomHostMapDigest(hosts),
		Hosts:   slices.Clone(hosts),
	}
}

// The digest is SHA-256 over the hosts in bytewise order, each followed by
// one 0x00 byte, whatever order they arrive in; no hosts hash nothing.
func TestLbCustomHostMapDigest(t *testing.T) {
	sum := sha256.Sum256([]byte("a.customer.example\x00b.customer.example\x00"))
	want := hex.EncodeToString(sum[:])
	for _, hosts := range [][]string{
		{"a.customer.example", "b.customer.example"},
		{"b.customer.example", "a.customer.example"},
	} {
		if got := LbCustomHostMapDigest(hosts); got != want {
			t.Errorf("%v: %s, want %s", hosts, got, want)
		}
	}
	empty := sha256.Sum256(nil)
	if got := LbCustomHostMapDigest(nil); got != hex.EncodeToString(empty[:]) {
		t.Errorf("no hosts: %s", got)
	}
	// a separator, so moving a byte across hosts moves the digest
	if LbCustomHostMapDigest([]string{"ab.example", "c.example"}) == LbCustomHostMapDigest([]string{"a.example", "bc.example"}) {
		t.Error("two host lists with the same bytes share a digest")
	}
}

// The probe name is the digest's first 12 hex digits under map.probe.invalid
// (RFC 6761 §6.4).
func TestLbMapProbeName(t *testing.T) {
	digest := LbCustomHostMapDigest([]string{"shop.customer.example"})
	probeName := LbMapProbeName(digest)
	if probeName != digest[:12]+".map.probe.invalid" {
		t.Errorf("probe name %s", probeName)
	}
	if !isLbMapNameUnder(probeName, LbMapProbeZone) || !isLbMapNameUnder(probeName, "invalid") {
		t.Errorf("%s is not under the probe zone", probeName)
	}
}

// One version renders to the map's probe line then one line per host, sorted,
// to tlsedge's upstream, and to one server_name line per host for port 80,
// each file headed by a comment with the version and digest.
func TestLbMapRenderWritesTheMapAndTheRedirectNames(t *testing.T) {
	customHostMap := lbMapTestVersion(7, "www.customer.example", "customer.example", "shop.customer.example")
	render, err := lbMapTestRenderConfig().Render(customHostMap, 16)
	if err != nil {
		t.Fatal(err)
	}
	header := "# lbmap: custom-host map version 7, digest " + customHostMap.Digest + " (§13.4); lbmap rewrites this file whole\n"
	wantMap := header +
		customHostMap.Digest[:12] + ".map.probe.invalid stream-service-block-tlsedge-443;\n" +
		"customer.example stream-service-block-tlsedge-443;\n" +
		"shop.customer.example stream-service-block-tlsedge-443;\n" +
		"www.customer.example stream-service-block-tlsedge-443;\n"
	if string(render.Map) != wantMap {
		t.Errorf("map:\n%s\nwant:\n%s", render.Map, wantMap)
	}
	wantHttp80 := header +
		"server_name customer.example;\n" +
		"server_name shop.customer.example;\n" +
		"server_name www.customer.example;\n"
	if string(render.Http80) != wantHttp80 {
		t.Errorf("port 80:\n%s\nwant:\n%s", render.Http80, wantHttp80)
	}
	if render.Version != 7 || render.Digest != customHostMap.Digest || render.ProbeName != LbMapProbeName(customHostMap.Digest) {
		t.Errorf("render says %d %s %s", render.Version, render.Digest, render.ProbeName)
	}
	if !slices.Equal(render.Hosts, []string{"customer.example", "shop.customer.example", "www.customer.example"}) {
		t.Errorf("hosts %v", render.Hosts)
	}

	// and the empty version still routes its probe name
	empty, err := lbMapTestRenderConfig().Render(lbMapTestVersion(8), 16)
	if err != nil {
		t.Fatal(err)
	}
	hosts, err := ParseLbMapHosts(empty.Map)
	if err != nil || len(hosts) != 0 {
		t.Errorf("an empty version holds %v: %v", hosts, err)
	}
	if !strings.Contains(string(empty.Map), empty.ProbeName+" stream-service-block-tlsedge-443;\n") {
		t.Errorf("the empty version has no probe line:\n%s", empty.Map)
	}
	if strings.Contains(string(empty.Http80), "server_name") {
		t.Errorf("the empty version names a host on port 80:\n%s", empty.Http80)
	}
}

// Each refusal refuses the whole version and names no host: a host under a
// root, a platform domain or name, a wildcard alias's zone or .invalid; one
// that is not a lowercase DNS name; a duplicate; a digest that does not match
// or is not hex; version zero; too many hosts; a format not known.
func TestLbMapRenderRefusesAWholeVersion(t *testing.T) {
	longLabel := strings.Repeat("a", 63)
	tooLong := strings.Join([]string{longLabel, longLabel, longLabel, strings.Repeat("b", 54), "example"}, ".")
	for _, c := range []struct {
		name          string
		customHostMap *LbCustomHostMap
	}{
		{name: "under the root", customHostMap: lbMapTestVersion(2, "shop.customer.example", "shop.root.example")},
		{name: "the root", customHostMap: lbMapTestVersion(2, "root.example")},
		{name: "a platform domain", customHostMap: lbMapTestVersion(2, "platform.example")},
		{name: "under a platform domain", customHostMap: lbMapTestVersion(2, "status.platform.example")},
		{name: "under a platform name", customHostMap: lbMapTestVersion(2, "x.api.other-platform.example")},
		{name: "under a wildcard alias's zone", customHostMap: lbMapTestVersion(2, "www.alias-platform.example")},
		{name: "under .invalid", customHostMap: lbMapTestVersion(2, "aaaaaaaaaaaa.map.probe.invalid")},
		{name: "upper case", customHostMap: lbMapTestVersion(2, "Shop.customer.example")},
		{name: "a wildcard", customHostMap: lbMapTestVersion(2, "*.customer.example")},
		{name: "an underscore", customHostMap: lbMapTestVersion(2, "_acme.customer.example")},
		{name: "a final dot", customHostMap: lbMapTestVersion(2, "shop.customer.example.")},
		{name: "one label", customHostMap: lbMapTestVersion(2, "default")},
		{name: "a leading hyphen", customHostMap: lbMapTestVersion(2, "-shop.customer.example")},
		{name: "a long label", customHostMap: lbMapTestVersion(2, strings.Repeat("a", 64)+".example")},
		{name: "a long name", customHostMap: lbMapTestVersion(2, tooLong)},
		{name: "a space", customHostMap: lbMapTestVersion(2, "shop.customer.example stream;")},
		{name: "a duplicate", customHostMap: lbMapTestVersion(2, "shop.customer.example", "shop.customer.example")},
		{name: "version zero", customHostMap: lbMapTestVersion(0, "shop.customer.example")},
		{name: "too many hosts", customHostMap: lbMapTestVersion(2, "a.customer.example", "b.customer.example", "c.customer.example")},
		{name: "a digest that does not match", customHostMap: &LbCustomHostMap{Format: LbMapFormat, Version: 2, Digest: LbCustomHostMapDigest([]string{"other.customer.example"}), Hosts: []string{"shop.customer.example"}}},
		{name: "a digest that is not hex", customHostMap: &LbCustomHostMap{Format: LbMapFormat, Version: 2, Digest: strings.ToUpper(LbCustomHostMapDigest([]string{"shop.customer.example"})), Hosts: []string{"shop.customer.example"}}},
		{name: "format zero", customHostMap: &LbCustomHostMap{Format: 0, Version: 2, Digest: LbCustomHostMapDigest(nil)}},
	} {
		render, err := lbMapTestRenderConfig().Render(c.customHostMap, 2)
		if !errors.Is(err, ErrLbMapRefused) || render != nil {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		// a host that is itself a platform name is named only as the platform's
		renderConfig := lbMapTestRenderConfig()
		for _, host := range c.customHostMap.Hosts {
			if slices.Contains(renderConfig.Roots, host) || slices.Contains(renderConfig.PlatformDomains, host) {
				continue
			}
			if strings.Contains(err.Error(), host) {
				t.Errorf("%s: the refusal names a host: %v", c.name, err)
			}
		}
	}
	newer := lbMapTestVersion(2, "shop.customer.example")
	newer.Format = LbMapFormat + 1
	if _, err := lbMapTestRenderConfig().Render(newer, 2); !errors.Is(err, ErrLbMapFormatTooNew) {
		t.Errorf("a newer format: %v", err)
	}
}

// The marker carries the render config through the nginx config warpctl
// renders, as one comment line, and reads back equal. A config with none says
// nothing; two, or one that does not parse or validate, is an error.
func TestLbMapRenderConfigMarker(t *testing.T) {
	renderConfig := lbMapTestRenderConfig()
	marker, err := renderConfig.Marker()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(marker, "\n") || !strings.HasPrefix(marker, "# warp-lbmap: ") {
		t.Fatalf("marker %q", marker)
	}
	config := "stream {\n    " + marker + "\n    map $ssl_preread_server_name $tls_split_upstream {\n    }\n}\n"
	found, err := FindLbMapRenderConfig([]byte(config))
	if err != nil {
		t.Fatal(err)
	}
	if found == nil || !slices.Equal(found.Roots, renderConfig.Roots) || !slices.Equal(found.PlatformDomains, renderConfig.PlatformDomains) || found.EdgeUpstream != renderConfig.EdgeUpstream || found.Format != renderConfig.Format {
		t.Errorf("found %+v", found)
	}
	if found, err := FindLbMapRenderConfig([]byte("stream {\n}\n")); found != nil || err != nil {
		t.Errorf("no marker: %+v %v", found, err)
	}
	if _, err := FindLbMapRenderConfig([]byte(config + config)); err == nil {
		t.Error("two markers")
	}
	for _, line := range []string{
		`# warp-lbmap: {"format":1`,
		`# warp-lbmap: {"format":1,"roots":["root.example"],"platform_domains":[],"edge_upstream":"x","extra":1}`,
		`# warp-lbmap: {"format":1,"roots":[],"platform_domains":[],"edge_upstream":"x"}`,
		`# warp-lbmap: {"format":2,"roots":["root.example"],"platform_domains":[],"edge_upstream":"x"}`,
		`# warp-lbmap: {"format":1,"roots":["Root.example"],"platform_domains":[],"edge_upstream":"x"}`,
		`# warp-lbmap: {"format":1,"roots":["root.example"],"platform_domains":[],"edge_upstream":"x; include y"}`,
	} {
		if _, err := FindLbMapRenderConfig([]byte(line + "\n")); err == nil {
			t.Errorf("%s: no error", line)
		}
	}
	if _, err := (&LbMapRenderConfig{Format: LbMapFormat}).Marker(); err == nil {
		t.Error("a config with no root made a marker")
	}
}

// The hosts a map file holds read back from a render, less the probe name,
// and a line that is not `<name> <upstream>;` is an error.
func TestParseLbMapHosts(t *testing.T) {
	render, err := lbMapTestRenderConfig().Render(lbMapTestVersion(3, "shop.customer.example", "customer.example"), 16)
	if err != nil {
		t.Fatal(err)
	}
	hosts, err := ParseLbMapHosts(render.Map)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(hosts, []string{"customer.example", "shop.customer.example"}) {
		t.Errorf("hosts %v", hosts)
	}
	if hosts, err := ParseLbMapHosts(nil); err != nil || len(hosts) != 0 {
		t.Errorf("an empty file: %v %v", hosts, err)
	}
	if _, err := ParseLbMapHosts([]byte("shop.customer.example\n")); err == nil {
		t.Error("a line with no upstream")
	}
}

// A load's lists: what the version adds to the map held, and drops from it.
func TestLbMapHostChanges(t *testing.T) {
	added, dropped := lbMapHostChanges(
		[]string{"a.customer.example", "b.customer.example"},
		[]string{"b.customer.example", "d.customer.example", "c.customer.example"},
	)
	if !slices.Equal(added, []string{"c.customer.example", "d.customer.example"}) || !slices.Equal(dropped, []string{"a.customer.example"}) {
		t.Errorf("added %v, dropped %v", added, dropped)
	}
	added, dropped = lbMapHostChanges(nil, nil)
	if added == nil || dropped == nil || len(added) != 0 || len(dropped) != 0 {
		t.Errorf("nothing changes: %v %v", added, dropped)
	}
}

// A write replaces the file whole through a rename, leaving no temp file, and
// temp files a dead write left are removed before lbmap starts.
func TestWriteLbMapFileReplacesWhole(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tls-custom-hosts.map")
	for _, content := range []string{"first;\n", "second;\n"} {
		if err := writeLbMapFile(path, []byte(content)); err != nil {
			t.Fatal(err)
		}
		got, err := os.ReadFile(path)
		if err != nil || string(got) != content {
			t.Errorf("read %q %v, want %q", got, err, content)
		}
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 {
		t.Errorf("the directory holds %v %v", entries, err)
	}
	leftover := filepath.Join(dir, ".tls-custom-hosts.map.lbmap-123")
	if err := os.WriteFile(leftover, []byte("half"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := removeLbMapTempFiles(path); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(leftover); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a leftover temp file stays: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Errorf("the map went with it: %v", err)
	}
}
