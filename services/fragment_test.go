package services

import (
	"bytes"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// A synthetic services.yml: example.com names and documentation addresses only. Its top version introduces
// mcp and app, which sort after evs and gkm, so merging a new service into that version, instead of
// adding one above it, would hand mcp's and app's ports to the newcomer. It keeps anchors and a merge key
// in the top version and aliases in the one under it, as a hand-kept file does. api allows a web origin
// and mmm, the static sites' service, serves a name of its own, as the real file's do.
const fragmentBaseYaml = `# the synthetic vault's services.yml
domain: example.com
domains:
    example.com: route53
versions:
# append new versions to the top
-   external_ports: 7000-7099
    internal_ports: 7100-7999
    routing_tables: 100-110
    parallel_block_count: 4
    services_docker_network: testservices
    lb: &lb
        ports:
            - 80
            - 443
        interfaces:
            edge-0.example.com:
                eth0:
                    docker_network: warpeth0
                    ipv4: 192.0.2.10
                    ipv6: "2001:db8::10"
            edge-1.example.com:
                eth0:
                    docker_network: warpeth0
                    ipv4: 192.0.2.11
                    ipv6: "2001:db8::11"
    services:
        # the issuer: the whole vault, as warp mounts by default
        api: &api
            status: standard
            cors_origins:
                - https://www.example.com
            hidden_prefixes:
                - api-hidden
            secret_files:
                - api-extra.yml
            ports:
                - 80
            blocks: &blocks
                - beta: 1
                - g1: 99
        mcp:
            ports:
                - 80
            blocks: *blocks
        mmm: &mmm
            expose_aliases:
                - www.example.net
            ports:
                - 80
            blocks: *blocks
        taskworker: &taskworker
            exposed: false
            ports:
                - 80
            blocks: *blocks
        web: &web
            expose_aliases:
                - www.example.com
            ports:
                - 80
            blocks: *blocks
        app:
            <<: *web
            expose_aliases:
                - app.example.com
        alt: &alt
            exposed: false
            hosts:
                - edge-1.example.com
            ports:
                - 80
            external_udp_ports:
                - 53
            blocks:
                - g1: 1
-   external_ports: 7000-7099
    internal_ports: 7100-7999
    routing_tables: 100-110
    parallel_block_count: 4
    services_docker_network: testservices
    lb: *lb
    services:
        api: *api
        mmm: *mmm
        taskworker: *taskworker
        web: *web
        alt: *alt
`

// A fragment parsed from text, failing the test on an error.
func testServicesFragment(t *testing.T, name string, text string) *ServicesFragment {
	t.Helper()
	fragment, err := ParseServicesFragment(name, []byte(text))
	if err != nil {
		t.Fatal(err)
	}
	return fragment
}

const fragmentEvsYaml = `version:
    services:
        evs:
            secret_files:
                - redis.yml
            ports:
                - 80
            blocks:
                - beta: 1
                - g1: 99
`

const fragmentGkmYaml = `version:
    services:
        gkm:
            ports:
                - 80
            blocks:
                - beta: 1
                - g1: 99
`

// The port blocks of a services.yml's text, through the loader and the allocator.
func fragmentPortBlocks(t *testing.T, text []byte) map[string]map[string]map[string]map[int]*PortBlock {
	t.Helper()
	servicesConfig, err := ParseServicesConfig(text, "services.yml")
	if err != nil {
		t.Fatal(err)
	}
	portBlocks, err := AllocatePortBlocks(servicesConfig, func(string, ...any) {})
	if err != nil {
		t.Fatal(err)
	}
	return portBlocks
}

// A new version above the top keeps every port block the file had exactly where it was, and gives the
// new services ports of their own.
func TestApplyFragmentKeepsEveryPriorPort(t *testing.T) {
	result, err := ApplyServicesFragments([]byte(fragmentBaseYaml), "services.yml",
		testServicesFragment(t, "evs.yml", fragmentEvsYaml),
		testServicesFragment(t, "gkm.yml", fragmentGkmYaml),
	)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(result.Changes, []string{"services.evs", "services.gkm"}) {
		t.Errorf("changes = %q", result.Changes)
	}
	before := fragmentPortBlocks(t, []byte(fragmentBaseYaml))
	after := fragmentPortBlocks(t, result.Text)
	for host, servicePortBlocks := range before {
		for service, blockPortBlocks := range servicePortBlocks {
			for block, portBlocks := range blockPortBlocks {
				for port, portBlock := range portBlocks {
					afterPortBlock := after[host][service][block][port]
					if afterPortBlock == nil || afterPortBlock.ExternalPort != portBlock.ExternalPort || !reflect.DeepEqual(afterPortBlock.InternalPorts, portBlock.InternalPorts) || afterPortBlock.RoutingTable != portBlock.RoutingTable {
						t.Errorf("%q %s %s %d moved: %+v, now %+v", host, service, block, port, portBlock, afterPortBlock)
					}
				}
			}
		}
	}
	for _, service := range []string{"evs", "gkm"} {
		for _, block := range []string{"beta", "g1"} {
			if after[""][service][block][80] == nil {
				t.Errorf("%s %s has no port", service, block)
			}
		}
	}
	if len(result.AddedPortBlocks) != 4 || !strings.HasPrefix(result.AddedPortBlocks[0], "evs beta port 80: external ") {
		t.Errorf("added port blocks = %q", result.AddedPortBlocks)
	}
}

// Why the fragment goes in a version of its own: merged into the top version, which introduced mcp and
// app, evs takes ports they hold, since a version assigns its new blocks in service order.
func TestMergingIntoTheTopVersionWouldMovePorts(t *testing.T) {
	naive := strings.Replace(fragmentBaseYaml, "    services:\n        # the issuer", "    services:\n        evs:\n            ports:\n                - 80\n            blocks:\n                - beta: 1\n                - g1: 99\n        # the issuer", 1)
	if naive == fragmentBaseYaml {
		t.Fatal("the fixture changed under the test")
	}
	_, err := compareServicesFragmentPortBlocks(mustParseServicesConfig(t, fragmentBaseYaml), mustParseServicesConfig(t, naive))
	if err == nil || !strings.Contains(err.Error(), "mcp") {
		t.Fatalf("a merge into the top version moved nothing of mcp's: %v", err)
	}
}

// The loader's config of a services.yml's text, failing the test on an error.
func mustParseServicesConfig(t *testing.T, text string) *ServicesConfig {
	t.Helper()
	servicesConfig, err := ParseServicesConfig([]byte(text), "services.yml")
	if err != nil {
		t.Fatal(err)
	}
	return servicesConfig
}

// The file outside the new version stays byte for byte: its comments, anchors and older versions.
func TestApplyFragmentKeepsTheRestOfTheFile(t *testing.T) {
	result, err := ApplyServicesFragments([]byte(fragmentBaseYaml), "services.yml", testServicesFragment(t, "evs.yml", fragmentEvsYaml))
	if err != nil {
		t.Fatal(err)
	}
	original := []byte(fragmentBaseYaml)
	// the new version goes in as a whole item, above the line the old top version starts on
	at := bytes.Index(original, []byte("-   external_ports: 7000-7099\n    internal_ports: 7100-7999\n    routing_tables: 100-110\n    parallel_block_count: 4\n    services_docker_network: testservices\n    lb: &lb"))
	inserted := len(result.Text) - len(original)
	if at < 0 || inserted <= 0 {
		t.Fatalf("no top version found (%d) or nothing inserted (%d)", at, inserted)
	}
	if !bytes.Equal(result.Text[:at], original[:at]) || !bytes.Equal(result.Text[at+inserted:], original[at:]) {
		t.Fatal("the file changed outside the new version")
	}
	newVersion := string(result.Text[at : at+inserted])
	if !strings.HasPrefix(newVersion, "-   external_ports: 7000-7099\n") || !bytes.Equal([]byte(newVersion), indentServicesFragmentTestItem(result.VersionText)) {
		t.Errorf("the new version is not the version text as an item:\n%s", newVersion)
	}
	if strings.ContainsAny(newVersion, "&*#") || strings.Contains(newVersion, "<<") {
		t.Errorf("the new version keeps an anchor, alias, merge key or comment:\n%s", newVersion)
	}
}

// The version text as a sequence item at column 0: a dash and three spaces, then four spaces a line.
func indentServicesFragmentTestItem(versionText []byte) []byte {
	lines := strings.SplitAfter(strings.TrimSuffix(string(versionText), "\n"), "\n")
	for index, line := range lines {
		if index == 0 {
			lines[index] = "-   " + line
		} else {
			lines[index] = "    " + line
		}
	}
	return []byte(strings.Join(lines, "") + "\n")
}

// A merge key and aliases in the top version are expanded into the new one, so a fragment that extends a
// service built from a merge keeps everything the merge brought.
func TestApplyFragmentExpandsMergeKeysAndAliases(t *testing.T) {
	result, err := ApplyServicesFragments([]byte(fragmentBaseYaml), "services.yml", testServicesFragment(t, "app.yml", `version:
    services:
        app:
            secret_files:
                - app-extra.yml
`))
	if err != nil {
		t.Fatal(err)
	}
	servicesConfig := mustParseServicesConfig(t, string(result.Text))
	app := servicesConfig.Versions[0].Services["app"]
	if !reflect.DeepEqual(app.ExposeAliases, []string{"app.example.com"}) || !reflect.DeepEqual(app.SecretFiles, []string{"app-extra.yml"}) || !reflect.DeepEqual(app.PortSpecs, []string{"80"}) || len(app.Blocks) != 2 {
		t.Errorf("app = %+v", app)
	}
	if !reflect.DeepEqual(result.Changes, []string{"services.app.secret_files"}) {
		t.Errorf("changes = %q", result.Changes)
	}
}

// A list the fragment extends gains its entries, sorted for secret_files; the rest of the block stays.
func TestApplyFragmentExtendsAnExistingService(t *testing.T) {
	result, err := ApplyServicesFragments([]byte(fragmentBaseYaml), "services.yml", testServicesFragment(t, "api.yml", `version:
    services:
        api:
            secret_files:
                - file-clusters-api.yml
            log_uri: true
`))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(result.Changes, []string{"services.api.secret_files: file-clusters-api.yml", "services.api.log_uri"}) {
		t.Errorf("changes = %q", result.Changes)
	}
	api := mustParseServicesConfig(t, string(result.Text)).Versions[0].Services["api"]
	if !reflect.DeepEqual(api.SecretFiles, []string{"api-extra.yml", "file-clusters-api.yml"}) || !api.LogUri || api.Status != "standard" {
		t.Errorf("api = %+v", api)
	}
	if len(result.AddedPortBlocks) != 0 {
		t.Errorf("an extended service gained port blocks: %q", result.AddedPortBlocks)
	}
}

// A fragment applied to a file that already holds it adds nothing, and the file stays as it was.
func TestApplyFragmentTwiceAddsNothing(t *testing.T) {
	evs := testServicesFragment(t, "evs.yml", fragmentEvsYaml)
	first, err := ApplyServicesFragments([]byte(fragmentBaseYaml), "services.yml", evs)
	if err != nil {
		t.Fatal(err)
	}
	second, err := ApplyServicesFragments(first.Text, "services.yml", evs)
	if err != nil {
		t.Fatal(err)
	}
	if second.Changed() || !bytes.Equal(second.Text, first.Text) || len(second.VersionText) != 0 {
		t.Errorf("a second apply changed %q", second.Changes)
	}
}

// A fragment shaped as mmm's (W10, QD-012): a registrar domain, a name that must stay unproxied, and both
// as aliases of a service the file has.
const fragmentDomainsYaml = `domains:
    example.org: route53
dns:
    unproxied:
        - key.example.net
version:
    services:
        mmm:
            expose_aliases:
                - example.org
                - key.example.net
`

// A fragment shaped as mmm's for QD-678: a host the lb sends no X-Frame-Options, and the host as an alias
// of a service the file has.
const fragmentNoFrameOptionsYaml = `no_frame_options:
    - key.example.net
version:
    services:
        mmm:
            expose_aliases:
                - key.example.net
`

// Whether every line of original is in text, in its order, so a merge only put lines in.
func servicesFragmentLinesKept(original string, text string) bool {
	lines := strings.SplitAfter(text, "\n")
	at := 0
	for _, line := range strings.SplitAfter(original, "\n") {
		for at < len(lines) && lines[at] != line {
			at++
		}
		if at == len(lines) {
			return false
		}
		at++
	}
	return true
}

// A registrar domain joins domains as its first entry and an unproxied name the file lacks a dns block
// for arrives in a block of its own above versions; every other line stays, and the aliases go in the
// new version as any list does.
func TestApplyFragmentAddsDomainsAndUnproxiedNames(t *testing.T) {
	result, err := ApplyServicesFragments([]byte(fragmentBaseYaml), "services.yml", testServicesFragment(t, "mmm.yml", fragmentDomainsYaml))
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"domains.example.org: route53", "dns.unproxied: key.example.net", "services.mmm.expose_aliases: example.org", "services.mmm.expose_aliases: key.example.net"}; !reflect.DeepEqual(result.Changes, want) {
		t.Errorf("changes = %q", result.Changes)
	}
	servicesConfig := mustParseServicesConfig(t, string(result.Text))
	if want := map[string]string{"example.com": "route53", "example.org": "route53"}; !reflect.DeepEqual(servicesConfig.DomainRegistrars(), want) {
		t.Errorf("domains = %v", servicesConfig.Domains)
	}
	if got := servicesConfig.DnsUnproxiedHosts(); !reflect.DeepEqual(got, []string{"key.example.net"}) {
		t.Errorf("unproxied = %q", got)
	}
	if mmm := servicesConfig.Versions[0].Services["mmm"]; len(servicesConfig.Versions) != 3 || !reflect.DeepEqual(mmm.ExposeAliases, []string{"www.example.net", "example.org", "key.example.net"}) {
		t.Errorf("%d versions, mmm = %+v", len(servicesConfig.Versions), mmm)
	}
	if !servicesFragmentLinesKept(fragmentBaseYaml, string(result.Text)) {
		t.Errorf("the merge changed a line of the file:\n%s", result.Text)
	}
	for _, want := range []string{"domains:\n    example.org: route53\n    example.com: route53\n", "dns:\n    unproxied:\n        - key.example.net\nversions:\n"} {
		if !strings.Contains(string(result.Text), want) {
			t.Errorf("the merged file lacks %q:\n%s", want, result.Text)
		}
	}
	if len(result.AddedPortBlocks) != 0 {
		t.Errorf("an alias gained port blocks: %q", result.AddedPortBlocks)
	}
}

// Outside the versions nothing is versioned, so a fragment whose version the file already holds adds its
// domain as one line and no version.
func TestApplyFragmentOutsideTheVersionsAddsNoVersion(t *testing.T) {
	fragment := testServicesFragment(t, "domains.yml", "domains:\n    example.org: cloudflare\nversion:\n    services:\n        api:\n            status: standard\n")
	result, err := ApplyServicesFragments([]byte(fragmentBaseYaml), "services.yml", fragment)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(result.Changes, []string{"domains.example.org: cloudflare"}) || len(result.VersionText) != 0 {
		t.Errorf("changes = %q, version %q", result.Changes, result.VersionText)
	}
	if want := strings.Replace(fragmentBaseYaml, "domains:\n", "domains:\n    example.org: cloudflare\n", 1); string(result.Text) != want {
		t.Errorf("the merged file is not the base with one line put in:\n%s", result.Text)
	}
}

// An unproxied name joins the file's dns block as its first entry, or its unproxied list as the first
// item, and the block's other settings stay; a name the file lists adds nothing.
func TestApplyFragmentJoinsTheFilesDnsBlock(t *testing.T) {
	fragment := testServicesFragment(t, "mmm.yml", fragmentDomainsYaml)
	cases := []struct {
		label     string
		dns       string
		want      string
		unproxied []string
		changed   bool
	}{
		{
			label:     "a dns block without the list",
			dns:       "dns:\n    ttl: 120\n    other_domain_services:\n        - web\n",
			want:      "dns:\n    unproxied:\n        - key.example.net\n    ttl: 120\n",
			unproxied: []string{"key.example.net"},
			changed:   true,
		},
		{
			label:     "a list of other names",
			dns:       "dns:\n    ttl: 120\n    unproxied:\n        - old.example.net\n",
			want:      "    unproxied:\n        - key.example.net\n        - old.example.net\n",
			unproxied: []string{"key.example.net", "old.example.net"},
			changed:   true,
		},
		{
			label:     "a list holding the name",
			dns:       "dns:\n    unproxied:\n        - Key.Example.Net\n",
			want:      "    unproxied:\n        - Key.Example.Net\nversions:\n",
			unproxied: []string{"key.example.net"},
		},
	}
	for _, c := range cases {
		base := strings.Replace(fragmentBaseYaml, "versions:\n", c.dns+"versions:\n", 1)
		result, err := ApplyServicesFragments([]byte(base), "services.yml", fragment)
		if err != nil {
			t.Errorf("%s: %v", c.label, err)
			continue
		}
		if !strings.Contains(string(result.Text), c.want) || !servicesFragmentLinesKept(base, string(result.Text)) {
			t.Errorf("%s: the merged file lacks %q or changed a line:\n%s", c.label, c.want, result.Text)
		}
		servicesConfig := mustParseServicesConfig(t, string(result.Text))
		if got := servicesConfig.DnsUnproxiedHosts(); !reflect.DeepEqual(got, c.unproxied) {
			t.Errorf("%s: unproxied = %q", c.label, got)
		}
		if strings.Contains(c.dns, "ttl: 120") && servicesConfig.GetDnsTtl() != 120 {
			t.Errorf("%s: the ttl moved", c.label)
		}
		if slices.Contains(result.Changes, "dns.unproxied: key.example.net") != c.changed {
			t.Errorf("%s: changes = %q", c.label, result.Changes)
		}
	}
}

// A no_frame_options host the file lacks the list for arrives in a block of its own above versions;
// every other line stays, and the alias goes in the new version as any list does.
func TestApplyFragmentAddsNoFrameOptionsHosts(t *testing.T) {
	result, err := ApplyServicesFragments([]byte(fragmentBaseYaml), "services.yml", testServicesFragment(t, "mmm.yml", fragmentNoFrameOptionsYaml))
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"no_frame_options: key.example.net", "services.mmm.expose_aliases: key.example.net"}; !reflect.DeepEqual(result.Changes, want) {
		t.Errorf("changes = %q", result.Changes)
	}
	servicesConfig := mustParseServicesConfig(t, string(result.Text))
	if got := servicesConfig.NoFrameOptionsHosts(); !reflect.DeepEqual(got, []string{"key.example.net"}) {
		t.Errorf("no_frame_options = %q", got)
	}
	if mmm := servicesConfig.Versions[0].Services["mmm"]; len(servicesConfig.Versions) != 3 || !reflect.DeepEqual(mmm.ExposeAliases, []string{"www.example.net", "key.example.net"}) {
		t.Errorf("%d versions, mmm = %+v", len(servicesConfig.Versions), mmm)
	}
	if !servicesFragmentLinesKept(fragmentBaseYaml, string(result.Text)) {
		t.Errorf("the merge changed a line of the file:\n%s", result.Text)
	}
	if want := "no_frame_options:\n    - key.example.net\nversions:\n"; !strings.Contains(string(result.Text), want) {
		t.Errorf("the merged file lacks %q:\n%s", want, result.Text)
	}
}

// A no_frame_options host joins the file's list as its first item, at the list's own indent, and a host
// the file lists, in any spelling nginx folds into it, adds nothing.
func TestApplyFragmentJoinsTheFilesNoFrameOptions(t *testing.T) {
	fragment := testServicesFragment(t, "mmm.yml", fragmentNoFrameOptionsYaml)
	cases := []struct {
		label   string
		list    string
		want    string
		hosts   []string
		changed bool
	}{
		{
			label:   "a list of other hosts",
			list:    "no_frame_options:\n    - old.example.net\n",
			want:    "no_frame_options:\n    - key.example.net\n    - old.example.net\n",
			hosts:   []string{"key.example.net", "old.example.net"},
			changed: true,
		},
		{
			label:   "a list whose dashes sit under its key",
			list:    "no_frame_options:\n- old.example.net\n",
			want:    "no_frame_options:\n- key.example.net\n- old.example.net\n",
			hosts:   []string{"key.example.net", "old.example.net"},
			changed: true,
		},
		{
			label: "a list holding the host",
			list:  "no_frame_options:\n    - Key.Example.Net.\n",
			want:  "no_frame_options:\n    - Key.Example.Net.\nversions:\n",
			hosts: []string{"key.example.net"},
		},
	}
	for _, c := range cases {
		base := strings.Replace(fragmentBaseYaml, "versions:\n", c.list+"versions:\n", 1)
		result, err := ApplyServicesFragments([]byte(base), "services.yml", fragment)
		if err != nil {
			t.Errorf("%s: %v", c.label, err)
			continue
		}
		if !strings.Contains(string(result.Text), c.want) || !servicesFragmentLinesKept(base, string(result.Text)) {
			t.Errorf("%s: the merged file lacks %q or changed a line:\n%s", c.label, c.want, result.Text)
		}
		if got := mustParseServicesConfig(t, string(result.Text)).NoFrameOptionsHosts(); !reflect.DeepEqual(got, c.hosts) {
			t.Errorf("%s: no_frame_options = %q", c.label, got)
		}
		if slices.Contains(result.Changes, "no_frame_options: key.example.net") != c.changed {
			t.Errorf("%s: changes = %q", c.label, result.Changes)
		}
	}
}

// A placeholder registrar, a domain the file or an earlier fragment gives another registrar, and a
// domains mapping, unproxied list or no_frame_options list written in flow style, which no line can join,
// are refused, and nothing is returned.
func TestApplyFragmentRefusesWhatItCannotAddOutsideTheVersions(t *testing.T) {
	version := "version:\n    services:\n        api:\n            status: standard\n"
	cases := []struct {
		label     string
		base      string
		fragments []string
		want      string
	}{
		{
			label:     "a placeholder registrar",
			fragments: []string{"domains:\n    example.org: fill-in-route53-or-cloudflare\n" + version},
			want:      `domains.example.org's registrar is "fill-in-route53-or-cloudflare": fill in cloudflare or route53`,
		},
		{
			label:     "the file's domain under another registrar",
			fragments: []string{"domains:\n    example.com: cloudflare\n" + version},
			want:      `domains.example.com is "route53" in the file`,
		},
		{
			label:     "two fragments' registrars",
			fragments: []string{"domains:\n    example.org: route53\n" + version, "domains:\n    example.org: cloudflare\n" + version},
			want:      `domains.example.org is "route53"`,
		},
		{
			label:     "a flow domains mapping",
			base:      strings.Replace(fragmentBaseYaml, "domains:\n    example.com: route53\n", "domains: {example.com: route53}\n", 1),
			fragments: []string{"domains:\n    example.org: route53\n" + version},
			want:      "domains is not a block mapping",
		},
		{
			label:     "a flow unproxied list",
			base:      strings.Replace(fragmentBaseYaml, "versions:\n", "dns:\n    unproxied: [old.example.net]\nversions:\n", 1),
			fragments: []string{"dns:\n    unproxied:\n        - key.example.net\n" + version},
			want:      "unproxied is not a block list",
		},
		{
			label:     "a flow no_frame_options list",
			base:      strings.Replace(fragmentBaseYaml, "versions:\n", "no_frame_options: [old.example.net]\nversions:\n", 1),
			fragments: []string{"no_frame_options:\n    - key.example.net\n" + version},
			want:      "no_frame_options is not a block list",
		},
	}
	for _, c := range cases {
		base := c.base
		if base == "" {
			base = fragmentBaseYaml
		}
		fragments := []*ServicesFragment{}
		for index, text := range c.fragments {
			fragments = append(fragments, testServicesFragment(t, fmt.Sprintf("fragment-%d.yml", index), text))
		}
		result, err := ApplyServicesFragments([]byte(base), "services.yml", fragments...)
		if err == nil || !strings.Contains(err.Error(), c.want) || !errors.Is(err, ErrServicesFragment) {
			t.Errorf("%s: %v, want an error naming %q", c.label, err, c.want)
		}
		if result != nil {
			t.Errorf("%s: a refused fragment returned a result", c.label)
		}
	}
}

// A fragment adding domains, names or no_frame_options hosts applied to a file that already holds them
// adds nothing.
func TestApplyFragmentTwiceAddsNothingOutsideTheVersions(t *testing.T) {
	for _, text := range []string{fragmentDomainsYaml, fragmentNoFrameOptionsYaml} {
		fragment := testServicesFragment(t, "mmm.yml", text)
		first, err := ApplyServicesFragments([]byte(fragmentBaseYaml), "services.yml", fragment)
		if err != nil {
			t.Fatal(err)
		}
		second, err := ApplyServicesFragments(first.Text, "services.yml", fragment)
		if err != nil {
			t.Fatal(err)
		}
		if second.Changed() || !bytes.Equal(second.Text, first.Text) {
			t.Errorf("a second apply changed %q", second.Changes)
		}
	}
}

// Outside its version a fragment's no_frame_options is a list of exact lowercase hosts, each listed once
// and written as a string.
func TestParseServicesFragmentReadsNoFrameOptions(t *testing.T) {
	version := "version:\n    services: {}\n"
	fragment, err := ParseServicesFragment("frame.yml", []byte("no_frame_options:\n    - key.example.net\n    - other.example.net\n"+version))
	if err != nil || !slices.Equal(fragment.noFrameOptions, []string{"key.example.net", "other.example.net"}) {
		t.Errorf("a list of hosts does not parse: %v", err)
	}
	for _, text := range []string{
		"no_frame_options: []\n" + version,
		"no_frame_options:\n" + version,
		"no_frame_options: key.example.net\n" + version,
		"no_frame_options:\n    key.example.net: true\n" + version,
		"no_frame_options:\n    - \"*.example.net\"\n" + version,
		"no_frame_options:\n    - https://key.example.net\n" + version,
		"no_frame_options:\n    - key.example.net:443\n" + version,
		"no_frame_options:\n    - Key.example.net\n" + version,
		"no_frame_options:\n    - key.example.net.\n" + version,
		"no_frame_options:\n    - key.example.net\n    - key.example.net\n" + version,
		"no_frame_options:\n    - [key.example.net]\n" + version,
		"no_frame_options:\n    - 53\n" + version,
		"no_frame_option:\n    - key.example.net\n" + version,
	} {
		if _, err := ParseServicesFragment("bad.yml", []byte(text)); err == nil || !errors.Is(err, ErrServicesFragment) {
			t.Errorf("%q parsed: %v", text, err)
		}
	}
}

// Outside its version a fragment holds only a domains mapping of exact domains to string registrars, a
// placeholder among them, and a dns block holding only unproxied, exact hosts listed once.
func TestParseServicesFragmentReadsDomainsAndDns(t *testing.T) {
	version := "version:\n    services: {}\n"
	fragment, err := ParseServicesFragment("placeholder.yml", []byte("domains:\n    example.org: fill-in-route53-or-cloudflare\n"+version))
	if err != nil || len(fragment.domains) != 1 || fragment.domains[0].registrar != "fill-in-route53-or-cloudflare" {
		t.Errorf("a placeholder registrar does not parse: %v", err)
	}
	for _, text := range []string{
		"domains:\n    - example.org\n" + version,
		"domains: {}\n" + version,
		"domains:\n    Example.org: route53\n" + version,
		"domains:\n    \"*.example.org\": route53\n" + version,
		"domains:\n    example.org:\n" + version,
		"domains:\n    example.org: 53\n" + version,
		"domains:\n    example.org: route53\n    example.org: route53\n" + version,
		"domains:\n    example.org: route53\n",
		"dns:\n    records: []\n" + version,
		"dns:\n    unproxied: []\n" + version,
		"dns:\n    unproxied:\n        - \"*.example.net\"\n" + version,
		"dns:\n    unproxied:\n        - key.example.net\n        - key.example.net\n" + version,
		"dns:\n    unproxied:\n        - Key.example.net\n" + version,
		"domain: example.org\n" + version,
	} {
		if _, err := ParseServicesFragment("bad.yml", []byte(text)); err == nil || !errors.Is(err, ErrServicesFragment) {
			t.Errorf("%q parsed: %v", text, err)
		}
	}
}

// A fragment that would change a value, reuse a public port another service owns, or need ports past
// the version's ranges is refused, and so is one the loader could not read.
func TestApplyFragmentRefusesAChangeOrAReuse(t *testing.T) {
	cases := []struct {
		label    string
		base     string
		fragment string
		want     string
	}{
		{
			label:    "a scalar changed",
			fragment: "version:\n    services:\n        api:\n            status: none\n",
			want:     "services.api.status",
		},
		{
			label:    "a list replaced",
			fragment: "version:\n    services:\n        api:\n            hidden_prefixes:\n                - other\n",
			want:     "services.api.hidden_prefixes differs",
		},
		{
			label:    "blocks reweighed",
			fragment: "version:\n    services:\n        api:\n            blocks:\n                - g1: 100\n",
			want:     "services.api.blocks differs",
		},
		{
			label:    "a public port another service owns",
			fragment: "version:\n    services:\n        dnsedge:\n            exposed: false\n            hosts:\n                - edge-1.example.com\n            ports:\n                - 80\n            external_udp_ports:\n                - 53\n            blocks:\n                - g1: 1\n",
			want:     "both claim external udp port 53",
		},
		{
			label:    "a mapping given for a value",
			fragment: "version:\n    services:\n        api:\n            status:\n                mode: none\n",
			want:     "cannot unmarshal",
		},
		{
			// the base fits 7100-7163, so only the merged file runs out
			label:    "internal ports past the range",
			base:     strings.ReplaceAll(fragmentBaseYaml, "internal_ports: 7100-7999", "internal_ports: 7100-7167"),
			fragment: fragmentEvsYaml,
			want:     "the merged file's ports: No more internal ports",
		},
	}
	for _, c := range cases {
		base := c.base
		if base == "" {
			base = fragmentBaseYaml
		}
		// a fragment the loader could not read is refused as it is parsed, the rest as it is applied
		var result *ServicesFragmentResult
		fragment, err := ParseServicesFragment(c.label, []byte(c.fragment))
		if err == nil {
			result, err = ApplyServicesFragments([]byte(base), "services.yml", fragment)
		}
		if err == nil || !strings.Contains(err.Error(), c.want) || !errors.Is(err, ErrServicesFragment) {
			t.Errorf("%s: %v, want an error naming %q", c.label, err, c.want)
		}
		if result != nil {
			t.Errorf("%s: a refused fragment returned a result", c.label)
		}
	}
}

// A fragment is one version mapping, each key spelled as the loader reads it.
func TestParseServicesFragmentRefusesWhatTheLoaderWouldNotRead(t *testing.T) {
	for _, text := range []string{
		"services:\n    evs:\n        ports:\n            - 80\n",
		"version:\n    services:\n        evs:\n            secret_file:\n                - redis.yml\n",
		"version:\n    sevices: {}\n",
		"version: []\n",
		"version: {}\n",
		"",
	} {
		if _, err := ParseServicesFragment("bad.yml", []byte(text)); err == nil || !errors.Is(err, ErrServicesFragment) {
			t.Errorf("%q parsed: %v", text, err)
		}
	}
}

// The copy a new version starts from means what the top version means, merge key and aliases included.
func TestCopiedTopVersionDecodesAsTheOriginal(t *testing.T) {
	var document yaml.Node
	if err := yaml.Unmarshal([]byte(fragmentBaseYaml), &document); err != nil {
		t.Fatal(err)
	}
	top := servicesFragmentMappingValue(document.Content[0], "versions").Content[0]
	var original, copied ServicesConfigVersion
	if err := top.Decode(&original); err != nil {
		t.Fatal(err)
	}
	if err := copyServicesFragmentNode(top).Decode(&copied); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(original, copied) {
		t.Errorf("the copy decodes as\n%+v\nnot\n%+v", copied, original)
	}
	if copied.Services["app"].PortSpecs == nil || len(copied.Services["app"].ExposeAliases) != 1 {
		t.Errorf("the merge key brought nothing: %+v", copied.Services["app"])
	}
}
