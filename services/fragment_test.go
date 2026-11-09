package services

import (
	"bytes"
	"errors"
	"reflect"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// A synthetic services.yml: example.com names and documentation addresses only. Its top version introduces
// mcp and app, which sort after evs and gkm, so merging a new service into that version, instead of
// adding one above it, would hand mcp's and app's ports to the newcomer. It keeps anchors and a merge key
// in the top version and aliases in the one under it, as a hand-kept file does.
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
			label:    "internal ports past the range",
			base:     strings.ReplaceAll(fragmentBaseYaml, "internal_ports: 7100-7999", "internal_ports: 7100-7159"),
			fragment: fragmentEvsYaml,
			want:     "No more internal ports",
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
