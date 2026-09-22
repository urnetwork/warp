package services

import (
	"reflect"
	"strings"
	"testing"
)

const settingsFixture = `# per host settings
edge-3.example.com: &tst
    env_vars: &tst_env
        BRINGYOUR_POSTGRES_HOSTNAME: 192.168.51.43
    routes:
        edge-2: 192.168.51.43
        edge-3: 192.168.51.180
        snow: 172.28.208.185
edge-5.example.com: *tst
sille:
    <<: *tst
    env_vars:
        <<: *tst_env
        BRINGYOUR_POSTGRES_HOSTNAME: 172.28.208.182
`

const settingsLanHostsFixture = settingsFixture + `
# The hosts on the lan routers' bridges with the addresses their dhcp static
# mappings assign. ` + "`run-routers.sh --update-settings`" + ` adds the hosts the live
# routers know and never removes one; ` + "`warpctl vyos`" + ` renders the lan routers
# from this block. A ` + "`routes`" + ` address inside a lan must match its entry here.
lan_hosts:
    edge-2:
        ip: 192.168.51.43
        mac: e4:43:4b:56:79:10
    edge-3:
        ip: 192.168.51.180
        mac: 6c:fe:54:2d:f2:f1
`

func TestSettingsLanHostsAndRoutesParse(t *testing.T) {
	hosts, err := ParseLanHosts([]byte(settingsLanHostsFixture))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]*LanHost{
		"edge-2": {Ip: "192.168.51.43", Mac: "e4:43:4b:56:79:10"},
		"edge-3": {Ip: "192.168.51.180", Mac: "6c:fe:54:2d:f2:f1"},
	}
	if !reflect.DeepEqual(hosts, want) {
		t.Fatalf("hosts = %+v", hosts)
	}
	// a document without the block has no hosts
	none, err := ParseLanHosts([]byte(settingsFixture))
	if err != nil || len(none) != 0 {
		t.Fatalf("hosts = %+v, %v", none, err)
	}
	// Keep each source map, including aliases and per-host overrides.
	routes := ParseLanRoutes([]byte(`a.example:
    routes: &routes {node: 192.0.2.43}
b.example:
    routes: *routes
c.example:
    routes: {node: 198.51.100.43}
`))
	if !reflect.DeepEqual(routes, map[string]map[string]string{
		"a.example": {"node": "192.0.2.43"},
		"b.example": {"node": "192.0.2.43"},
		"c.example": {"node": "198.51.100.43"},
	}) {
		t.Fatalf("routes = %v", routes)
	}
	if got := ParseLanRoutes([]byte("lan_hosts:\n    a:\n        ip: 10.0.0.1\n        mac: 00:00:00:00:00:01\n")); len(got) != 0 {
		t.Fatalf("routes = %v", got)
	}
}

func TestSettingsLanHostsValidation(t *testing.T) {
	cases := map[string]string{
		"bad name":    "lan_hosts:\n    Edge_2:\n        ip: 192.168.51.43\n        mac: e4:43:4b:56:79:10\n",
		"bad ip":      "lan_hosts:\n    edge-2:\n        ip: 2001:db8::1\n        mac: e4:43:4b:56:79:10\n",
		"bad mac":     "lan_hosts:\n    edge-2:\n        ip: 192.168.51.43\n        mac: E4-43-4B-56-79-10\n",
		"shared ip":   "lan_hosts:\n    a:\n        ip: 192.168.51.43\n        mac: e4:43:4b:56:79:10\n    b:\n        ip: 192.168.51.43\n        mac: e4:43:4b:56:79:11\n",
		"shared mac":  "lan_hosts:\n    a:\n        ip: 192.168.51.43\n        mac: e4:43:4b:56:79:10\n    b:\n        ip: 192.168.51.44\n        mac: e4:43:4b:56:79:10\n",
		"missing mac": "lan_hosts:\n    a:\n        ip: 192.168.51.43\n",
		"empty entry": "lan_hosts:\n    a:\n",
	}
	for name, document := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseLanHosts([]byte(document)); err == nil {
				t.Fatalf("%q must be refused", document)
			}
		})
	}
}

// The merge adds what the router knows, keeps what the file says on a
// conflict, and rewrites only the block: the anchors, merges and comments
// around it are untouched.
func TestSettingsMergeLanHosts(t *testing.T) {
	discovered := map[string]*LanHost{
		// a new host
		"tinypilot": {Ip: "192.168.51.42", Mac: "d8:3a:dd:31:58:2f"},
		// known and identical
		"edge-2": {Ip: "192.168.51.43", Mac: "e4:43:4b:56:79:10"},
		// known, the router disagrees
		"edge-3": {Ip: "192.168.51.181", Mac: "6c:fe:54:2d:f2:f1"},
	}
	merge, err := MergeLanHosts([]byte(settingsLanHostsFixture), discovered)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(merge.Added, []string{"tinypilot"}) {
		t.Fatalf("added = %v", merge.Added)
	}
	if len(merge.Conflicts) != 1 || !strings.Contains(merge.Conflicts[0], "edge-3: settings 192.168.51.180 6c:fe:54:2d:f2:f1, router 192.168.51.181") {
		t.Fatalf("conflicts = %v", merge.Conflicts)
	}
	if merge.Hosts["edge-3"].Ip != "192.168.51.180" {
		t.Fatal("a conflict must keep the settings value")
	}
	document := string(merge.Document)
	// everything before the block is byte for byte
	if !strings.HasPrefix(document, settingsFixture) {
		t.Fatalf("the per host settings changed:\n%s", document)
	}
	for _, want := range []string{"&tst", "*tst", "<<: *tst_env", "# per host settings", "    tinypilot:\n        ip: 192.168.51.42\n        mac: d8:3a:dd:31:58:2f\n", "    edge-3:\n        ip: 192.168.51.180\n"} {
		if !strings.Contains(document, want) {
			t.Errorf("merged document lacks %q:\n%s", want, document)
		}
	}
	if strings.Count(document, "lan_hosts:") != 1 || strings.Count(document, "# The hosts on the lan routers' bridges") != 1 {
		t.Fatalf("the block is not rewritten in place:\n%s", document)
	}
	reparsed, err := ParseLanHosts(merge.Document)
	if err != nil || len(reparsed) != 3 {
		t.Fatalf("reparsed = %+v, %v", reparsed, err)
	}
	// idempotent
	again, err := MergeLanHosts(merge.Document, discovered)
	if err != nil {
		t.Fatal(err)
	}
	if string(again.Document) != document || len(again.Added) != 0 {
		t.Fatal("a second merge must change nothing")
	}

	// a document without the block gets it appended, the rest untouched
	appended, err := MergeLanHosts([]byte(settingsFixture), map[string]*LanHost{"edge-2": {Ip: "192.168.51.43", Mac: "e4:43:4b:56:79:10"}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(appended.Document), settingsFixture) || !strings.HasSuffix(string(appended.Document), "lan_hosts:\n    edge-2:\n        ip: 192.168.51.43\n        mac: e4:43:4b:56:79:10\n") {
		t.Fatalf("appended document:\n%s", appended.Document)
	}
	if !reflect.DeepEqual(appended.Added, []string{"edge-2"}) {
		t.Fatalf("added = %v", appended.Added)
	}

	// a block in the middle of the document keeps what follows it
	middle := "a: 1\n\nlan_hosts:\n    edge-2:\n        ip: 192.168.51.43\n        mac: e4:43:4b:56:79:10\n\nz: 2\n"
	merged, err := MergeLanHosts([]byte(middle), map[string]*LanHost{"edge-6": {Ip: "192.168.51.193", Mac: "48:df:37:7a:71:58"}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(merged.Document), "a: 1\n\n") || !strings.HasSuffix(string(merged.Document), "        mac: 48:df:37:7a:71:58\n\nz: 2\n") {
		t.Fatalf("middle merge:\n%s", merged.Document)
	}

	// a live host that collides with a settings host is refused
	if _, err := MergeLanHosts([]byte(settingsLanHostsFixture), map[string]*LanHost{"other": {Ip: "192.168.51.43", Mac: "00:00:00:00:00:01"}}); err == nil {
		t.Fatal("a shared ip must be refused")
	}
}
