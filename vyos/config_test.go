package vyos

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

func TestCompareMatchesDeviceOrder(t *testing.T) {
	// each pair is (earlier, later) in the order the device prints siblings
	ordered := [][2]string{
		{"all-ping", "broadcast-ping"},
		{"broadcast-ping", "ipv6-name WANv6_IN"},
		{"ipv6-name WANv6_IN", "ipv6-name WANv6_LOCAL"},
		{"ipv6-name WANv6_LOCAL", "ipv6-receive-redirects"},
		{"ipv6-receive-redirects", "ipv6-src-route"},
		// letters sort before punctuation, so ipv6-* precedes ip-src-route
		{"ipv6-src-route", "ip-src-route"},
		{"ip-src-route", "log-martians"},
		{"name WAN_IN", "name WAN_LOCAL"},
		// the split at the last hyphen makes http a prefix of https
		{"http-port", "https-port"},
		{"http-port", "older-ciphers"},
		{"ipv6-name WANv6_IN", "ip-src-route"},
		// digit runs compare numerically
		{"rule 10", "rule 20"},
		{"rule 20", "rule 100"},
		{"rule 100", "rule 110"},
		{"rule 5000", "rule 5001"},
		{"eth1", "eth10"},
		{"eth9", "eth10"},
		{"interface-route 192.0.2.9/32", "interface-route 192.0.2.10/32"},
		{"interface-route 192.0.2.12/32", "route6 ::/0"},
		// a prefix sorts first
		{"ip", "ipv6"},
		{"max-age", "max-interval"},
		{"shared-network-name LAN_BR", "static-arp"},
		{"ethernet eth8", "loopback lo"},
		{"loopback lo", "openvpn vtun1"},
		{"server synthetic-server-1.example", "server synthetic-server-2.example"},
		{"facility all", "facility protocols"},
		// tilde sorts before everything, including the end of the string
		{"a~b", "a"},
		{"A", "a"},
	}
	for _, pair := range ordered {
		if got := Compare(pair[0], pair[1]); got != -1 {
			t.Errorf("Compare(%q, %q) = %d, want -1", pair[0], pair[1], got)
		}
		if got := Compare(pair[1], pair[0]); got != 1 {
			t.Errorf("Compare(%q, %q) = %d, want 1", pair[1], pair[0], got)
		}
	}
	for _, same := range []string{"", "rule 10", "0", "00", "ip"} {
		if got := Compare(same, same); got != 0 {
			t.Errorf("Compare(%q, %q) = %d, want 0", same, same, got)
		}
	}
	if got := Compare("rule 010", "rule 10"); got != 0 {
		t.Errorf("leading zeros must not change the numeric order, got %d", got)
	}
}

func readFixture(t *testing.T, name string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// These sanitized synthetic fixtures retain the device grammar, ordering,
// quoting and footer layout without keeping live identities or credentials.
func TestParseRoundTripsLiveConfigs(t *testing.T) {
	for _, name := range []string{"synthetic-router-a-config.boot", "synthetic-router-b-config.boot"} {
		text := readFixture(t, name)
		config, err := Parse(text)
		if err != nil {
			t.Fatal(err)
		}
		if got := config.String(); got != text {
			t.Fatalf("round trip changed the file:\n%s", firstDifference(text, got))
		}
		if len(config.Comments) != 3 {
			t.Fatalf("comments = %d, want the three footer lines", len(config.Comments))
		}
		if !strings.HasPrefix(config.Comments[1], "/* === vyatta-config-version:") {
			t.Fatalf("second comment = %q", config.Comments[1])
		}
		again, err := Parse(config.String())
		if err != nil {
			t.Fatal(err)
		}
		if !again.Root.Equal(config.Root) {
			t.Fatal("reparsing the rendering produced a different tree")
		}
	}
}

func firstDifference(want string, got string) string {
	wantLines := strings.Split(want, "\n")
	gotLines := strings.Split(got, "\n")
	for i := 0; i < len(wantLines) || i < len(gotLines); i++ {
		var wantLine, gotLine string
		if i < len(wantLines) {
			wantLine = wantLines[i]
		}
		if i < len(gotLines) {
			gotLine = gotLines[i]
		}
		if wantLine != gotLine {
			return "line " + strconv.Itoa(i+1) + ":\n  want: " + wantLine + "\n  got:  " + gotLine
		}
	}
	return "no line differs"
}

func TestParseLiveConfigStructure(t *testing.T) {
	config, err := Parse(readFixture(t, "synthetic-router-a-config.boot"))
	if err != nil {
		t.Fatal(err)
	}
	root := config.Root
	if got := root.LeafValues("system", "host-name"); !reflect.DeepEqual(got, []string{"synthetic-router-a"}) {
		t.Fatalf("host-name = %v", got)
	}
	// a multi-valued leaf keeps the device's order
	if got := root.LeafValues("interfaces", "ethernet", "eth1", "address"); !reflect.DeepEqual(got, []string{"192.0.2.8/27", "2001:db8::3/48"}) {
		t.Fatalf("eth1 address = %v", got)
	}
	if got := root.LeafValues("system", "name-server"); !reflect.DeepEqual(got, []string{"192.0.2.1", "192.0.2.2", "2001:db8::1f"}) {
		t.Fatalf("name-server = %v", got)
	}
	// quoted values lose their quotes
	if got := root.LeafValues("firewall", "name", "WAN_IN", "rule", "40", "description"); !reflect.DeepEqual(got, []string{"warp synthetic-us-fmt-5-edge-3 eno3 http"}) {
		t.Fatalf("rule 40 description = %v", got)
	}
	// valueless leaves and empty containers survive
	if !root.HasLeaf("firewall", "ipv6-name", "WANv6_IN", "enable-default-log") {
		t.Fatal("enable-default-log is missing")
	}
	if got := root.LeafValues("firewall", "ipv6-name", "WANv6_IN", "enable-default-log"); len(got) != 0 {
		t.Fatalf("enable-default-log values = %v, want none", got)
	}
	if !root.HasLeaf("service", "nat", "rule", "5000", "exclude") {
		t.Fatal("exclude is missing")
	}
	if lo := root.Lookup("interfaces", "loopback", "lo"); lo == nil || !lo.Empty() {
		t.Fatal("loopback lo should be an empty container")
	}
	if destination := root.Lookup("firewall", "name", "WAN_IN", "rule", "20", "destination"); destination == nil || !destination.Empty() {
		t.Fatal("rule 20 destination should be an empty container")
	}
	if root.Lookup("firewall", "name", "MISSING") != nil {
		t.Fatal("Lookup of an absent tag must be nil")
	}
	if got := root.LeafValues("firewall", "name", "WAN_IN", "rule", "40", "missing"); got != nil {
		t.Fatalf("absent leaf values = %v, want nil", got)
	}
}

func TestParseRejectsUncommittedChangeMarkers(t *testing.T) {
	for _, marker := range []string{"+", "-", ">"} {
		text := "firewall {\n" + marker + "    all-ping enable\n}\n"
		_, err := Parse(text)
		if !errors.Is(err, ErrUncommitted) {
			t.Errorf("marker %q: err = %v, want ErrUncommitted", marker, err)
		}
	}
}

func TestParseIgnoresEditPromptAndCarriageReturns(t *testing.T) {
	config, err := Parse("firewall {\r\n    all-ping enable\r\n}\r\n[edit]\r\n")
	if err != nil {
		t.Fatal(err)
	}
	if got := config.Root.LeafValues("firewall", "all-ping"); !reflect.DeepEqual(got, []string{"enable"}) {
		t.Fatalf("all-ping = %v", got)
	}
	if got := config.String(); got != "firewall {\n    all-ping enable\n}\n" {
		t.Fatalf("rendering = %q", got)
	}
}

func TestParseQuotingAndSpecialValues(t *testing.T) {
	text := strings.Join([]string{
		"service {",
		"    dhcp-server {",
		`        shared-network-name "LAN BR" {`,
		"            authoritative enable",
		"        }",
		"    }",
		"    nat {",
		"        rule 5000 {",
		`            description ""`,
		"            exclude",
		"        }",
		"    }",
		"}",
		"system {",
		"    login {",
		"        user synthetic-admin {",
		"            authentication {",
		`                encrypted-password "****************"`,
		"            }",
		"        }",
		"    }",
		`    time-zone "America/Los Angeles"`,
		"}",
		"",
	}, "\n")
	config, err := Parse(text)
	if err != nil {
		t.Fatal(err)
	}
	root := config.Root
	if network := root.Lookup("service", "dhcp-server", "shared-network-name", "LAN BR"); network == nil {
		t.Fatal("tag with a quoted value was not parsed")
	}
	if got := root.LeafValues("service", "nat", "rule", "5000", "description"); !reflect.DeepEqual(got, []string{""}) {
		t.Fatalf("empty description = %#v", got)
	}
	if got := root.LeafValues("system", "login", "user", "synthetic-admin", "authentication", "encrypted-password"); !reflect.DeepEqual(got, []string{MaskedSecret}) {
		t.Fatalf("masked secret = %#v", got)
	}
	if got := config.String(); got != text {
		t.Fatalf("rendering differs:\n%s", firstDifference(text, got))
	}
	escaped, err := Parse(`system {` + "\n" + `    description "say \"hi\""` + "\n}\n")
	if err != nil {
		t.Fatal(err)
	}
	if got := escaped.Root.LeafValues("system", "description"); !reflect.DeepEqual(got, []string{`say "hi"`}) {
		t.Fatalf("escaped quote = %#v", got)
	}
}

func TestQuoteFollowsDeviceRule(t *testing.T) {
	cases := map[string]string{
		"":                                   `""`,
		"enable":                             "enable",
		"192.0.2.8/27":                       "192.0.2.8/27",
		"$5$abc$def":                         "$5$abc$def",
		"Allow established/related":          `"Allow established/related"`,
		"a*b":                                `"a*b"`,
		"a;b":                                `"a;b"`,
		"a{b":                                `"a{b"`,
		"a}b":                                `"a}b"`,
		"tab\there":                          "\"tab\there\"",
		"wss://x:443+key+allowUntrustedCert": "wss://x:443+key+allowUntrustedCert",
	}
	for value, want := range cases {
		if got := Quote(value); got != want {
			t.Errorf("Quote(%q) = %s, want %s", value, got, want)
		}
	}
}

func TestParseErrors(t *testing.T) {
	cases := map[string]string{
		"missing close":   "firewall {\n    all-ping enable\n",
		"extra close":     "firewall {\n}\n}\n",
		"three tokens":    "firewall {\n    a b c\n}\n",
		"tag too long":    "firewall {\n    a b c {\n    }\n}\n",
		"open quote":      "firewall {\n    description \"oops\n}\n",
		"unterminated /*": "firewall {\n}\n/* never closed\n",
	}
	for name, text := range cases {
		if _, err := Parse(text); err == nil {
			t.Errorf("%s: expected a parse error", name)
		}
	}
}

func TestBuilderAndPaths(t *testing.T) {
	root := NewNode()
	rule := root.Child("firewall").Tag("name", "WAN_IN").Tag("rule", "10")
	rule.SetLeaf("action", "accept")
	rule.SetLeaf("description", "warp host eth0 lb 80")
	rule.Child("destination").SetLeaf("port", "80")
	root.Child("firewall").Tag("name", "WAN_IN").SetLeaf("default-action", "drop")
	eth1 := root.Child("interfaces").Tag("ethernet", "eth1")
	eth1.AddLeafValue("address", "192.0.2.3/24")
	eth1.AddLeafValue("address", "2001:db8::20/64")
	eth1.AddLeafValue("address", "192.0.2.3/24")
	root.Child("interfaces").Tag("loopback", "lo")
	root.Child("service").Child("nat").Tag("rule", "5000").SetLeaf("exclude")
	root.Child("system").SetLeaf("name-server", "192.0.2.1", "192.0.2.2", "192.0.2.1")

	if got := root.LeafValues("interfaces", "ethernet", "eth1", "address"); !reflect.DeepEqual(got, []string{"192.0.2.3/24", "2001:db8::20/64"}) {
		t.Fatalf("address = %v", got)
	}
	if got := root.LeafValues("system", "name-server"); !reflect.DeepEqual(got, []string{"192.0.2.1", "192.0.2.2"}) {
		t.Fatalf("name-server = %v", got)
	}
	want := [][]string{
		{"firewall", "name", "WAN_IN", "default-action", "drop"},
		{"firewall", "name", "WAN_IN", "rule", "10", "action", "accept"},
		{"firewall", "name", "WAN_IN", "rule", "10", "description", "warp host eth0 lb 80"},
		{"firewall", "name", "WAN_IN", "rule", "10", "destination", "port", "80"},
		{"interfaces", "ethernet", "eth1", "address", "192.0.2.3/24"},
		{"interfaces", "ethernet", "eth1", "address", "2001:db8::20/64"},
		{"interfaces", "loopback", "lo"},
		{"service", "nat", "rule", "5000", "exclude"},
		{"system", "name-server", "192.0.2.1"},
		{"system", "name-server", "192.0.2.2"},
	}
	if got := root.Paths(); !reflect.DeepEqual(got, want) {
		t.Fatalf("Paths() =\n%v\nwant\n%v", got, want)
	}
	rendered := root.String()
	wantRendered := strings.Join([]string{
		"firewall {",
		"    name WAN_IN {",
		"        default-action drop",
		"        rule 10 {",
		"            action accept",
		`            description "warp host eth0 lb 80"`,
		"            destination {",
		"                port 80",
		"            }",
		"        }",
		"    }",
		"}",
		"interfaces {",
		"    ethernet eth1 {",
		"        address 192.0.2.3/24",
		"        address 2001:db8::20/64",
		"    }",
		"    loopback lo {",
		"    }",
		"}",
		"service {",
		"    nat {",
		"        rule 5000 {",
		"            exclude",
		"        }",
		"    }",
		"}",
		"system {",
		"    name-server 192.0.2.1",
		"    name-server 192.0.2.2",
		"}",
		"",
	}, "\n")
	if rendered != wantRendered {
		t.Fatalf("rendering differs:\n%s", firstDifference(wantRendered, rendered))
	}
	reparsed, err := Parse(rendered)
	if err != nil {
		t.Fatal(err)
	}
	if !reparsed.Root.Equal(root) {
		t.Fatal("built tree and reparsed tree differ")
	}
	if config := (&Config{Root: root, Comments: []string{"/* a */", "/* b */"}}); !strings.HasSuffix(config.String(), "}\n\n\n/* a */\n/* b */\n") {
		t.Fatalf("footer layout = %q", config.String()[len(config.String())-30:])
	}
}

func TestEqualDistinguishesValueOrderAndStructure(t *testing.T) {
	a := NewNode()
	a.Child("system").SetLeaf("name-server", "192.0.2.1", "192.0.2.2")
	b := NewNode()
	b.Child("system").SetLeaf("name-server", "192.0.2.2", "192.0.2.1")
	if a.Equal(b) {
		t.Fatal("value order must matter for Equal")
	}
	c := NewNode()
	c.Child("system").SetLeaf("name-server", "192.0.2.1", "192.0.2.2")
	if !a.Equal(c) {
		t.Fatal("identical trees must be equal")
	}
	d := NewNode()
	d.Child("system").Child("name-server")
	if a.Equal(d) {
		t.Fatal("a leaf and a container of the same name are not equal")
	}
}

// The device orders siblings by node name before it orders the instances of
// a tag node, so `name WAN_IN {` prints before the `name-server` leaves even
// though "name WAN_IN" as a whole would sort after "name-server".
func TestRenderOrdersByNameThenTag(t *testing.T) {
	root := NewNode()
	root.Child("x").SetLeaf("name-server", "192.0.2.1")
	root.Child("x").Tag("name", "WAN_IN").SetLeaf("default-action", "drop")
	root.Child("x").Tag("name", "WAN_LOCAL")
	root.Child("x").Tag("rule", "100")
	root.Child("x").Tag("rule", "20")
	root.Child("x").SetLeaf("rule-limit", "1")
	want := strings.Join([]string{
		"x {",
		"    name WAN_IN {",
		"        default-action drop",
		"    }",
		"    name WAN_LOCAL {",
		"    }",
		"    name-server 192.0.2.1",
		"    rule 20 {",
		"    }",
		"    rule 100 {",
		"    }",
		"    rule-limit 1",
		"}",
		"",
	}, "\n")
	if got := root.String(); got != want {
		t.Fatalf("rendering differs:\n%s", firstDifference(want, got))
	}
	if got := root.Child("x").ContainerKeys(); !reflect.DeepEqual(got, []Key{{Name: "name", Tag: "WAN_IN"}, {Name: "name", Tag: "WAN_LOCAL"}, {Name: "rule", Tag: "20"}, {Name: "rule", Tag: "100"}}) {
		t.Fatalf("ContainerKeys = %v", got)
	}
	if got := root.Child("x").LeafNames(); !reflect.DeepEqual(got, []string{"name-server", "rule-limit"}) {
		t.Fatalf("LeafNames = %v", got)
	}
}
