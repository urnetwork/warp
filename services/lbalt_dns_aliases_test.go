package services

// Tests of the dns_aliases rules (validateDnsAliases) for lb_alt
// (server/LBALT.md D14): the lb_alt service may declare dns-only names, every
// name has one owner, and a one-family name of the lb_alt service needs the
// name it narrows. The configs are lbAltServicesYaml's (lbalt_test.go).

import (
	"reflect"
	"strings"
	"testing"
)

// connect's dns aliases, in the shape of main's alt.* names
const lbAltDnsAliasesLine = "        dns_aliases: [alt.example.com, alt-v4.example.com, alt-v6.example.com]"

// lbAltServicesYaml with an alt service pinned to edge-b, which runs it with
// no lb in front, declaring dnsAliases (a yaml flow list)
func lbAltDnsAltServiceYaml(t *testing.T, servicesYaml string, dnsAliases string) string {
	t.Helper()
	return lbAltInsertAfter(t, servicesYaml, "          - g1: 1",
		"      alt:",
		"        exposed: false",
		"        hosts: [edge-b.example]",
		"        ports: [80]",
		"        dns_aliases: "+dnsAliases,
		"        blocks:",
		"          - g1: 1",
	)
}

// The lb_alt service, though an lb service, may declare dns aliases, with its
// default off (the canary) or on.
func TestDnsAliasesAllowedOnTheLbAltService(t *testing.T) {
	for _, connectDefault := range []string{"false", "true"} {
		servicesYaml := lbAltInsertAfter(t, lbAltYaml(lbAltSettings{connect: connectDefault}), "      connect:", lbAltDnsAliasesLine)
		version := loadLbAltVersion(t, servicesYaml)
		if got, want := version.Services["connect"].DnsAliases, []string{"alt.example.com", "alt-v4.example.com", "alt-v6.example.com"}; !reflect.DeepEqual(got, want) {
			t.Fatalf("connect dns aliases = %v, want %v", got, want)
		}
	}
}

// Any other lb service is still refused: connect when it declares no lb_alt,
// and api beside the lb_alt service.
func TestDnsAliasesRefusedOnAnLbServiceThatIsNotLbAlt(t *testing.T) {
	for _, servicesYaml := range []string{
		lbAltInsertAfter(t, lbAltYaml(lbAltSettings{}), "      connect:", lbAltDnsAliasesLine),
		lbAltInsertAfter(t, lbAltYaml(lbAltSettings{connect: "false"}), "      api:", "        dns_aliases: [api-direct.example.com]"),
	} {
		_, err := loadInlineServicesConfig(t, servicesYaml)
		if err == nil || !strings.Contains(err.Error(), "is neither a host-pinned service with no lb in front nor the lb_alt service") {
			t.Errorf("err = %v, want the dns aliases refused", err)
		}
	}
}

// A dns alias has one owner across services: alt and connect may not both list
// alt.example.com, so the handover moves the names in one version, which
// loads.
func TestDnsAliasesHaveOneOwner(t *testing.T) {
	servicesYaml := lbAltInsertAfter(t, lbAltYaml(lbAltSettings{connect: "false"}), "      connect:", lbAltDnsAliasesLine)
	_, err := loadInlineServicesConfig(t, lbAltDnsAltServiceYaml(t, servicesYaml, "[alt.example.com]"))
	if err == nil || !strings.Contains(err.Error(), `services "alt" and "connect" both declare the dns alias "alt.example.com", and a dns name has one owner`) {
		t.Fatalf("err = %v, want the second owner refused", err)
	}
	// the handover: alt keeps only a name connect does not list
	loadLbAltVersion(t, lbAltDnsAltServiceYaml(t, servicesYaml, "[alt-old.example.com]"))
}

// A dns alias has no certificate or server name, so no service may also serve
// it, as an expose alias, an expose domain or a redirect alias. That holds
// for alt's names as well as the lb_alt service's.
func TestDnsAliasesRefuseANameTheLbServes(t *testing.T) {
	baseYaml := lbAltYaml(lbAltSettings{connect: "false"})
	cases := []struct {
		servedLine string
		dnsAlias   string
		altService bool
	}{
		{servedLine: "        expose_aliases: [alt.example.com]", dnsAlias: "connect"},
		{servedLine: "        expose_domains: [alt.example.com]", dnsAlias: "connect"},
		{servedLine: "        redirect_aliases: {alt.example.com: api.example.com}", dnsAlias: "connect"},
		{servedLine: "        expose_aliases: [ALT.example.com]", dnsAlias: "connect"},
		{servedLine: "        expose_aliases: [alt-old.example.com]", dnsAlias: "alt", altService: true},
	}
	for _, c := range cases {
		servicesYaml := lbAltInsertAfter(t, baseYaml, "      api:", c.servedLine)
		want := `service "connect" dns alias "alt.example.com" is also a name the lb serves for service "api"`
		if c.altService {
			servicesYaml = lbAltDnsAltServiceYaml(t, servicesYaml, "[alt-old.example.com]")
			want = `service "alt" dns alias "alt-old.example.com" is also a name the lb serves for service "api"`
		} else {
			servicesYaml = lbAltInsertAfter(t, servicesYaml, "      connect:", lbAltDnsAliasesLine)
		}
		_, err := loadInlineServicesConfig(t, servicesYaml)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: err = %v, want %q", c.servedLine, err, want)
		}
	}
}

// A one-family name of the lb_alt service aliases the weighted set of the name
// it narrows while lb_alt is on for only some interfaces, so that name must
// be listed too. A host-pinned service's names hold addresses directly and
// need no such name.
func TestDnsAliasesOfTheLbAltServiceNeedTheNameTheyNarrow(t *testing.T) {
	baseYaml := lbAltYaml(lbAltSettings{connect: "false"})
	_, err := loadInlineServicesConfig(t, lbAltInsertAfter(t, baseYaml, "      connect:", "        dns_aliases: [alt-v4.example.com, alt-v6.example.com]"))
	if err == nil || !strings.Contains(err.Error(), `service "connect" dns alias "alt-v4.example.com" carries one address family of "alt.example.com", which the service does not list`) {
		t.Fatalf("err = %v, want the narrowed name required", err)
	}
	loadLbAltVersion(t, lbAltInsertAfter(t, baseYaml, "      connect:", "        dns_aliases: [alt.example.com, alt-v6.example.com]"))
	loadLbAltVersion(t, lbAltDnsAltServiceYaml(t, baseYaml, "[alt-v4.example.com]"))
}

func TestDnsAliasFamilyBase(t *testing.T) {
	cases := []struct {
		name     string
		base     string
		narrowed bool
	}{
		{name: "alt-v4.example.com", base: "alt.example.com", narrowed: true},
		{name: "alt-v6.example.com", base: "alt.example.com", narrowed: true},
		{name: "main-alt-v6.example.com", base: "main-alt.example.com", narrowed: true},
		{name: "alt-v4-v6.example.com", base: "alt-v4.example.com", narrowed: true},
		{name: "alt.example.com", base: "", narrowed: false},
		{name: "v4.example.com", base: "", narrowed: false},
		{name: "*.alt-v4.example.com", base: "", narrowed: false},
		{name: "alt-v4", base: "", narrowed: false},
	}
	for _, c := range cases {
		base, narrowed := DnsAliasFamilyBase(c.name)
		if base != c.base || narrowed != c.narrowed {
			t.Errorf("%s = %q %t, want %q %t", c.name, base, narrowed, c.base, c.narrowed)
		}
	}
}
