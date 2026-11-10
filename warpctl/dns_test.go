package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/route53"
	"github.com/aws/aws-sdk-go-v2/service/route53/types"

	"github.com/urnetwork/warp/services"
)

// the derivation on the vyos fixture: three lb hosts behind routers, one
// transparent proxy host, a legacy host, the alt service on fireside
func newDnsTestInput(t *testing.T, mutate func(string) string) dnsPlanInput {
	t.Helper()
	servicesYaml, err := os.ReadFile(filepath.Join("testdata", "services-vyos.yml"))
	if err != nil {
		t.Fatal(err)
	}
	env := setupTestVault(t, []byte(mutate(string(servicesYaml))))
	return dnsPlanInput{Env: env, ServicesConfig: getServicesConfig(env)}
}

func dnsFixtureWithDns(servicesYaml string) string {
	// alt dns names, a service alias per family, a wildcard, an unmanaged apex
	servicesYaml = strings.Replace(servicesYaml, "domain: example.com\ndomains:\n    example.com: route53\n",
		"domain: example.com\ndomains:\n    example.com: route53\n    example.net: cloudflare\nexpose_aliases:\n    - fireside.example.com\n    - \"*.fireside.example.com\"\n    - \"*.fireside.example.net\"\n    - cosmic.example.com\nlb_hidden_prefixes:\n    - wrong-birdie-whicker-pompeii\ndns:\n    ttl: 120\n    unmanaged:\n        - example.com\n        - www.example.com\n    other_domain_services:\n        - web\n", 1)
	servicesYaml = strings.Replace(servicesYaml, "        web:\n            ports:\n                - 80\n            blocks:\n                - g1: 1\n        svc-c:\n",
		"        web:\n            expose_aliases:\n                - example.com\n                - www.example.com\n                - api.example.com\n                - api-v4.example.com\n                - api-v6.example.com\n                - \"*.connect.example.com\"\n                - api.example.org\n                - example.net\n                - www.example.net\n                - www-v6.example.net\n            ports:\n                - 80\n            blocks:\n                - g1: 1\n        svc-c:\n", 1)
	servicesYaml = strings.Replace(servicesYaml, "            external_udp_forward_ports:\n                53: 4053\n            blocks:\n                - g1: 1\n        proxy:\n",
		"            external_udp_forward_ports:\n                53: 4053\n            dns_aliases:\n                - alt.example.com\n                - alt-v4.example.com\n                - alt-v6.example.com\n            blocks:\n                - g1: 1\n        proxy:\n", 1)
	return servicesYaml
}

func findDnsName(t *testing.T, domain *dnsDomain, name string) *dnsName {
	t.Helper()
	for _, derived := range domain.Names {
		if derived.Name == name {
			return derived
		}
	}
	t.Fatalf("%s is not derived; names are %v", name, dnsNameList(domain))
	return nil
}

func dnsNameList(domain *dnsDomain) []string {
	names := []string{}
	for _, derived := range domain.Names {
		names = append(names, derived.Name)
	}
	return names
}

func TestDnsDerivesTheRecordsOfADomain(t *testing.T) {
	input := newDnsTestInput(t, dnsFixtureWithDns)
	domains, err := dnsDerive(input)
	if err != nil {
		t.Fatal(err)
	}
	if len(domains) != 2 || domains[0].Domain != "example.com" || domains[0].Registrar != "route53" || domains[1].Domain != "example.net" || domains[1].Registrar != "cloudflare" {
		t.Fatalf("domains = %+v", domains)
	}
	com := domains[0]
	env := input.Env

	// interface records for every lb interface, the legacy host included
	edge3 := findDnsName(t, com, "edge-3-eno1np0.example.com")
	if edge3.Kind != dnsAddresses || !reflect.DeepEqual(edge3.Ipv4, []string{"203.0.113.84"}) || !reflect.DeepEqual(edge3.Ipv6, []string{"2001:db8:99:5880:e643:4bff:fe94:e380"}) {
		t.Fatalf("edge-3 eno1np0 = %+v", edge3)
	}
	legacy := findDnsName(t, com, "legacy-0-eno2.example.com")
	if legacy.Kind != dnsAddresses || !reflect.DeepEqual(legacy.Ipv4, []string{"198.51.100.62"}) {
		t.Fatalf("legacy-0 eno2 = %+v", legacy)
	}
	fireside := findDnsName(t, com, "fireside-eno1np0.example.com")
	if !reflect.DeepEqual(fireside.Ipv4, []string{"203.0.113.92"}) {
		t.Fatalf("fireside eno1np0 = %+v", fireside)
	}

	// the lb set: every interface with a front, weighted, the transparent
	// proxy host excluded
	lb := findDnsName(t, com, env+"-lb.example.com")
	if lb.Kind != dnsLbSet || !lb.HasIpv4 || !lb.HasIpv6 {
		t.Fatalf("lb = %+v", lb)
	}
	wantMembers := []dnsMember{
		{Id: "edge-0-eno2", Ipv4: "198.51.100.42", Ipv6: "2001:db8:173:5200:e643:4bff:fe23:a341", Weight: 10},
		{Id: "edge-3-eno1np0", Ipv4: "203.0.113.84", Ipv6: "2001:db8:99:5880:e643:4bff:fe94:e380", Weight: 100},
		{Id: "edge-3-eno2np1", Ipv4: "203.0.113.85", Ipv6: "2001:db8:99:5860:e643:4bff:fe94:e381", Weight: 100},
		{Id: "edge-5-enp33s0f1np1", Ipv4: "203.0.113.91", Ipv6: "2001:db8:99:5930:9a03:9bff:fe56:593", Weight: 100},
		{Id: "legacy-0-eno2", Ipv4: "198.51.100.62", Ipv6: "2001:db8:173:52:e643:4bff:fe23:a341", Weight: 100},
	}
	if !reflect.DeepEqual(lb.Members, wantMembers) {
		t.Fatalf("lb members = %+v", lb.Members)
	}
	lbV4 := findDnsName(t, com, env+"-lb-v4.example.com")
	if lbV4.Kind != dnsAliasTo || lbV4.Target != env+"-lb.example.com" || !lbV4.HasIpv4 || lbV4.HasIpv6 || len(lbV4.Ipv4) != 5 || len(lbV4.Ipv6) != 0 {
		t.Fatalf("lb-v4 = %+v", lbV4)
	}
	lbV6 := findDnsName(t, com, env+"-lb-v6.example.com")
	if lbV6.HasIpv4 || !lbV6.HasIpv6 || len(lbV6.Ipv6) != 5 {
		t.Fatalf("lb-v6 = %+v", lbV6)
	}

	// exposed services alias the lb, with their aliases per family
	for name, families := range map[string][2]bool{
		env + "-web.example.com":   {true, true},
		env + "-svc-c.example.com": {true, true},
		env + "-proxy.example.com": {true, true},
		"api.example.com":          {true, true},
		"api-v4.example.com":       {true, false},
		"api-v6.example.com":       {false, true},
		"*.connect.example.com":    {true, true},
		"*.fireside.example.com":   {true, true},
	} {
		derived := findDnsName(t, com, name)
		if derived.Kind != dnsAliasTo || derived.HasIpv4 != families[0] || derived.HasIpv6 != families[1] {
			t.Errorf("%s = %+v, want alias families %v", name, derived, families)
		}
	}
	if got := findDnsName(t, com, "api.example.com").Target; got != env+"-lb.example.com" {
		t.Errorf("api target = %s", got)
	}
	if got := findDnsName(t, com, "*.fireside.example.com").Target; got != "fireside.example.com" {
		t.Errorf("wildcard target = %s", got)
	}
	// the transparent host: its own addresses
	firesideHost := findDnsName(t, com, "fireside.example.com")
	if firesideHost.Kind != dnsAddresses || !reflect.DeepEqual(firesideHost.Ipv4, []string{"203.0.113.92"}) || !reflect.DeepEqual(firesideHost.Ipv6, []string{"2001:db8:99:5960:3a05:25ff:fe32:e5ab"}) {
		t.Errorf("fireside = %+v", firesideHost)
	}
	// alt runs with no lb in front: direct records and its dns aliases
	alt := findDnsName(t, com, env+"-alt.example.com")
	if alt.Kind != dnsAddresses || !reflect.DeepEqual(alt.Ipv4, []string{"203.0.113.92"}) || !reflect.DeepEqual(alt.Ipv6, []string{"2001:db8:99:5960:3a05:25ff:fe32:e5ab"}) {
		t.Errorf("alt = %+v", alt)
	}
	altV6 := findDnsName(t, com, "alt-v6.example.com")
	if altV6.HasIpv4 || !altV6.HasIpv6 || len(altV6.Ipv4) != 0 || !reflect.DeepEqual(altV6.Ipv6, []string{"2001:db8:99:5960:3a05:25ff:fe32:e5ab"}) {
		t.Errorf("alt-v6 = %+v", altV6)
	}
	if !findDnsName(t, com, env+"-alt-v4.example.com").HasIpv4 {
		t.Error("alt-v4 lacks A")
	}
	// alt is not an lb service
	for _, derived := range com.Names {
		if derived.Name == env+"-alt.example.com" && derived.Kind == dnsAliasTo {
			t.Error("alt must not alias the lb")
		}
	}
	// an lb service gets no automatic -v4/-v6 names: it lists them itself
	for _, derived := range com.Names {
		if derived.Name == env+"-web-v4.example.com" || derived.Name == env+"-web-v6.example.com" {
			t.Errorf("%s must not be derived", derived.Name)
		}
	}
	// unmanaged and foreign names are noted, never derived
	for _, absent := range []string{"example.com", "www.example.com", "api.example.org", "cosmic.example.com"} {
		for _, derived := range com.Names {
			if derived.Name == absent {
				t.Errorf("%s must not be derived", absent)
			}
		}
	}
	notes := strings.Join(com.Notes, "\n")
	for _, want := range []string{"example.com: unmanaged", "www.example.com: unmanaged", "api.example.org: not under a registrar domain", "cosmic.example.com: not an lb host"} {
		if !strings.Contains(notes, want) {
			t.Errorf("notes lack %q:\n%s", want, notes)
		}
	}
	// names are sorted and unique
	names := dnsNameList(com)
	if !sort.StringsAreSorted(names) {
		t.Errorf("names are not sorted: %v", names)
	}

	// the other domain carries only the lb set and the web aliases under it
	net := domains[1]
	if net.Primary || !com.Primary {
		t.Fatal("example.com is the primary domain")
	}
	if got := dnsNameList(net); !reflect.DeepEqual(got, []string{"example.net", env + "-lb.example.net", "www-v6.example.net", "www.example.net"}) {
		t.Fatalf("example.net names = %v", got)
	}
	if findDnsName(t, net, env+"-lb.example.net").Kind != dnsLbSet {
		t.Error("example.net lacks the lb set")
	}
	apex := findDnsName(t, net, "example.net")
	if apex.Kind != dnsAliasTo || apex.Target != env+"-lb.example.net" || !apex.HasIpv4 || !apex.HasIpv6 || len(apex.Ipv4) != 5 {
		t.Errorf("example.net = %+v", apex)
	}
	if wwwV6 := findDnsName(t, net, "www-v6.example.net"); wwwV6.HasIpv4 || !wwwV6.HasIpv6 {
		t.Errorf("www-v6.example.net = %+v", wwwV6)
	}
	// the primary domain's derivation notes what the other domains leave alone
	if !strings.Contains(notes, "*.fireside.example.net: not under the primary domain, left alone") {
		t.Errorf("notes lack the expose alias note:\n%s", notes)
	}
	if len(net.Notes) != 0 {
		t.Errorf("example.net notes = %v", net.Notes)
	}
}

func TestDnsDerivationRefusesAnUnknownOtherDomainService(t *testing.T) {
	input := newDnsTestInput(t, func(servicesYaml string) string {
		return strings.Replace(dnsFixtureWithDns(servicesYaml), "    other_domain_services:\n        - web\n", "    other_domain_services:\n        - alt\n", 1)
	})
	if _, err := dnsDerive(input); err == nil || !strings.Contains(err.Error(), "not an exposed service") {
		t.Fatalf("err = %v", err)
	}
	input = newDnsTestInput(t, func(servicesYaml string) string {
		return strings.Replace(dnsFixtureWithDns(servicesYaml), "    other_domain_services:\n        - web\n", "    other_domain_services:\n        - nope\n", 1)
	})
	if _, err := dnsDerive(input); err == nil || !strings.Contains(err.Error(), "unknown service") {
		t.Fatalf("err = %v", err)
	}
}

func TestDnsDerivationWithAnEnvAlias(t *testing.T) {
	input := newDnsTestInput(t, dnsFixtureWithDns)
	input.EnvAliases = []string{"prod"}
	domains, err := dnsDerive(input)
	if err != nil {
		t.Fatal(err)
	}
	com := domains[0]
	if findDnsName(t, com, "prod-lb.example.com").Kind != dnsLbSet {
		t.Error("prod-lb is not the lb set")
	}
	if got := findDnsName(t, com, "prod-web.example.com").Target; got != "prod-lb.example.com" {
		t.Errorf("prod-web target = %s", got)
	}
	if got := findDnsName(t, com, "prod-alt.example.com").Kind; got != dnsAddresses {
		t.Errorf("prod-alt kind = %v", got)
	}
	// the service aliases stay on the env's lb
	if got := findDnsName(t, com, "api.example.com").Target; got != input.Env+"-lb.example.com" {
		t.Errorf("api target = %s", got)
	}
}

// W9: a host-pinned service whose public ports are tcp alone has the same
// direct records as one with udp ports, here the dns edge of the vyos fixture
// with its udp claim taken out.
func TestDnsDerivesDirectRecordsForATcpOnlyHostPinnedService(t *testing.T) {
	withDnsEdge := vyosFixtureWithDnsEdge(t)
	input := newDnsTestInput(t, func(servicesYaml string) string {
		servicesYaml = withDnsEdge(servicesYaml)
		udpClaim := "            external_udp_ports:\n                - 53\n            external_tcp_ports:\n"
		if !strings.Contains(servicesYaml, udpClaim) {
			t.Fatalf("the dns edge fixture has no %q", udpClaim)
		}
		return strings.Replace(servicesYaml, udpClaim, "            external_tcp_ports:\n", 1)
	})
	if dnsedgeConfig := input.ServicesConfig.Latest().Services["dnsedge"]; len(dnsedgeConfig.ExternalUdpPorts) != 0 || len(dnsedgeConfig.ExternalTcpPorts) != 1 {
		t.Fatalf("dnsedge claims udp %v and tcp %v, want tcp alone", dnsedgeConfig.ExternalUdpPorts, dnsedgeConfig.ExternalTcpPorts)
	}
	domains, err := dnsDerive(input)
	if err != nil {
		t.Fatal(err)
	}
	com := domains[0]
	dnsedge := findDnsName(t, com, input.Env+"-dnsedge.example.com")
	if dnsedge.Kind != dnsAddresses || !reflect.DeepEqual(dnsedge.Ipv4, []string{"203.0.113.93"}) || !reflect.DeepEqual(dnsedge.Ipv6, []string{"2001:db8:99:5940::53"}) {
		t.Errorf("dnsedge = %+v", dnsedge)
	}
	if dnsedgeV4 := findDnsName(t, com, input.Env+"-dnsedge-v4.example.com"); !dnsedgeV4.HasIpv4 || dnsedgeV4.HasIpv6 {
		t.Errorf("dnsedge-v4 = %+v", dnsedgeV4)
	}
	if dnsedgeV6 := findDnsName(t, com, input.Env+"-dnsedge-v6.example.com"); dnsedgeV6.HasIpv4 || !dnsedgeV6.HasIpv6 {
		t.Errorf("dnsedge-v6 = %+v", dnsedgeV6)
	}
}

func TestDnsDerivationRefusesADnsAliasOnAnLbService(t *testing.T) {
	servicesYaml, err := os.ReadFile(filepath.Join("testdata", "services-vyos.yml"))
	if err != nil {
		t.Fatal(err)
	}
	mutated := strings.Replace(string(servicesYaml), "        web:\n            ports:\n                - 80\n", "        web:\n            dns_aliases:\n                - web.example.com\n            ports:\n                - 80\n", 1)
	vaultDir := t.TempDir()
	env := "dnstest"
	if err := os.MkdirAll(filepath.Join(vaultDir, env), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(vaultDir, env, "services.yml"), []byte(mutated), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := services.LoadServicesConfigFrom(vaultDir, env); err == nil || !strings.Contains(err.Error(), "dns_aliases") {
		t.Fatalf("err = %v, want a dns_aliases refusal", err)
	}
}

func TestDnsFamilySuffix(t *testing.T) {
	for name, want := range map[string][2]bool{
		"api.example.com":          {true, true},
		"api-v4.example.com":       {true, false},
		"main-lb-v6.example.com":   {false, true},
		"v4.example.com":           {true, true},
		"*.connect-v4.example.com": {true, true},
	} {
		hasIpv4, hasIpv6 := dnsFamilySuffix(name)
		if hasIpv4 != want[0] || hasIpv6 != want[1] {
			t.Errorf("%s = %v %v, want %v", name, hasIpv4, hasIpv6, want)
		}
	}
	if got := dnsShortHost("fireside.example.com", "example.com"); got != "fireside" {
		t.Errorf("short host = %s", got)
	}
	if got := dnsShortHost("edge.other.net", "example.com"); got != "edge-other-net" {
		t.Errorf("short host = %s", got)
	}
}

// The route53 rendering: plain sets for addresses, weighted sets with a
// health check per member and family for the lb, alias sets for the aliases.
func TestDnsRoute53Desired(t *testing.T) {
	input := newDnsTestInput(t, dnsFixtureWithDns)
	domains, err := dnsDerive(input)
	if err != nil {
		t.Fatal(err)
	}
	rrsets, err := route53Desired(domains[0], input)
	if err != nil {
		t.Fatal(err)
	}
	byKey := map[string]*route53Rrset{}
	for _, rrset := range rrsets {
		byKey[rrset.key()] = rrset
	}
	env := input.Env
	lbA := byKey[env+"-lb.example.com|A|edge-3-eno1np0"]
	if lbA == nil || lbA.Weight != 100 || lbA.Ttl != 120 || !reflect.DeepEqual(lbA.Values, []string{"203.0.113.84"}) || lbA.HealthCheck == nil {
		t.Fatalf("lb member = %+v", lbA)
	}
	// HTTPS with SNI on 443, so a check crosses the lb's SNI split (§19 W7)
	if lbA.HealthCheck.Type != types.HealthCheckTypeHttps || !lbA.HealthCheck.EnableSni ||
		lbA.HealthCheck.Address != "203.0.113.84" || lbA.HealthCheck.Port != 443 || lbA.HealthCheck.Path != "/wrong-birdie-whicker-pompeii/status" || lbA.HealthCheck.Host != env+"-lb.example.com" || lbA.HealthCheck.Name != "A-edge-3-eno1np0" {
		t.Fatalf("health check = %+v", lbA.HealthCheck)
	}
	lbAAAA := byKey[env+"-lb.example.com|AAAA|edge-0-eno2"]
	if lbAAAA == nil || lbAAAA.Weight != 10 || lbAAAA.HealthCheck.Name != "AAAA-edge-0-eno2" {
		t.Fatalf("lb ipv6 member = %+v", lbAAAA)
	}
	if byKey["api.example.com|A|"] == nil || byKey["api.example.com|A|"].AliasTarget != env+"-lb.example.com" || byKey["api.example.com|AAAA|"] == nil {
		t.Fatal("api alias sets are missing")
	}
	if byKey["api-v4.example.com|AAAA|"] != nil || byKey["api-v4.example.com|A|"] == nil {
		t.Fatal("api-v4 must alias A only")
	}
	altA := byKey[env+"-alt.example.com|A|"]
	if altA == nil || altA.AliasTarget != "" || !reflect.DeepEqual(altA.Values, []string{"203.0.113.92"}) || altA.HealthCheck != nil {
		t.Fatalf("alt = %+v", altA)
	}
	if byKey["alt-v6.example.com|A|"] != nil || byKey["alt-v6.example.com|AAAA|"] == nil {
		t.Fatal("alt-v6 must carry AAAA only")
	}
	if byKey["fireside-eno1np0.example.com|A|"] == nil {
		t.Fatal("interface record missing")
	}
}

// fakeRoute53 holds one zone's record sets and the account's health checks.
type fakeRoute53 struct {
	zone         string
	rrsets       []types.ResourceRecordSet
	healthChecks []types.HealthCheck
	tags         map[string]map[string]string
	changes      []types.Change
	created      []types.HealthCheckConfig
	deleted      []string
	nextId       int
	// a health check another zone's set still references
	inUse string
	// the writes in order: create, change and delete
	writes []string
}

func (f *fakeRoute53) ListHostedZones(ctx context.Context, params *route53.ListHostedZonesInput, optFns ...func(*route53.Options)) (*route53.ListHostedZonesOutput, error) {
	return &route53.ListHostedZonesOutput{HostedZones: []types.HostedZone{
		{Id: aws.String("/hostedzone/ZPRIVATE"), Name: aws.String("example.com."), Config: &types.HostedZoneConfig{PrivateZone: true}},
		{Id: aws.String("/hostedzone/" + f.zone), Name: aws.String("example.com.")},
	}}, nil
}

func (f *fakeRoute53) ListResourceRecordSets(ctx context.Context, params *route53.ListResourceRecordSetsInput, optFns ...func(*route53.Options)) (*route53.ListResourceRecordSetsOutput, error) {
	if aws.ToString(params.HostedZoneId) != f.zone {
		return nil, fmt.Errorf("unknown zone %s", aws.ToString(params.HostedZoneId))
	}
	// two pages, to exercise the pagination
	if params.StartRecordName == nil && len(f.rrsets) > 1 {
		return &route53.ListResourceRecordSetsOutput{ResourceRecordSets: f.rrsets[:1], IsTruncated: true, NextRecordName: f.rrsets[1].Name, NextRecordType: f.rrsets[1].Type, NextRecordIdentifier: f.rrsets[1].SetIdentifier}, nil
	}
	if params.StartRecordName != nil {
		return &route53.ListResourceRecordSetsOutput{ResourceRecordSets: f.rrsets[1:]}, nil
	}
	return &route53.ListResourceRecordSetsOutput{ResourceRecordSets: f.rrsets}, nil
}

func (f *fakeRoute53) ChangeResourceRecordSets(ctx context.Context, params *route53.ChangeResourceRecordSetsInput, optFns ...func(*route53.Options)) (*route53.ChangeResourceRecordSetsOutput, error) {
	for _, change := range params.ChangeBatch.Changes {
		if change.ResourceRecordSet.HealthCheckId != nil && aws.ToString(change.ResourceRecordSet.HealthCheckId) == "" {
			return nil, fmt.Errorf("empty health check id on %s", aws.ToString(change.ResourceRecordSet.Name))
		}
	}
	f.changes = append(f.changes, params.ChangeBatch.Changes...)
	f.writes = append(f.writes, "change")
	// apply them, so a later sync reads what this one left
	same := func(a *types.ResourceRecordSet, b *types.ResourceRecordSet) bool {
		return aws.ToString(a.Name) == aws.ToString(b.Name) && a.Type == b.Type && aws.ToString(a.SetIdentifier) == aws.ToString(b.SetIdentifier)
	}
	for _, change := range params.ChangeBatch.Changes {
		set := change.ResourceRecordSet
		kept := []types.ResourceRecordSet{}
		for _, existing := range f.rrsets {
			if !same(&existing, set) {
				kept = append(kept, existing)
			}
		}
		if change.Action == types.ChangeActionUpsert || change.Action == types.ChangeActionCreate {
			kept = append(kept, *set)
		}
		f.rrsets = kept
	}
	return &route53.ChangeResourceRecordSetsOutput{}, nil
}

func (f *fakeRoute53) ListHealthChecks(ctx context.Context, params *route53.ListHealthChecksInput, optFns ...func(*route53.Options)) (*route53.ListHealthChecksOutput, error) {
	return &route53.ListHealthChecksOutput{HealthChecks: f.healthChecks}, nil
}

func (f *fakeRoute53) CreateHealthCheck(ctx context.Context, params *route53.CreateHealthCheckInput, optFns ...func(*route53.Options)) (*route53.CreateHealthCheckOutput, error) {
	f.nextId++
	id := fmt.Sprintf("hc-%d", f.nextId)
	f.writes = append(f.writes, "create")
	f.created = append(f.created, *params.HealthCheckConfig)
	f.healthChecks = append(f.healthChecks, types.HealthCheck{Id: aws.String(id), HealthCheckConfig: params.HealthCheckConfig})
	return &route53.CreateHealthCheckOutput{HealthCheck: &types.HealthCheck{Id: aws.String(id), HealthCheckConfig: params.HealthCheckConfig}}, nil
}

func (f *fakeRoute53) DeleteHealthCheck(ctx context.Context, params *route53.DeleteHealthCheckInput, optFns ...func(*route53.Options)) (*route53.DeleteHealthCheckOutput, error) {
	if aws.ToString(params.HealthCheckId) == f.inUse {
		return nil, &types.HealthCheckInUse{Message: aws.String("in use")}
	}
	f.deleted = append(f.deleted, aws.ToString(params.HealthCheckId))
	f.writes = append(f.writes, "delete")
	kept := []types.HealthCheck{}
	for _, check := range f.healthChecks {
		if aws.ToString(check.Id) != aws.ToString(params.HealthCheckId) {
			kept = append(kept, check)
		}
	}
	f.healthChecks = kept
	return &route53.DeleteHealthCheckOutput{}, nil
}

func (f *fakeRoute53) ChangeTagsForResource(ctx context.Context, params *route53.ChangeTagsForResourceInput, optFns ...func(*route53.Options)) (*route53.ChangeTagsForResourceOutput, error) {
	if f.tags == nil {
		f.tags = map[string]map[string]string{}
	}
	tags := map[string]string{}
	for _, tag := range params.AddTags {
		tags[aws.ToString(tag.Key)] = aws.ToString(tag.Value)
	}
	f.tags[aws.ToString(params.ResourceId)] = tags
	return &route53.ChangeTagsForResourceOutput{}, nil
}

// A check as earlier syncs and the manual setup made them: on port 80, with no SNI.
func route53HealthCheckFixture(id string, checkType types.HealthCheckType, address string, path string, host string) types.HealthCheck {
	return types.HealthCheck{Id: aws.String(id), HealthCheckConfig: &types.HealthCheckConfig{
		Type: checkType, IPAddress: aws.String(address), Port: aws.Int32(80), ResourcePath: aws.String(path), FullyQualifiedDomainName: aws.String(host),
	}}
}

// A check as this sync makes them: HTTPS with SNI on 443.
func route53HttpsHealthCheckFixture(id string, address string, path string, host string) types.HealthCheck {
	return types.HealthCheck{Id: aws.String(id), HealthCheckConfig: &types.HealthCheckConfig{
		Type: types.HealthCheckTypeHttps, IPAddress: aws.String(address), Port: aws.Int32(443), ResourcePath: aws.String(path),
		FullyQualifiedDomainName: aws.String(host), EnableSNI: aws.Bool(true),
	}}
}

// The reconciliation against an account in the state the manual setup left:
// a weighted alias set with a legacy member name and a string-match health
// check, a service alias as a weighted set, a stale health check, and a
// record at an unrelated name that must survive.
func TestDnsRoute53Reconciles(t *testing.T) {
	input := newDnsTestInput(t, dnsFixtureWithDns)
	domains, err := dnsDerive(input)
	if err != nil {
		t.Fatal(err)
	}
	env := input.Env
	statusPath := "/wrong-birdie-whicker-pompeii/status"
	lbHost := env + "-lb.example.com"
	fake := &fakeRoute53{
		zone:  "Z1",
		inUse: "hc-legacy",
		rrsets: []types.ResourceRecordSet{
			// a legacy weighted alias member with a string match check
			{Name: aws.String(lbHost + "."), Type: types.RRTypeA, SetIdentifier: aws.String("r-us-tst-5-8-edge-3"), Weight: aws.Int64(100), HealthCheckId: aws.String("hc-legacy"),
				AliasTarget: &types.AliasTarget{DNSName: aws.String("r-us-tst-5-8-edge-3.example.com."), HostedZoneId: aws.String("Z1")}},
			// a member that already matches, once its health check is reused
			{Name: aws.String(lbHost + "."), Type: types.RRTypeA, SetIdentifier: aws.String("edge-3-eno2np1"), Weight: aws.Int64(100), TTL: aws.Int64(120), HealthCheckId: aws.String("hc-keep"),
				ResourceRecords: []types.ResourceRecord{{Value: aws.String("203.0.113.85")}}},
			// the service alias as a single member weighted set
			{Name: aws.String("api.example.com."), Type: types.RRTypeA, SetIdentifier: aws.String("main-lb"), Weight: aws.Int64(100),
				AliasTarget: &types.AliasTarget{DNSName: aws.String(lbHost + "."), HostedZoneId: aws.String("Z1")}},
			// an interface record with the wrong ttl
			{Name: aws.String("edge-3-eno1np0.example.com."), Type: types.RRTypeA, TTL: aws.Int64(300), ResourceRecords: []types.ResourceRecord{{Value: aws.String("203.0.113.84")}}},
			// the wildcard, escaped as route53 returns it, already right
			{Name: aws.String(`\052.connect.example.com.`), Type: types.RRTypeA, AliasTarget: &types.AliasTarget{DNSName: aws.String(lbHost + "."), HostedZoneId: aws.String("Z1")}},
			// an unmanaged apex and an unrelated name must survive
			{Name: aws.String("example.com."), Type: types.RRTypeA, AliasTarget: &types.AliasTarget{DNSName: aws.String("d1.cloudfront.net."), HostedZoneId: aws.String("Z2FDTNDATAQYW2")}},
			{Name: aws.String("vpn-0.example.com."), Type: types.RRTypeA, TTL: aws.Int64(300), ResourceRecords: []types.ResourceRecord{{Value: aws.String("192.0.2.1")}}},
		},
		healthChecks: []types.HealthCheck{
			route53HealthCheckFixture("hc-legacy", types.HealthCheckTypeHttpStrMatch, "203.0.113.84", statusPath, lbHost),
			route53HttpsHealthCheckFixture("hc-keep", "203.0.113.85", statusPath, lbHost),
			route53HealthCheckFixture("hc-stale", types.HealthCheckTypeHttp, "203.0.113.99", statusPath, lbHost),
			route53HealthCheckFixture("hc-other", types.HealthCheckTypeHttp, "203.0.113.99", "/status", "other.example.net"),
		},
	}
	provider := &route53Provider{api: fake, ctx: context.Background()}

	planned, err := provider.Plan(domains[0], input)
	if err != nil {
		t.Fatal(err)
	}
	if len(fake.changes) != 0 || len(fake.created) != 0 || len(fake.deleted) != 0 {
		t.Fatal("plan must not change anything")
	}
	plan := []string{}
	for _, change := range planned {
		plan = append(plan, change.String())
	}
	planText := strings.Join(plan, "\n")
	for _, want := range []string{
		"+ health check A-edge-3-eno1np0 https://[203.0.113.84]:443" + statusPath,
		"- A " + lbHost + " -> r-us-tst-5-8-edge-3.example.com set=r-us-tst-5-8-edge-3 weight=100",
		"~ A edge-3-eno1np0.example.com 203.0.113.84 ttl=120 (was A edge-3-eno1np0.example.com 203.0.113.84 ttl=300)",
		"- A api.example.com -> " + lbHost + " set=main-lb weight=100",
		"+ A api.example.com -> " + lbHost,
		"- health check hc-stale http://[203.0.113.99]:80" + statusPath,
		"- health check hc-legacy",
	} {
		if !strings.Contains(planText, want) {
			t.Errorf("plan lacks %q:\n%s", want, planText)
		}
	}
	for _, absent := range []string{"vpn-0.example.com", "d1.cloudfront.net", "hc-other", "+ A *.connect.example.com", "~ A *.connect.example.com", "- A *.connect.example.com", "edge-3-eno2np1 weight=100 (was"} {
		if strings.Contains(planText, absent) {
			t.Errorf("plan must not touch %q:\n%s", absent, planText)
		}
	}
	// the wildcard's A alias already matches; only its AAAA alias is new
	if !strings.Contains(planText, "+ AAAA *.connect.example.com -> "+lbHost) {
		t.Errorf("plan lacks the wildcard AAAA alias:\n%s", planText)
	}

	applied, err := provider.Apply(domains[0], input)
	if err != nil {
		t.Fatal(err)
	}
	if len(applied) != len(planned) {
		t.Fatalf("applied %d changes, planned %d", len(applied), len(planned))
	}
	// the health checks come first and get tagged, then the sets reference them
	created := map[string]bool{}
	for _, config := range fake.created {
		created[aws.ToString(config.IPAddress)] = true
		if config.Type != types.HealthCheckTypeHttps || !aws.ToBool(config.EnableSNI) || aws.ToInt32(config.Port) != 443 ||
			aws.ToInt32(config.RequestInterval) != 10 || aws.ToInt32(config.FailureThreshold) != 3 {
			t.Errorf("health check config = %+v", config)
		}
	}
	if !created["203.0.113.84"] || created["203.0.113.85"] {
		t.Fatalf("created health checks for %v", created)
	}
	for id, tags := range fake.tags {
		if tags["warp"] != env || !strings.HasPrefix(tags["Name"], "A-") && !strings.HasPrefix(tags["Name"], "AAAA-") {
			t.Errorf("health check %s tags = %v", id, tags)
		}
	}
	deletes, upserts := 0, 0
	for _, change := range fake.changes {
		set := change.ResourceRecordSet
		switch change.Action {
		case types.ChangeActionDelete:
			deletes++
			if strings.HasPrefix(aws.ToString(set.Name), "vpn-0") || aws.ToString(set.Name) == "example.com." {
				t.Errorf("deleted an unmanaged set %s", aws.ToString(set.Name))
			}
		case types.ChangeActionUpsert:
			upserts++
			if set.SetIdentifier != nil && set.HealthCheckId == nil && aws.ToString(set.Name) == lbHost+"." {
				t.Errorf("lb member %s has no health check", aws.ToString(set.SetIdentifier))
			}
			if aws.ToString(set.SetIdentifier) == "edge-3-eno2np1" && set.Type == types.RRTypeA {
				t.Error("the matching member must not be rewritten")
			}
			if set.AliasTarget != nil && set.AliasTarget.HostedZoneId == nil {
				t.Errorf("alias %s lacks the zone", aws.ToString(set.Name))
			}
		}
	}
	if deletes < 2 || upserts < 10 {
		t.Fatalf("deletes=%d upserts=%d", deletes, upserts)
	}
	// the legacy check is still referenced elsewhere: noted, not an error
	if !reflect.DeepEqual(fake.deleted, []string{"hc-stale"}) {
		t.Fatalf("deleted health checks = %v", fake.deleted)
	}
	if notes := strings.Join(domains[0].Notes, "\n"); !strings.Contains(notes, "hc-legacy is still referenced") {
		t.Fatalf("notes = %s", notes)
	}
}

// The cloudflare rendering and reconciliation through the v4 api: one record
// per address, cnames for aliases, addresses for single family aliases, and
// only the managed names touched.
func TestDnsCloudflareReconciles(t *testing.T) {
	input := newDnsTestInput(t, dnsFixtureWithDns)
	domains, err := dnsDerive(input)
	if err != nil {
		t.Fatal(err)
	}
	net := domains[1]
	env := input.Env
	records := cloudflareDesired(net, input)
	byKey := map[string]*cloudflareRecord{}
	for _, record := range records {
		byKey[record.key()] = record
	}
	if byKey["A|"+env+"-lb.example.net|203.0.113.84"] == nil || byKey["A|"+env+"-lb.example.net|203.0.113.92"] != nil {
		t.Fatal("the lb set must list the front interfaces only")
	}
	if byKey["CNAME|www.example.net|"+env+"-lb.example.net"] == nil || byKey["CNAME|example.net|"+env+"-lb.example.net"] == nil {
		t.Fatal("the web alias cnames are missing")
	}
	if byKey["AAAA|www-v6.example.net|2001:db8:99:5880:e643:4bff:fe94:e380"] == nil || byKey["CNAME|www-v6.example.net|"+env+"-lb.example.net"] != nil {
		t.Fatal("a single family alias must carry addresses, not a cname")
	}
	for _, record := range records {
		if strings.HasPrefix(record.Name, env+"-web") || strings.Contains(record.Name, "fireside") {
			t.Fatalf("the other domain must carry only the lb set and the web aliases: %+v", record)
		}
		if record.Proxied || record.Ttl != 120 || record.Comment != "warpctl dns "+env {
			t.Fatalf("record = %+v", record)
		}
	}

	type request struct {
		method string
		path   string
		body   map[string]any
	}
	requests := []request{}
	existing := []map[string]any{
		{"id": "r1", "type": "A", "name": env + "-lb.example.net", "content": "203.0.113.84", "ttl": 120, "proxied": false, "comment": "warpctl dns " + env},
		{"id": "r2", "type": "A", "name": env + "-lb.example.net", "content": "198.51.100.1", "ttl": 120, "proxied": false},
		// the web apex points at the primary domain's lb today, proxied: it
		// moves to this domain's lb set and stays proxied
		{"id": "r3", "type": "CNAME", "name": "example.net", "content": env + "-lb.example.com", "ttl": 1, "proxied": true},
		{"id": "r4", "type": "A", "name": "other.example.net", "content": "192.0.2.5", "ttl": 300, "proxied": false},
		{"id": "r5", "type": "CNAME", "name": env + "-web.example.net", "content": env + "-lb.example.net", "ttl": 300, "proxied": true},
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer token-1" {
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprint(w, `{"success":false,"errors":[{"code":10000,"message":"Authentication error"}]}`)
			return
		}
		var body map[string]any
		if r.Body != nil {
			json.NewDecoder(r.Body).Decode(&body)
		}
		requests = append(requests, request{method: r.Method, path: r.URL.Path, body: body})
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/zones":
			fmt.Fprint(w, `{"success":true,"errors":[],"result":[{"id":"zone-net","name":"example.net"}]}`)
		case r.Method == http.MethodGet && r.URL.Path == "/zones/zone-net/dns_records":
			page := r.URL.Query().Get("page")
			var result []map[string]any
			if page == "1" {
				result = existing[:2]
			} else {
				result = existing[2:]
			}
			data, _ := json.Marshal(map[string]any{"success": true, "errors": []any{}, "result": result, "result_info": map[string]any{"page": map[string]int{"1": 1, "2": 2}[page], "total_pages": 2}})
			w.Write(data)
		default:
			fmt.Fprint(w, `{"success":true,"errors":[],"result":{"id":"new"}}`)
		}
	}))
	defer server.Close()

	provider := &cloudflareProvider{ctx: context.Background(), client: server.Client(), baseUrl: server.URL, token: "token-1"}
	planned, err := provider.Plan(net, input)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range requests {
		if r.method != http.MethodGet {
			t.Fatalf("plan issued %s %s", r.method, r.path)
		}
	}
	plan := []string{}
	for _, change := range planned {
		plan = append(plan, change.String())
	}
	planText := strings.Join(plan, "\n")
	for _, want := range []string{
		"- A " + env + "-lb.example.net 198.51.100.1 ttl=120",
		"- CNAME example.net " + env + "-lb.example.com ttl=1 proxied",
		"+ CNAME example.net " + env + "-lb.example.net ttl=1 proxied",
		"+ CNAME www.example.net " + env + "-lb.example.net ttl=120",
		"+ A " + env + "-lb.example.net 203.0.113.85 ttl=120",
	} {
		if !strings.Contains(planText, want) {
			t.Errorf("plan lacks %q:\n%s", want, planText)
		}
	}
	// names outside the pattern stay, however they look
	for _, absent := range []string{"other.example.net", env + "-web.example.net", "203.0.113.84 ttl=120 (was"} {
		if strings.Contains(planText, absent) {
			t.Errorf("plan touches %q:\n%s", absent, planText)
		}
	}

	requests = nil
	if _, err := provider.Apply(net, input); err != nil {
		t.Fatal(err)
	}
	var deletes, puts, posts []request
	for _, r := range requests {
		switch r.method {
		case http.MethodDelete:
			deletes = append(deletes, r)
		case http.MethodPut:
			puts = append(puts, r)
		case http.MethodPost:
			posts = append(posts, r)
		}
	}
	deletePaths := []string{}
	for _, r := range deletes {
		deletePaths = append(deletePaths, r.path)
	}
	sort.Strings(deletePaths)
	if !reflect.DeepEqual(deletePaths, []string{"/zones/zone-net/dns_records/r2", "/zones/zone-net/dns_records/r3"}) {
		t.Fatalf("deletes = %+v", deletes)
	}
	if len(puts) != 0 {
		t.Fatalf("puts = %+v", puts)
	}
	if len(posts) < 5 {
		t.Fatalf("posts = %d", len(posts))
	}
	for _, r := range posts {
		if r.body["comment"] != "warpctl dns "+env {
			t.Fatalf("post body = %v", r.body)
		}
		proxied := r.body["name"] == "example.net"
		if r.body["proxied"] != proxied {
			t.Fatalf("post body = %v, want proxied=%v", r.body, proxied)
		}
		if proxied && r.body["ttl"] != float64(1) {
			t.Fatalf("a proxied record must carry the automatic ttl: %v", r.body)
		}
	}

	// a bad token is reported, nothing else
	provider.token = "wrong"
	if _, err := provider.Plan(net, input); err == nil || !strings.Contains(err.Error(), "Authentication error") {
		t.Fatalf("err = %v", err)
	}
}

func TestDnsCloudflareTokenSources(t *testing.T) {
	t.Setenv("CLOUDFLARE_API_TOKEN", "")
	dir := t.TempDir()
	file := filepath.Join(dir, "cloudflare")
	if err := os.WriteFile(file, []byte("file-token\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if token, err := cloudflareToken(file); err != nil || token != "file-token" {
		t.Fatalf("token = %q, %v", token, err)
	}
	t.Setenv("CLOUDFLARE_API_TOKEN", "env-token")
	if token, err := cloudflareToken(file); err != nil || token != "env-token" {
		t.Fatalf("token = %q, %v", token, err)
	}
	t.Setenv("CLOUDFLARE_API_TOKEN", "")
	if _, err := cloudflareToken(""); err == nil {
		t.Fatal("no token source must be an error")
	}
	setTestWarpHome(t, dir)
	if got := defaultCloudflareTokenFile(); got != "" {
		t.Fatalf("default token file = %q without root/servers/cloudflare", got)
	}
	if err := os.MkdirAll(filepath.Join(dir, "root", "servers"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "root", "servers", "cloudflare"), []byte("t"), 0600); err != nil {
		t.Fatal(err)
	}
	if got := defaultCloudflareTokenFile(); got != filepath.Join(dir, "root", "servers", "cloudflare") {
		t.Fatalf("default token file = %q", got)
	}
}

// The move from the HTTP checks on port 80 that earlier syncs made to HTTPS
// with SNI on 443 (§19 W7): every member gets its new check first, its set
// moves to it, and only then does the old one go, so no set ever references a
// deleted check and no check of ours is left behind; a second sync changes
// nothing.
func TestDnsRoute53MovesHttpChecksToHttps(t *testing.T) {
	input := newDnsTestInput(t, dnsFixtureWithDns)
	domains, err := dnsDerive(input)
	if err != nil {
		t.Fatal(err)
	}
	statusPath := "/wrong-birdie-whicker-pompeii/status"
	lbHost := input.Env + "-lb.example.com"
	desired, err := route53Desired(domains[0], input)
	if err != nil {
		t.Fatal(err)
	}
	// the zone as the last HTTP sync left it: every desired set in place, each
	// member on a plain HTTP check of port 80
	fake := &fakeRoute53{zone: "Z1"}
	oldCheckIds := []string{}
	for _, rrset := range desired {
		set := route53RecordSet(rrset, "Z1", nil)
		if rrset.HealthCheck != nil {
			oldId := fmt.Sprintf("hc-http-%d", len(oldCheckIds))
			oldCheckIds = append(oldCheckIds, oldId)
			fake.healthChecks = append(fake.healthChecks, route53HealthCheckFixture(oldId, types.HealthCheckTypeHttp, rrset.HealthCheck.Address, statusPath, lbHost))
			set.HealthCheckId = aws.String(oldId)
		}
		fake.rrsets = append(fake.rrsets, *set)
	}
	if len(oldCheckIds) < 4 {
		t.Fatalf("%d members in the fixture", len(oldCheckIds))
	}
	provider := &route53Provider{api: fake, ctx: context.Background()}

	planned, err := provider.Plan(domains[0], input)
	if err != nil {
		t.Fatal(err)
	}
	creates, moves, deletes := 0, 0, 0
	for _, change := range planned {
		text := change.String()
		switch {
		case strings.HasPrefix(text, "+ health check ") && strings.Contains(text, "https://") && strings.Contains(text, ":443"+statusPath):
			creates++
		case strings.HasPrefix(text, "~ ") && strings.Contains(text, " set=") && strings.Contains(text, "health-check"):
			moves++
		case strings.HasPrefix(text, "- health check hc-http-") && strings.Contains(text, "http://") && strings.Contains(text, ":80"+statusPath):
			deletes++
		default:
			t.Errorf("unexpected change %s", text)
		}
	}
	if creates != len(oldCheckIds) || moves != len(oldCheckIds) || deletes != len(oldCheckIds) {
		t.Fatalf("%d creates, %d moves, %d deletes for %d members", creates, moves, deletes, len(oldCheckIds))
	}

	if _, err := provider.Apply(domains[0], input); err != nil {
		t.Fatal(err)
	}
	// every create before the first change, every delete after the last
	lastCreate, firstChange, lastChange, firstDelete := -1, len(fake.writes), -1, len(fake.writes)
	for i, write := range fake.writes {
		switch write {
		case "create":
			lastCreate = i
		case "change":
			firstChange = min(firstChange, i)
			lastChange = i
		case "delete":
			firstDelete = min(firstDelete, i)
		}
	}
	if !(lastCreate < firstChange && lastChange < firstDelete) {
		t.Errorf("writes out of order: %v", fake.writes)
	}
	if !slices.Equal(fake.deleted, oldCheckIds) {
		t.Errorf("deleted %v, want %v", fake.deleted, oldCheckIds)
	}
	// no set references a check that is gone, and no check of ours is unreferenced
	checkIds := map[string]bool{}
	for _, check := range fake.healthChecks {
		checkIds[aws.ToString(check.Id)] = true
		if check.HealthCheckConfig.Type != types.HealthCheckTypeHttps || !aws.ToBool(check.HealthCheckConfig.EnableSNI) || aws.ToInt32(check.HealthCheckConfig.Port) != 443 {
			t.Errorf("check %s is %s on %d", aws.ToString(check.Id), check.HealthCheckConfig.Type, aws.ToInt32(check.HealthCheckConfig.Port))
		}
	}
	referenced := map[string]bool{}
	for _, set := range fake.rrsets {
		if set.HealthCheckId == nil {
			continue
		}
		if !checkIds[aws.ToString(set.HealthCheckId)] {
			t.Errorf("%s references a deleted check", aws.ToString(set.Name))
		}
		referenced[aws.ToString(set.HealthCheckId)] = true
	}
	if len(referenced) != len(fake.healthChecks) {
		t.Errorf("%d checks, %d referenced", len(fake.healthChecks), len(referenced))
	}

	// a rerun is a no-op
	replanned, err := provider.Plan(domains[0], input)
	if err != nil {
		t.Fatal(err)
	}
	if len(replanned) != 0 {
		t.Fatalf("a rerun plans %v", replanned)
	}
	writes := len(fake.writes)
	if changes, err := provider.Apply(domains[0], input); err != nil || len(changes) != 0 || len(fake.writes) != writes {
		t.Fatalf("a rerun applied %v, %v, %d writes", changes, err, len(fake.writes)-writes)
	}
}

// A drained interface leaves the <env>-lb sets, both families, on every
// domain and in each alias of them, and keeps its interface record, which the
// split's gate and probes reach it by (W1).
func TestDnsDrainedInterfaceLeavesTheLbSets(t *testing.T) {
	input := newDnsTestInput(t, dnsFixtureWithDns)
	input.Drained = []string{"edge-3-eno1np0"}
	domains, err := dnsDerive(input)
	if err != nil {
		t.Fatal(err)
	}
	for _, domain := range domains {
		lbSet := findDnsName(t, domain, input.Env+"-lb."+domain.Domain)
		for _, member := range lbSet.Members {
			if member.Id == "edge-3-eno1np0" {
				t.Errorf("%s: the drained interface is still a member", domain.Domain)
			}
		}
		if len(lbSet.DrainedMembers) != 1 || lbSet.DrainedMembers[0].Id != "edge-3-eno1np0" {
			t.Errorf("%s: drained members %+v", domain.Domain, lbSet.DrainedMembers)
		}
		for _, address := range append(append([]string{}, lbSet.Ipv4...), lbSet.Ipv6...) {
			if address == "203.0.113.84" || address == "2001:db8:99:5880:e643:4bff:fe94:e380" {
				t.Errorf("%s: the set resolves to the drained address %s", domain.Domain, address)
			}
		}
	}
	primary := domains[0]
	for _, alias := range []string{input.Env + "-lb-v4.example.com", input.Env + "-lb-v6.example.com", "api.example.com"} {
		name := findDnsName(t, primary, alias)
		for _, address := range append(append([]string{}, name.Ipv4...), name.Ipv6...) {
			if address == "203.0.113.84" || address == "2001:db8:99:5880:e643:4bff:fe94:e380" {
				t.Errorf("%s resolves to the drained interface", alias)
			}
		}
	}
	interfaceRecord := findDnsName(t, primary, "edge-3-eno1np0.example.com")
	if !reflect.DeepEqual(interfaceRecord.Ipv4, []string{"203.0.113.84"}) {
		t.Errorf("the drained interface's own record is %v", interfaceRecord.Ipv4)
	}

	// cloudflare carries the set as plain records, the drained address absent
	for _, record := range cloudflareDesired(domains[1], input) {
		if record.Content == "203.0.113.84" || record.Content == "2001:db8:99:5880:e643:4bff:fe94:e380" {
			t.Errorf("cloudflare record %s %s holds the drained address", record.Type, record.Name)
		}
	}
}

// A drain names a member, and never all of them: an unknown name and a drain
// of every interface both refuse, so a typo cannot silently leave an interface
// under test in the answers, and the set is never empty.
func TestDnsDrainRefusesAnUnknownNameOrEveryInterface(t *testing.T) {
	input := newDnsTestInput(t, dnsFixtureWithDns)
	input.Drained = []string{"edge-3-eno9"}
	if _, err := dnsDerive(input); err == nil || !strings.Contains(err.Error(), `"edge-3-eno9"`) {
		t.Errorf("an unknown drain: %v", err)
	}
	// the transparent interface is no member, so it cannot be drained either
	input.Drained = []string{"fireside-eno1np0"}
	if _, err := dnsDerive(input); err == nil {
		t.Error("a transparent interface drained")
	}
	input.Drained = nil
	domains, err := dnsDerive(input)
	if err != nil {
		t.Fatal(err)
	}
	for _, member := range findDnsName(t, domains[0], input.Env+"-lb.example.com").Members {
		input.Drained = append(input.Drained, member.Id)
	}
	if _, err := dnsDerive(input); err == nil || !strings.Contains(err.Error(), "drains every lb interface") {
		t.Errorf("every interface drained: %v", err)
	}
}

// On route53 a drain deletes the interface's member sets, both families, and
// keeps its health checks probing; a rerun changes nothing; the rejoin points
// new sets at the same checks, creating none.
func TestDnsRoute53DrainKeepsTheHealthCheck(t *testing.T) {
	input := newDnsTestInput(t, dnsFixtureWithDns)
	domains, err := dnsDerive(input)
	if err != nil {
		t.Fatal(err)
	}
	fake := &fakeRoute53{zone: "Z1"}
	provider := &route53Provider{api: fake, ctx: context.Background()}
	// an account as a full sync leaves it
	if _, err := provider.Apply(domains[0], input); err != nil {
		t.Fatal(err)
	}
	checkIdOf := map[string]string{}
	for _, set := range fake.rrsets {
		if aws.ToString(set.SetIdentifier) == "edge-3-eno1np0" {
			checkIdOf[string(set.Type)] = aws.ToString(set.HealthCheckId)
		}
	}
	if checkIdOf["A"] == "" || checkIdOf["AAAA"] == "" {
		t.Fatalf("the synced member sets %v", checkIdOf)
	}
	createdBefore := len(fake.created)

	input.Drained = []string{"edge-3-eno1np0"}
	drainedDomains, err := dnsDerive(input)
	if err != nil {
		t.Fatal(err)
	}
	planned, err := provider.Plan(drainedDomains[0], input)
	if err != nil {
		t.Fatal(err)
	}
	plan := []string{}
	for _, change := range planned {
		plan = append(plan, change.String())
	}
	planText := strings.Join(plan, "\n")
	for _, want := range []string{"- A " + input.Env + "-lb.example.com", "- AAAA " + input.Env + "-lb.example.com"} {
		if !strings.Contains(planText, want) || !strings.Contains(planText, "set=edge-3-eno1np0") {
			t.Errorf("the drain plans no %q:\n%s", want, planText)
		}
	}
	if len(planned) != 2 || strings.Contains(planText, "health check") {
		t.Fatalf("the drain plans more than the two sets:\n%s", planText)
	}
	if _, err := provider.Apply(drainedDomains[0], input); err != nil {
		t.Fatal(err)
	}
	checkIds := map[string]bool{}
	for _, check := range fake.healthChecks {
		checkIds[aws.ToString(check.Id)] = true
	}
	if !checkIds[checkIdOf["A"]] || !checkIds[checkIdOf["AAAA"]] || 0 < len(fake.deleted) {
		t.Errorf("the drain deleted a health check: %v", fake.deleted)
	}
	for _, set := range fake.rrsets {
		if aws.ToString(set.SetIdentifier) == "edge-3-eno1np0" {
			t.Errorf("a drained member set is left: %s %s", set.Type, aws.ToString(set.Name))
		}
	}
	if replanned, err := provider.Plan(drainedDomains[0], input); err != nil || len(replanned) != 0 {
		t.Fatalf("a rerun of the drain plans %v, %v", replanned, err)
	}

	// the rejoin
	input.Drained = nil
	if _, err := provider.Apply(domains[0], input); err != nil {
		t.Fatal(err)
	}
	if len(fake.created) != createdBefore {
		t.Errorf("the rejoin created %d checks", len(fake.created)-createdBefore)
	}
	for _, set := range fake.rrsets {
		if aws.ToString(set.SetIdentifier) == "edge-3-eno1np0" && aws.ToString(set.HealthCheckId) != checkIdOf[string(set.Type)] {
			t.Errorf("the rejoined %s set references %s, not its kept check", set.Type, aws.ToString(set.HealthCheckId))
		}
	}
	if replanned, err := provider.Plan(domains[0], input); err != nil || len(replanned) != 0 {
		t.Fatalf("a rerun of the rejoin plans %v, %v", replanned, err)
	}
}

// W11's records on the dns fixture: the report host's addresses from two of
// edge-3's lb interfaces and its MX, its DMARC authorization's TXT under a
// wildcard, and a HELO-style name holding one interface's addresses alone.
func dnsFixtureWithRecords(servicesYaml string) string {
	return strings.Replace(dnsFixtureWithDns(servicesYaml), "    other_domain_services:\n        - web\n",
		"    other_domain_services:\n        - web\n"+
			"    records:\n"+
			"        -   name: rpt.example.com\n"+
			"            interfaces:\n"+
			"                -   host: edge-3.example.com\n"+
			"                    interface: eno1np0\n"+
			"                -   host: edge-3.example.com\n"+
			"                    interface: eno2np1\n"+
			"            mx:\n"+
			"                - 10 rpt.example.com\n"+
			"        -   name: \"*._report._dmarc.rpt.example.com\"\n"+
			"            txt:\n"+
			"                - v=DMARC1\n"+
			"        -   name: send-1.example.com\n"+
			"            interfaces:\n"+
			"                -   host: edge-0.example.com\n"+
			"                    interface: eno2\n", 1)
}

func TestDnsDerivesDeclaredRecords(t *testing.T) {
	input := newDnsTestInput(t, dnsFixtureWithRecords)
	domains, err := dnsDerive(input)
	if err != nil {
		t.Fatal(err)
	}
	com := domains[0]
	rpt := findDnsName(t, com, "rpt.example.com")
	if rpt.Kind != dnsRecordSet || !reflect.DeepEqual(rpt.Ipv4, []string{"203.0.113.84", "203.0.113.85"}) ||
		!reflect.DeepEqual(rpt.Ipv6, []string{"2001:db8:99:5880:e643:4bff:fe94:e380", "2001:db8:99:5860:e643:4bff:fe94:e381"}) ||
		!reflect.DeepEqual(rpt.Mx, []string{"10 rpt.example.com"}) || len(rpt.Txt) != 0 {
		t.Fatalf("rpt = %+v", rpt)
	}
	dmarc := findDnsName(t, com, "*._report._dmarc.rpt.example.com")
	if dmarc.Kind != dnsRecordSet || dmarc.HasIpv4 || dmarc.HasIpv6 || !reflect.DeepEqual(dmarc.Txt, []string{"v=DMARC1"}) {
		t.Fatalf("dmarc = %+v", dmarc)
	}
	send := findDnsName(t, com, "send-1.example.com")
	if !reflect.DeepEqual(send.Ipv4, []string{"198.51.100.42"}) || len(send.Mx) != 0 {
		t.Fatalf("send-1 = %+v", send)
	}
	for _, name := range dnsNameList(domains[1]) {
		if strings.Contains(name, "rpt") || strings.Contains(name, "send-1") {
			t.Errorf("example.net carries %s", name)
		}
	}
	if summary := dnsNameSummary(rpt); !strings.Contains(summary, "MX 10 rpt.example.com") {
		t.Errorf("summary = %s", summary)
	}
}

// route53 renders a declared record's addresses, MX and TXT, the TXT value
// quoted as route53 holds it.
func TestDnsRoute53RendersDeclaredRecords(t *testing.T) {
	input := newDnsTestInput(t, dnsFixtureWithRecords)
	domains, err := dnsDerive(input)
	if err != nil {
		t.Fatal(err)
	}
	rrsets, err := route53Desired(domains[0], input)
	if err != nil {
		t.Fatal(err)
	}
	byKey := map[string]*route53Rrset{}
	for _, rrset := range rrsets {
		byKey[rrset.Name+" "+rrset.Type] = rrset
	}
	for key, want := range map[string][]string{
		"rpt.example.com A":                    {"203.0.113.84", "203.0.113.85"},
		"rpt.example.com MX":                   {"10 rpt.example.com"},
		"*._report._dmarc.rpt.example.com TXT": {`"v=DMARC1"`},
		"send-1.example.com A":                 {"198.51.100.42"},
		"send-1.example.com AAAA":              {"2001:db8:173:5200:e643:4bff:fe23:a341"},
		"rpt.example.com AAAA":                 {"2001:db8:99:5860:e643:4bff:fe94:e381", "2001:db8:99:5880:e643:4bff:fe94:e380"},
	} {
		rrset := byKey[key]
		if rrset == nil || !reflect.DeepEqual(rrset.Values, want) || rrset.Ttl != 120 || rrset.AliasTarget != "" || rrset.SetId != "" {
			t.Errorf("%s = %+v, want %q at ttl 120", key, rrset, want)
		}
	}
	for _, absent := range []string{"*._report._dmarc.rpt.example.com A", "send-1.example.com MX", "rpt.example.com TXT"} {
		if byKey[absent] != nil {
			t.Errorf("%s is rendered", absent)
		}
	}
}

// The sync publishes the records, matches what route53 returns for them
// (the wildcard as \052, TXT quoted, an MX exchange with its dot), so a
// rerun plans nothing, and leaves the MX and TXT of every other name alone.
func TestDnsRoute53SyncsDeclaredRecordsAndRerunsToNothing(t *testing.T) {
	input := newDnsTestInput(t, dnsFixtureWithRecords)
	domains, err := dnsDerive(input)
	if err != nil {
		t.Fatal(err)
	}
	fake := &fakeRoute53{
		zone: "Z1",
		rrsets: []types.ResourceRecordSet{
			// already right, as route53 returns them
			{Name: aws.String(`\052._report._dmarc.rpt.example.com.`), Type: types.RRTypeTxt, TTL: aws.Int64(120), ResourceRecords: []types.ResourceRecord{{Value: aws.String(`"v=DMARC1"`)}}},
			{Name: aws.String("rpt.example.com."), Type: types.RRTypeMx, TTL: aws.Int64(120), ResourceRecords: []types.ResourceRecord{{Value: aws.String("10 RPT.example.com.")}}},
			// a derived name's own TXT and MX, which no record declares
			{Name: aws.String("edge-3-eno1np0.example.com."), Type: types.RRTypeTxt, TTL: aws.Int64(300), ResourceRecords: []types.ResourceRecord{{Value: aws.String(`"site-verification=synthetic"`)}}},
			{Name: aws.String("send-1.example.com."), Type: types.RRTypeMx, TTL: aws.Int64(300), ResourceRecords: []types.ResourceRecord{{Value: aws.String("20 mx.example.org.")}}},
			// a TXT that differs, at a name whose record declares TXT
			{Name: aws.String("rpt.example.com."), Type: types.RRTypeTxt, TTL: aws.Int64(300), ResourceRecords: []types.ResourceRecord{{Value: aws.String(`"stale"`)}}},
		},
	}
	provider := &route53Provider{api: fake, ctx: context.Background()}
	planned, err := provider.Plan(domains[0], input)
	if err != nil {
		t.Fatal(err)
	}
	planText := ""
	for _, change := range planned {
		planText += change.String() + "\n"
	}
	for _, want := range []string{
		"+ A rpt.example.com 203.0.113.84,203.0.113.85 ttl=120",
		"+ AAAA rpt.example.com 2001:db8:99:5860:e643:4bff:fe94:e381,2001:db8:99:5880:e643:4bff:fe94:e380 ttl=120",
		"+ A send-1.example.com 198.51.100.42 ttl=120",
	} {
		if !strings.Contains(planText, want) {
			t.Errorf("plan lacks %q:\n%s", want, planText)
		}
	}
	for _, absent := range []string{"_dmarc", "MX rpt.example.com", "site-verification", "mx.example.org"} {
		if strings.Contains(planText, absent) {
			t.Errorf("plan touches %q:\n%s", absent, planText)
		}
	}
	// rpt's records declare no TXT, so a TXT there is not the sync's either
	if strings.Contains(planText, "stale") {
		t.Errorf("plan touches a TXT no record declares:\n%s", planText)
	}

	if _, err := provider.Apply(domains[0], input); err != nil {
		t.Fatal(err)
	}
	// route53 hands TXT back quoted and MX with the exchange's dot, as written
	rerun, err := provider.Plan(domains[0], input)
	if err != nil {
		t.Fatal(err)
	}
	if len(rerun) != 0 {
		t.Errorf("a rerun plans %v", rerun)
	}
	for _, set := range fake.rrsets {
		if set.Type == types.RRTypeTxt && aws.ToString(set.Name) == `\052._report._dmarc.rpt.example.com.` {
			if value := aws.ToString(set.ResourceRecords[0].Value); value != `"v=DMARC1"` {
				t.Errorf("the DMARC TXT is %s", value)
			}
		}
	}
}

// A TXT value keeps its quotes through route53's form, a multi-string value
// stays split, and an MX normalizes case and its trailing dot.
func TestDnsRoute53NormalizesTxtAndMx(t *testing.T) {
	for value, want := range map[string]string{
		`"v=DMARC1"`:       `"v=DMARC1"`,
		`v=DMARC1`:         `"v=DMARC1"`,
		`"a" "b"`:          `"a" "b"`,
		`"with \"quote\""`: `"with \"quote\""`,
		`"back\\slash"`:    `"back\\slash"`,
		` "v=spf1 -all" `:  `"v=spf1 -all"`,
	} {
		if got := route53Txt(value); got != want {
			t.Errorf("route53Txt(%s) = %s, want %s", value, got, want)
		}
	}
	for value, want := range map[string]string{
		"10 rpt.example.com":     "10 rpt.example.com",
		"10 RPT.Example.com.":    "10 rpt.example.com",
		"  10   rpt.example.com": "10 rpt.example.com",
	} {
		if got := route53Mx(value); got != want {
			t.Errorf("route53Mx(%q) = %q, want %q", value, got, want)
		}
	}
}

// The vyos fixture's dns block with two names it lists unproxied (QD-012):
// www.example.net, which the derivation publishes as web's alias, and
// key.example.net, which it does not derive.
func dnsFixtureWithUnproxied(servicesYaml string) string {
	return strings.Replace(dnsFixtureWithDns(servicesYaml), "dns:\n    ttl: 120\n", "dns:\n    ttl: 120\n    unproxied:\n        - www.example.net\n        - key.example.net\n", 1)
}

// A cloudflare zone serving records, one page, that counts the requests that
// would write.
func dnsCloudflareZone(t *testing.T, records []map[string]any) (*cloudflareProvider, func() []string) {
	t.Helper()
	writes := []string{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/zones":
			fmt.Fprint(w, `{"success":true,"errors":[],"result":[{"id":"zone-net","name":"example.net"}]}`)
		case r.Method == http.MethodGet && r.URL.Path == "/zones/zone-net/dns_records":
			data, _ := json.Marshal(map[string]any{"success": true, "errors": []any{}, "result": records, "result_info": map[string]any{"page": 1, "total_pages": 1}})
			w.Write(data)
		default:
			writes = append(writes, r.Method+" "+r.URL.Path)
			fmt.Fprint(w, `{"success":true,"errors":[],"result":{"id":"new"}}`)
		}
	}))
	t.Cleanup(server.Close)
	provider := &cloudflareProvider{ctx: context.Background(), client: server.Client(), baseUrl: server.URL, token: "synthetic"}
	return provider, func() []string { return writes }
}

// A name the dns block lists unproxied that cloudflare proxies stops both the
// plan and the sync before any write, whether the derivation publishes the
// name or not, and proxied names it does not list keep the sync's rule: they
// stay proxied (QD-012).
func TestDnsCloudflareRefusesAProxiedUnproxiedName(t *testing.T) {
	input := newDnsTestInput(t, dnsFixtureWithUnproxied)
	if got := input.ServicesConfig.DnsUnproxiedHosts(); !slices.Equal(got, []string{"key.example.net", "www.example.net"}) {
		t.Fatalf("unproxied = %q", got)
	}
	domains, err := dnsDerive(input)
	if err != nil {
		t.Fatal(err)
	}
	net := domains[1]
	if net.Domain != "example.net" || net.Registrar != "cloudflare" {
		t.Fatalf("domains[1] = %s %s", net.Domain, net.Registrar)
	}
	findDnsName(t, net, "www.example.net")
	for _, name := range dnsNameList(net) {
		if name == "key.example.net" {
			t.Fatal("key.example.net is derived; the case wants a name the derivation leaves alone")
		}
	}
	env := input.Env
	cases := []struct {
		label  string
		record map[string]any
	}{
		{
			label:  "a derived name",
			record: map[string]any{"id": "r1", "type": "CNAME", "name": "www.example.net", "content": env + "-lb.example.net", "ttl": 1, "proxied": true},
		},
		{
			label:  "a name the sync leaves alone",
			record: map[string]any{"id": "r2", "type": "A", "name": "Key.Example.Net", "content": "192.0.2.7", "ttl": 1, "proxied": true},
		},
	}
	for _, c := range cases {
		provider, writes := dnsCloudflareZone(t, []map[string]any{
			// the apex is proxied and listed nowhere: it stays as it is
			{"id": "r0", "type": "CNAME", "name": "example.net", "content": env + "-lb.example.net", "ttl": 1, "proxied": true},
			c.record,
		})
		name := strings.ToLower(c.record["name"].(string))
		if _, err := provider.Plan(net, input); err == nil || !strings.Contains(err.Error(), name) || !strings.Contains(err.Error(), "unproxied") {
			t.Errorf("%s: plan = %v", c.label, err)
		}
		if _, err := provider.Apply(net, input); err == nil || !strings.Contains(err.Error(), name) {
			t.Errorf("%s: sync = %v", c.label, err)
		}
		if 0 < len(writes()) {
			t.Errorf("%s: the refused sync wrote %q", c.label, writes())
		}
	}

	// unproxied, the same names plan what they plan without the list, and the
	// name the derivation leaves alone stays alone
	records := []map[string]any{
		{"id": "r0", "type": "CNAME", "name": "example.net", "content": env + "-lb.example.net", "ttl": 1, "proxied": true},
		{"id": "r1", "type": "CNAME", "name": "www.example.net", "content": env + "-lb.example.net", "ttl": 120, "proxied": false, "comment": "warpctl dns " + env},
		{"id": "r2", "type": "A", "name": "key.example.net", "content": "192.0.2.7", "ttl": 300, "proxied": false},
	}
	provider, _ := dnsCloudflareZone(t, records)
	planned, err := provider.Plan(net, input)
	if err != nil {
		t.Fatal(err)
	}
	withoutInput := newDnsTestInput(t, dnsFixtureWithDns)
	withoutDomains, err := dnsDerive(withoutInput)
	if err != nil {
		t.Fatal(err)
	}
	withoutProvider, _ := dnsCloudflareZone(t, records)
	withoutPlanned, err := withoutProvider.Plan(withoutDomains[1], withoutInput)
	if err != nil {
		t.Fatal(err)
	}
	plan := []string{}
	for _, change := range planned {
		plan = append(plan, change.String())
		if strings.Contains(change.String(), "key.example.net") || strings.Contains(change.String(), "www.example.net") {
			t.Errorf("the plan changes an unproxied name that is as it should be: %s", change)
		}
	}
	withoutPlan := []string{}
	for _, change := range withoutPlanned {
		withoutPlan = append(withoutPlan, change.String())
	}
	if !slices.Equal(plan, withoutPlan) {
		t.Errorf("the list changed the plan:\n%s\nwithout it:\n%s", strings.Join(plan, "\n"), strings.Join(withoutPlan, "\n"))
	}
}

// A declared record on a cloudflare domain refuses the plan there, before any
// call, until a cloudflare domain needs one.
func TestDnsCloudflareRefusesADeclaredRecord(t *testing.T) {
	input := newDnsTestInput(t, func(servicesYaml string) string {
		return strings.Replace(dnsFixtureWithRecords(servicesYaml), "                - v=DMARC1\n", "                - v=DMARC1\n        -   name: rpt.example.net\n            mx:\n                - 10 rpt.example.net\n", 1)
	})
	domains, err := dnsDerive(input)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("the refused plan called cloudflare: %s %s", r.Method, r.URL)
		http.Error(w, "no", http.StatusInternalServerError)
	}))
	defer server.Close()
	provider := &cloudflareProvider{ctx: context.Background(), client: server.Client(), baseUrl: server.URL, token: "synthetic"}
	_, err = provider.Plan(domains[1], input)
	if err == nil || !strings.Contains(err.Error(), "rpt.example.net") || !strings.Contains(err.Error(), "route53 alone") {
		t.Fatalf("plan = %v", err)
	}
}

// Documents without records derive what they did before, so nothing new is
// planned.
func TestDnsWithoutRecordsDerivesAsBefore(t *testing.T) {
	without, err := dnsDerive(newDnsTestInput(t, dnsFixtureWithDns))
	if err != nil {
		t.Fatal(err)
	}
	with, err := dnsDerive(newDnsTestInput(t, dnsFixtureWithRecords))
	if err != nil {
		t.Fatal(err)
	}
	added := map[string]bool{"rpt.example.com": true, "*._report._dmarc.rpt.example.com": true, "send-1.example.com": true}
	for index, domain := range without {
		names := []string{}
		for _, name := range dnsNameList(with[index]) {
			if !added[name] {
				names = append(names, name)
			}
		}
		if !slices.Equal(names, dnsNameList(domain)) {
			t.Errorf("%s derives %q, before %q", domain.Domain, names, dnsNameList(domain))
		}
	}
}

// The vyos fixture with the dns block, a third registrar domain, example.org,
// standing for the user root, and, when selfHosted, the dns block listing it
// self_hosted, as it does once the root's NS moved to the dns edges (§12.4
// step 3).
func dnsFixtureWithSelfHosted(servicesYaml string, selfHosted bool) string {
	servicesYaml = strings.Replace(dnsFixtureWithDns(servicesYaml), "    example.net: cloudflare\n", "    example.net: cloudflare\n    example.org: route53\n", 1)
	if selfHosted {
		servicesYaml = strings.Replace(servicesYaml, "dns:\n    ttl: 120\n", "dns:\n    self_hosted:\n        - Example.org.\n    ttl: 120\n", 1)
	}
	return servicesYaml
}

// A provider that answers every plan and sync with no change, keeping the
// domains it was asked about.
type recordingDnsProvider struct {
	planned []string
	applied []string
}

func (self *recordingDnsProvider) Plan(domain *dnsDomain, input dnsPlanInput) ([]dnsChange, error) {
	self.planned = append(self.planned, domain.Domain)
	return nil, nil
}

func (self *recordingDnsProvider) Apply(domain *dnsDomain, input dnsPlanInput) ([]dnsChange, error) {
	self.applied = append(self.applied, domain.Domain)
	return nil, nil
}

// Runs a plan and a sync of domains through recorder, returning what they
// printed and the registrars a provider was made for.
func dnsReconcileRecorded(t *testing.T, domains []*dnsDomain, input dnsPlanInput, recorder *recordingDnsProvider) (string, []string) {
	t.Helper()
	previousOutput := Out.Writer()
	output := &strings.Builder{}
	Out.SetOutput(output)
	t.Cleanup(func() { Out.SetOutput(previousOutput) })
	registrars := []string{}
	provider := func(registrar string) (dnsProvider, error) {
		registrars = append(registrars, registrar)
		return recorder, nil
	}
	for _, apply := range []bool{false, true} {
		if err := dnsReconcile(domains, input, provider, apply); err != nil {
			t.Fatal(err)
		}
	}
	return output.String(), registrars
}

// Once the root's NS moved and the dns block lists it self_hosted, warpctl dns
// derives no name in it and neither plan nor sync asks its registrar about it,
// so nothing there is changed, while the other domains are planned and synced
// as before.
func TestDnsSelfHostedDomainPlansNoChange(t *testing.T) {
	input := newDnsTestInput(t, func(servicesYaml string) string {
		return dnsFixtureWithSelfHosted(servicesYaml, true)
	})
	if !slices.Equal(input.ServicesConfig.DnsSelfHostedDomains(), []string{"example.org"}) || !input.ServicesConfig.IsDnsSelfHosted("EXAMPLE.org") {
		t.Fatalf("self-hosted domains %v", input.ServicesConfig.DnsSelfHostedDomains())
	}
	domains, err := dnsDerive(input)
	if err != nil {
		t.Fatal(err)
	}
	derived := []string{}
	for _, domain := range domains {
		derived = append(derived, domain.Domain)
		if domain.SelfHosted != (domain.Domain == "example.org") {
			t.Errorf("%s: self-hosted %t", domain.Domain, domain.SelfHosted)
		}
		if domain.SelfHosted && (0 < len(domain.Names) || domain.Registrar != "route53" || domain.Primary) {
			t.Errorf("the self-hosted domain derives %v on %s, primary %t", dnsNameList(domain), domain.Registrar, domain.Primary)
		}
		if !domain.SelfHosted && len(domain.Names) == 0 {
			t.Errorf("%s derives nothing", domain.Domain)
		}
	}
	if !slices.Equal(derived, []string{"example.com", "example.net", "example.org"}) {
		t.Fatalf("derived domains %v", derived)
	}

	recorder := &recordingDnsProvider{}
	output, registrars := dnsReconcileRecorded(t, domains, input, recorder)
	for _, asked := range [][]string{recorder.planned, recorder.applied} {
		if !slices.Equal(asked, []string{"example.com", "example.net"}) {
			t.Errorf("the provider was asked about %v", asked)
		}
	}
	// a provider for each of the two other domains, in each run
	if len(registrars) != 4 {
		t.Errorf("providers made for %v", registrars)
	}
	for _, line := range []string{
		"== example.org (route53, served by the dns edges) plan\n",
		"== example.org (route53, served by the dns edges) sync\n",
		"   left alone\n",
	} {
		if !strings.Contains(output, line) {
			t.Errorf("the output lacks %q:\n%s", line, output)
		}
	}
	for _, line := range strings.Split(output, "\n") {
		if strings.Contains(line, "example.org") && !strings.HasPrefix(line, "== example.org ") && !strings.HasPrefix(line, "   note: ") {
			t.Errorf("a line names the self-hosted domain: %q", line)
		}
	}
}

// Without the list, the same domain is derived and planned like any other, so
// it is the flag that stops the reconciling.
func TestDnsWithoutSelfHostedTheRootIsPlanned(t *testing.T) {
	input := newDnsTestInput(t, func(servicesYaml string) string {
		return dnsFixtureWithSelfHosted(servicesYaml, false)
	})
	domains, err := dnsDerive(input)
	if err != nil {
		t.Fatal(err)
	}
	root := domains[len(domains)-1]
	if root.Domain != "example.org" || root.SelfHosted {
		t.Fatalf("the last domain is %s, self-hosted %t", root.Domain, root.SelfHosted)
	}
	findDnsName(t, root, input.Env+"-lb.example.org")
	findDnsName(t, root, "api.example.org")
	recorder := &recordingDnsProvider{}
	dnsReconcileRecorded(t, domains, input, recorder)
	if !slices.Contains(recorder.planned, "example.org") || !slices.Contains(recorder.applied, "example.org") {
		t.Errorf("planned %v, synced %v", recorder.planned, recorder.applied)
	}
}

// The list refuses the primary domain, whose records the sync derives, a name
// that is no registrar domain, which a typo would otherwise leave reconciled,
// and a declared record under a self-hosted domain, which the sync could no
// longer publish.
func TestDnsSelfHostedRefusesWhatItCannotLeaveAlone(t *testing.T) {
	for _, test := range []struct {
		mutate func(string) string
		want   string
	}{
		{
			func(servicesYaml string) string {
				return strings.Replace(dnsFixtureWithSelfHosted(servicesYaml, true), "        - Example.org.\n", "        - example.com\n", 1)
			},
			"the primary domain example.com",
		},
		{
			func(servicesYaml string) string {
				return strings.Replace(dnsFixtureWithSelfHosted(servicesYaml, true), "        - Example.org.\n", "        - example.invalid\n", 1)
			},
			`"example.invalid", which is no registrar domain`,
		},
		{
			func(servicesYaml string) string {
				return strings.Replace(dnsFixtureWithSelfHosted(servicesYaml, true), "    other_domain_services:\n        - web\n",
					"    other_domain_services:\n        - web\n    records:\n        -   name: _dmarc.example.org\n            txt:\n                - v=DMARC1\n", 1)
			},
			"dns record _dmarc.example.org is under example.org",
		},
	} {
		if _, err := dnsDerive(newDnsTestInput(t, test.mutate)); err == nil || !strings.Contains(err.Error(), test.want) {
			t.Errorf("want a refusal naming %q, got %v", test.want, err)
		}
	}
}
