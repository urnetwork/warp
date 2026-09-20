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
	if lbA.HealthCheck.Address != "203.0.113.84" || lbA.HealthCheck.Port != 80 || lbA.HealthCheck.Path != "/wrong-birdie-whicker-pompeii/status" || lbA.HealthCheck.Host != env+"-lb.example.com" || lbA.HealthCheck.Name != "A-edge-3-eno1np0" {
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
	return &route53.ChangeResourceRecordSetsOutput{}, nil
}

func (f *fakeRoute53) ListHealthChecks(ctx context.Context, params *route53.ListHealthChecksInput, optFns ...func(*route53.Options)) (*route53.ListHealthChecksOutput, error) {
	return &route53.ListHealthChecksOutput{HealthChecks: f.healthChecks}, nil
}

func (f *fakeRoute53) CreateHealthCheck(ctx context.Context, params *route53.CreateHealthCheckInput, optFns ...func(*route53.Options)) (*route53.CreateHealthCheckOutput, error) {
	f.nextId++
	id := fmt.Sprintf("hc-%d", f.nextId)
	f.created = append(f.created, *params.HealthCheckConfig)
	f.healthChecks = append(f.healthChecks, types.HealthCheck{Id: aws.String(id), HealthCheckConfig: params.HealthCheckConfig})
	return &route53.CreateHealthCheckOutput{HealthCheck: &types.HealthCheck{Id: aws.String(id), HealthCheckConfig: params.HealthCheckConfig}}, nil
}

func (f *fakeRoute53) DeleteHealthCheck(ctx context.Context, params *route53.DeleteHealthCheckInput, optFns ...func(*route53.Options)) (*route53.DeleteHealthCheckOutput, error) {
	if aws.ToString(params.HealthCheckId) == f.inUse {
		return nil, &types.HealthCheckInUse{Message: aws.String("in use")}
	}
	f.deleted = append(f.deleted, aws.ToString(params.HealthCheckId))
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

func route53HealthCheckFixture(id string, checkType types.HealthCheckType, address string, path string, host string) types.HealthCheck {
	return types.HealthCheck{Id: aws.String(id), HealthCheckConfig: &types.HealthCheckConfig{
		Type: checkType, IPAddress: aws.String(address), Port: aws.Int32(80), ResourcePath: aws.String(path), FullyQualifiedDomainName: aws.String(host),
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
			route53HealthCheckFixture("hc-keep", types.HealthCheckTypeHttp, "203.0.113.85", statusPath, lbHost),
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
		"+ health check A-edge-3-eno1np0 http://[203.0.113.84]:80" + statusPath,
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
		if config.Type != types.HealthCheckTypeHttp || aws.ToInt32(config.RequestInterval) != 10 || aws.ToInt32(config.FailureThreshold) != 3 {
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
	t.Setenv("WARP_HOME", dir)
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
