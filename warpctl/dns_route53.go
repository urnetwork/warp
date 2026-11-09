package main

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/route53"
	"github.com/aws/aws-sdk-go-v2/service/route53/types"
)

// route53Api is the slice of the route53 client the sync uses, so tests can
// stand in for it.
type route53Api interface {
	ListHostedZones(ctx context.Context, params *route53.ListHostedZonesInput, optFns ...func(*route53.Options)) (*route53.ListHostedZonesOutput, error)
	ListResourceRecordSets(ctx context.Context, params *route53.ListResourceRecordSetsInput, optFns ...func(*route53.Options)) (*route53.ListResourceRecordSetsOutput, error)
	ChangeResourceRecordSets(ctx context.Context, params *route53.ChangeResourceRecordSetsInput, optFns ...func(*route53.Options)) (*route53.ChangeResourceRecordSetsOutput, error)
	ListHealthChecks(ctx context.Context, params *route53.ListHealthChecksInput, optFns ...func(*route53.Options)) (*route53.ListHealthChecksOutput, error)
	CreateHealthCheck(ctx context.Context, params *route53.CreateHealthCheckInput, optFns ...func(*route53.Options)) (*route53.CreateHealthCheckOutput, error)
	DeleteHealthCheck(ctx context.Context, params *route53.DeleteHealthCheckInput, optFns ...func(*route53.Options)) (*route53.DeleteHealthCheckOutput, error)
	ChangeTagsForResource(ctx context.Context, params *route53.ChangeTagsForResourceInput, optFns ...func(*route53.Options)) (*route53.ChangeTagsForResourceOutput, error)
}

// route53Provider reconciles a route53 hosted zone.
type route53Provider struct {
	api route53Api
	ctx context.Context
}

func newRoute53Provider(ctx context.Context) (*route53Provider, error) {
	cfg, err := awsconfig.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("aws credentials: %w", err)
	}
	return &route53Provider{api: route53.NewFromConfig(cfg), ctx: ctx}, nil
}

// route53 health check settings for the lb set members. A check is HTTPS on
// 443 with SNI, the <env>-lb host's name, so it crosses the lb's SNI split
// as a visitor would, and a broken split drops the interface from the
// platform answers (§19 W7). warpctl's checks were HTTP on 80 before.
const (
	route53HealthCheckType      = types.HealthCheckTypeHttps
	route53HealthCheckPort      = 443
	route53HealthCheckInterval  = 10
	route53HealthCheckThreshold = 3
	// the tag every health check the sync creates carries, so a later run
	// can tell its own checks apart
	route53OwnerTag = "warp"
	// route53 accepts up to 1000 changes per batch; stay well below
	route53ChangeBatchSize = 200
)

// route53Rrset is a desired or observed record set in normalized form.
type route53Rrset struct {
	Name string
	Type string
	// the set identifier of a weighted member, empty for a simple set
	SetId  string
	Weight int64
	Ttl    int64
	Values []string
	// an alias record: the target name, no ttl or values
	AliasTarget string
	// the health check the weighted member references: its config for a
	// desired set (resolved to an id at apply), its id for an observed one
	HealthCheck   *route53HealthCheckConfig
	HealthCheckId string
	// a drained member's (W1): only its health check is desired, which keeps
	// probing the interface while no set references it, and no set is
	CheckOnly bool
}

func (r *route53Rrset) key() string {
	return r.Name + "|" + r.Type + "|" + r.SetId
}

func (r *route53Rrset) String() string {
	parts := []string{r.Type, r.Name}
	if r.AliasTarget != "" {
		parts = append(parts, "-> "+r.AliasTarget)
	} else {
		parts = append(parts, strings.Join(r.Values, ","), "ttl="+strconv.FormatInt(r.Ttl, 10))
	}
	if r.SetId != "" {
		parts = append(parts, fmt.Sprintf("set=%s weight=%d", r.SetId, r.Weight))
	}
	if r.HealthCheck != nil {
		parts = append(parts, "health-check")
	}
	return strings.Join(parts, " ")
}

// route53HealthCheckConfig identifies a health check by what it probes.
type route53HealthCheckConfig struct {
	// HTTPS for a check the sync makes; an observed check's own type
	Type    types.HealthCheckType
	Address string
	Port    int32
	Path    string
	Host    string
	// whether the check sends Host as its SNI
	EnableSni bool
	// the Name tag: <A|AAAA>-<set id>
	Name string
}

// The key names every field the sync sets, so an observed check matches a
// desired one only when it probes the same way.
func (c route53HealthCheckConfig) key() string {
	return fmt.Sprintf("%s|%s|%d|%s|%s|%t", c.Type, c.Address, c.Port, c.Path, c.Host, c.EnableSni)
}

// The url scheme a check of this type requests.
func (c route53HealthCheckConfig) scheme() string {
	switch c.Type {
	case types.HealthCheckTypeHttps, types.HealthCheckTypeHttpsStrMatch:
		return "https"
	}
	return "http"
}

func (c route53HealthCheckConfig) String() string {
	return fmt.Sprintf("health check %s %s://[%s]:%d%s host %s", c.Name, c.scheme(), c.Address, c.Port, c.Path, c.Host)
}

// route53Desired renders the derived names of a domain as record sets.
func route53Desired(domain *dnsDomain, input dnsPlanInput) ([]*route53Rrset, error) {
	statusPath, err := dnsStatusPath(input.ServicesConfig)
	if err != nil {
		return nil, err
	}
	ttl := int64(input.ServicesConfig.GetDnsTtl())
	healthCheckHost := fmt.Sprintf("%s-lb.%s", input.Env, input.ServicesConfig.GetDomain())
	rrsets := []*route53Rrset{}
	for _, name := range domain.Names {
		switch name.Kind {
		case dnsAddresses:
			if name.HasIpv4 && 0 < len(name.Ipv4) {
				rrsets = append(rrsets, &route53Rrset{Name: name.Name, Type: "A", Ttl: ttl, Values: sortedCopy(name.Ipv4)})
			}
			if name.HasIpv6 && 0 < len(name.Ipv6) {
				rrsets = append(rrsets, &route53Rrset{Name: name.Name, Type: "AAAA", Ttl: ttl, Values: sortedCopy(name.Ipv6)})
			}
		case dnsLbSet:
			for _, member := range name.Members {
				rrsets = append(rrsets, &route53Rrset{
					Name: name.Name, Type: "A", SetId: member.Id, Weight: int64(member.Weight), Ttl: ttl, Values: []string{member.Ipv4},
					HealthCheck: &route53HealthCheckConfig{Type: route53HealthCheckType, Address: member.Ipv4, Port: route53HealthCheckPort, Path: statusPath, Host: healthCheckHost, EnableSni: true, Name: "A-" + member.Id},
				})
				if member.Ipv6 != "" {
					rrsets = append(rrsets, &route53Rrset{
						Name: name.Name, Type: "AAAA", SetId: member.Id, Weight: int64(member.Weight), Ttl: ttl, Values: []string{member.Ipv6},
						HealthCheck: &route53HealthCheckConfig{Type: route53HealthCheckType, Address: member.Ipv6, Port: route53HealthCheckPort, Path: statusPath, Host: healthCheckHost, EnableSni: true, Name: "AAAA-" + member.Id},
					})
				}
			}
			for _, member := range name.DrainedMembers {
				rrsets = append(rrsets, &route53Rrset{
					Name: name.Name, Type: "A", SetId: member.Id, CheckOnly: true,
					HealthCheck: &route53HealthCheckConfig{Type: route53HealthCheckType, Address: member.Ipv4, Port: route53HealthCheckPort, Path: statusPath, Host: healthCheckHost, EnableSni: true, Name: "A-" + member.Id},
				})
				if member.Ipv6 != "" {
					rrsets = append(rrsets, &route53Rrset{
						Name: name.Name, Type: "AAAA", SetId: member.Id, CheckOnly: true,
						HealthCheck: &route53HealthCheckConfig{Type: route53HealthCheckType, Address: member.Ipv6, Port: route53HealthCheckPort, Path: statusPath, Host: healthCheckHost, EnableSni: true, Name: "AAAA-" + member.Id},
					})
				}
			}
		case dnsAliasTo:
			if name.HasIpv4 {
				rrsets = append(rrsets, &route53Rrset{Name: name.Name, Type: "A", AliasTarget: name.Target})
			}
			if name.HasIpv6 {
				rrsets = append(rrsets, &route53Rrset{Name: name.Name, Type: "AAAA", AliasTarget: name.Target})
			}
		case dnsRecordSet:
			// a declared record (W11): its addresses, then its MX and TXT,
			// each set in the form route53Mx and route53Txt read back
			if name.HasIpv4 && 0 < len(name.Ipv4) {
				rrsets = append(rrsets, &route53Rrset{Name: name.Name, Type: "A", Ttl: ttl, Values: sortedCopy(name.Ipv4)})
			}
			if name.HasIpv6 && 0 < len(name.Ipv6) {
				rrsets = append(rrsets, &route53Rrset{Name: name.Name, Type: "AAAA", Ttl: ttl, Values: sortedCopy(name.Ipv6)})
			}
			if 0 < len(name.Mx) {
				values := []string{}
				for _, mx := range name.Mx {
					values = append(values, route53Mx(mx))
				}
				rrsets = append(rrsets, &route53Rrset{Name: name.Name, Type: "MX", Ttl: ttl, Values: sortedCopy(values)})
			}
			if 0 < len(name.Txt) {
				values := []string{}
				for _, txt := range name.Txt {
					values = append(values, route53Txt(`"`+txt+`"`))
				}
				rrsets = append(rrsets, &route53Rrset{Name: name.Name, Type: "TXT", Ttl: ttl, Values: sortedCopy(values)})
			}
		}
	}
	return rrsets, nil
}

// route53Mx normalizes an MX value: the preference, one space, the exchange
// lower case without a trailing dot, as route53 may return it with one.
func route53Mx(value string) string {
	fields := strings.Fields(value)
	if len(fields) != 2 {
		return strings.TrimSpace(value)
	}
	return fields[0] + " " + strings.TrimSuffix(strings.ToLower(fields[1]), ".")
}

// route53Txt normalizes a TXT value as route53 holds it: each
// character-string in double quotes, quotes and backslashes inside escaped,
// the strings one space apart. route53 returns a value quoted, so a value
// read back compares equal to the one written, and text with no quotes is
// one string.
func route53Txt(value string) string {
	value = strings.TrimSpace(value)
	quote := func(text string) string {
		return `"` + strings.ReplaceAll(strings.ReplaceAll(text, `\`, `\\`), `"`, `\"`) + `"`
	}
	if !strings.HasPrefix(value, `"`) {
		return quote(value)
	}
	parts := []string{}
	for 0 < len(value) {
		if value[0] == ' ' {
			value = value[1:]
			continue
		}
		if value[0] != '"' {
			// not a quoted string: keep the rest as one string
			parts = append(parts, quote(value))
			break
		}
		var text strings.Builder
		index := 1
		for ; index < len(value) && value[index] != '"'; index++ {
			if value[index] == '\\' && index+1 < len(value) {
				index++
			}
			text.WriteByte(value[index])
		}
		parts = append(parts, quote(text.String()))
		if len(value) <= index {
			break
		}
		value = value[index+1:]
	}
	return strings.Join(parts, " ")
}

func sortedCopy(values []string) []string {
	out := append([]string{}, values...)
	sort.Strings(out)
	return out
}

// route53Name normalizes a route53 record name: lower case, no trailing dot,
// the wildcard octal escape decoded.
func route53Name(name string) string {
	name = strings.TrimSuffix(strings.ToLower(name), ".")
	return strings.ReplaceAll(name, `\052`, "*")
}

func (self *route53Provider) zoneId(domain string) (string, error) {
	var marker *string
	for {
		out, err := self.api.ListHostedZones(self.ctx, &route53.ListHostedZonesInput{Marker: marker})
		if err != nil {
			return "", fmt.Errorf("route53 list hosted zones: %w", err)
		}
		for _, zone := range out.HostedZones {
			if zone.Config != nil && zone.Config.PrivateZone {
				continue
			}
			if route53Name(aws.ToString(zone.Name)) == domain {
				return strings.TrimPrefix(aws.ToString(zone.Id), "/hostedzone/"), nil
			}
		}
		if !out.IsTruncated || out.NextMarker == nil {
			break
		}
		marker = out.NextMarker
	}
	return "", fmt.Errorf("route53 has no public hosted zone for %s", domain)
}

// observed lists the record sets of the zone at the managed names, of the
// types the sync manages there: name -> type.
func (self *route53Provider) observed(zoneId string, managed map[string]map[string]bool) ([]*route53Rrset, error) {
	rrsets := []*route53Rrset{}
	params := &route53.ListResourceRecordSetsInput{HostedZoneId: aws.String(zoneId)}
	for {
		out, err := self.api.ListResourceRecordSets(self.ctx, params)
		if err != nil {
			return nil, fmt.Errorf("route53 list record sets: %w", err)
		}
		for _, set := range out.ResourceRecordSets {
			name := route53Name(aws.ToString(set.Name))
			recordType := string(set.Type)
			if !managed[name][recordType] {
				continue
			}
			rrset := &route53Rrset{Name: name, Type: recordType, SetId: aws.ToString(set.SetIdentifier), HealthCheckId: aws.ToString(set.HealthCheckId)}
			if set.Weight != nil {
				rrset.Weight = *set.Weight
			}
			if set.AliasTarget != nil {
				rrset.AliasTarget = route53Name(aws.ToString(set.AliasTarget.DNSName))
			} else {
				rrset.Ttl = aws.ToInt64(set.TTL)
				for _, record := range set.ResourceRecords {
					value := aws.ToString(record.Value)
					switch recordType {
					case "MX":
						value = route53Mx(value)
					case "TXT":
						value = route53Txt(value)
					}
					rrset.Values = append(rrset.Values, value)
				}
				sort.Strings(rrset.Values)
			}
			rrsets = append(rrsets, rrset)
		}
		if !out.IsTruncated {
			break
		}
		params.StartRecordName = out.NextRecordName
		params.StartRecordType = out.NextRecordType
		params.StartRecordIdentifier = out.NextRecordIdentifier
	}
	return rrsets, nil
}

// route53HealthCheck is an existing health check with what identifies it.
type route53HealthCheck struct {
	Id     string
	Config route53HealthCheckConfig
	// a check with our status path and lb host is ours, whatever its type:
	// reused when it is the HTTPS check with SNI the sync creates, removed
	// once nothing references it. The HTTP checks earlier syncs made, and the
	// manual setup's HTTP_STR_MATCH ones, are ours too, so a sync replaces
	// them, deleting each only after its successor is created and the set
	// moved to it, and never leaves one behind.
	Ours     bool
	Reusable bool
}

// The health check types a check of ours may have.
var route53OurHealthCheckTypes = []types.HealthCheckType{
	types.HealthCheckTypeHttp,
	types.HealthCheckTypeHttpStrMatch,
	types.HealthCheckTypeHttps,
	types.HealthCheckTypeHttpsStrMatch,
}

func (self *route53Provider) healthChecks(statusPath string, host string) ([]*route53HealthCheck, error) {
	checks := []*route53HealthCheck{}
	var marker *string
	for {
		out, err := self.api.ListHealthChecks(self.ctx, &route53.ListHealthChecksInput{Marker: marker})
		if err != nil {
			return nil, fmt.Errorf("route53 list health checks: %w", err)
		}
		for _, check := range out.HealthChecks {
			config := check.HealthCheckConfig
			if config == nil {
				continue
			}
			healthCheck := &route53HealthCheck{
				Id: aws.ToString(check.Id),
				Config: route53HealthCheckConfig{
					Type:      config.Type,
					Address:   aws.ToString(config.IPAddress),
					Port:      aws.ToInt32(config.Port),
					Path:      aws.ToString(config.ResourcePath),
					Host:      strings.ToLower(aws.ToString(config.FullyQualifiedDomainName)),
					EnableSni: aws.ToBool(config.EnableSNI),
				},
			}
			lbCheck := healthCheck.Config.Path == statusPath && healthCheck.Config.Host == host
			healthCheck.Ours = lbCheck && slices.Contains(route53OurHealthCheckTypes, config.Type)
			healthCheck.Reusable = lbCheck && config.Type == route53HealthCheckType
			checks = append(checks, healthCheck)
		}
		if !out.IsTruncated || out.NextMarker == nil {
			break
		}
		marker = out.NextMarker
	}
	return checks, nil
}

// route53Reconciliation is the computed difference for one zone.
type route53Reconciliation struct {
	zoneId string
	// health checks to create, keyed by config key
	createChecks []route53HealthCheckConfig
	// existing checks reused, config key -> id
	reuseChecks map[string]string
	upserts     []*route53Rrset
	deletes     []*route53Rrset
	// health checks of ours no desired set references once the changes apply
	deleteChecks []*route53HealthCheck
	changes      []dnsChange
}

func (self *route53Provider) reconcile(domain *dnsDomain, input dnsPlanInput) (*route53Reconciliation, error) {
	desired, err := route53Desired(domain, input)
	if err != nil {
		return nil, err
	}
	zoneId, err := self.zoneId(domain.Domain)
	if err != nil {
		return nil, err
	}
	// a derived name's addresses and cnames are the sync's; its MX and TXT
	// only where a declared record sets them (W11), so the mail and
	// verification records another name holds stay as they are
	managed := map[string]map[string]bool{}
	for _, rrset := range desired {
		if managed[rrset.Name] == nil {
			managed[rrset.Name] = map[string]bool{"A": true, "AAAA": true, "CNAME": true}
		}
		managed[rrset.Name][rrset.Type] = true
	}
	observed, err := self.observed(zoneId, managed)
	if err != nil {
		return nil, err
	}
	statusPath, err := dnsStatusPath(input.ServicesConfig)
	if err != nil {
		return nil, err
	}
	checks, err := self.healthChecks(statusPath, fmt.Sprintf("%s-lb.%s", input.Env, input.ServicesConfig.GetDomain()))
	if err != nil {
		return nil, err
	}
	existingChecks := map[string]*route53HealthCheck{}
	for _, check := range checks {
		if check.Reusable {
			existingChecks[check.Config.key()] = check
		}
	}

	reconciliation := &route53Reconciliation{zoneId: zoneId, reuseChecks: map[string]string{}}
	neededChecks := map[string]bool{}
	seenCreate := map[string]bool{}
	for _, rrset := range desired {
		if rrset.HealthCheck == nil {
			continue
		}
		key := rrset.HealthCheck.key()
		neededChecks[key] = true
		if existing, ok := existingChecks[key]; ok {
			reconciliation.reuseChecks[key] = existing.Id
			continue
		}
		if !seenCreate[key] {
			seenCreate[key] = true
			reconciliation.createChecks = append(reconciliation.createChecks, *rrset.HealthCheck)
			reconciliation.changes = append(reconciliation.changes, dnsChange{Op: "+", What: rrset.HealthCheck.String()})
		}
	}

	observedByKey := map[string]*route53Rrset{}
	for _, rrset := range observed {
		observedByKey[rrset.key()] = rrset
	}
	desiredByKey := map[string]*route53Rrset{}
	for _, rrset := range desired {
		if rrset.CheckOnly {
			// a drained member: its check is needed above, and its set goes
			continue
		}
		desiredByKey[rrset.key()] = rrset
		existing, ok := observedByKey[rrset.key()]
		if ok && route53Same(existing, rrset, reconciliation.reuseChecks) {
			continue
		}
		reconciliation.upserts = append(reconciliation.upserts, rrset)
		if ok {
			reconciliation.changes = append(reconciliation.changes, dnsChange{Op: "~", What: rrset.String() + " (was " + existing.String() + ")"})
		} else {
			reconciliation.changes = append(reconciliation.changes, dnsChange{Op: "+", What: rrset.String()})
		}
	}
	for _, rrset := range observed {
		if _, ok := desiredByKey[rrset.key()]; ok {
			continue
		}
		reconciliation.deletes = append(reconciliation.deletes, rrset)
		reconciliation.changes = append(reconciliation.changes, dnsChange{Op: "-", What: rrset.String()})
	}
	for _, check := range checks {
		if check.Ours && !(check.Reusable && neededChecks[check.Config.key()]) {
			reconciliation.deleteChecks = append(reconciliation.deleteChecks, check)
			reconciliation.changes = append(reconciliation.changes, dnsChange{Op: "-", What: fmt.Sprintf("health check %s %s://[%s]:%d%s", check.Id, check.Config.scheme(), check.Config.Address, check.Config.Port, check.Config.Path)})
		}
	}
	return reconciliation, nil
}

// route53Same reports whether an observed set already matches a desired one,
// including the health check it references.
func route53Same(observed *route53Rrset, desired *route53Rrset, reuseChecks map[string]string) bool {
	if observed.AliasTarget != desired.AliasTarget || observed.Weight != desired.Weight {
		return false
	}
	if desired.AliasTarget == "" && (observed.Ttl != desired.Ttl || !stringsEqual(observed.Values, desired.Values)) {
		return false
	}
	wantCheck := ""
	if desired.HealthCheck != nil {
		id, ok := reuseChecks[desired.HealthCheck.key()]
		if !ok {
			// the check does not exist yet, so the set has to be written
			return false
		}
		wantCheck = id
	}
	return observed.HealthCheckId == wantCheck
}

func (self *route53Provider) Plan(domain *dnsDomain, input dnsPlanInput) ([]dnsChange, error) {
	reconciliation, err := self.reconcile(domain, input)
	if err != nil {
		return nil, err
	}
	return reconciliation.changes, nil
}

func (self *route53Provider) Apply(domain *dnsDomain, input dnsPlanInput) ([]dnsChange, error) {
	reconciliation, err := self.reconcile(domain, input)
	if err != nil {
		return nil, err
	}
	// health checks first, so the sets can reference them
	for _, config := range reconciliation.createChecks {
		out, err := self.api.CreateHealthCheck(self.ctx, &route53.CreateHealthCheckInput{
			CallerReference: aws.String(fmt.Sprintf("warp-%s-%d", config.Name, time.Now().UnixNano())),
			HealthCheckConfig: &types.HealthCheckConfig{
				Type:                     config.Type,
				IPAddress:                aws.String(config.Address),
				Port:                     aws.Int32(config.Port),
				ResourcePath:             aws.String(config.Path),
				FullyQualifiedDomainName: aws.String(config.Host),
				EnableSNI:                aws.Bool(config.EnableSni),
				RequestInterval:          aws.Int32(route53HealthCheckInterval),
				FailureThreshold:         aws.Int32(route53HealthCheckThreshold),
			},
		})
		if err != nil {
			return nil, fmt.Errorf("route53 create %s: %w", config, err)
		}
		id := aws.ToString(out.HealthCheck.Id)
		reconciliation.reuseChecks[config.key()] = id
		if _, err := self.api.ChangeTagsForResource(self.ctx, &route53.ChangeTagsForResourceInput{
			ResourceType: types.TagResourceTypeHealthcheck,
			ResourceId:   aws.String(id),
			AddTags: []types.Tag{
				{Key: aws.String("Name"), Value: aws.String(config.Name)},
				{Key: aws.String(route53OwnerTag), Value: aws.String(input.Env)},
			},
		}); err != nil {
			return nil, fmt.Errorf("route53 tag health check %s: %w", id, err)
		}
	}
	changes := []types.Change{}
	for _, rrset := range reconciliation.deletes {
		changes = append(changes, types.Change{Action: types.ChangeActionDelete, ResourceRecordSet: route53RecordSet(rrset, reconciliation.zoneId, reconciliation.reuseChecks)})
	}
	for _, rrset := range reconciliation.upserts {
		changes = append(changes, types.Change{Action: types.ChangeActionUpsert, ResourceRecordSet: route53RecordSet(rrset, reconciliation.zoneId, reconciliation.reuseChecks)})
	}
	for start := 0; start < len(changes); start += route53ChangeBatchSize {
		end := start + route53ChangeBatchSize
		if len(changes) < end {
			end = len(changes)
		}
		if _, err := self.api.ChangeResourceRecordSets(self.ctx, &route53.ChangeResourceRecordSetsInput{
			HostedZoneId: aws.String(reconciliation.zoneId),
			ChangeBatch:  &types.ChangeBatch{Comment: aws.String("warpctl dns sync " + input.Env), Changes: changes[start:end]},
		}); err != nil {
			return nil, fmt.Errorf("route53 change record sets: %w", err)
		}
	}
	for _, check := range reconciliation.deleteChecks {
		if _, err := self.api.DeleteHealthCheck(self.ctx, &route53.DeleteHealthCheckInput{HealthCheckId: aws.String(check.Id)}); err != nil {
			// a check another zone's set still references (the primary
			// domain has not been synced yet) goes on the next run
			var inUse *types.HealthCheckInUse
			if errors.As(err, &inUse) {
				domain.Notes = append(domain.Notes, fmt.Sprintf("health check %s is still referenced by another record set; left for the next sync", check.Id))
				continue
			}
			return nil, fmt.Errorf("route53 delete health check %s: %w", check.Id, err)
		}
	}
	return reconciliation.changes, nil
}

// route53RecordSet renders a normalized set for a change batch.
func route53RecordSet(rrset *route53Rrset, zoneId string, checks map[string]string) *types.ResourceRecordSet {
	set := &types.ResourceRecordSet{Name: aws.String(rrset.Name + "."), Type: types.RRType(rrset.Type)}
	if rrset.SetId != "" {
		set.SetIdentifier = aws.String(rrset.SetId)
		set.Weight = aws.Int64(rrset.Weight)
	}
	if rrset.AliasTarget != "" {
		set.AliasTarget = &types.AliasTarget{HostedZoneId: aws.String(zoneId), DNSName: aws.String(rrset.AliasTarget + "."), EvaluateTargetHealth: false}
	} else {
		set.TTL = aws.Int64(rrset.Ttl)
		for _, value := range rrset.Values {
			set.ResourceRecords = append(set.ResourceRecords, types.ResourceRecord{Value: aws.String(value)})
		}
	}
	switch {
	case rrset.HealthCheck != nil:
		if id, ok := checks[rrset.HealthCheck.key()]; ok {
			set.HealthCheckId = aws.String(id)
		}
	case rrset.HealthCheckId != "":
		set.HealthCheckId = aws.String(rrset.HealthCheckId)
	}
	return set
}
