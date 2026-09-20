package main

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"golang.org/x/exp/maps"

	"github.com/urnetwork/warp/services"
)

// `warpctl dns plan|sync` derives the public records of every domain in
// `domains` from the latest services config version and reconciles the
// registrar (route53 or cloudflare) with them.
//
// The primary domain P (`domain`) carries the whole pattern:
//
//   - `<env>-lb.P`: the lb interfaces that run a front (not the transparent
//     ones), weighted by dns_weight and health checked on route53, round
//     robin on cloudflare, with `<env>-lb-v4.P` and `<env>-lb-v6.P` for one
//     address family each
//   - `<env>-<service>.P` for every exposed service, and the service's
//     expose_aliases and expose_domains under P: aliases of `<env>-lb.P`,
//     where a name whose first label ends in -v4 or -v6 carries one family
//   - `<host>-<iface>.P`: the address of every lb interface
//   - `<env>-<service>.P` for a host-pinned service with no lb in front (the
//     alt service) with -v4 and -v6 names, and its dns_aliases under P: the
//     interface addresses of its hosts
//   - a top level expose alias `<host>.P` of an lb host: the host's
//     addresses; `*.<host>.P`: an alias of it
//
// Every other domain X carries only `<env>-lb.X` and, aliased to it, the
// expose aliases under X of the services the dns block lists in
// other_domain_services (the web service).
//
// A name in the dns `unmanaged` list is left alone. Names at other domains
// are reported and skipped. Nothing outside the derived names is touched.
// --envalias adds the `<alias>-lb` and `<alias>-<service>` names an lb
// serves for that alias.

// dnsNameKind is how a name resolves.
type dnsNameKind int

const (
	// the name holds addresses directly
	dnsAddresses dnsNameKind = iota
	// the name is the weighted lb set
	dnsLbSet
	// the name is an alias of another derived name in the same domain
	dnsAliasTo
)

// dnsMember is one weighted member of an lb set: an lb interface.
type dnsMember struct {
	// the set identifier: <host>-<iface>
	Id     string
	Ipv4   string
	Ipv6   string
	Weight int
}

// dnsName is one derived name and how it resolves.
type dnsName struct {
	Name string
	Kind dnsNameKind
	// dnsAddresses: the addresses, dnsAliasTo: the target's addresses
	// filtered to the families
	Ipv4 []string
	Ipv6 []string
	// dnsLbSet
	Members []dnsMember
	// dnsAliasTo
	Target string
	// which families the name carries (an alias -v4 name carries only A)
	HasIpv4 bool
	HasIpv6 bool
	// where the name comes from, for the plan
	Source string
}

// dnsDomain is the derived names of one domain.
type dnsDomain struct {
	Domain    string
	Registrar string
	Primary   bool
	Names     []*dnsName
	// what the derivation skipped and why, in order
	Notes []string
}

// dnsPlanInput is what the derivation needs from the environment.
type dnsPlanInput struct {
	Env            string
	EnvAliases     []string
	ServicesConfig *services.ServicesConfig
}

// dnsFamilySuffix reports whether a name's first label ends in -v4 or -v6,
// and returns the families it carries.
func dnsFamilySuffix(name string) (hasIpv4 bool, hasIpv6 bool) {
	label, _, _ := strings.Cut(name, ".")
	switch {
	case strings.HasSuffix(label, "-v4"):
		return true, false
	case strings.HasSuffix(label, "-v6"):
		return false, true
	}
	return true, true
}

// dnsShortHost is the host's label in a derived name: the host without the
// primary domain, with any remaining dots folded into dashes.
func dnsShortHost(host string, domain string) string {
	short := strings.TrimSuffix(host, "."+domain)
	return strings.ReplaceAll(short, ".", "-")
}

// dnsUnderDomain reports whether name is domain itself or a name under it.
func dnsUnderDomain(name string, domain string) bool {
	return name == domain || strings.HasSuffix(name, "."+domain)
}

func dnsUnderAnyDomain(name string, domains []string) bool {
	for _, domain := range domains {
		if dnsUnderDomain(name, domain) {
			return true
		}
	}
	return false
}

// dnsInterface is one lb interface with its addresses.
type dnsInterface struct {
	host          string
	interfaceName string
	block         *services.LbBlock
}

// dnsDerivation carries what every domain's derivation shares.
type dnsDerivation struct {
	input      dnsPlanInput
	primary    string
	interfaces []dnsInterface
	lbHosts    map[string]bool
	members    []dnsMember
	// whether any lb set member has an IPv6 address
	hasIpv6Member bool
	envNames      []string
	serviceNames  []string
}

func (self *dnsDerivation) hostAddresses(host string) (ipv4s []string, ipv6s []string) {
	for _, lbInterface := range self.interfaces {
		if lbInterface.host != host {
			continue
		}
		if lbInterface.block.Ipv4 != "" {
			ipv4s = append(ipv4s, lbInterface.block.Ipv4)
		}
		if lbInterface.block.Ipv6 != "" {
			ipv6s = append(ipv6s, lbInterface.block.Ipv6)
		}
	}
	return ipv4s, ipv6s
}

// dnsDerive builds the desired names of every registrar domain.
func dnsDerive(input dnsPlanInput) ([]*dnsDomain, error) {
	servicesConfig := input.ServicesConfig
	latest := servicesConfig.Latest()
	if latest == nil || latest.Lb == nil {
		return nil, fmt.Errorf("the services config has no lb")
	}
	derivation := &dnsDerivation{
		input:    input,
		primary:  servicesConfig.GetDomain(),
		lbHosts:  map[string]bool{},
		envNames: append([]string{input.Env}, input.EnvAliases...),
	}
	hosts := maps.Keys(latest.Lb.Interfaces)
	sort.Strings(hosts)
	for _, host := range hosts {
		interfaceNames := maps.Keys(latest.Lb.Interfaces[host])
		sort.Strings(interfaceNames)
		for _, interfaceName := range interfaceNames {
			block := latest.Lb.Interfaces[host][interfaceName]
			if block == nil {
				continue
			}
			for _, address := range []string{block.Ipv4, block.Ipv6} {
				if address == "" {
					continue
				}
				if _, err := netip.ParseAddr(address); err != nil {
					return nil, fmt.Errorf("%s %s address %q: %w", host, interfaceName, address, err)
				}
			}
			derivation.interfaces = append(derivation.interfaces, dnsInterface{host: host, interfaceName: interfaceName, block: block})
			derivation.lbHosts[host] = true
			if block.Transparent || block.Ipv4 == "" {
				continue
			}
			derivation.members = append(derivation.members, dnsMember{
				Id:     fmt.Sprintf("%s-%s", dnsShortHost(host, derivation.primary), interfaceName),
				Ipv4:   block.Ipv4,
				Ipv6:   block.Ipv6,
				Weight: block.GetDnsWeight(),
			})
			if block.Ipv6 != "" {
				derivation.hasIpv6Member = true
			}
		}
	}
	if len(derivation.members) == 0 {
		return nil, fmt.Errorf("no lb interface runs a front; the %s-lb set would be empty", input.Env)
	}
	derivation.serviceNames = maps.Keys(latest.Services)
	sort.Strings(derivation.serviceNames)
	for _, service := range servicesConfig.DnsOtherDomainServices() {
		serviceConfig, ok := latest.Services[service]
		if !ok || serviceConfig == nil {
			return nil, fmt.Errorf("dns other_domain_services names unknown service %q", service)
		}
		if !serviceConfig.IsExposed() {
			return nil, fmt.Errorf("dns other_domain_services names %q, which is not an exposed service", service)
		}
	}

	registrars := servicesConfig.DomainRegistrars()
	domains := []*dnsDomain{}
	for _, domain := range servicesConfig.DomainNames() {
		registrar := registrars[domain]
		if registrar == "" {
			continue
		}
		derived, err := derivation.domain(domain, registrar)
		if err != nil {
			return nil, err
		}
		domains = append(domains, derived)
	}
	return domains, nil
}

// domain derives one registrar domain.
func (self *dnsDerivation) domain(domain string, registrar string) (*dnsDomain, error) {
	servicesConfig := self.input.ServicesConfig
	latest := servicesConfig.Latest()
	derived := &dnsDomain{Domain: domain, Registrar: registrar, Primary: domain == self.primary}
	byName := map[string]*dnsName{}
	add := func(name *dnsName) error {
		name.Name = strings.ToLower(name.Name)
		if servicesConfig.IsDnsUnmanaged(name.Name) {
			derived.Notes = append(derived.Notes, fmt.Sprintf("%s: unmanaged (%s)", name.Name, name.Source))
			return nil
		}
		if existing, ok := byName[name.Name]; ok {
			if dnsNamesEqual(existing, name) {
				return nil
			}
			return fmt.Errorf("%s is derived twice with different records (%s and %s)", name.Name, existing.Source, name.Source)
		}
		byName[name.Name] = name
		derived.Names = append(derived.Names, name)
		return nil
	}
	// an alias under this domain of the env's lb set, one family per -v4/-v6 name
	addLbAlias := func(alias string, source string) error {
		hasIpv4, hasIpv6 := dnsFamilySuffix(alias)
		hasIpv6 = hasIpv6 && self.hasIpv6Member
		if !hasIpv4 && !hasIpv6 {
			derived.Notes = append(derived.Notes, fmt.Sprintf("%s: no lb member has an ipv6 address (%s)", alias, source))
			return nil
		}
		return add(&dnsName{Name: alias, Kind: dnsAliasTo, Target: fmt.Sprintf("%s-lb.%s", self.input.Env, domain), HasIpv4: hasIpv4, HasIpv6: hasIpv6, Source: source})
	}
	// an alias of a service that lies elsewhere: noted once, on the primary
	// domain, when no registrar domain carries it
	foreign := func(alias string, source string) {
		if derived.Primary && !dnsUnderAnyDomain(alias, servicesConfig.DomainNames()) {
			derived.Notes = append(derived.Notes, fmt.Sprintf("%s: not under a registrar domain (%s)", alias, source))
		}
	}

	// the lb set, on every domain
	for _, env := range self.envNames {
		lbName := fmt.Sprintf("%s-lb.%s", env, domain)
		if err := add(&dnsName{Name: lbName, Kind: dnsLbSet, Members: self.members, HasIpv4: true, HasIpv6: self.hasIpv6Member, Source: "lb set"}); err != nil {
			return nil, err
		}
		if !derived.Primary {
			continue
		}
		for _, family := range []string{"v4", "v6"} {
			hasIpv4, hasIpv6 := family == "v4", family == "v6"
			if hasIpv6 && !self.hasIpv6Member {
				continue
			}
			if err := add(&dnsName{Name: fmt.Sprintf("%s-lb-%s.%s", env, family, domain), Kind: dnsAliasTo, Target: lbName, HasIpv4: hasIpv4, HasIpv6: hasIpv6, Source: "lb set " + family}); err != nil {
				return nil, err
			}
		}
	}

	if !derived.Primary {
		// another domain: only the listed services' aliases under it
		for _, service := range servicesConfig.DnsOtherDomainServices() {
			serviceConfig := latest.Services[service]
			aliases := append(append([]string{}, serviceConfig.ExposeAliases...), serviceConfig.ExposeDomains...)
			for _, alias := range aliases {
				alias = strings.ToLower(alias)
				if !dnsUnderDomain(alias, domain) {
					continue
				}
				if err := addLbAlias(alias, "service "+service+" alias"); err != nil {
					return nil, err
				}
			}
		}
		return self.finish(derived, byName)
	}

	// the primary domain: interface records
	for _, lbInterface := range self.interfaces {
		if lbInterface.block.Ipv4 == "" {
			derived.Notes = append(derived.Notes, fmt.Sprintf("%s %s: no ipv4, no interface record", lbInterface.host, lbInterface.interfaceName))
			continue
		}
		name := &dnsName{
			Name:    fmt.Sprintf("%s-%s.%s", dnsShortHost(lbInterface.host, self.primary), lbInterface.interfaceName, domain),
			Kind:    dnsAddresses,
			Ipv4:    []string{lbInterface.block.Ipv4},
			HasIpv4: true,
			Source:  fmt.Sprintf("lb interface %s %s", lbInterface.host, lbInterface.interfaceName),
		}
		if lbInterface.block.Ipv6 != "" {
			name.Ipv6 = []string{lbInterface.block.Ipv6}
			name.HasIpv6 = true
		}
		if err := add(name); err != nil {
			return nil, err
		}
	}

	// services
	for _, service := range self.serviceNames {
		serviceConfig := latest.Services[service]
		if serviceConfig == nil {
			continue
		}
		aliases := append(append([]string{}, serviceConfig.ExposeAliases...), serviceConfig.ExposeDomains...)
		if serviceConfig.IsExposed() {
			// behind the lb
			for _, env := range self.envNames {
				if err := add(&dnsName{Name: fmt.Sprintf("%s-%s.%s", env, service, domain), Kind: dnsAliasTo, Target: fmt.Sprintf("%s-lb.%s", env, domain), HasIpv4: true, HasIpv6: self.hasIpv6Member, Source: "service " + service}); err != nil {
					return nil, err
				}
			}
			for _, alias := range aliases {
				alias = strings.ToLower(alias)
				if !dnsUnderDomain(alias, domain) {
					foreign(alias, "service "+service)
					continue
				}
				if err := addLbAlias(alias, "service "+service+" alias"); err != nil {
					return nil, err
				}
			}
			continue
		}
		// a host-pinned service with no lb in front: the alt service
		if len(serviceConfig.Hosts) == 0 || (len(serviceConfig.ExternalUdpPorts) == 0 && len(serviceConfig.DnsAliases) == 0) {
			continue
		}
		ipv4s, ipv6s := []string{}, []string{}
		for _, host := range serviceConfig.Hosts {
			if !self.lbHosts[host] {
				derived.Notes = append(derived.Notes, fmt.Sprintf("service %s host %s has no lb interface and no addresses", service, host))
				continue
			}
			hostIpv4s, hostIpv6s := self.hostAddresses(host)
			ipv4s = append(ipv4s, hostIpv4s...)
			ipv6s = append(ipv6s, hostIpv6s...)
		}
		if len(ipv4s) == 0 {
			derived.Notes = append(derived.Notes, fmt.Sprintf("service %s: no host address, no records", service))
			continue
		}
		direct := func(name string, hasIpv4 bool, hasIpv6 bool, source string) error {
			hasIpv6 = hasIpv6 && 0 < len(ipv6s)
			if !hasIpv4 && !hasIpv6 {
				derived.Notes = append(derived.Notes, fmt.Sprintf("%s: no host has an ipv6 address (service %s)", name, service))
				return nil
			}
			record := &dnsName{Name: name, Kind: dnsAddresses, HasIpv4: hasIpv4, HasIpv6: hasIpv6, Source: source}
			if hasIpv4 {
				record.Ipv4 = append([]string{}, ipv4s...)
			}
			if hasIpv6 {
				record.Ipv6 = append([]string{}, ipv6s...)
			}
			return add(record)
		}
		for _, env := range self.envNames {
			if err := direct(fmt.Sprintf("%s-%s.%s", env, service, domain), true, true, "service "+service+" (direct)"); err != nil {
				return nil, err
			}
			if err := direct(fmt.Sprintf("%s-%s-v4.%s", env, service, domain), true, false, "service "+service+" (direct) v4"); err != nil {
				return nil, err
			}
			if err := direct(fmt.Sprintf("%s-%s-v6.%s", env, service, domain), false, true, "service "+service+" (direct) v6"); err != nil {
				return nil, err
			}
		}
		for _, alias := range serviceConfig.DnsAliases {
			alias = strings.ToLower(alias)
			if !dnsUnderDomain(alias, domain) {
				derived.Notes = append(derived.Notes, fmt.Sprintf("%s: not under the primary domain, left alone (service %s dns alias)", alias, service))
				continue
			}
			hasIpv4, hasIpv6 := dnsFamilySuffix(alias)
			if err := direct(alias, hasIpv4, hasIpv6, "service "+service+" dns alias"); err != nil {
				return nil, err
			}
		}
	}

	// top level expose aliases of lb hosts: the plain names first, so a
	// wildcard can alias its base
	exposeAliases := append([]string{}, servicesConfig.ExposeAliases...)
	sort.SliceStable(exposeAliases, func(i int, j int) bool {
		return !strings.HasPrefix(exposeAliases[i], "*.") && strings.HasPrefix(exposeAliases[j], "*.")
	})
	for _, alias := range exposeAliases {
		alias = strings.ToLower(alias)
		if !dnsUnderDomain(alias, domain) {
			if !dnsUnderAnyDomain(alias, servicesConfig.DomainNames()) {
				derived.Notes = append(derived.Notes, fmt.Sprintf("%s: not under a registrar domain (expose alias)", alias))
			} else {
				derived.Notes = append(derived.Notes, fmt.Sprintf("%s: not under the primary domain, left alone (expose alias)", alias))
			}
			continue
		}
		base := strings.TrimPrefix(alias, "*.")
		label := strings.TrimSuffix(base, "."+domain)
		host := ""
		for candidate := range self.lbHosts {
			if dnsShortHost(candidate, self.primary) == label {
				host = candidate
			}
		}
		if host == "" {
			derived.Notes = append(derived.Notes, fmt.Sprintf("%s: not an lb host, left alone (expose alias)", alias))
			continue
		}
		ipv4s, ipv6s := self.hostAddresses(host)
		if len(ipv4s) == 0 {
			derived.Notes = append(derived.Notes, fmt.Sprintf("%s: host %s has no address (expose alias)", alias, host))
			continue
		}
		if _, derivedBase := byName[base]; base != alias && derivedBase {
			if err := add(&dnsName{Name: alias, Kind: dnsAliasTo, Target: base, HasIpv4: true, HasIpv6: 0 < len(ipv6s), Source: "expose alias " + host + " wildcard"}); err != nil {
				return nil, err
			}
			continue
		}
		if err := add(&dnsName{Name: alias, Kind: dnsAddresses, Ipv4: ipv4s, Ipv6: ipv6s, HasIpv4: true, HasIpv6: 0 < len(ipv6s), Source: "expose alias " + host}); err != nil {
			return nil, err
		}
	}
	return self.finish(derived, byName)
}

// finish resolves the aliases' addresses (a registrar without aliases
// carries them as records), checks every target exists and orders the names.
func (self *dnsDerivation) finish(derived *dnsDomain, byName map[string]*dnsName) (*dnsDomain, error) {
	for _, name := range derived.Names {
		if name.Kind != dnsAliasTo {
			continue
		}
		target, ok := byName[name.Target]
		if !ok {
			return nil, fmt.Errorf("%s aliases %s, which is not derived (unmanaged?)", name.Name, name.Target)
		}
		ipv4s, ipv6s := dnsResolve(target, byName, 0)
		if name.HasIpv4 {
			name.Ipv4 = ipv4s
		}
		if name.HasIpv6 {
			name.Ipv6 = ipv6s
		}
		if name.HasIpv4 && len(name.Ipv4) == 0 {
			return nil, fmt.Errorf("%s aliases %s, which has no ipv4 address", name.Name, name.Target)
		}
	}
	sort.Slice(derived.Names, func(i int, j int) bool {
		return derived.Names[i].Name < derived.Names[j].Name
	})
	return derived, nil
}

// dnsResolve returns the addresses a name ultimately holds.
func dnsResolve(name *dnsName, byName map[string]*dnsName, depth int) (ipv4s []string, ipv6s []string) {
	if depth > 8 {
		return nil, nil
	}
	switch name.Kind {
	case dnsAddresses:
		return name.Ipv4, name.Ipv6
	case dnsLbSet:
		for _, member := range name.Members {
			ipv4s = append(ipv4s, member.Ipv4)
			if member.Ipv6 != "" {
				ipv6s = append(ipv6s, member.Ipv6)
			}
		}
		return ipv4s, ipv6s
	default:
		target, ok := byName[name.Target]
		if !ok {
			return nil, nil
		}
		ipv4s, ipv6s = dnsResolve(target, byName, depth+1)
		if !name.HasIpv4 {
			ipv4s = nil
		}
		if !name.HasIpv6 {
			ipv6s = nil
		}
		return ipv4s, ipv6s
	}
}

func dnsNamesEqual(a *dnsName, b *dnsName) bool {
	if a.Kind != b.Kind || a.Target != b.Target || a.HasIpv4 != b.HasIpv4 || a.HasIpv6 != b.HasIpv6 {
		return false
	}
	if !stringsEqual(a.Ipv4, b.Ipv4) || !stringsEqual(a.Ipv6, b.Ipv6) || len(a.Members) != len(b.Members) {
		return false
	}
	for i := range a.Members {
		if a.Members[i] != b.Members[i] {
			return false
		}
	}
	return true
}

func stringsEqual(a []string, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// dnsChange is one planned change, for the plan output.
type dnsChange struct {
	// "+" create, "~" update, "-" delete
	Op   string
	What string
}

func (c dnsChange) String() string {
	return c.Op + " " + c.What
}

// dnsProvider reconciles one domain with its derived names.
type dnsProvider interface {
	// Plan computes the changes for the domain without applying them.
	Plan(domain *dnsDomain, input dnsPlanInput) ([]dnsChange, error)
	// Apply computes and applies the changes, returning what it did.
	Apply(domain *dnsDomain, input dnsPlanInput) ([]dnsChange, error)
}

// dnsStatusPath is the lb status route the route53 health checks request.
func dnsStatusPath(servicesConfig *services.ServicesConfig) (string, error) {
	if len(servicesConfig.LbHiddenPrefixes) == 0 {
		return "", fmt.Errorf("the services config has no lb_hidden_prefixes for the health check path")
	}
	return "/" + strings.Trim(servicesConfig.LbHiddenPrefixes[0], "/") + "/status", nil
}
