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
// registrar (route53 or cloudflare) with them. The records are, per domain D:
//
//   - `<host>-<iface>.D`: the address of every lb interface (A, and AAAA when
//     the interface has an IPv6 address)
//   - `<env>-lb.D`: the lb interfaces that run a front (not the transparent
//     ones), weighted by dns_weight and health checked on route53, round
//     robin on cloudflare; `<env>-lb-v4.D` and `<env>-lb-v6.D` carry one
//     address family
//   - `<env>-<service>.D` for every exposed service, and the service's
//     expose_aliases and expose_domains under D: aliases of `<env>-lb.D`,
//     where a name whose first label ends in -v4 or -v6 carries one family
//   - `<env>-<service>.D` for a host-pinned service with no lb in front (the
//     alt service), and its dns_aliases under D: the interface addresses of
//     its hosts, again with -v4 and -v6 names per family
//   - a top level expose alias `<host>.D` of an lb host: the host's
//     addresses; `*.<host>.D`: an alias of it
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

// dnsDerive builds the desired names of every registrar domain.
func dnsDerive(input dnsPlanInput) ([]*dnsDomain, error) {
	servicesConfig := input.ServicesConfig
	latest := servicesConfig.Latest()
	if latest == nil || latest.Lb == nil {
		return nil, fmt.Errorf("the services config has no lb")
	}
	primary := servicesConfig.GetDomain()
	registrars := servicesConfig.DomainRegistrars()

	// the lb interfaces in host, interface order
	type lbInterface struct {
		host          string
		interfaceName string
		block         *services.LbBlock
	}
	interfaces := []lbInterface{}
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
			interfaces = append(interfaces, lbInterface{host: host, interfaceName: interfaceName, block: block})
		}
	}
	hostAddresses := func(host string) (ipv4s []string, ipv6s []string) {
		for _, lbInterface := range interfaces {
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
	lbHosts := map[string]bool{}
	for _, lbInterface := range interfaces {
		lbHosts[lbInterface.host] = true
	}
	for _, lbInterface := range interfaces {
		for _, address := range []string{lbInterface.block.Ipv4, lbInterface.block.Ipv6} {
			if address == "" {
				continue
			}
			if _, err := netip.ParseAddr(address); err != nil {
				return nil, fmt.Errorf("%s %s address %q: %w", lbInterface.host, lbInterface.interfaceName, address, err)
			}
		}
	}

	envNames := append([]string{input.Env}, input.EnvAliases...)
	serviceNames := maps.Keys(latest.Services)
	sort.Strings(serviceNames)

	domains := []*dnsDomain{}
	for _, domain := range servicesConfig.DomainNames() {
		registrar := registrars[domain]
		if registrar == "" {
			continue
		}
		derived := &dnsDomain{Domain: domain, Registrar: registrar}
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

		// interface records
		for _, lbInterface := range interfaces {
			if lbInterface.block.Ipv4 == "" {
				derived.Notes = append(derived.Notes, fmt.Sprintf("%s %s: no ipv4, no interface record", lbInterface.host, lbInterface.interfaceName))
				continue
			}
			name := &dnsName{
				Name:    fmt.Sprintf("%s-%s.%s", dnsShortHost(lbInterface.host, primary), lbInterface.interfaceName, domain),
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

		// the lb set and its family names
		members := []dnsMember{}
		for _, lbInterface := range interfaces {
			if lbInterface.block.Transparent || lbInterface.block.Ipv4 == "" {
				continue
			}
			members = append(members, dnsMember{
				Id:     fmt.Sprintf("%s-%s", dnsShortHost(lbInterface.host, primary), lbInterface.interfaceName),
				Ipv4:   lbInterface.block.Ipv4,
				Ipv6:   lbInterface.block.Ipv6,
				Weight: lbInterface.block.GetDnsWeight(),
			})
		}
		if len(members) == 0 {
			return nil, fmt.Errorf("no lb interface runs a front; the %s-lb set would be empty", input.Env)
		}
		hasIpv6Member := false
		for _, member := range members {
			if member.Ipv6 != "" {
				hasIpv6Member = true
			}
		}
		for _, env := range envNames {
			lbName := fmt.Sprintf("%s-lb.%s", env, domain)
			if err := add(&dnsName{Name: lbName, Kind: dnsLbSet, Members: members, HasIpv4: true, HasIpv6: hasIpv6Member, Source: "lb set"}); err != nil {
				return nil, err
			}
			for _, family := range []string{"v4", "v6"} {
				hasIpv4, hasIpv6 := family == "v4", family == "v6"
				if hasIpv6 && !hasIpv6Member {
					continue
				}
				if err := add(&dnsName{Name: fmt.Sprintf("%s-lb-%s.%s", env, family, domain), Kind: dnsAliasTo, Target: lbName, HasIpv4: hasIpv4, HasIpv6: hasIpv6, Source: "lb set " + family}); err != nil {
					return nil, err
				}
			}
		}

		// services
		for _, service := range serviceNames {
			serviceConfig := latest.Services[service]
			if serviceConfig == nil {
				continue
			}
			if serviceConfig.IsExposed() {
				// behind the lb
				for _, env := range envNames {
					lbName := fmt.Sprintf("%s-lb.%s", env, domain)
					serviceName := fmt.Sprintf("%s-%s.%s", env, service, domain)
					if err := add(&dnsName{Name: serviceName, Kind: dnsAliasTo, Target: lbName, HasIpv4: true, HasIpv6: hasIpv6Member, Source: "service " + service}); err != nil {
						return nil, err
					}
					for _, family := range []string{"v4", "v6"} {
						hasIpv4, hasIpv6 := family == "v4", family == "v6"
						if hasIpv6 && !hasIpv6Member {
							continue
						}
						if err := add(&dnsName{Name: fmt.Sprintf("%s-%s-%s.%s", env, service, family, domain), Kind: dnsAliasTo, Target: lbName, HasIpv4: hasIpv4, HasIpv6: hasIpv6, Source: "service " + service + " " + family}); err != nil {
							return nil, err
						}
					}
				}
				aliases := append(append([]string{}, serviceConfig.ExposeAliases...), serviceConfig.ExposeDomains...)
				for _, alias := range aliases {
					alias = strings.ToLower(alias)
					if !dnsUnderDomain(alias, domain) {
						if !dnsUnderAnyDomain(alias, servicesConfig.DomainNames()) && domain == primary {
							derived.Notes = append(derived.Notes, fmt.Sprintf("%s: not under a registrar domain (service %s)", alias, service))
						}
						continue
					}
					hasIpv4, hasIpv6 := dnsFamilySuffix(alias)
					hasIpv6 = hasIpv6 && hasIpv6Member
					if !hasIpv4 && !hasIpv6 {
						derived.Notes = append(derived.Notes, fmt.Sprintf("%s: no member has an ipv6 address (service %s)", alias, service))
						continue
					}
					if err := add(&dnsName{Name: alias, Kind: dnsAliasTo, Target: fmt.Sprintf("%s-lb.%s", input.Env, domain), HasIpv4: hasIpv4, HasIpv6: hasIpv6, Source: "service " + service + " alias"}); err != nil {
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
				if !lbHosts[host] {
					derived.Notes = append(derived.Notes, fmt.Sprintf("service %s host %s has no lb interface and no addresses", service, host))
					continue
				}
				hostIpv4s, hostIpv6s := hostAddresses(host)
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
			for _, env := range envNames {
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
					if !dnsUnderAnyDomain(alias, servicesConfig.DomainNames()) && domain == primary {
						derived.Notes = append(derived.Notes, fmt.Sprintf("%s: not under a registrar domain (service %s)", alias, service))
					}
					continue
				}
				hasIpv4, hasIpv6 := dnsFamilySuffix(alias)
				if err := direct(alias, hasIpv4, hasIpv6, "service "+service+" dns alias"); err != nil {
					return nil, err
				}
			}
		}

		// top level expose aliases of lb hosts: the plain names first, so a
		// wildcard can alias its base when the base is derived too
		exposeAliases := append([]string{}, servicesConfig.ExposeAliases...)
		sort.SliceStable(exposeAliases, func(i int, j int) bool {
			return !strings.HasPrefix(exposeAliases[i], "*.") && strings.HasPrefix(exposeAliases[j], "*.")
		})
		for _, alias := range exposeAliases {
			alias = strings.ToLower(alias)
			if !dnsUnderDomain(alias, domain) {
				if !dnsUnderAnyDomain(alias, servicesConfig.DomainNames()) && domain == primary {
					derived.Notes = append(derived.Notes, fmt.Sprintf("%s: not under a registrar domain (expose alias)", alias))
				}
				continue
			}
			base := strings.TrimPrefix(alias, "*.")
			label := strings.TrimSuffix(base, "."+domain)
			host := ""
			for candidate := range lbHosts {
				if dnsShortHost(candidate, primary) == label {
					host = candidate
				}
			}
			if host == "" {
				derived.Notes = append(derived.Notes, fmt.Sprintf("%s: not an lb host, left alone (expose alias)", alias))
				continue
			}
			ipv4s, ipv6s := hostAddresses(host)
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

		// resolve the aliases' addresses for registrars without aliases and
		// check every target exists
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
		domains = append(domains, derived)
	}
	return domains, nil
}

func dnsUnderAnyDomain(name string, domains []string) bool {
	for _, domain := range domains {
		if dnsUnderDomain(name, domain) {
			return true
		}
	}
	return false
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
