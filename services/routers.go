package services

import (
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"sort"

	"golang.org/x/exp/maps"
)

// RouterNamePattern is the router hostname convention: <site>-<n>-<m> with
// single digit n and m. The digits "nm" form the router id that the IPv6 and
// management addressing derive from.
var RouterNamePattern = regexp.MustCompile(`^([a-z0-9]+(?:-[a-z0-9]+)*)-([0-9])-([0-9])$`)

// RouterLanInterfacePattern is a router LAN port name: ethP with a single
// digit P, which the port's /64 encodes.
var RouterLanInterfacePattern = regexp.MustCompile(`^eth([0-9])$`)

var routerInterfaceNamePattern = regexp.MustCompile(`^[a-z][a-z0-9]*$`)
var publicPortNamePattern = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)
var routerPublicKeyNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)
var routerLoginNamePattern = regexp.MustCompile(`^[a-z_][a-z0-9_-]*$`)

// RouterId returns the digits "nm" of a router named <site>-<n>-<m>.
func RouterId(router string) (string, error) {
	groups := RouterNamePattern.FindStringSubmatch(router)
	if groups == nil {
		return "", fmt.Errorf("router %q does not follow the <site>-<n>-<m> hostname convention", router)
	}
	return groups[2] + groups[3], nil
}

// RouterLanPort returns the port digit of a router LAN interface named ethP.
func RouterLanPort(interfaceName string) (int, error) {
	groups := RouterLanInterfacePattern.FindStringSubmatch(interfaceName)
	if groups == nil {
		return 0, fmt.Errorf("router interface %q is not a single digit eth port", interfaceName)
	}
	return int(groups[1][0] - '0'), nil
}

// validateRouters checks the routers section on its own: names follow the
// convention, addresses parse and agree with each other, ports are listed
// once and every router has an admin login.
func validateRouters(servicesConfig *ServicesConfig) error {
	names := maps.Keys(servicesConfig.Routers)
	sort.Strings(names)
	managementAddresses := map[string]string{}
	for _, name := range names {
		router := servicesConfig.Routers[name]
		if router == nil {
			return fmt.Errorf("router %q has no config", name)
		}
		if _, err := RouterId(name); err != nil {
			return err
		}
		managementAddress, err := netip.ParseAddr(router.ManagementIpv4)
		if err != nil || !managementAddress.Is4() {
			return fmt.Errorf("router %q management_ipv4 %q is not an ipv4 address", name, router.ManagementIpv4)
		}
		if other, ok := managementAddresses[router.ManagementIpv4]; ok {
			return fmt.Errorf("routers %q and %q share management_ipv4 %s", other, name, router.ManagementIpv4)
		}
		managementAddresses[router.ManagementIpv4] = name
		if !routerInterfaceNamePattern.MatchString(router.WanInterface) {
			return fmt.Errorf("router %q wan_interface %q is not an interface name", name, router.WanInterface)
		}
		wanIpv4, err := netip.ParsePrefix(router.WanIpv4)
		if err != nil || !wanIpv4.Addr().Is4() {
			return fmt.Errorf("router %q wan_ipv4 %q is not an ipv4 address with a prefix length", name, router.WanIpv4)
		}
		if wanIpv4.Bits() >= 31 {
			return fmt.Errorf("router %q wan_ipv4 %q leaves no room for hosts", name, router.WanIpv4)
		}
		wanGatewayIpv4, err := netip.ParseAddr(router.WanGatewayIpv4)
		if err != nil || !wanGatewayIpv4.Is4() {
			return fmt.Errorf("router %q wan_gateway_ipv4 %q is not an ipv4 address", name, router.WanGatewayIpv4)
		}
		if !wanIpv4.Masked().Contains(wanGatewayIpv4) {
			return fmt.Errorf("router %q wan_gateway_ipv4 %s is outside wan_ipv4 %s", name, router.WanGatewayIpv4, router.WanIpv4)
		}
		if wanGatewayIpv4 == wanIpv4.Addr() {
			return fmt.Errorf("router %q wan_gateway_ipv4 %s is the router's own address", name, router.WanGatewayIpv4)
		}
		wanIpv6Prefix, err := netip.ParsePrefix(router.WanIpv6Prefix)
		if err != nil || !wanIpv6Prefix.Addr().Is6() || wanIpv6Prefix.Addr().Is4In6() {
			return fmt.Errorf("router %q wan_ipv6_prefix %q is not an ipv6 prefix", name, router.WanIpv6Prefix)
		}
		if wanIpv6Prefix.Bits() != 48 || wanIpv6Prefix.Masked() != wanIpv6Prefix {
			return fmt.Errorf("router %q wan_ipv6_prefix %q must be a /48 with zero host bits", name, router.WanIpv6Prefix)
		}
		wanGatewayIpv6, err := netip.ParseAddr(router.WanGatewayIpv6)
		if err != nil || !wanGatewayIpv6.Is6() || wanGatewayIpv6.Is4In6() {
			return fmt.Errorf("router %q wan_gateway_ipv6 %q is not an ipv6 address", name, router.WanGatewayIpv6)
		}
		if !wanIpv6Prefix.Contains(wanGatewayIpv6) {
			return fmt.Errorf("router %q wan_gateway_ipv6 %s is outside wan_ipv6_prefix %s", name, router.WanGatewayIpv6, router.WanIpv6Prefix)
		}
		if len(router.LanInterfaces) == 0 {
			return fmt.Errorf("router %q has no lan_interfaces", name)
		}
		seenInterfaces := map[string]bool{router.WanInterface: true}
		for _, lanInterface := range router.LanInterfaces {
			if _, err := RouterLanPort(lanInterface); err != nil {
				return fmt.Errorf("router %q: %w", name, err)
			}
			if seenInterfaces[lanInterface] {
				return fmt.Errorf("router %q lists interface %s twice", name, lanInterface)
			}
			seenInterfaces[lanInterface] = true
		}
		for _, bridgeInterface := range router.BridgeInterfaces {
			if !routerInterfaceNamePattern.MatchString(bridgeInterface) {
				return fmt.Errorf("router %q bridge interface %q is not an interface name", name, bridgeInterface)
			}
			if seenInterfaces[bridgeInterface] {
				return fmt.Errorf("router %q lists interface %s twice", name, bridgeInterface)
			}
			seenInterfaces[bridgeInterface] = true
		}
		if router.LanIpv4 != "" {
			lanIpv4, err := netip.ParsePrefix(router.LanIpv4)
			if err != nil || !lanIpv4.Addr().Is4() || lanIpv4.Bits() != 24 {
				return fmt.Errorf("router %q lan_ipv4 %q must be an ipv4 address with a /24 prefix length", name, router.LanIpv4)
			}
			if lanIpv4.Addr() == lanIpv4.Masked().Addr() {
				return fmt.Errorf("router %q lan_ipv4 %q must be the bridge address, not the network", name, router.LanIpv4)
			}
		}
		for _, nameServer := range router.NameServers {
			if _, err := netip.ParseAddr(nameServer); err != nil {
				return fmt.Errorf("router %q name server %q is not an ip address", name, nameServer)
			}
		}
		if router.EdgeosRelease == "" || router.EdgeosConfigVersion == "" {
			return fmt.Errorf("router %q needs edgeos_release and edgeos_config_version for the config.boot footer", name)
		}
		for _, size := range []struct {
			field string
			value int
		}{{"conntrack_table_size", router.ConntrackTableSize}, {"conntrack_hash_size", router.ConntrackHashSize}} {
			if size.value < 0 || RouterConntrackSizeMax < size.value {
				return fmt.Errorf("router %q %s %d is outside 1..%d", name, size.field, size.value, RouterConntrackSizeMax)
			}
		}
		if router.ConntrackTableSize != 0 && router.ConntrackHashSize != 0 && router.ConntrackTableSize < router.ConntrackHashSize {
			return fmt.Errorf("router %q conntrack_hash_size %d exceeds conntrack_table_size %d", name, router.ConntrackHashSize, router.ConntrackTableSize)
		}
		if router.OffloadsIpv6Forwarding() && !router.OffloadsIpv4Forwarding() {
			return fmt.Errorf("router %q offload_ipv6_forwarding needs offload_ipv4_forwarding", name)
		}
		if len(router.Login) == 0 {
			return fmt.Errorf("router %q has no login users", name)
		}
		hasAdmin := false
		logins := maps.Keys(router.Login)
		sort.Strings(logins)
		for _, user := range logins {
			login := router.Login[user]
			if !routerLoginNamePattern.MatchString(user) {
				return fmt.Errorf("router %q login %q is not a user name", name, user)
			}
			if login == nil || login.EncryptedPassword == "" {
				return fmt.Errorf("router %q login %q has no encrypted_password", name, user)
			}
			switch login.GetLevel() {
			case "admin":
				hasAdmin = true
			case "operator":
			default:
				return fmt.Errorf("router %q login %q level %q is not admin or operator", name, user, login.Level)
			}
			keyNames := maps.Keys(login.PublicKeys)
			sort.Strings(keyNames)
			for _, keyName := range keyNames {
				publicKey := login.PublicKeys[keyName]
				if !routerPublicKeyNamePattern.MatchString(keyName) {
					return fmt.Errorf("router %q login %q public key %q is not a key name", name, user, keyName)
				}
				if publicKey == nil || publicKey.Type == "" || publicKey.Key == "" {
					return fmt.Errorf("router %q login %q public key %q needs a type and a key", name, user, keyName)
				}
			}
		}
		if !hasAdmin {
			return fmt.Errorf("router %q has no admin login", name)
		}
		if !router.HasAdminPublicKey() {
			return fmt.Errorf("router %q has no admin login with a public key; ssh password authentication is disabled on the routers", name)
		}
	}
	return nil
}

// RouterConntrackSizeMax bounds `system conntrack table-size` and
// `hash-size`, as the EdgeOS templates do.
const RouterConntrackSizeMax = 50000000

// validateRouterInterfaces checks the lb interfaces of one version against
// the routers: an attached interface names an existing router and one of
// its LAN ports, no port carries two interfaces, and an attached
// interface's IPv6 address lies in the /64 its port advertises.
func validateRouterInterfaces(servicesConfig *ServicesConfig, version *ServicesConfigVersion) error {
	if version == nil || version.Lb == nil {
		return nil
	}
	type portClaim struct {
		router        string
		interfaceName string
	}
	claims := map[portClaim]string{}
	hosts := maps.Keys(version.Lb.Interfaces)
	sort.Strings(hosts)
	for _, host := range hosts {
		interfaceNames := maps.Keys(version.Lb.Interfaces[host])
		sort.Strings(interfaceNames)
		for _, interfaceName := range interfaceNames {
			lbBlock := version.Lb.Interfaces[host][interfaceName]
			if lbBlock == nil || (lbBlock.Router == "" && lbBlock.RouterInterface == "") {
				continue
			}
			hostInterface := fmt.Sprintf("%s %s", host, interfaceName)
			if lbBlock.Router == "" || lbBlock.RouterInterface == "" {
				return fmt.Errorf("%s sets only one of router and router_interface", hostInterface)
			}
			router, ok := servicesConfig.Routers[lbBlock.Router]
			if !ok {
				return fmt.Errorf("%s names unknown router %q", hostInterface, lbBlock.Router)
			}
			if !slices.Contains(router.LanInterfaces, lbBlock.RouterInterface) {
				return fmt.Errorf("%s names %s %s, which is not one of its lan_interfaces", hostInterface, lbBlock.Router, lbBlock.RouterInterface)
			}
			claim := portClaim{router: lbBlock.Router, interfaceName: lbBlock.RouterInterface}
			if other, claimed := claims[claim]; claimed {
				return fmt.Errorf("%s and %s are both attached to %s %s", other, hostInterface, lbBlock.Router, lbBlock.RouterInterface)
			}
			claims[claim] = hostInterface
			if lbBlock.Ipv4 == "" {
				return fmt.Errorf("%s is attached to a router but has no ipv4", hostInterface)
			}
			ipv4, err := netip.ParseAddr(lbBlock.Ipv4)
			if err != nil || !ipv4.Is4() {
				return fmt.Errorf("%s ipv4 %q is not an ipv4 address", hostInterface, lbBlock.Ipv4)
			}
			wanIpv4, err := netip.ParsePrefix(router.WanIpv4)
			if err == nil && !wanIpv4.Masked().Contains(ipv4) {
				return fmt.Errorf("%s ipv4 %s is outside the %s wan block %s", hostInterface, lbBlock.Ipv4, lbBlock.Router, router.WanIpv4)
			}
			if lbBlock.Ipv6 != "" {
				ipv6, err := netip.ParseAddr(lbBlock.Ipv6)
				if err != nil || !ipv6.Is6() {
					return fmt.Errorf("%s ipv6 %q is not an ipv6 address", hostInterface, lbBlock.Ipv6)
				}
				lanPrefix, err := RouterLanIpv6Prefix(lbBlock.Router, router, lbBlock.RouterInterface)
				if err != nil {
					return err
				}
				if !lanPrefix.Contains(ipv6) {
					return fmt.Errorf("%s ipv6 %s is outside %s, the /64 that %s %s advertises", hostInterface, lbBlock.Ipv6, lanPrefix, lbBlock.Router, lbBlock.RouterInterface)
				}
			}
		}
	}
	return nil
}

// RouterWanIpv6 returns the router's WAN address: the router id as the last
// hextet of the site block's first /64, e.g. 2001:470:99::58/64, the /64
// the upstream gateway lives in. The address is deliberately not on the
// whole /48: with the /48 on-link, a packet for any site address the
// router does not route itself would trigger neighbour discovery on the
// WAN port instead of leaving through the gateway, which cuts the router
// off from the blocks the upstream routes to the other routers.
func RouterWanIpv6(name string, router *RouterConfig) (netip.Prefix, error) {
	id, err := RouterId(name)
	if err != nil {
		return netip.Prefix{}, err
	}
	prefix, err := netip.ParsePrefix(router.WanIpv6Prefix)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("router %q wan_ipv6_prefix %q: %w", name, router.WanIpv6Prefix, err)
	}
	hextet, err := parseHextet(id)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("router %q: %w", name, err)
	}
	bytes := prefix.Addr().As16()
	bytes[14] = byte(hextet >> 8)
	bytes[15] = byte(hextet)
	return netip.PrefixFrom(netip.AddrFrom16(bytes), 64), nil
}

// RouterIpv6Block returns the /56 the upstream routes to the router: the
// router id followed by two zero digits in the fourth hextet, e.g.
// 2001:470:99:5800::/56 for by-us-fmt-5-8. Every port /64 the router
// advertises lies inside it.
func RouterIpv6Block(name string, router *RouterConfig) (netip.Prefix, error) {
	return routerIpv6Prefix(name, router, "00", 56)
}

// RouterLegacyIpv6Prefix returns the /64 the pre-convention configuration
// of a router advertised on its host port: the bare router id in the
// fourth hextet, e.g. 2001:470:99:58::/64. It lies outside RouterIpv6Block.
func RouterLegacyIpv6Prefix(name string, router *RouterConfig) (netip.Prefix, error) {
	return routerIpv6Prefix(name, router, "", 64)
}

// routerIpv6Prefix builds a prefix of the site block whose fourth hextet is
// the router id followed by suffix.
func routerIpv6Prefix(name string, router *RouterConfig, suffix string, bits int) (netip.Prefix, error) {
	id, err := RouterId(name)
	if err != nil {
		return netip.Prefix{}, err
	}
	prefix, err := netip.ParsePrefix(router.WanIpv6Prefix)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("router %q wan_ipv6_prefix %q: %w", name, router.WanIpv6Prefix, err)
	}
	hextet, err := parseHextet(id + suffix)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("router %q: %w", name, err)
	}
	bytes := prefix.Addr().As16()
	bytes[6] = byte(hextet >> 8)
	bytes[7] = byte(hextet)
	return netip.PrefixFrom(netip.AddrFrom16(bytes), bits).Masked(), nil
}

// RouterLanIpv6Prefix returns the /64 a router port advertises: the fourth
// hextet is the router id, the port digit and a zero, e.g.
// 2001:470:99:5880::/64 for port eth8 of by-us-fmt-5-8.
func RouterLanIpv6Prefix(name string, router *RouterConfig, lanInterface string) (netip.Prefix, error) {
	port, err := RouterLanPort(lanInterface)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("router %q: %w", name, err)
	}
	return routerIpv6Prefix(name, router, fmt.Sprintf("%d0", port), 64)
}

// RouterLanIpv4 returns the management bridge address: 192.168.nm.1/24
// unless lan_ipv4 overrides it.
func RouterLanIpv4(name string, router *RouterConfig) (netip.Prefix, error) {
	if router.LanIpv4 != "" {
		prefix, err := netip.ParsePrefix(router.LanIpv4)
		if err != nil {
			return netip.Prefix{}, fmt.Errorf("router %q lan_ipv4 %q: %w", name, router.LanIpv4, err)
		}
		return prefix, nil
	}
	id, err := RouterId(name)
	if err != nil {
		return netip.Prefix{}, err
	}
	return netip.ParsePrefix(fmt.Sprintf("192.168.%s.1/24", id))
}

func parseHextet(digits string) (uint16, error) {
	var value uint16
	for i := 0; i < len(digits); i++ {
		c := digits[i]
		var nibble uint16
		switch {
		case '0' <= c && c <= '9':
			nibble = uint16(c - '0')
		case 'a' <= c && c <= 'f':
			nibble = uint16(c-'a') + 10
		default:
			return 0, fmt.Errorf("%q is not a hex hextet", digits)
		}
		value = value<<4 | nibble
	}
	if len(digits) > 4 {
		return 0, fmt.Errorf("%q is longer than a hextet", digits)
	}
	return value, nil
}

// validatePublicPorts checks the ports a host-pinned service asks the router
// to open: each is one of the service's own ports, named once, with a name
// that fits a firewall rule description.
func validatePublicPorts(version *ServicesConfigVersion) error {
	if version == nil {
		return nil
	}
	orderedServices := maps.Keys(version.Services)
	sort.Strings(orderedServices)
	for _, service := range orderedServices {
		serviceConfig := version.Services[service]
		if serviceConfig == nil || len(serviceConfig.PublicPorts) == 0 {
			continue
		}
		if len(serviceConfig.Hosts) == 0 {
			return fmt.Errorf("service %q declares public ports without a hosts list", service)
		}
		httpPorts := serviceConfig.AllHttpPorts()["tcp"]
		names := map[string]int{}
		ports := maps.Keys(serviceConfig.PublicPorts)
		sort.Ints(ports)
		for _, port := range ports {
			name := serviceConfig.PublicPorts[port]
			if !slices.Contains(httpPorts, port) {
				return fmt.Errorf("service %q public port %d is not one of its ports", service, port)
			}
			if !publicPortNamePattern.MatchString(name) {
				return fmt.Errorf("service %q public port %d name %q is not a lowercase word", service, port, name)
			}
			if other, seen := names[name]; seen {
				return fmt.Errorf("service %q public ports %d and %d share the name %q", service, other, port, name)
			}
			names[name] = port
		}
	}
	return nil
}

// validateRouterForwards checks the custom rewrites declared on lb
// interfaces: an interface forward needs an attached router and is a real,
// non-identity port pair.
func validateRouterForwards(version *ServicesConfigVersion) error {
	if version == nil || version.Lb == nil {
		return nil
	}
	hosts := maps.Keys(version.Lb.Interfaces)
	sort.Strings(hosts)
	for _, host := range hosts {
		interfaceNames := maps.Keys(version.Lb.Interfaces[host])
		sort.Strings(interfaceNames)
		for _, interfaceName := range interfaceNames {
			lbBlock := version.Lb.Interfaces[host][interfaceName]
			if lbBlock == nil {
				continue
			}
			forwards := map[string]map[int]int{"tcp": lbBlock.RouterTcpForwardPorts, "udp": lbBlock.RouterUdpForwardPorts}
			for _, protocol := range []string{"tcp", "udp"} {
				if len(forwards[protocol]) == 0 {
					continue
				}
				if lbBlock.Router == "" {
					return fmt.Errorf("%s %s declares router %s forward ports but no router", host, interfaceName, protocol)
				}
				publicPorts := maps.Keys(forwards[protocol])
				sort.Ints(publicPorts)
				for _, publicPort := range publicPorts {
					if err := validateForwardPair(protocol, publicPort, forwards[protocol][publicPort]); err != nil {
						return fmt.Errorf("%s %s router forward: %w", host, interfaceName, err)
					}
				}
			}
		}
	}
	return nil
}

func validateForwardPair(protocol string, publicPort int, targetPort int) error {
	if publicPort < 1 || 65535 < publicPort || targetPort < 1 || 65535 < targetPort {
		return fmt.Errorf("%s forward %d->%d uses a port outside 1..65535", protocol, publicPort, targetPort)
	}
	if publicPort == targetPort {
		return fmt.Errorf("%s forward %d->%d is an identity mapping", protocol, publicPort, targetPort)
	}
	return nil
}

var dnsNamePattern = regexp.MustCompile(`^(\*\.)?[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$`)

// validateDnsAliases checks the direct dns names a service declares: only a
// host-pinned service that runs with no lb in front may, and each name is a
// hostname.
func validateDnsAliases(version *ServicesConfigVersion) error {
	if version == nil {
		return nil
	}
	orderedServices := maps.Keys(version.Services)
	sort.Strings(orderedServices)
	for _, service := range orderedServices {
		serviceConfig := version.Services[service]
		if serviceConfig == nil || len(serviceConfig.DnsAliases) == 0 {
			continue
		}
		if len(serviceConfig.Hosts) == 0 || serviceConfig.IsExposed() {
			return fmt.Errorf("service %q declares dns_aliases but is not a host-pinned service with no lb in front; an lb service names its aliases in expose_aliases", service)
		}
		seen := map[string]bool{}
		for _, name := range serviceConfig.DnsAliases {
			if !dnsNamePattern.MatchString(name) {
				return fmt.Errorf("service %q dns alias %q is not a hostname", service, name)
			}
			if seen[name] {
				return fmt.Errorf("service %q dns alias %q is listed twice", service, name)
			}
			seen[name] = true
		}
	}
	return nil
}
