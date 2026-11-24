package services

import (
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"sort"
	"strings"

	"golang.org/x/exp/maps"
)

// RouterNamePattern is the router hostname convention: <site>-<n>-<m> with a
// single digit n and a single hex digit m, so the tenth router of site 5 is
// <site>-5-a. The characters "nm" form the router id that the IPv6 and
// management addressing derive from.
var RouterNamePattern = regexp.MustCompile(`^([a-z0-9]+(?:-[a-z0-9]+)*)-([0-9])-([0-9a-f])$`)

// RouterLanInterfacePattern is a router LAN port name: ethP with a single
// digit P, which the port's /64 encodes.
var RouterLanInterfacePattern = regexp.MustCompile(`^eth([0-9])$`)

var routerInterfaceNamePattern = regexp.MustCompile(`^[a-z][a-z0-9]*$`)
var lanHostNamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*$`)
var routerDescriptionPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9 -]*$`)
var publicPortNamePattern = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)
var routerPublicKeyNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)
var routerLoginNamePattern = regexp.MustCompile(`^[a-z_][a-z0-9_-]*$`)

// RouterId returns the id "nm" of a router named <site>-<n>-<m>, e.g. 58 for
// <site>-5-8 and 5a for <site>-5-a. The id is hex in the IPv6 hextets; only
// an all-digit id names a management /24 (RouterLanIpv4).
func RouterId(router string) (string, error) {
	groups := RouterNamePattern.FindStringSubmatch(router)
	if groups == nil {
		return "", fmt.Errorf("router %q does not follow the <site>-<n>-<m> hostname convention (n a digit, m a hex digit)", router)
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
	if err := validateGateways(servicesConfig); err != nil {
		return err
	}
	names := maps.Keys(servicesConfig.Routers)
	sort.Strings(names)
	managementAddresses := map[string]string{}
	for _, name := range names {
		router := servicesConfig.Routers[name]
		if router == nil {
			return fmt.Errorf("router %q has no config", name)
		}
		switch router.GetClass() {
		case RouterClassEdge, RouterClassLan, RouterClassGatewayEdge:
			if _, err := RouterId(name); err != nil {
				return err
			}
		case RouterClassGateway:
			if !GatewayNamePattern.MatchString(name) {
				return fmt.Errorf("router %q is a gateway and does not follow the <site>-<n>-gateway-<k> hostname convention", name)
			}
		default:
			return fmt.Errorf("router %q class %q is not edge, lan, gateway or gateway_edge", name, router.Class)
		}
		if router.ManagementIpv4 != "" || !router.Planned {
			managementAddress, err := netip.ParseAddr(router.ManagementIpv4)
			if err != nil || !managementAddress.Is4() {
				return fmt.Errorf("router %q management_ipv4 %q is not an ipv4 address", name, router.ManagementIpv4)
			}
			if other, ok := managementAddresses[router.ManagementIpv4]; ok {
				return fmt.Errorf("routers %q and %q share management_ipv4 %s", other, name, router.ManagementIpv4)
			}
			managementAddresses[router.ManagementIpv4] = name
		}
		if router.Unms == "" {
			return fmt.Errorf("router %q has no unms connection; every router is attached to uisp (or is `pending` attachment)", name)
		}
		if err := validateRouterCommon(name, router); err != nil {
			return err
		}
		if router.GetClass() == RouterClassGateway {
			if err := validateGatewayRouter(servicesConfig, name, router); err != nil {
				return err
			}
			continue
		}
		if router.WanGatewayIpv4 != "" || router.WanIpv6Prefix != "" || router.WanGatewayIpv6 != "" {
			return fmt.Errorf("router %q sets wan_gateway_ipv4, wan_ipv6_prefix or wan_gateway_ipv6; they come from its gateway", name)
		}
		gateway, ok := servicesConfig.Gateways[router.Gateway]
		if router.Gateway == "" || !ok {
			return fmt.Errorf("router %q names no gateway of the gateways section (%q)", name, router.Gateway)
		}
		router.WanGatewayIpv4 = gateway.Ipv4Gateway
		router.WanIpv6Prefix = gateway.Ipv6
		router.WanGatewayIpv6 = gateway.Ipv6Gateway
		if router.GetClass() != RouterClassGatewayEdge && (router.IspInterface != "" || router.IspIpv6 != "" || len(router.BlockInterfaces) != 0) {
			return fmt.Errorf("router %q is a %s router; isp_interface, isp_ipv6 and block_interfaces belong to a gateway or gateway_edge router", name, router.GetClass())
		}
		if !routerInterfaceNamePattern.MatchString(router.WanInterface) {
			return fmt.Errorf("router %q wan_interface %q is not an interface name", name, router.WanInterface)
		}
		wanIpv4, err := netip.ParsePrefix(router.WanIpv4)
		if err != nil || !wanIpv4.Addr().Is4() {
			return fmt.Errorf("router %q wan_ipv4 %q is not an ipv4 address with a prefix length", name, router.WanIpv4)
		}
		block, _ := netip.ParsePrefix(gateway.Ipv4)
		if wanIpv4.Masked() != block {
			return fmt.Errorf("router %q wan_ipv4 %s is not on the %s block %s", name, router.WanIpv4, router.Gateway, gateway.Ipv4)
		}
		if !usableIpv4Host(block, wanIpv4.Addr()) || wanIpv4.Addr().String() == gateway.Ipv4Gateway {
			return fmt.Errorf("router %q wan_ipv4 %s is not a usable address of %s", name, router.WanIpv4, gateway.Ipv4)
		}
		switch router.GetClass() {
		case RouterClassEdge:
			if len(router.LanInterfaces) == 0 {
				return fmt.Errorf("router %q has no lan_interfaces", name)
			}
			if len(router.PublicPorts) != 0 {
				return fmt.Errorf("router %q is an edge router; public ports are declared on the lb interfaces it fronts", name)
			}
		case RouterClassLan:
			if len(router.LanInterfaces) != 0 {
				return fmt.Errorf("router %q is a lan router; every port but the WAN is a bridge_interfaces member", name)
			}
			if len(router.BridgeInterfaces) == 0 {
				return fmt.Errorf("router %q has no bridge_interfaces", name)
			}
			if err := validateRouterPublicPorts(name, router); err != nil {
				return err
			}
		case RouterClassGatewayEdge:
			if err := validateGatewayEdgeRouter(servicesConfig, name, router); err != nil {
				return err
			}
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
			if !usableIpv4Host(lanIpv4, lanIpv4.Addr()) {
				return fmt.Errorf("router %q lan_ipv4 %q must be a usable bridge address, not the network or broadcast", name, router.LanIpv4)
			}
		}
		// a router id with a letter derives no management /24
		if _, err := RouterLanIpv4(name, router); err != nil {
			return err
		}
	}
	_, err := routerAddressOwners(servicesConfig)
	return err
}

// validateGatewayEdgeRouter checks what a gateway edge router adds to an edge
// router: the isp point to point isp_ipv6 on its wan_interface, which also
// gives its IPv6 default gateway, and that it is the only router on its
// gateway, which no gateway router of ours already serves.
func validateGatewayEdgeRouter(servicesConfig *ServicesConfig, name string, router *RouterConfig) error {
	if router.IspInterface != "" || len(router.BlockInterfaces) != 0 {
		return fmt.Errorf("router %q is a gateway_edge router; its isp link is its wan_interface, and no router sits behind it on block_interfaces", name)
	}
	if len(router.LanInterfaces) == 0 {
		return fmt.Errorf("router %q has no lan_interfaces", name)
	}
	if len(router.PublicPorts) != 0 {
		return fmt.Errorf("router %q is a gateway_edge router; public ports are declared on the lb interfaces it fronts", name)
	}
	ispIpv6, _, err := GatewayIspIpv6(router)
	if err != nil {
		return fmt.Errorf("router %q: %w", name, err)
	}
	// the /48 arrives through the tunnel, not on-link at the gateway's
	// ipv6_gateway
	router.WanGatewayIpv6 = ispIpv6.String()
	if manager, ok := servicesConfig.Routers[router.Gateway]; ok && manager != nil && manager.GetClass() == RouterClassGateway {
		return fmt.Errorf("router %q is the gateway_edge router of %s, which is a gateway router of ours already", name, router.Gateway)
	}
	for _, other := range servicesConfig.RouterNames() {
		otherConfig := servicesConfig.Routers[other]
		if other != name && otherConfig != nil && otherConfig.GetClass() != RouterClassGateway && otherConfig.Gateway == router.Gateway {
			return fmt.Errorf("router %q is the gateway_edge router of %s, and router %q is on %s too; no router sits behind a gateway_edge router", name, router.Gateway, other, router.Gateway)
		}
	}
	return nil
}

// Shared validation applies before any class-specific early return.
func validateRouterCommon(name string, router *RouterConfig) error {
	if router.EdgeosRelease == "" || router.EdgeosConfigVersion == "" {
		return fmt.Errorf("router %q needs edgeos_release and edgeos_config_version for the config.boot footer", name)
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
	for _, nameServer := range router.NameServers {
		if _, err := netip.ParseAddr(nameServer); err != nil {
			return fmt.Errorf("router %q name server %q is not an ip address", name, nameServer)
		}
	}
	for _, size := range []struct {
		field string
		value int
	}{
		{field: "conntrack_table_size", value: router.ConntrackTableSize},
		{field: "conntrack_hash_size", value: router.ConntrackHashSize},
	} {
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
	return nil
}

// Seed public address ownership before checking any version's attachments.
// Management and private bridge addresses are separate routing domains.
func routerAddressOwners(servicesConfig *ServicesConfig) (map[netip.Addr]string, error) {
	owners := map[netip.Addr]string{}
	claim := func(address netip.Addr, owner string) error {
		if other, ok := owners[address]; ok {
			return fmt.Errorf("%s and %s share address %s", other, owner, address)
		}
		owners[address] = owner
		return nil
	}
	for _, name := range servicesConfig.GatewayNames() {
		gateway := servicesConfig.Gateways[name]
		for _, value := range []string{gateway.Ipv4Gateway, gateway.Ipv6Gateway} {
			address, _ := netip.ParseAddr(value)
			if err := claim(address, fmt.Sprintf("gateway %q", name)); err != nil {
				return nil, err
			}
		}
	}
	for _, name := range servicesConfig.RouterNames() {
		router := servicesConfig.Routers[name]
		wanIpv4, _ := netip.ParsePrefix(router.WanIpv4)
		owner := fmt.Sprintf("router %q", name)
		if err := claim(wanIpv4.Addr(), owner); err != nil {
			return nil, err
		}
		// a gateway's and a gateway edge router's IPv6 uplink is the isp's
		// point to point /126, not an address on the gateway's first /64
		if router.GetClass() == RouterClassGateway || router.GetClass() == RouterClassGatewayEdge {
			ispIpv6, ownIpv6, err := GatewayIspIpv6(router)
			if err != nil {
				return nil, err
			}
			if err := claim(ispIpv6, fmt.Sprintf("isp link of %s", owner)); err != nil {
				return nil, err
			}
			if err := claim(ownIpv6.Addr(), owner); err != nil {
				return nil, err
			}
			continue
		}
		wanIpv6, err := RouterWanIpv6(name, router)
		if err != nil {
			return nil, err
		}
		if wanIpv6.Addr() == wanIpv6.Masked().Addr() {
			return nil, fmt.Errorf("%s derives the reserved wan ipv6 subnet address %s", owner, wanIpv6.Addr())
		}
		if err := claim(wanIpv6.Addr(), owner); err != nil {
			return nil, err
		}
	}
	return owners, nil
}

// validateGatewayRouter checks a gateway of ours: a gateways entry of the
// same name, the isp link, and the downstream ports.
func validateGatewayRouter(servicesConfig *ServicesConfig, name string, router *RouterConfig) error {
	gateway, ok := servicesConfig.Gateways[name]
	if !ok {
		return fmt.Errorf("router %q is a gateway without a gateways entry of the same name", name)
	}
	if router.Gateway != "" || router.WanInterface != "" || router.WanGatewayIpv4 != "" || router.WanIpv6Prefix != "" || router.WanGatewayIpv6 != "" {
		return fmt.Errorf("router %q is a gateway; its blocks are the gateways entry and its uplink is isp_interface, wan_ipv4 and isp_ipv6", name)
	}
	if !routerInterfaceNamePattern.MatchString(router.IspInterface) {
		return fmt.Errorf("router %q isp_interface %q is not an interface name", name, router.IspInterface)
	}
	block, _ := netip.ParsePrefix(gateway.Ipv4)
	wanIpv4, err := netip.ParsePrefix(router.WanIpv4)
	if err != nil || !wanIpv4.Addr().Is4() || wanIpv4.Masked() != block {
		return fmt.Errorf("router %q wan_ipv4 %q is not an address on its block %s", name, router.WanIpv4, gateway.Ipv4)
	}
	if !usableIpv4Host(block, wanIpv4.Addr()) || wanIpv4.Addr().String() == gateway.Ipv4Gateway {
		return fmt.Errorf("router %q wan_ipv4 %s is not a usable address of %s (the isp holds %s)", name, router.WanIpv4, gateway.Ipv4, gateway.Ipv4Gateway)
	}
	if _, _, err := GatewayIspIpv6(router); err != nil {
		return fmt.Errorf("router %q: %w", name, err)
	}
	// the derived fields the other classes carry, for the shared renderers
	router.WanGatewayIpv4 = gateway.Ipv4Gateway
	router.WanIpv6Prefix = gateway.Ipv6
	router.WanGatewayIpv6 = gateway.Ipv6Gateway
	if len(router.BlockInterfaces) == 0 {
		return fmt.Errorf("router %q has no block_interfaces for the routers behind it", name)
	}
	if len(router.LanInterfaces) != 0 || len(router.PublicPorts) != 0 {
		return fmt.Errorf("router %q is a gateway; it has neither lan_interfaces nor public_ports", name)
	}
	seen := map[string]bool{router.IspInterface: true}
	for _, port := range append(append([]string{}, router.BlockInterfaces...), router.BridgeInterfaces...) {
		if !routerInterfaceNamePattern.MatchString(port) {
			return fmt.Errorf("router %q port %q is not an interface name", name, port)
		}
		if seen[port] {
			return fmt.Errorf("router %q lists interface %s twice", name, port)
		}
		seen[port] = true
	}
	if len(router.BridgeInterfaces) != 0 && router.LanIpv4 == "" {
		return fmt.Errorf("router %q bridges a management port but has no lan_ipv4; a gateway has no router id to derive it from", name)
	}
	if router.LanIpv4 != "" {
		lanIpv4, err := netip.ParsePrefix(router.LanIpv4)
		if err != nil || !lanIpv4.Addr().Is4() || lanIpv4.Bits() != 24 || !usableIpv4Host(lanIpv4, lanIpv4.Addr()) {
			return fmt.Errorf("router %q lan_ipv4 %q must be the bridge address with a /24 prefix length", name, router.LanIpv4)
		}
	}
	return nil
}

// validateRouterPublicPorts checks a lan router's forwards: a real public
// port, a lan host name (resolved against settings.yml when the config is
// generated), a target port and a protocol.
func validateRouterPublicPorts(name string, router *RouterConfig) error {
	publicPorts := maps.Keys(router.PublicPorts)
	sort.Ints(publicPorts)
	for _, publicPort := range publicPorts {
		forward := router.PublicPorts[publicPort]
		if publicPort < 1 || 65535 < publicPort {
			return fmt.Errorf("router %q public port %d is outside 1..65535", name, publicPort)
		}
		if forward == nil || !lanHostNamePattern.MatchString(forward.Host) {
			return fmt.Errorf("router %q public port %d needs a lan host name", name, publicPort)
		}
		if forward.Port < 1 || 65535 < forward.Port {
			return fmt.Errorf("router %q public port %d target port %d is outside 1..65535", name, publicPort, forward.Port)
		}
		switch forward.GetProtocol() {
		case "tcp", "udp", "tcp_udp":
		default:
			return fmt.Errorf("router %q public port %d protocol %q is not tcp, udp or tcp_udp", name, publicPort, forward.Protocol)
		}
		if forward.Description != "" && !routerDescriptionPattern.MatchString(forward.Description) {
			return fmt.Errorf("router %q public port %d description %q is not a lowercase phrase", name, publicPort, forward.Description)
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
	addresses, err := routerAddressOwners(servicesConfig)
	if err != nil {
		return err
	}
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
			if class := router.GetClass(); class != RouterClassEdge && class != RouterClassGatewayEdge {
				return fmt.Errorf("%s is attached to %s, which is a %s router, not an edge router", hostInterface, lbBlock.Router, class)
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
			if !usableIpv4Host(wanIpv4, ipv4) {
				return fmt.Errorf("%s ipv4 %s is a reserved address of %s", hostInterface, ipv4, wanIpv4.Masked())
			}
			if other, ok := addresses[ipv4]; ok {
				return fmt.Errorf("%s and %s share address %s", other, hostInterface, ipv4)
			}
			addresses[ipv4] = hostInterface
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
				if ipv6 == lanPrefix.Addr() || ipv6 == lanPrefix.Addr().Next() {
					return fmt.Errorf("%s ipv6 %s is a reserved address of %s %s", hostInterface, ipv6, lbBlock.Router, lbBlock.RouterInterface)
				}
				if other, ok := addresses[ipv6]; ok {
					return fmt.Errorf("%s and %s share address %s", other, hostInterface, ipv6)
				}
				addresses[ipv6] = hostInterface
			}
		}
	}
	return nil
}

// RouterWanIpv6 returns the router's WAN address: the router id as the last
// hextet of the site block's first /64, e.g. 2001:db8:1::58/64, the /64
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
// 2001:db8:1:5800::/56 for zz-zz-tst-5-8. Every port /64 the router
// advertises lies inside it.
func RouterIpv6Block(name string, router *RouterConfig) (netip.Prefix, error) {
	return routerIpv6Prefix(name, router, "00", 56)
}

// RouterBridgeIpv6Prefix returns the /64 a lan router advertises on its
// bridge: the first /64 of its routed /56, e.g. 2001:db8:1:5100::/64 for
// zz-zz-tst-5-1.
func RouterBridgeIpv6Prefix(name string, router *RouterConfig) (netip.Prefix, error) {
	return routerIpv6Prefix(name, router, "00", 64)
}

// RouterLegacyIpv6Prefix returns the /64 the pre-convention configuration
// of a router advertised on its host port: the bare router id in the
// fourth hextet, e.g. 2001:db8:1:58::/64. It lies outside RouterIpv6Block.
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
// 2001:db8:1:5880::/64 for port eth8 of zz-zz-tst-5-8.
func RouterLanIpv6Prefix(name string, router *RouterConfig, lanInterface string) (netip.Prefix, error) {
	port, err := RouterLanPort(lanInterface)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("router %q: %w", name, err)
	}
	return routerIpv6Prefix(name, router, fmt.Sprintf("%d0", port), 64)
}

// RouterLanIpv4 returns the management bridge address: 192.168.nm.1/24
// unless lan_ipv4 overrides it. A router id with a letter (5a) names no
// octet, so such a router must declare lan_ipv4.
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
	if strings.ContainsAny(id, "abcdef") {
		return netip.Prefix{}, fmt.Errorf("router %q needs lan_ipv4: its router id %s derives no 192.168.nm.1/24 management bridge", name, id)
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

// The name a dns alias narrows to one address family, and whether it does: a
// name whose first label ends in -v4 or -v6 carries only that family of the
// same name without the suffix (alt-v4.example.com of alt.example.com).
func DnsAliasFamilyBase(name string) (string, bool) {
	label, rest, ok := strings.Cut(name, ".")
	if !ok {
		return "", false
	}
	for _, suffix := range []string{"-v4", "-v6"} {
		if base, narrowed := strings.CutSuffix(label, suffix); narrowed && base != "" {
			return base + "." + rest, true
		}
	}
	return "", false
}

// Checks the dns-only names services declare: names `warpctl dns` publishes
// with no certificate and no server name. Two kinds of service may declare
// them:
//   - a host-pinned service that runs with no lb in front (alt), whose names
//     hold its hosts' interface addresses;
//   - the lb_alt service (server/LBALT.md D14), whose names resolve to the lb
//     interfaces lb_alt is in effect on, though it is an lb service.
//
// Each name is a hostname with exactly one owner: one service lists it, once,
// and no service also serves it as an expose alias, expose domain or redirect
// alias, which would give it a certificate and a server name. A name of the
// lb_alt service that carries one address family (-v4 or -v6) needs the name
// it narrows listed too: while lb_alt is on for only some lb interfaces, that
// name holds their weighted set, and the narrow name aliases it.
func validateDnsAliases(version *ServicesConfigVersion) error {
	if version == nil {
		return nil
	}
	lbAltService, _ := LbAltService(version)
	orderedServices := maps.Keys(version.Services)
	sort.Strings(orderedServices)

	// the names the lb serves for a service, each with the first service
	// serving it
	servedNameServices := map[string]string{}
	for _, service := range orderedServices {
		serviceConfig := version.Services[service]
		if serviceConfig == nil {
			continue
		}
		redirectNames := maps.Keys(serviceConfig.RedirectAliases)
		sort.Strings(redirectNames)
		servedNames := slices.Concat(serviceConfig.ExposeAliases, serviceConfig.ExposeDomains, redirectNames)
		for _, servedName := range servedNames {
			servedName = strings.TrimSuffix(strings.ToLower(servedName), ".")
			if _, ok := servedNameServices[servedName]; !ok {
				servedNameServices[servedName] = service
			}
		}
	}

	dnsAliasServices := map[string]string{}
	for _, service := range orderedServices {
		serviceConfig := version.Services[service]
		if serviceConfig == nil || len(serviceConfig.DnsAliases) == 0 {
			continue
		}
		hostPinned := 0 < len(serviceConfig.Hosts) && !serviceConfig.IsExposed()
		if !hostPinned && service != lbAltService {
			return fmt.Errorf("service %q declares dns_aliases but is neither a host-pinned service with no lb in front nor the lb_alt service; an lb service names its aliases in expose_aliases", service)
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
			if otherService, ok := dnsAliasServices[name]; ok {
				return fmt.Errorf("services %q and %q both declare the dns alias %q, and a dns name has one owner", otherService, service, name)
			}
			dnsAliasServices[name] = service
			if servingService, ok := servedNameServices[name]; ok {
				return fmt.Errorf("service %q dns alias %q is also a name the lb serves for service %q, and a dns name has one owner: a dns alias has no certificate or server name", service, name, servingService)
			}
		}
		if service != lbAltService {
			continue
		}
		for _, name := range serviceConfig.DnsAliases {
			if base, narrowed := DnsAliasFamilyBase(name); narrowed && !seen[base] {
				return fmt.Errorf("service %q dns alias %q carries one address family of %q, which the service does not list; while lb_alt is on for only some lb interfaces, %q aliases the weighted set of %q", service, name, base, name, base)
			}
		}
	}
	return nil
}
