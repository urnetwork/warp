package services

import (
	"fmt"
	"net/netip"
	"regexp"
	"sort"

	"golang.org/x/exp/maps"
)

// The gateways of a site: the upstream of every WAN block. A gateway the
// isp manages is tracked for its blocks only; a gateway we manage is also a
// router of class gateway with the same name, which carries the isp point
// to point link and forwards the blocks to the routers behind it.

// GatewayNamePattern is the gateway hostname convention:
// <site>-<n>-gateway-<k>, e.g. by-us-fmt-5-gateway-3.
var GatewayNamePattern = regexp.MustCompile(`^([a-z0-9]+(?:-[a-z0-9]+)*)-([0-9]+)-gateway-([0-9]+)$`)

// GatewayConfig is one gateway's blocks: what the routers behind it derive
// their WAN addressing from.
type GatewayConfig struct {
	Description string `yaml:"description,omitempty"`
	// the ipv4 block and the gateway's address in it, e.g. 65.49.70.64/27
	// and 65.49.70.65
	Ipv4        string `yaml:"ipv4"`
	Ipv4Gateway string `yaml:"ipv4_gateway"`
	// the routed /48 and the gateway's address on its first /64, e.g.
	// 2001:470:99::/48 and 2001:470:99::1
	Ipv6        string `yaml:"ipv6"`
	Ipv6Gateway string `yaml:"ipv6_gateway"`
}

// GatewayNames returns the gateways in sorted order.
func (self *ServicesConfig) GatewayNames() []string {
	names := maps.Keys(self.Gateways)
	sort.Strings(names)
	return names
}

// IsManagedGateway reports whether a gateway is a router of ours.
func (self *ServicesConfig) IsManagedGateway(name string) bool {
	router, ok := self.Routers[name]
	return ok && router != nil && router.GetClass() == RouterClassGateway
}

// RoutersBehind returns the edge and lan routers on a gateway's blocks, in
// name order.
func (self *ServicesConfig) RoutersBehind(gateway string) []string {
	routers := []string{}
	for _, name := range self.RouterNames() {
		router := self.Routers[name]
		if router != nil && router.GetClass() != RouterClassGateway && router.Gateway == gateway {
			routers = append(routers, name)
		}
	}
	return routers
}

// validateGateways checks the gateways section: names follow the
// convention, the blocks parse and hold their gateway addresses, and no two
// gateways share a block.
func validateGateways(servicesConfig *ServicesConfig) error {
	ipv4Blocks := map[string]string{}
	ipv6Blocks := map[string]string{}
	for _, name := range servicesConfig.GatewayNames() {
		gateway := servicesConfig.Gateways[name]
		if gateway == nil {
			return fmt.Errorf("gateway %q has no config", name)
		}
		if !GatewayNamePattern.MatchString(name) {
			return fmt.Errorf("gateway %q does not follow the <site>-<n>-gateway-<k> hostname convention", name)
		}
		ipv4, err := netip.ParsePrefix(gateway.Ipv4)
		if err != nil || !ipv4.Addr().Is4() || ipv4.Masked() != ipv4 {
			return fmt.Errorf("gateway %q ipv4 %q is not an ipv4 block with zero host bits", name, gateway.Ipv4)
		}
		if ipv4.Bits() >= 31 {
			return fmt.Errorf("gateway %q ipv4 %q leaves no room for routers", name, gateway.Ipv4)
		}
		ipv4Gateway, err := netip.ParseAddr(gateway.Ipv4Gateway)
		if err != nil || !ipv4Gateway.Is4() || !ipv4.Contains(ipv4Gateway) || ipv4Gateway == ipv4.Addr() {
			return fmt.Errorf("gateway %q ipv4_gateway %q is not a usable address of %s", name, gateway.Ipv4Gateway, gateway.Ipv4)
		}
		ipv6, err := netip.ParsePrefix(gateway.Ipv6)
		if err != nil || !ipv6.Addr().Is6() || ipv6.Addr().Is4In6() || ipv6.Bits() != 48 || ipv6.Masked() != ipv6 {
			return fmt.Errorf("gateway %q ipv6 %q is not a /48 with zero host bits", name, gateway.Ipv6)
		}
		ipv6Gateway, err := netip.ParseAddr(gateway.Ipv6Gateway)
		if err != nil || !ipv6Gateway.Is6() || !netip.PrefixFrom(ipv6.Addr(), 64).Contains(ipv6Gateway) || ipv6Gateway == ipv6.Addr() {
			return fmt.Errorf("gateway %q ipv6_gateway %q is not on the first /64 of %s", name, gateway.Ipv6Gateway, gateway.Ipv6)
		}
		if other, ok := ipv4Blocks[ipv4.String()]; ok {
			return fmt.Errorf("gateways %q and %q share the block %s", other, name, ipv4)
		}
		ipv4Blocks[ipv4.String()] = name
		if other, ok := ipv6Blocks[ipv6.String()]; ok {
			return fmt.Errorf("gateways %q and %q share the block %s", other, name, ipv6)
		}
		ipv6Blocks[ipv6.String()] = name
	}
	return nil
}

// GatewayIspAddresses returns the addresses of a managed gateway's isp
// point to point link: the isp at the lower usable address of each prefix
// and the router at the next one (a /31 holds exactly the two; a /126
// holds ::1 for the isp and ::2 for the router).
func GatewayIspAddresses(router *RouterConfig) (ispIpv4 netip.Addr, ownIpv4 netip.Prefix, ispIpv6 netip.Addr, ownIpv6 netip.Prefix, err error) {
	if router.IspIpv4 != "" {
		p2p, parseErr := netip.ParsePrefix(router.IspIpv4)
		if parseErr != nil || !p2p.Addr().Is4() || p2p.Bits() != 31 || p2p.Masked() != p2p {
			return ispIpv4, ownIpv4, ispIpv6, ownIpv6, fmt.Errorf("isp_ipv4 %q is not a /31 with zero host bits", router.IspIpv4)
		}
		ispIpv4 = p2p.Addr()
		ownIpv4 = netip.PrefixFrom(p2p.Addr().Next(), 31)
	}
	p2p6, parseErr := netip.ParsePrefix(router.IspIpv6)
	if parseErr != nil || !p2p6.Addr().Is6() || p2p6.Addr().Is4In6() || p2p6.Bits() != 126 || p2p6.Masked() != p2p6 {
		return ispIpv4, ownIpv4, ispIpv6, ownIpv6, fmt.Errorf("isp_ipv6 %q is not a /126 with zero host bits", router.IspIpv6)
	}
	ispIpv6 = p2p6.Addr().Next()
	ownIpv6 = netip.PrefixFrom(ispIpv6.Next(), 126)
	return ispIpv4, ownIpv4, ispIpv6, ownIpv6, nil
}
