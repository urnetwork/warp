package main

import (
	"fmt"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/exp/maps"

	"github.com/urnetwork/warp/services"
	"github.com/urnetwork/warp/vyos"
)

// VyosGenerator renders the EdgeOS config.boot of every router in the
// services config. The base configuration is the same for every router and
// the host specific part (LAN ports, interface routes and firewall rules)
// comes from the lb interfaces attached to the router.
//
// The firewall opens on each attached interface exactly what is served
// there. On a plain lb interface: the lb http ports on tcp, each lb stream
// port on the protocol of the service it maps to when that service runs on
// the host (a forward target or a port kept private for a draining lb
// generation stays closed), and the lb forward ports whose target is served
// on the host (warp's host-side dnat rewrites them to the lb's listener
// there on both address families; the lb never binds the public port, and
// the router only admits it). On a transparent interface no lb front runs (its unit only
// reconciles the routing table), so only the host-pinned services' own
// ports open: their public udp ports and the allocated external ports they
// list as public_ports.
//
// A host-pinned service's external_udp_forward_ports are the block's own
// dnat on the host (public udp 53 to whodis on 4053) on both address
// families, so the router only admits the public port on both. Destination
// nat on the router itself is declared, never inferred: an interface's
// router_tcp_forward_ports and router_udp_forward_ports are custom rewrites
// to that host, whose target port the router also opens. EdgeOS nat is
// IPv4-only, so those rewrites and their target rules are IPv4-only.
type VyosGenerator struct {
	env            string
	servicesConfig *services.ServicesConfig
	portBlocks     map[string]map[string]map[string]map[int]*PortBlock
	systemdUnits   *SystemdUnits
	// config/<env>/settings.yml: the lan routers' hosts, and the hosts'
	// `routes` addresses that must agree with them. Loaded when the config
	// has a lan router.
	settingsPath string
	lanHosts     map[string]*services.LanHost
	lanRoutes    map[string]string
}

func NewVyosGenerator(env string) (*VyosGenerator, error) {
	servicesConfig := getServicesConfig(env)
	if len(servicesConfig.Routers) == 0 {
		return nil, fmt.Errorf("services config for %s has no routers", env)
	}
	generator := &VyosGenerator{
		env:            env,
		servicesConfig: servicesConfig,
		portBlocks:     getPortBlocks(env),
		systemdUnits:   NewSystemdUnits(env, "", "", true),
		lanHosts:       map[string]*services.LanHost{},
		lanRoutes:      map[string]string{},
	}
	if generator.hasClass(services.RouterClassLan) {
		settingsPath, err := services.SettingsPath(env)
		if err != nil {
			return nil, fmt.Errorf("a lan router needs config/%s/settings.yml: %w", env, err)
		}
		document, err := os.ReadFile(settingsPath)
		if err != nil {
			return nil, err
		}
		lanHosts, err := services.ParseLanHosts(document)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", settingsPath, err)
		}
		generator.settingsPath = settingsPath
		generator.lanHosts = lanHosts
		generator.lanRoutes = services.ParseLanRoutes(document)
	}
	return generator, nil
}

// hasClass reports whether any router is of the class.
func (self *VyosGenerator) hasClass(class string) bool {
	for _, routerConfig := range self.servicesConfig.Routers {
		if routerConfig != nil && routerConfig.GetClass() == class {
			return true
		}
	}
	return false
}

// Class returns a router's class.
func (self *VyosGenerator) Class(router string) (string, error) {
	routerConfig, ok := self.servicesConfig.Routers[router]
	if !ok {
		return "", fmt.Errorf("unknown router %q", router)
	}
	return routerConfig.GetClass(), nil
}

// Routers returns the router names in sorted order.
func (self *VyosGenerator) Routers() []string {
	return self.servicesConfig.RouterNames()
}

// ManagementIpv4 returns the management vpn address of a router.
func (self *VyosGenerator) ManagementIpv4(router string) (string, error) {
	routerConfig, ok := self.servicesConfig.Routers[router]
	if !ok {
		return "", fmt.Errorf("unknown router %q", router)
	}
	return routerConfig.ManagementIpv4, nil
}

// vyosAttachment is one lb interface plugged into a router port.
type vyosAttachment struct {
	host          string
	interfaceName string
	lbBlock       *services.LbBlock
	// the router port, ethP
	routerInterface string
}

// attachments lists the lb interfaces attached to the router, ordered by
// host and interface.
func (self *VyosGenerator) attachments(router string) []*vyosAttachment {
	latest := self.servicesConfig.Latest()
	attachments := []*vyosAttachment{}
	if latest.Lb == nil {
		return attachments
	}
	hosts := maps.Keys(latest.Lb.Interfaces)
	sort.Strings(hosts)
	for _, host := range hosts {
		interfaceNames := maps.Keys(latest.Lb.Interfaces[host])
		sort.Strings(interfaceNames)
		for _, interfaceName := range interfaceNames {
			lbBlock := latest.Lb.Interfaces[host][interfaceName]
			if lbBlock == nil || lbBlock.Router != router {
				continue
			}
			attachments = append(attachments, &vyosAttachment{
				host:            host,
				interfaceName:   interfaceName,
				lbBlock:         lbBlock,
				routerInterface: lbBlock.RouterInterface,
			})
		}
	}
	return attachments
}

// vyosRule is one accept rule: a public port on an attached interface.
type vyosRule struct {
	port     int
	protocol string
	// what owns the port, for the rule description: "lb 443", "alt 443 udp",
	// "proxy g1 socks"
	label string
}

// vyosDnat is one destination nat on the router: a public port on an
// attached interface rewritten to the port a host-pinned service owns.
type vyosDnat struct {
	publicPort int
	targetPort int
	protocol   string
	label      string
}

type vyosRuleKey struct {
	port  int
	label string
}

type vyosRuleSet struct {
	protocols map[vyosRuleKey]map[string]bool
}

func newVyosRuleSet() *vyosRuleSet {
	return &vyosRuleSet{protocols: map[vyosRuleKey]map[string]bool{}}
}

// has reports whether any owner already opens the port on the protocol.
func (self *vyosRuleSet) has(port int, protocol string) bool {
	for key, protocols := range self.protocols {
		if key.port == port && protocols[protocol] {
			return true
		}
	}
	return false
}

func (self *vyosRuleSet) add(port int, protocol string, label string) {
	key := vyosRuleKey{port: port, label: label}
	protocols, ok := self.protocols[key]
	if !ok {
		protocols = map[string]bool{}
		self.protocols[key] = protocols
	}
	protocols[protocol] = true
}

// rules returns the rules ordered by port then label, with a port that one
// owner publishes on both protocols merged into one tcp_udp rule.
func (self *vyosRuleSet) rules() []vyosRule {
	keys := maps.Keys(self.protocols)
	sort.Slice(keys, func(i int, j int) bool {
		if keys[i].port != keys[j].port {
			return keys[i].port < keys[j].port
		}
		return keys[i].label < keys[j].label
	})
	rules := []vyosRule{}
	for _, key := range keys {
		protocols := self.protocols[key]
		var protocol string
		switch {
		case protocols["tcp"] && protocols["udp"]:
			protocol = "tcp_udp"
		case protocols["tcp"]:
			protocol = "tcp"
		default:
			protocol = "udp"
		}
		rules = append(rules, vyosRule{port: key.port, protocol: protocol, label: key.label})
	}
	return rules
}

// publicRules derives the IPv4 and IPv6 accept rules and the IPv4
// destination nats for one attached interface from what is served on it.
func (self *VyosGenerator) publicRules(attachment *vyosAttachment) (ipv4Rules []vyosRule, ipv6Rules []vyosRule, dnats []vyosDnat, err error) {
	latest := self.servicesConfig.Latest()
	host := attachment.host
	lbConfig := latest.Lb
	if lbConfig == nil {
		return nil, nil, nil, fmt.Errorf("%s %s: the services config has no lb", host, attachment.interfaceName)
	}
	// the block's port services with the lb defaults merged in, as the lb
	// units and port blocks see them
	attachment.lbBlock.SetDefaultStreamPortServices(&lbConfig.StreamPortServiceConfig)
	allPortServices := attachment.lbBlock.AllPortServices()

	// the stream ports the lb on this host serves: protocol -> port -> service,
	// the same condition the lb's nginx stream blocks use
	served := map[string]map[int]string{"tcp": {}, "udp": {}}
	// the public udp ports host-pinned services on this host own themselves,
	// and the public udp ports their own dnat aliases to those
	externalUdp := map[int]string{}
	externalUdpAliases := map[int]string{}
	// the rewrites declared for the router: protocol -> public port -> dnat
	forwards := map[string]map[int]vyosDnat{"tcp": {}, "udp": {}}
	declareForward := func(protocol string, publicPort int, targetPort int, label string) error {
		if existing, ok := forwards[protocol][publicPort]; ok && (existing.targetPort != targetPort || existing.label != label) {
			return fmt.Errorf("%s %s: %s port %d is forwarded twice (%s and %s)", host, attachment.interfaceName, protocol, publicPort, existing.label, label)
		}
		forwards[protocol][publicPort] = vyosDnat{publicPort: publicPort, targetPort: targetPort, protocol: protocol, label: label}
		return nil
	}
	// the pool ports host-pinned services on this host open: port -> label
	poolPorts := map[int]string{}
	for _, service := range self.systemdUnits.services(host) {
		switch service {
		case "lb", "config-updater":
			continue
		}
		serviceConfig, ok := latest.Services[service]
		if !ok || serviceConfig == nil {
			continue
		}
		if serviceConfig.IsExposed() {
			for protocol, ports := range serviceConfig.AllStreamPorts() {
				for _, port := range ports {
					if allPortServices[protocol][port] == service {
						served[protocol][port] = service
					}
				}
			}
		}
		if !attachment.lbBlock.Transparent || !serviceConfig.IncludesHost(host) {
			continue
		}
		for _, port := range serviceConfig.AllExternalPorts()["udp"] {
			externalUdp[port] = service
		}
		for publicPort := range serviceConfig.ExternalUdpForwardPorts {
			externalUdpAliases[publicPort] = service
		}
		if len(serviceConfig.PublicPorts) == 0 {
			continue
		}
		publicPorts := maps.Keys(serviceConfig.PublicPorts)
		sort.Ints(publicPorts)
		for _, blockWeights := range serviceConfig.Blocks {
			blocks := maps.Keys(blockWeights)
			sort.Strings(blocks)
			for _, block := range blocks {
				for _, servicePort := range publicPorts {
					portBlock, ok := self.portBlocks[""][service][block][servicePort]
					if !ok || portBlock == nil || portBlock.externalPort == 0 {
						return nil, nil, nil, fmt.Errorf("%s %s: service %s block %s port %d has no external port", host, attachment.interfaceName, service, block, servicePort)
					}
					poolPorts[portBlock.externalPort] = fmt.Sprintf("%s %s %s", service, block, serviceConfig.PublicPorts[servicePort])
				}
			}
		}
	}

	// a forward target, or a port kept private while the previous lb
	// generation drains, is never opened directly
	forwardPorts := lbConfig.AllForwardPorts()
	closed := map[int]bool{}
	for _, port := range rollingPrivateForwardTargetPorts(self.servicesConfig) {
		closed[port] = true
	}
	for _, protocolForwardPorts := range forwardPorts {
		for _, servicePort := range protocolForwardPorts {
			closed[servicePort] = true
		}
	}

	ipv4Set := newVyosRuleSet()
	ipv6Set := newVyosRuleSet()
	for _, ipv6 := range []bool{false, true} {
		set := ipv4Set
		if ipv6 {
			if attachment.lbBlock.Ipv6 == "" {
				continue
			}
			set = ipv6Set
		}
		// a transparent interface has no lb front: its lb unit only keeps the
		// routing table, and the services bind the interface themselves
		if !attachment.lbBlock.Transparent {
			for _, port := range lbConfig.Ports() {
				set.add(port, "tcp", fmt.Sprintf("lb %d", port))
			}
			for _, protocol := range []string{"tcp", "udp"} {
				for port := range served[protocol] {
					if closed[port] {
						continue
					}
					set.add(port, protocol, fmt.Sprintf("lb %d", port))
				}
				for publicPort, servicePort := range forwardPorts[protocol] {
					if served[protocol][servicePort] != "" {
						set.add(publicPort, protocol, fmt.Sprintf("lb %d", publicPort))
					}
				}
			}
		}
		for port, service := range externalUdp {
			set.add(port, "udp", fmt.Sprintf("%s %d udp", service, port))
		}
		for port, service := range externalUdpAliases {
			set.add(port, "udp", fmt.Sprintf("%s %d udp", service, port))
		}
		for port, label := range poolPorts {
			set.add(port, "tcp", label)
			set.add(port, "udp", label)
		}
	}
	// the interface's own rewrites open their target on the router, since
	// nothing else declares it; EdgeOS nat is IPv4-only, so is this
	interfaceForwards := map[string]map[int]int{"tcp": attachment.lbBlock.RouterTcpForwardPorts, "udp": attachment.lbBlock.RouterUdpForwardPorts}
	for _, protocol := range []string{"tcp", "udp"} {
		publicPorts := maps.Keys(interfaceForwards[protocol])
		sort.Ints(publicPorts)
		for _, publicPort := range publicPorts {
			targetPort := interfaceForwards[protocol][publicPort]
			label := fmt.Sprintf("forward %d to %d %s", publicPort, targetPort, protocol)
			if err := declareForward(protocol, publicPort, targetPort, label); err != nil {
				return nil, nil, nil, err
			}
			if !ipv4Set.has(targetPort, protocol) {
				ipv4Set.add(targetPort, protocol, label)
			}
		}
	}
	// a rewritten public port must not also be served on the interface,
	// where the rewrite would silently capture the served traffic
	for _, protocol := range []string{"tcp", "udp"} {
		publicPorts := maps.Keys(forwards[protocol])
		sort.Ints(publicPorts)
		for _, publicPort := range publicPorts {
			if ipv4Set.has(publicPort, protocol) {
				return nil, nil, nil, fmt.Errorf("%s %s: %s port %d is both served and rewritten (%s)", host, attachment.interfaceName, protocol, publicPort, forwards[protocol][publicPort].label)
			}
			dnats = append(dnats, forwards[protocol][publicPort])
		}
	}
	sort.Slice(dnats, func(i int, j int) bool {
		if dnats[i].publicPort != dnats[j].publicPort {
			return dnats[i].publicPort < dnats[j].publicPort
		}
		return dnats[i].protocol < dnats[j].protocol
	})

	ipv4Rules = ipv4Set.rules()
	ipv6Rules = ipv6Set.rules()
	for _, rules := range [][]vyosRule{ipv4Rules, ipv6Rules} {
		for i := range rules {
			if strings.HasPrefix(rules[i].label, "lb ") && rules[i].protocol != "tcp_udp" {
				rules[i].label += " " + rules[i].protocol
			}
		}
	}
	return ipv4Rules, ipv6Rules, dnats, nil
}

func (self *VyosGenerator) shortHost(host string) string {
	return strings.TrimSuffix(host, "."+self.servicesConfig.GetDomain())
}

// vyosProtectedPaths lists what a migration must never delete: losing any
// of these on a remote router cuts the management path.
func vyosProtectedPaths(routerConfig *services.RouterConfig) [][]string {
	uplink := routerConfig.WanInterface
	if routerConfig.GetClass() == services.RouterClassGateway {
		uplink = routerConfig.IspInterface
	}
	return [][]string{
		{"interfaces", "ethernet", uplink},
		{"interfaces", "openvpn"},
		{"service", "ssh"},
		{"system", "gateway-address"},
		{"system", "login"},
	}
}

// ProtectedPaths returns the migration guard for a router.
func (self *VyosGenerator) ProtectedPaths(router string) ([][]string, error) {
	routerConfig, ok := self.servicesConfig.Routers[router]
	if !ok {
		return nil, fmt.Errorf("unknown router %q", router)
	}
	return vyosProtectedPaths(routerConfig), nil
}

// GenerateAll renders every router.
func (self *VyosGenerator) GenerateAll() (map[string]*vyos.Config, error) {
	configs := map[string]*vyos.Config{}
	for _, router := range self.Routers() {
		config, err := self.Generate(router)
		if err != nil {
			return nil, err
		}
		configs[router] = config
	}
	return configs, nil
}

// vyosAddresses is what the hostname convention derives for a router.
type vyosAddresses struct {
	wanIpv4    netip.Prefix
	wanIpv6    netip.Prefix
	siteIpv6   netip.Prefix
	ipv6Block  netip.Prefix
	legacyIpv6 netip.Prefix
	lanIpv4    netip.Prefix
	// the resolvers, and the IPv6 ones among them for the router adverts
	nameServers     []string
	ipv6NameServers []string
}

func (self *VyosGenerator) addresses(router string, routerConfig *services.RouterConfig) (*vyosAddresses, error) {
	wanIpv4, err := netip.ParsePrefix(routerConfig.WanIpv4)
	if err != nil {
		return nil, fmt.Errorf("router %s wan_ipv4: %w", router, err)
	}
	wanIpv6, err := services.RouterWanIpv6(router, routerConfig)
	if err != nil {
		return nil, err
	}
	siteIpv6, err := netip.ParsePrefix(routerConfig.WanIpv6Prefix)
	if err != nil {
		return nil, fmt.Errorf("router %s wan_ipv6_prefix: %w", router, err)
	}
	ipv6Block, err := services.RouterIpv6Block(router, routerConfig)
	if err != nil {
		return nil, err
	}
	legacyIpv6, err := services.RouterLegacyIpv6Prefix(router, routerConfig)
	if err != nil {
		return nil, err
	}
	lanIpv4, err := services.RouterLanIpv4(router, routerConfig)
	if err != nil {
		return nil, err
	}
	addresses := &vyosAddresses{
		wanIpv4:     wanIpv4,
		wanIpv6:     wanIpv6,
		siteIpv6:    siteIpv6,
		ipv6Block:   ipv6Block,
		legacyIpv6:  legacyIpv6,
		lanIpv4:     lanIpv4,
		nameServers: routerConfig.GetNameServers(),
	}
	for _, nameServer := range addresses.nameServers {
		if address, err := netip.ParseAddr(nameServer); err == nil && address.Is6() {
			addresses.ipv6NameServers = append(addresses.ipv6NameServers, nameServer)
		}
	}
	return addresses, nil
}

// Generate renders one router of the edge or lan class; the gateway class
// has no generator yet.
//
// The base configuration is hardened the same way on every router: the WAN
// chains drop by default and log the drops through one rate-limited rule
// instead of the unbounded default log, echo requests to the router itself
// are rate limited while every other icmp type (path mtu discovery,
// neighbour discovery) passes, the router sends no icmp redirects, ssh
// takes keys only, the gui refuses the older tls ciphers, nothing is
// reported to the vendor, the conntrack table is sized per router and
// forwarding offload is an explicit toggle. The WAN IPv6 address sits on
// the gateway's /64 and the router blackholes the rest of its own /56 (and
// the pre-convention /64 of its id) so an unrouted address in them is
// dropped on the router rather than looped back to the upstream.
func (self *VyosGenerator) Generate(router string) (*vyos.Config, error) {
	routerConfig, ok := self.servicesConfig.Routers[router]
	if !ok {
		return nil, fmt.Errorf("unknown router %q", router)
	}
	switch routerConfig.GetClass() {
	case services.RouterClassEdge:
		return self.generateEdge(router, routerConfig)
	case services.RouterClassLan:
		return self.generateLan(router, routerConfig)
	case services.RouterClassGateway:
		return self.generateGateway(router, routerConfig)
	default:
		return nil, fmt.Errorf("router %s: unknown class %s", router, routerConfig.GetClass())
	}
}

// the bogon sources a gateway drops on its isp link, besides the site's own
// blocks (which never arrive from the isp side): unallocated, private,
// loopback, link local, documentation and multicast space
var (
	vyosBogonsIpv4 = []string{
		"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
		"192.0.0.0/24", "192.0.2.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24",
		"224.0.0.0/4", "240.0.0.0/4",
	}
	vyosBogonsIpv6 = []string{
		"::/128", "::1/128", "::ffff:0:0/96", "100::/64", "2001:2::/48", "2001:db8::/32", "3ffe::/16",
		"fc00::/7", "fe80::/10", "fec0::/10", "ff00::/8",
	}
)

// generateGateway renders a gateway of ours. The isp keeps the ipv4 block
// on-link at its own gateway address on the isp link, so the gateway holds
// an address of the block there and carries the routers behind it the way
// an edge router carries its hosts: each router's address and the hosts it
// routes are /32 routes to the block bridge, proxy-arped for on the isp
// link, and the isp's gateway is proxy-arped for on the bridge. The /48
// arrives over the isp point to point tunnel; the bridge holds the site's
// ::1/64, one /56 is routed per router behind it and the rest of the /48
// is blackholed. Bogons (the site's own blocks among them, bar the isp
// gateway's icmp) are dropped on the isp link and everything else is
// forwarded unfiltered, since the routers behind it filter; the gateway
// itself is protected like every router; no nat; a management bridge on
// the reserved port.
func (self *VyosGenerator) generateGateway(router string, routerConfig *services.RouterConfig) (*vyos.Config, error) {
	gateway, ok := self.servicesConfig.Gateways[router]
	if !ok {
		return nil, fmt.Errorf("router %s is a gateway without a gateways entry", router)
	}
	block4, err := netip.ParsePrefix(gateway.Ipv4)
	if err != nil {
		return nil, fmt.Errorf("gateway %s ipv4: %w", router, err)
	}
	block6, err := netip.ParsePrefix(gateway.Ipv6)
	if err != nil {
		return nil, fmt.Errorf("gateway %s ipv6: %w", router, err)
	}
	gateway4, err := netip.ParseAddr(gateway.Ipv4Gateway)
	if err != nil {
		return nil, fmt.Errorf("gateway %s ipv4_gateway: %w", router, err)
	}
	gateway6, err := netip.ParseAddr(gateway.Ipv6Gateway)
	if err != nil {
		return nil, fmt.Errorf("gateway %s ipv6_gateway: %w", router, err)
	}
	ispIpv6, ownIpv6, err := services.GatewayIspIpv6(routerConfig)
	if err != nil {
		return nil, fmt.Errorf("router %s: %w", router, err)
	}
	wanIpv4, err := netip.ParsePrefix(routerConfig.WanIpv4)
	if err != nil {
		return nil, fmt.Errorf("router %s wan_ipv4: %w", router, err)
	}
	behind := []vyosGatewayRouter{}
	if blocks, err := self.GatewayRoutes(self.servicesConfig.RoutersBehind(router)); err != nil {
		return nil, err
	} else if len(blocks) == 1 {
		behind = blocks[0].Routers
	}
	nameServers := routerConfig.GetNameServers()

	root := vyos.NewNode()

	// firewall: the site's blocks and the bogons never arrive from the isp
	firewall := root.Child("firewall")
	firewall.SetLeaf("all-ping", "enable")
	firewall.SetLeaf("broadcast-ping", "disable")
	group := firewall.Child("group")
	bogons4 := group.Tag("network-group", "BOGONS")
	bogons4.SetLeaf("description", "Sources that never arrive from the isp")
	bogons4.SetLeaf("network", append([]string{block4.String()}, vyosBogonsIpv4...)...)
	bogons6 := group.Tag("ipv6-network-group", "BOGONS6")
	bogons6.SetLeaf("description", "Sources that never arrive from the isp")
	bogons6.SetLeaf("ipv6-network", append([]string{block6.String()}, vyosBogonsIpv6...)...)
	firewall.SetLeaf("ipv6-receive-redirects", "disable")
	firewall.SetLeaf("ipv6-src-route", "disable")
	firewall.SetLeaf("ip-src-route", "disable")
	firewall.SetLeaf("log-martians", "enable")
	firewall.SetLeaf("receive-redirects", "disable")
	firewall.SetLeaf("send-redirects", "disable")
	firewall.SetLeaf("source-validation", "disable")
	firewall.SetLeaf("syn-cookies", "enable")

	wanIn := firewall.Tag("name", "WAN_IN")
	wanIn.SetLeaf("default-action", "accept")
	wanIn.SetLeaf("description", "ISP to the blocks: bogons dropped, the routers behind filter")
	vyosIspGatewayIcmpRule(wanIn, gateway4.String())
	vyosBogonRule(wanIn, "network-group", "BOGONS")
	wanLocal := firewall.Tag("name", "WAN_LOCAL")
	wanLocal.SetLeaf("default-action", "drop")
	wanLocal.SetLeaf("description", "ISP to the gateway")
	vyosIspGatewayIcmpRule(wanLocal, gateway4.String())
	vyosBogonRule(wanLocal, "network-group", "BOGONS")
	vyosStateRules(wanLocal)
	vyosIcmpEchoRules(wanLocal, "icmp")
	vyosLogDropRule(wanLocal)
	wanIn6 := firewall.Tag("ipv6-name", "WANv6_IN")
	wanIn6.SetLeaf("default-action", "accept")
	wanIn6.SetLeaf("description", "ISP to the blocks: bogons dropped, the routers behind filter")
	vyosBogonRule(wanIn6, "ipv6-network-group", "BOGONS6")
	wanLocal6 := firewall.Tag("ipv6-name", "WANv6_LOCAL")
	wanLocal6.SetLeaf("default-action", "drop")
	wanLocal6.SetLeaf("description", "ISP to the gateway")
	vyosBogonRule(wanLocal6, "ipv6-network-group", "BOGONS6")
	vyosStateRules(wanLocal6)
	vyosIcmpEchoRules(wanLocal6, "ipv6-icmp")
	vyosLogDropRule(wanLocal6)

	// interfaces: the block bridge (the site's ::1/64; ipv4 is routed and
	// proxy-arped through, the isp's gateway being on-link on the isp
	// side), the management bridge, the isp link
	interfaces := root.Child("interfaces")
	blocks := interfaces.Tag("bridge", "br0")
	blocks.SetLeaf("address", netip.PrefixFrom(gateway6, 64).String())
	blocks.SetLeaf("aging", "300")
	blocks.SetLeaf("bridged-conntrack", "disable")
	blocks.SetLeaf("description", "Blocks")
	blocks.SetLeaf("hello-time", "2")
	blocks.SetLeaf("max-age", "20")
	blocks.Child("ip").SetLeaf("enable-proxy-arp")
	blocks.SetLeaf("priority", "32768")
	blocks.SetLeaf("promiscuous", "enable")
	blocks.SetLeaf("stp", "false")
	for _, port := range routerConfig.BlockInterfaces {
		ethernet := interfaces.Tag("ethernet", port)
		ethernet.Child("bridge-group").SetLeaf("bridge", "br0")
		ethernet.SetLeaf("description", "Blocks")
		ethernet.SetLeaf("duplex", "auto")
		ethernet.SetLeaf("speed", "auto")
	}
	var lanIpv4 netip.Prefix
	if len(routerConfig.BridgeInterfaces) > 0 {
		lanIpv4, err = netip.ParsePrefix(routerConfig.LanIpv4)
		if err != nil {
			return nil, fmt.Errorf("router %s lan_ipv4: %w", router, err)
		}
		management := interfaces.Tag("bridge", "br1")
		management.SetLeaf("address", lanIpv4.String())
		management.SetLeaf("aging", "300")
		management.SetLeaf("bridged-conntrack", "disable")
		management.SetLeaf("description", "Local Bridge")
		management.SetLeaf("hello-time", "2")
		management.SetLeaf("max-age", "20")
		management.SetLeaf("priority", "32768")
		management.SetLeaf("promiscuous", "enable")
		management.SetLeaf("stp", "false")
		for _, port := range routerConfig.BridgeInterfaces {
			ethernet := interfaces.Tag("ethernet", port)
			ethernet.Child("bridge-group").SetLeaf("bridge", "br1")
			ethernet.SetLeaf("description", "Local Bridge")
			ethernet.SetLeaf("duplex", "auto")
			ethernet.SetLeaf("speed", "auto")
		}
	}
	isp := interfaces.Tag("ethernet", routerConfig.IspInterface)
	isp.SetLeaf("address", wanIpv4.String(), ownIpv6.String())
	isp.SetLeaf("description", "ISP")
	isp.SetLeaf("duplex", "auto")
	isp.Child("firewall").Child("in").SetLeaf("ipv6-name", "WANv6_IN")
	isp.Child("firewall").Child("in").SetLeaf("name", "WAN_IN")
	isp.Child("firewall").Child("local").SetLeaf("ipv6-name", "WANv6_LOCAL")
	isp.Child("firewall").Child("local").SetLeaf("name", "WAN_LOCAL")
	isp.Child("ip").SetLeaf("enable-proxy-arp")
	isp.SetLeaf("speed", "auto")
	interfaces.Tag("loopback", "lo")
	interfaces.Tag("openvpn", "vtun1").SetLeaf("config-file", routerConfig.GetManagementVpnConfigFile())

	// protocols: the ipv6 default route up the tunnel (the ipv4 one is the
	// isp's on-link gateway); per router behind the gateway, its address
	// and its hosts as /32s to the bridge and its /56 to its WAN address;
	// the rest of the /48 dropped here
	static := root.Child("protocols").Child("static")
	static.Tag("route6", "::/0").Tag("next-hop", ispIpv6.String()).SetLeaf("interface", routerConfig.IspInterface)
	static.Tag("route6", block6.String()).Child("blackhole")
	for _, gatewayRouter := range behind {
		for _, address := range append([]string{gatewayRouter.WanIpv4}, gatewayRouter.HostIpv4...) {
			static.Tag("interface-route", address+"/32").Tag("next-hop-interface", "br0")
		}
		static.Tag("route6", gatewayRouter.Ipv6Block.String()).Tag("next-hop", gatewayRouter.WanIpv6.String()).SetLeaf("interface", "br0")
	}

	// service: dhcp and the resolver on the management bridge only
	service := root.Child("service")
	if lanIpv4.IsValid() {
		vyosDhcp(service, lanIpv4, nil)
		forwarding := service.Child("dns").Child("forwarding")
		forwarding.SetLeaf("cache-size", "10000")
		forwarding.SetLeaf("force-public-dns-boost")
		forwarding.SetLeaf("listen-on", "br1")
	}
	gui := service.Child("gui")
	gui.SetLeaf("http-port", "80")
	gui.SetLeaf("https-port", "443")
	gui.SetLeaf("older-ciphers", "disable")
	ssh := service.Child("ssh")
	ssh.SetLeaf("disable-password-authentication")
	ssh.SetLeaf("port", "22")
	ssh.SetLeaf("protocol-version", "v2")
	vyosUnms(service, routerConfig)

	vyosSystem(root, router, routerConfig, nameServers, gateway4.String())
	return &vyos.Config{Root: root, Comments: vyosFooter(routerConfig)}, nil
}

// vyosIspGatewayIcmpRule admits icmp from the isp's gateway address, which
// lies inside the site's own ipv4 block and would otherwise fall to the
// bogon drop: its path mtu and unreachable errors must reach the routers.
func vyosIspGatewayIcmpRule(chain *vyos.Node, gateway string) {
	rule := chain.Tag("rule", "4")
	rule.SetLeaf("action", "accept")
	rule.SetLeaf("description", "Allow icmp from the isp gateway")
	rule.SetLeaf("log", "disable")
	rule.SetLeaf("protocol", "icmp")
	rule.Child("source").SetLeaf("address", gateway)
}

// vyosBogonRule drops what a firewall group lists as source, ahead of
// everything but the isp gateway's icmp.
func vyosBogonRule(chain *vyos.Node, groupKind string, groupName string) {
	rule := chain.Tag("rule", "5")
	rule.SetLeaf("action", "drop")
	rule.SetLeaf("description", "Drop bogon sources")
	rule.SetLeaf("log", "disable")
	rule.SetLeaf("protocol", "all")
	rule.Child("source").Child("group").SetLeaf(groupKind, groupName)
}

// generateEdge renders an edge router: the management bridge, one routed
// port per attached host and the firewall of what is served there.
func (self *VyosGenerator) generateEdge(router string, routerConfig *services.RouterConfig) (*vyos.Config, error) {
	addresses, err := self.addresses(router, routerConfig)
	if err != nil {
		return nil, err
	}
	root := vyos.NewNode()
	wanIn, _, wanIn6, _ := vyosFirewall(root, addresses, true)

	// interfaces
	interfaces := root.Child("interfaces")
	vyosBridge(interfaces, routerConfig, addresses.lanIpv4.String())
	vyosWanInterface(interfaces, routerConfig, addresses, true)
	for _, lanInterface := range routerConfig.LanInterfaces {
		lanIpv6, err := services.RouterLanIpv6Prefix(router, routerConfig, lanInterface)
		if err != nil {
			return nil, err
		}
		ethernet := interfaces.Tag("ethernet", lanInterface)
		ethernet.SetLeaf("address", netip.PrefixFrom(lanIpv6.Addr().Next(), 64).String())
		ethernet.SetLeaf("duplex", "auto")
		ethernet.Child("ip").SetLeaf("enable-proxy-arp")
		vyosRouterAdvert(ethernet, lanIpv6, addresses.ipv6NameServers)
		ethernet.SetLeaf("speed", "auto")
	}
	interfaces.Tag("loopback", "lo")
	interfaces.Tag("openvpn", "vtun1").SetLeaf("config-file", routerConfig.GetManagementVpnConfigFile())

	static := vyosStaticRoutes(root, routerConfig, addresses)

	// service
	service := root.Child("service")
	vyosDhcp(service, addresses.lanIpv4, nil)
	vyosCommonServices(service, routerConfig)
	nat := service.Child("nat")
	vyosMasquerade(nat, routerConfig, addresses, !routerConfig.MasqueradeWanBlock)

	vyosSystem(root, router, routerConfig, addresses.nameServers, routerConfig.WanGatewayIpv4)

	// hosts
	ipv4RuleNumber := vyosHostRuleStart
	ipv6RuleNumber := vyosHostRuleStart
	dnatRuleNumber := vyosHostRuleStart
	for _, attachment := range self.attachments(router) {
		ipv4Rules, ipv6Rules, dnats, err := self.publicRules(attachment)
		if err != nil {
			return nil, err
		}
		ipv4, err := netip.ParseAddr(attachment.lbBlock.Ipv4)
		if err != nil {
			return nil, fmt.Errorf("%s %s ipv4: %w", attachment.host, attachment.interfaceName, err)
		}
		static.Tag("interface-route", netip.PrefixFrom(ipv4, 32).String()).Tag("next-hop-interface", attachment.routerInterface)
		for _, rule := range ipv4Rules {
			vyosHostRule(wanIn, ipv4RuleNumber, attachment.lbBlock.Ipv4, rule, self.shortHost(attachment.host), attachment.interfaceName)
			ipv4RuleNumber += vyosHostRuleStride
		}
		for _, rule := range ipv6Rules {
			vyosHostRule(wanIn6, ipv6RuleNumber, attachment.lbBlock.Ipv6, rule, self.shortHost(attachment.host), attachment.interfaceName)
			ipv6RuleNumber += vyosHostRuleStride
		}
		for _, dnat := range dnats {
			vyosDnatRule(nat, dnatRuleNumber, routerConfig.WanInterface, attachment.lbBlock.Ipv4, dnat, self.shortHost(attachment.host), attachment.interfaceName)
			dnatRuleNumber += vyosHostRuleStride
		}
	}

	return &vyos.Config{Root: root, Comments: vyosFooter(routerConfig)}, nil
}

// generateLan renders a lan router: every port but the WAN bridged into
// the regional lan, the hosts pinned by dhcp to the addresses of
// config/<env>/settings.yml lan_hosts, the lan masqueraded, and the
// declared public ports forwarded to lan hosts. Nothing from the WAN block
// is admitted into the lan on its own: a private lan has no "allow local".
func (self *VyosGenerator) generateLan(router string, routerConfig *services.RouterConfig) (*vyos.Config, error) {
	addresses, err := self.addresses(router, routerConfig)
	if err != nil {
		return nil, err
	}
	bridgeIpv6, err := services.RouterBridgeIpv6Prefix(router, routerConfig)
	if err != nil {
		return nil, err
	}
	lan := addresses.lanIpv4.Masked()
	lanHosts, err := self.lanHostsIn(lan)
	if err != nil {
		return nil, fmt.Errorf("router %s: %w", router, err)
	}
	bridgeAddress6 := bridgeIpv6.Addr().Next()

	root := vyos.NewNode()
	wanIn, _, _, _ := vyosFirewall(root, addresses, false)

	// interfaces
	interfaces := root.Child("interfaces")
	bridge := vyosBridge(interfaces, routerConfig, addresses.lanIpv4.String(), netip.PrefixFrom(bridgeAddress6, 64).String())
	// the hosts resolve through the router, on both families
	vyosRouterAdvert(bridge, bridgeIpv6, []string{bridgeAddress6.String()})
	vyosWanInterface(interfaces, routerConfig, addresses, false)
	interfaces.Tag("loopback", "lo")
	interfaces.Tag("openvpn", "vtun1").SetLeaf("config-file", routerConfig.GetManagementVpnConfigFile())

	vyosStaticRoutes(root, routerConfig, addresses)

	// service
	service := root.Child("service")
	vyosDhcp(service, addresses.lanIpv4, lanHosts)
	vyosCommonServices(service, routerConfig)
	nat := service.Child("nat")
	ruleNumber := vyosHostRuleStart
	publicPorts := maps.Keys(routerConfig.PublicPorts)
	sort.Ints(publicPorts)
	for _, publicPort := range publicPorts {
		forward := routerConfig.PublicPorts[publicPort]
		host, ok := lanHosts[forward.Host]
		if !ok {
			return nil, fmt.Errorf("router %s public port %d forwards to %s, which is not a lan_hosts entry of config/%s/settings.yml inside %s", router, publicPort, forward.Host, self.env, lan)
		}
		description := forward.Description
		if description == "" {
			description = fmt.Sprintf("%d to %d %s", publicPort, forward.Port, forward.GetProtocol())
		}
		description = fmt.Sprintf("warp %s %s", forward.Host, description)
		accept := wanIn.Tag("rule", strconv.Itoa(ruleNumber))
		accept.SetLeaf("action", "accept")
		accept.SetLeaf("description", description)
		accept.Child("destination").SetLeaf("address", host.Ip)
		accept.Child("destination").SetLeaf("port", strconv.Itoa(forward.Port))
		accept.SetLeaf("log", "disable")
		accept.SetLeaf("protocol", forward.GetProtocol())
		rewrite := nat.Tag("rule", strconv.Itoa(ruleNumber))
		rewrite.SetLeaf("description", description)
		rewrite.Child("destination").SetLeaf("port", strconv.Itoa(publicPort))
		rewrite.SetLeaf("inbound-interface", routerConfig.WanInterface)
		rewrite.Child("inside-address").SetLeaf("address", host.Ip)
		rewrite.Child("inside-address").SetLeaf("port", strconv.Itoa(forward.Port))
		rewrite.SetLeaf("log", "disable")
		rewrite.SetLeaf("protocol", forward.GetProtocol())
		rewrite.SetLeaf("type", "destination")
		ruleNumber += vyosHostRuleStride
	}
	// the whole lan is private: everything leaves as the router
	vyosMasquerade(nat, routerConfig, addresses, false)

	vyosSystem(root, router, routerConfig, addresses.nameServers, routerConfig.WanGatewayIpv4)
	return &vyos.Config{Root: root, Comments: vyosFooter(routerConfig)}, nil
}

// lanHostsIn returns the lan_hosts inside a lan, checking that the hosts'
// `routes` addresses in settings.yml agree with them.
func (self *VyosGenerator) lanHostsIn(lan netip.Prefix) (map[string]*services.LanHost, error) {
	hosts := map[string]*services.LanHost{}
	for name, host := range self.lanHosts {
		if ip, err := netip.ParseAddr(host.Ip); err == nil && lan.Contains(ip) {
			hosts[name] = host
		}
	}
	names := maps.Keys(self.lanRoutes)
	sort.Strings(names)
	for _, name := range names {
		route, err := netip.ParseAddr(self.lanRoutes[name])
		if err != nil || !lan.Contains(route) {
			continue
		}
		host, ok := hosts[name]
		if !ok {
			return nil, fmt.Errorf("settings.yml routes %s %s lies in %s but %s has no %s entry; run run-routers.sh --update-settings", name, route, lan, services.LanHostsKey, name)
		}
		if host.Ip != route.String() {
			return nil, fmt.Errorf("settings.yml routes %s %s disagrees with %s %s", name, route, services.LanHostsKey, host.Ip)
		}
	}
	return hosts, nil
}

// vyosFirewall renders the four WAN chains and binds nothing yet: the
// caller adds the host rules. allowLocal admits the site's own blocks into
// the routed side, which a private lan does not want.
func vyosFirewall(root *vyos.Node, addresses *vyosAddresses, allowLocal bool) (wanIn *vyos.Node, wanLocal *vyos.Node, wanIn6 *vyos.Node, wanLocal6 *vyos.Node) {
	firewall := root.Child("firewall")
	firewall.SetLeaf("all-ping", "enable")
	firewall.SetLeaf("broadcast-ping", "disable")
	firewall.SetLeaf("ipv6-receive-redirects", "disable")
	firewall.SetLeaf("ipv6-src-route", "disable")
	firewall.SetLeaf("ip-src-route", "disable")
	firewall.SetLeaf("log-martians", "enable")
	firewall.SetLeaf("receive-redirects", "disable")
	firewall.SetLeaf("send-redirects", "disable")
	firewall.SetLeaf("source-validation", "disable")
	firewall.SetLeaf("syn-cookies", "enable")

	wanIn = firewall.Tag("name", "WAN_IN")
	wanIn.SetLeaf("default-action", "drop")
	wanIn.SetLeaf("description", "WAN to internal")
	vyosStateRules(wanIn)
	if allowLocal {
		vyosAllowLocalRule(wanIn, addresses.wanIpv4.Masked().String())
	}
	vyosIcmpRule(wanIn, "40", "icmp")
	vyosLogDropRule(wanIn)

	wanLocal = firewall.Tag("name", "WAN_LOCAL")
	wanLocal.SetLeaf("default-action", "drop")
	wanLocal.SetLeaf("description", "WAN to router")
	vyosStateRules(wanLocal)
	vyosIcmpEchoRules(wanLocal, "icmp")
	vyosLogDropRule(wanLocal)

	wanIn6 = firewall.Tag("ipv6-name", "WANv6_IN")
	wanIn6.SetLeaf("default-action", "drop")
	wanIn6.SetLeaf("description", "WAN inbound traffic forwarded to LAN")
	vyosStateRules(wanIn6)
	if allowLocal {
		vyosAllowLocalRule(wanIn6, addresses.siteIpv6.Masked().String())
	}
	vyosIcmpRule(wanIn6, "40", "ipv6-icmp")
	vyosLogDropRule(wanIn6)

	wanLocal6 = firewall.Tag("ipv6-name", "WANv6_LOCAL")
	wanLocal6.SetLeaf("default-action", "drop")
	wanLocal6.SetLeaf("description", "WAN inbound traffic to the router")
	vyosStateRules(wanLocal6)
	vyosIcmpEchoRules(wanLocal6, "ipv6-icmp")
	vyosLogDropRule(wanLocal6)
	return wanIn, wanLocal, wanIn6, wanLocal6
}

// vyosBridge renders the bridge with its addresses and its member ports.
func vyosBridge(interfaces *vyos.Node, routerConfig *services.RouterConfig, bridgeAddresses ...string) *vyos.Node {
	bridge := interfaces.Tag("bridge", "br0")
	bridge.SetLeaf("address", bridgeAddresses...)
	bridge.SetLeaf("aging", "300")
	bridge.SetLeaf("bridged-conntrack", "disable")
	bridge.SetLeaf("description", "Local Bridge")
	bridge.SetLeaf("hello-time", "2")
	bridge.SetLeaf("max-age", "20")
	bridge.SetLeaf("priority", "32768")
	bridge.SetLeaf("promiscuous", "enable")
	bridge.SetLeaf("stp", "false")
	for _, bridgeInterface := range routerConfig.BridgeInterfaces {
		ethernet := interfaces.Tag("ethernet", bridgeInterface)
		ethernet.Child("bridge-group").SetLeaf("bridge", "br0")
		ethernet.SetLeaf("description", "Local Bridge")
		ethernet.SetLeaf("duplex", "auto")
		ethernet.SetLeaf("speed", "auto")
	}
	return bridge
}

// vyosWanInterface renders the WAN port with its firewall; proxyArp lets
// an edge router answer for the hosts whose addresses it routes.
func vyosWanInterface(interfaces *vyos.Node, routerConfig *services.RouterConfig, addresses *vyosAddresses, proxyArp bool) {
	wan := interfaces.Tag("ethernet", routerConfig.WanInterface)
	wan.SetLeaf("address", addresses.wanIpv4.String(), addresses.wanIpv6.String())
	wan.SetLeaf("description", "Internet")
	wan.SetLeaf("duplex", "auto")
	wan.Child("firewall").Child("in").SetLeaf("ipv6-name", "WANv6_IN")
	wan.Child("firewall").Child("in").SetLeaf("name", "WAN_IN")
	wan.Child("firewall").Child("local").SetLeaf("ipv6-name", "WANv6_LOCAL")
	wan.Child("firewall").Child("local").SetLeaf("name", "WAN_LOCAL")
	if proxyArp {
		wan.Child("ip").SetLeaf("enable-proxy-arp")
	}
	wan.SetLeaf("speed", "auto")
}

// vyosRouterAdvert advertises a /64 on an interface, with the resolvers.
func vyosRouterAdvert(node *vyos.Node, prefix netip.Prefix, nameServers []string) {
	ipv6 := node.Child("ipv6")
	ipv6.SetLeaf("dup-addr-detect-transmits", "1")
	advert := ipv6.Child("router-advert")
	advert.SetLeaf("cur-hop-limit", "64")
	advert.SetLeaf("link-mtu", "0")
	advert.SetLeaf("managed-flag", "false")
	advert.SetLeaf("max-interval", "600")
	if 0 < len(nameServers) {
		advert.SetLeaf("name-server", nameServers...)
	}
	advert.SetLeaf("other-config-flag", "false")
	advertised := advert.Tag("prefix", prefix.String())
	advertised.SetLeaf("autonomous-flag", "true")
	advertised.SetLeaf("on-link-flag", "true")
	advertised.SetLeaf("valid-lifetime", "2592000")
	advert.SetLeaf("reachable-time", "0")
	advert.SetLeaf("retrans-timer", "0")
	advert.SetLeaf("send-advert", "true")
}

// vyosStaticRoutes renders the default route and the blackholes.
func vyosStaticRoutes(root *vyos.Node, routerConfig *services.RouterConfig, addresses *vyosAddresses) *vyos.Node {
	static := root.Child("protocols").Child("static")
	static.Tag("route6", "::/0").Tag("next-hop", routerConfig.WanGatewayIpv6).SetLeaf("interface", routerConfig.WanInterface)
	// the upstream routes the router's /56 here; an address in it that no
	// port advertises is dropped here rather than sent back up the default
	// route, and so is the pre-convention /64 of the router id in case the
	// upstream still routes it
	static.Tag("route6", addresses.ipv6Block.String()).Child("blackhole")
	static.Tag("route6", addresses.legacyIpv6.String()).Child("blackhole")
	return static
}

// the dhcp range of a bridge, leaving the low addresses to the router and
// to hand assignment
const (
	vyosDhcpRangeStart = 38
	vyosDhcpRangeStop  = 243
)

// vyosDhcp renders the bridge's dhcp with the static mappings, if any.
func vyosDhcp(service *vyos.Node, lanIpv4 netip.Prefix, staticMappings map[string]*services.LanHost) {
	dhcp := service.Child("dhcp-server")
	dhcp.SetLeaf("disabled", "false")
	dhcp.SetLeaf("hostfile-update", "disable")
	lanNetwork := lanIpv4.Masked()
	lanBytes := lanNetwork.Addr().As4()
	dhcpStart, dhcpStop := lanBytes, lanBytes
	dhcpStart[3] = vyosDhcpRangeStart
	dhcpStop[3] = vyosDhcpRangeStop
	subnet := dhcp.Tag("shared-network-name", "LAN_BR")
	subnet.SetLeaf("authoritative", "enable")
	subnetNode := subnet.Tag("subnet", lanNetwork.String())
	subnetNode.SetLeaf("default-router", lanIpv4.Addr().String())
	subnetNode.SetLeaf("dns-server", lanIpv4.Addr().String())
	subnetNode.SetLeaf("lease", "86400")
	subnetNode.Tag("start", netip.AddrFrom4(dhcpStart).String()).SetLeaf("stop", netip.AddrFrom4(dhcpStop).String())
	names := maps.Keys(staticMappings)
	sort.Strings(names)
	for _, name := range names {
		mapping := subnetNode.Tag("static-mapping", name)
		mapping.SetLeaf("ip-address", staticMappings[name].Ip)
		mapping.SetLeaf("mac-address", staticMappings[name].Mac)
	}
	dhcp.SetLeaf("static-arp", "disable")
	dhcp.SetLeaf("use-dnsmasq", "disable")
}

// vyosCommonServices renders the resolver, the gui, ssh and uisp.
func vyosCommonServices(service *vyos.Node, routerConfig *services.RouterConfig) {
	forwarding := service.Child("dns").Child("forwarding")
	forwarding.SetLeaf("cache-size", "10000")
	forwarding.SetLeaf("force-public-dns-boost")
	forwarding.SetLeaf("listen-on", "br0")
	gui := service.Child("gui")
	gui.SetLeaf("http-port", "80")
	gui.SetLeaf("https-port", "443")
	gui.SetLeaf("older-ciphers", "disable")
	ssh := service.Child("ssh")
	// keys only: every router carries the fleet key (validated), and the
	// gui keeps the password
	ssh.SetLeaf("disable-password-authentication")
	ssh.SetLeaf("port", "22")
	ssh.SetLeaf("protocol-version", "v2")
	vyosUnms(service, routerConfig)
}

// vyosUnms renders the uisp attachment, or the empty stanza of a router
// that is not in uisp yet.
func vyosUnms(service *vyos.Node, routerConfig *services.RouterConfig) {
	unms := service.Child("unms")
	if routerConfig.Unms != services.UnmsPending {
		unms.SetLeaf("connection", routerConfig.Unms)
	}
}

// vyosMasquerade renders the egress nat: everything leaves as the router,
// unless the WAN block is excluded so hosts holding its addresses keep them.
func vyosMasquerade(nat *vyos.Node, routerConfig *services.RouterConfig, addresses *vyosAddresses, excludeWanBlock bool) {
	if excludeWanBlock {
		exclude := nat.Tag("rule", "5000")
		exclude.SetLeaf("description", "Exclude local")
		exclude.SetLeaf("exclude")
		exclude.SetLeaf("log", "disable")
		exclude.SetLeaf("outbound-interface", routerConfig.WanInterface)
		exclude.SetLeaf("protocol", "all")
		exclude.Child("source").SetLeaf("address", addresses.wanIpv4.Masked().String())
		exclude.SetLeaf("type", "masquerade")
	}
	masquerade := nat.Tag("rule", "5001")
	masquerade.SetLeaf("description", "masquerade for WAN")
	masquerade.SetLeaf("log", "disable")
	masquerade.SetLeaf("outbound-interface", routerConfig.WanInterface)
	masquerade.SetLeaf("protocol", "all")
	masquerade.SetLeaf("type", "masquerade")
}

// vyosSystem renders the system section; gatewayAddress is the ipv4
// default gateway, empty while a planned gateway waits for its /31.
func vyosSystem(root *vyos.Node, router string, routerConfig *services.RouterConfig, nameServers []string, gatewayAddress string) {
	system := root.Child("system")
	system.Child("analytics-handler").SetLeaf("send-analytics-report", "false")
	conntrack := system.Child("conntrack")
	if routerConfig.ConntrackHashSize != 0 {
		conntrack.SetLeaf("hash-size", strconv.Itoa(routerConfig.ConntrackHashSize))
	}
	// conntrack helpers can be abused to open ports from inside the lan
	// (nat slipstreaming); none of them are needed here
	modules := conntrack.Child("modules")
	for _, module := range []string{"ftp", "gre", "h323", "pptp", "sip", "tftp"} {
		modules.Child(module).SetLeaf("disable")
	}
	if routerConfig.ConntrackTableSize != 0 {
		conntrack.SetLeaf("table-size", strconv.Itoa(routerConfig.ConntrackTableSize))
	}
	system.Child("crash-handler").SetLeaf("send-crash-report", "false")
	if gatewayAddress != "" {
		system.SetLeaf("gateway-address", gatewayAddress)
	}
	system.SetLeaf("host-name", router)
	logins := maps.Keys(routerConfig.Login)
	sort.Strings(logins)
	for _, userName := range logins {
		login := routerConfig.Login[userName]
		user := system.Child("login").Tag("user", userName)
		authentication := user.Child("authentication")
		authentication.SetLeaf("encrypted-password", login.EncryptedPassword)
		keyNames := maps.Keys(login.PublicKeys)
		sort.Strings(keyNames)
		for _, keyName := range keyNames {
			publicKey := authentication.Tag("public-keys", keyName)
			publicKey.SetLeaf("key", login.PublicKeys[keyName].Key)
			publicKey.SetLeaf("type", login.PublicKeys[keyName].Type)
		}
		user.SetLeaf("level", login.GetLevel())
	}
	system.SetLeaf("name-server", nameServers...)
	ntp := system.Child("ntp")
	for i := 0; i < 4; i++ {
		ntp.Tag("server", fmt.Sprintf("%d.ubnt.pool.ntp.org", i))
	}
	offload := system.Child("offload")
	offload.Child("ipv4").SetLeaf("forwarding", vyosEnabled(routerConfig.OffloadsIpv4Forwarding()))
	offload.Child("ipv6").SetLeaf("forwarding", vyosEnabled(routerConfig.OffloadsIpv6Forwarding()))
	syslog := system.Child("syslog").Child("global")
	syslog.Tag("facility", "all").SetLeaf("level", "notice")
	syslog.Tag("facility", "protocols").SetLeaf("level", "debug")
	system.SetLeaf("time-zone", "UTC")
}

// vyosFooter carries the firmware markers of the config.boot footer.
func vyosFooter(routerConfig *services.RouterConfig) []string {
	return []string{
		"/* Warning: Do not remove the following line. */",
		fmt.Sprintf("/* === vyatta-config-version: \"%s\" === */", routerConfig.EdgeosConfigVersion),
		fmt.Sprintf("/* Release version: %s */", routerConfig.EdgeosRelease),
	}
}

// vyosGatewayBlock is one gateway: what its upstream must route to the
// routers behind it.
type vyosGatewayBlock struct {
	Name        string
	Description string
	// the router of ours that is the gateway, empty for an isp gateway
	ManagedBy   string
	Ipv4Block   netip.Prefix
	GatewayIpv4 string
	SitePrefix  netip.Prefix
	GatewayIpv6 string
	Routers     []vyosGatewayRouter
}

// vyosGatewayRouter is one router behind a gateway.
type vyosGatewayRouter struct {
	Name string
	// the router's own address on the block, which a gateway of ours routes
	// to its block bridge and proxy-arps for on the isp link, as it does the
	// router's hosts
	WanIpv4 string
	// the /56 the gateway routes to the router's WAN address
	Ipv6Block netip.Prefix
	WanIpv6   netip.Addr
	// the pre-convention /64 the upstream may still route here; the router
	// blackholes it, so the route is to be retired
	LegacyIpv6 netip.Prefix
	// the host addresses the router answers for on the WAN with proxy arp
	HostIpv4 []string
	// a lan router: the private lan it masquerades
	Lan netip.Prefix
}

// GatewayRoutes lists, per gateway, what must be routed to the routers
// behind it. IPv6 needs one static route per router: its /56 to its WAN
// address in the gateway's /64. IPv4 needs none upstream: the block is
// on-link at the gateway and each router proxy-arps for the host addresses
// it routes to its ports (a gateway of ours does the same for the routers
// behind it and their hosts on the isp link). A gateway of ours renders
// these routes into its own configuration; an isp gateway needs them
// requested.
func (self *VyosGenerator) GatewayRoutes(routers []string) ([]vyosGatewayBlock, error) {
	blocks := map[string]*vyosGatewayBlock{}
	for _, router := range routers {
		routerConfig, ok := self.servicesConfig.Routers[router]
		if !ok {
			return nil, fmt.Errorf("unknown router %q", router)
		}
		if routerConfig.GetClass() == services.RouterClassGateway {
			// the gateway is the upstream itself
			continue
		}
		gateway, ok := self.servicesConfig.Gateways[routerConfig.Gateway]
		if !ok {
			return nil, fmt.Errorf("router %s names unknown gateway %q", router, routerConfig.Gateway)
		}
		wanIpv6, err := services.RouterWanIpv6(router, routerConfig)
		if err != nil {
			return nil, err
		}
		ipv6Block, err := services.RouterIpv6Block(router, routerConfig)
		if err != nil {
			return nil, err
		}
		legacyIpv6, err := services.RouterLegacyIpv6Prefix(router, routerConfig)
		if err != nil {
			return nil, err
		}
		block, ok := blocks[routerConfig.Gateway]
		if !ok {
			ipv4Block, err := netip.ParsePrefix(gateway.Ipv4)
			if err != nil {
				return nil, fmt.Errorf("gateway %s ipv4: %w", routerConfig.Gateway, err)
			}
			sitePrefix, err := netip.ParsePrefix(gateway.Ipv6)
			if err != nil {
				return nil, fmt.Errorf("gateway %s ipv6: %w", routerConfig.Gateway, err)
			}
			block = &vyosGatewayBlock{
				Name:        routerConfig.Gateway,
				Description: gateway.Description,
				Ipv4Block:   ipv4Block,
				GatewayIpv4: gateway.Ipv4Gateway,
				SitePrefix:  sitePrefix,
				GatewayIpv6: gateway.Ipv6Gateway,
			}
			if self.servicesConfig.IsManagedGateway(routerConfig.Gateway) {
				block.ManagedBy = routerConfig.Gateway
			}
			blocks[routerConfig.Gateway] = block
		}
		hostIpv4 := []string{}
		for _, attachment := range self.attachments(router) {
			hostIpv4 = append(hostIpv4, attachment.lbBlock.Ipv4)
		}
		gatewayRouter := vyosGatewayRouter{
			Name:       router,
			WanIpv4:    strings.SplitN(routerConfig.WanIpv4, "/", 2)[0],
			Ipv6Block:  ipv6Block,
			WanIpv6:    wanIpv6.Addr(),
			LegacyIpv6: legacyIpv6,
			HostIpv4:   hostIpv4,
		}
		if routerConfig.GetClass() == services.RouterClassLan {
			lanIpv4, err := services.RouterLanIpv4(router, routerConfig)
			if err != nil {
				return nil, err
			}
			gatewayRouter.Lan = lanIpv4.Masked()
		}
		block.Routers = append(block.Routers, gatewayRouter)
	}
	keys := maps.Keys(blocks)
	sort.Strings(keys)
	ordered := []vyosGatewayBlock{}
	for _, key := range keys {
		block := blocks[key]
		sort.Slice(block.Routers, func(i int, j int) bool {
			return block.Routers[i].Name < block.Routers[j].Name
		})
		ordered = append(ordered, *block)
	}
	return ordered, nil
}

// vyosGatewayRoutesText renders the gateway routes: per gateway, one line
// per route, comments for what needs no route and what to retire, and
// whether the gateway renders them itself or must be asked.
func vyosGatewayRoutesText(blocks []vyosGatewayBlock) string {
	var out strings.Builder
	for i, block := range blocks {
		if i > 0 {
			out.WriteString("\n")
		}
		fmt.Fprintf(&out, "# %s: %s via %s and %s via %s", block.Name, block.SitePrefix, block.GatewayIpv6, block.Ipv4Block, block.GatewayIpv4)
		if block.Description != "" {
			fmt.Fprintf(&out, " (%s)", block.Description)
		}
		out.WriteString("\n")
		if block.ManagedBy != "" {
			fmt.Fprintf(&out, "# ours: warpctl vyos renders these routes into %s\n", block.ManagedBy)
		} else {
			fmt.Fprintf(&out, "# the isp's: request these routes\n")
		}
		fmt.Fprintf(&out, "# IPv6: route each router's /56 to its WAN address in the gateway's /64\n")
		for _, router := range block.Routers {
			fmt.Fprintf(&out, "route %s next-hop %s    # %s\n", router.Ipv6Block, router.WanIpv6, router.Name)
		}
		if block.ManagedBy != "" {
			fmt.Fprintf(&out, "# IPv4: no route; %s is on-link at the isp's %s and %s routes each router and its hosts to its block bridge, proxy-arping for them on the isp link\n", block.Ipv4Block, block.GatewayIpv4, block.ManagedBy)
		} else {
			fmt.Fprintf(&out, "# IPv4: no route; %s is on-link at %s and each router proxy-arps for its hosts\n", block.Ipv4Block, block.GatewayIpv4)
		}
		for _, router := range block.Routers {
			hosts := "none attached"
			switch {
			case router.Lan.IsValid():
				hosts = fmt.Sprintf("lan %s masqueraded, no public hosts", router.Lan)
			case 0 < len(router.HostIpv4):
				hosts = strings.Join(router.HostIpv4, " ")
			}
			if block.ManagedBy != "" {
				fmt.Fprintf(&out, "#   %s at %s: %s\n", router.Name, router.WanIpv4, hosts)
			} else {
				fmt.Fprintf(&out, "#   %s: %s\n", router.Name, hosts)
			}
		}
		if block.ManagedBy == "" {
			fmt.Fprintf(&out, "# retire once the router runs the generated configuration (it blackholes these)\n")
			for _, router := range block.Routers {
				fmt.Fprintf(&out, "#   no route %s next-hop %s    # %s\n", router.LegacyIpv6, router.WanIpv6, router.Name)
			}
		}
	}
	return out.String()
}

// host rules start at 100 and step by 10 so the base rules keep their fixed
// numbers and an operator can wedge a temporary rule between two of ours.
// The same numbering serves the destination nat rules, which sit below the
// masquerade rules at 5000.
const (
	vyosHostRuleStart  = 100
	vyosHostRuleStride = 10
)

// vyosDnatRule rewrites one public port arriving on the WAN interface for a
// host address to the port the host's service owns. The firewall sees the
// rewritten port, so the accept rule for the target port admits it.
func vyosDnatRule(nat *vyos.Node, number int, wanInterface string, address string, dnat vyosDnat, shortHost string, interfaceName string) {
	node := nat.Tag("rule", strconv.Itoa(number))
	node.SetLeaf("description", fmt.Sprintf("warp %s %s %s", shortHost, interfaceName, dnat.label))
	node.Child("destination").SetLeaf("address", address)
	node.Child("destination").SetLeaf("port", strconv.Itoa(dnat.publicPort))
	node.SetLeaf("inbound-interface", wanInterface)
	node.Child("inside-address").SetLeaf("address", address)
	node.Child("inside-address").SetLeaf("port", strconv.Itoa(dnat.targetPort))
	node.SetLeaf("log", "disable")
	node.SetLeaf("protocol", dnat.protocol)
	node.SetLeaf("type", "destination")
}

func vyosStateRules(chain *vyos.Node) {
	established := chain.Tag("rule", "10")
	established.SetLeaf("action", "accept")
	established.SetLeaf("description", "Allow established/related")
	established.Child("state").SetLeaf("established", "enable")
	established.Child("state").SetLeaf("related", "enable")
	invalid := chain.Tag("rule", "20")
	invalid.SetLeaf("action", "drop")
	invalid.SetLeaf("description", "Drop invalid state")
	invalid.Child("state").SetLeaf("invalid", "enable")
}

func vyosAllowLocalRule(chain *vyos.Node, prefix string) {
	local := chain.Tag("rule", "30")
	local.SetLeaf("action", "accept")
	local.SetLeaf("description", "Allow local")
	local.SetLeaf("log", "disable")
	local.SetLeaf("protocol", "all")
	local.Child("source").SetLeaf("address", prefix)
}

// the rate an accept rule for echo requests to the router admits, and the
// rate the drop-logging rule of each chain logs at; both are iptables limit
// matches (a token bucket per rule, not per source)
const (
	vyosEchoRate     = "10/second"
	vyosEchoBurst    = "20"
	vyosLogDropRate  = "5/second"
	vyosLogDropBurst = "10"
	// the drop-logging rule sits above every host rule and below the
	// default action
	vyosLogDropRuleNumber = "9000"
)

func vyosEnabled(enabled bool) string {
	if enabled {
		return "enable"
	}
	return "disable"
}

// vyosIcmpEchoRules admits echo requests to the router at a bounded rate
// (rule 30, then rule 31 drops the excess) and every other icmp type
// unconditionally (rule 32), so path mtu discovery and neighbour discovery
// are never throttled.
func vyosIcmpEchoRules(chain *vyos.Node, protocol string) {
	setEcho := func(rule *vyos.Node) {
		if protocol == "ipv6-icmp" {
			rule.Child("icmpv6").SetLeaf("type", "echo-request")
		} else {
			rule.Child("icmp").SetLeaf("type", "8")
		}
	}
	echo := chain.Tag("rule", "30")
	echo.SetLeaf("action", "accept")
	echo.SetLeaf("description", "Allow icmp echo up to the limit")
	setEcho(echo)
	echo.Child("limit").SetLeaf("burst", vyosEchoBurst)
	echo.Child("limit").SetLeaf("rate", vyosEchoRate)
	echo.SetLeaf("log", "disable")
	echo.SetLeaf("protocol", protocol)
	excess := chain.Tag("rule", "31")
	excess.SetLeaf("action", "drop")
	excess.SetLeaf("description", "Drop icmp echo over the limit")
	setEcho(excess)
	excess.SetLeaf("log", "disable")
	excess.SetLeaf("protocol", protocol)
	vyosIcmpRule(chain, "32", protocol)
}

// vyosLogDropRule logs a bounded sample of what the chain's default action
// drops: the rule matches only up to its rate, and everything else falls
// through to the silent default drop.
func vyosLogDropRule(chain *vyos.Node) {
	rule := chain.Tag("rule", vyosLogDropRuleNumber)
	rule.SetLeaf("action", "drop")
	rule.SetLeaf("description", "Log a sample of the dropped traffic")
	rule.Child("limit").SetLeaf("burst", vyosLogDropBurst)
	rule.Child("limit").SetLeaf("rate", vyosLogDropRate)
	rule.SetLeaf("log", "enable")
	rule.SetLeaf("protocol", "all")
}

func vyosIcmpRule(chain *vyos.Node, number string, protocol string) {
	icmp := chain.Tag("rule", number)
	icmp.SetLeaf("action", "accept")
	icmp.SetLeaf("description", "Allow icmp")
	icmp.SetLeaf("log", "disable")
	icmp.SetLeaf("protocol", protocol)
}

func vyosHostRule(chain *vyos.Node, number int, address string, rule vyosRule, shortHost string, interfaceName string) {
	node := chain.Tag("rule", strconv.Itoa(number))
	node.SetLeaf("action", "accept")
	node.SetLeaf("description", fmt.Sprintf("warp %s %s %s", shortHost, interfaceName, rule.label))
	node.Child("destination").SetLeaf("address", address)
	node.Child("destination").SetLeaf("port", strconv.Itoa(rule.port))
	node.SetLeaf("log", "disable")
	node.SetLeaf("protocol", rule.protocol)
}
