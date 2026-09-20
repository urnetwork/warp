package main

import (
	"fmt"
	"net/netip"
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
}

func NewVyosGenerator(env string) (*VyosGenerator, error) {
	servicesConfig := getServicesConfig(env)
	if len(servicesConfig.Routers) == 0 {
		return nil, fmt.Errorf("services config for %s has no routers", env)
	}
	return &VyosGenerator{
		env:            env,
		servicesConfig: servicesConfig,
		portBlocks:     getPortBlocks(env),
		systemdUnits:   NewSystemdUnits(env, "", "", true),
	}, nil
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
	return [][]string{
		{"interfaces", "ethernet", routerConfig.WanInterface},
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

// Generate renders one router.
func (self *VyosGenerator) Generate(router string) (*vyos.Config, error) {
	routerConfig, ok := self.servicesConfig.Routers[router]
	if !ok {
		return nil, fmt.Errorf("unknown router %q", router)
	}
	wanIpv4, err := netip.ParsePrefix(routerConfig.WanIpv4)
	if err != nil {
		return nil, fmt.Errorf("router %s wan_ipv4: %w", router, err)
	}
	wanIpv6, err := services.RouterWanIpv6(router, routerConfig)
	if err != nil {
		return nil, err
	}
	lanIpv4, err := services.RouterLanIpv4(router, routerConfig)
	if err != nil {
		return nil, err
	}
	nameServers := routerConfig.GetNameServers()
	ipv6NameServers := []string{}
	for _, nameServer := range nameServers {
		if address, err := netip.ParseAddr(nameServer); err == nil && address.Is6() {
			ipv6NameServers = append(ipv6NameServers, nameServer)
		}
	}

	root := vyos.NewNode()

	// firewall
	firewall := root.Child("firewall")
	firewall.SetLeaf("all-ping", "enable")
	firewall.SetLeaf("broadcast-ping", "disable")
	firewall.SetLeaf("ipv6-receive-redirects", "disable")
	firewall.SetLeaf("ipv6-src-route", "disable")
	firewall.SetLeaf("ip-src-route", "disable")
	firewall.SetLeaf("log-martians", "enable")
	firewall.SetLeaf("receive-redirects", "disable")
	firewall.SetLeaf("send-redirects", "enable")
	firewall.SetLeaf("source-validation", "disable")
	firewall.SetLeaf("syn-cookies", "enable")

	wanIn := firewall.Tag("name", "WAN_IN")
	wanIn.SetLeaf("default-action", "drop")
	wanIn.SetLeaf("description", "WAN to internal")
	vyosStateRules(wanIn)
	vyosAllowLocalRule(wanIn, wanIpv4.Masked().String())
	vyosIcmpRule(wanIn, "40", "icmp")

	wanLocal := firewall.Tag("name", "WAN_LOCAL")
	wanLocal.SetLeaf("default-action", "drop")
	wanLocal.SetLeaf("description", "WAN to router")
	vyosStateRules(wanLocal)
	vyosIcmpRule(wanLocal, "30", "icmp")

	wanIn6 := firewall.Tag("ipv6-name", "WANv6_IN")
	wanIn6.SetLeaf("default-action", "drop")
	wanIn6.SetLeaf("description", "WAN inbound traffic forwarded to LAN")
	wanIn6.SetLeaf("enable-default-log")
	vyosStateRules(wanIn6)
	vyosAllowLocalRule(wanIn6, wanIpv6.Masked().String())
	vyosIcmpRule(wanIn6, "40", "ipv6-icmp")

	wanLocal6 := firewall.Tag("ipv6-name", "WANv6_LOCAL")
	wanLocal6.SetLeaf("default-action", "drop")
	wanLocal6.SetLeaf("description", "WAN inbound traffic to the router")
	wanLocal6.SetLeaf("enable-default-log")
	vyosStateRules(wanLocal6)
	vyosIcmpRule(wanLocal6, "30", "ipv6-icmp")

	// interfaces
	interfaces := root.Child("interfaces")
	bridge := interfaces.Tag("bridge", "br0")
	bridge.SetLeaf("address", lanIpv4.String())
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
	wan := interfaces.Tag("ethernet", routerConfig.WanInterface)
	wan.SetLeaf("address", wanIpv4.String(), wanIpv6.String())
	wan.SetLeaf("description", "Internet")
	wan.SetLeaf("duplex", "auto")
	wan.Child("firewall").Child("in").SetLeaf("ipv6-name", "WANv6_IN")
	wan.Child("firewall").Child("in").SetLeaf("name", "WAN_IN")
	wan.Child("firewall").Child("local").SetLeaf("ipv6-name", "WANv6_LOCAL")
	wan.Child("firewall").Child("local").SetLeaf("name", "WAN_LOCAL")
	wan.Child("ip").SetLeaf("enable-proxy-arp")
	wan.SetLeaf("speed", "auto")
	for _, lanInterface := range routerConfig.LanInterfaces {
		lanIpv6, err := services.RouterLanIpv6Prefix(router, routerConfig, lanInterface)
		if err != nil {
			return nil, err
		}
		ethernet := interfaces.Tag("ethernet", lanInterface)
		ethernet.SetLeaf("address", netip.PrefixFrom(lanIpv6.Addr().Next(), 64).String())
		ethernet.SetLeaf("duplex", "auto")
		ethernet.Child("ip").SetLeaf("enable-proxy-arp")
		ipv6 := ethernet.Child("ipv6")
		ipv6.SetLeaf("dup-addr-detect-transmits", "1")
		advert := ipv6.Child("router-advert")
		advert.SetLeaf("cur-hop-limit", "64")
		advert.SetLeaf("link-mtu", "0")
		advert.SetLeaf("managed-flag", "false")
		advert.SetLeaf("max-interval", "600")
		if 0 < len(ipv6NameServers) {
			advert.SetLeaf("name-server", ipv6NameServers...)
		}
		advert.SetLeaf("other-config-flag", "false")
		prefix := advert.Tag("prefix", lanIpv6.String())
		prefix.SetLeaf("autonomous-flag", "true")
		prefix.SetLeaf("on-link-flag", "true")
		prefix.SetLeaf("valid-lifetime", "2592000")
		advert.SetLeaf("reachable-time", "0")
		advert.SetLeaf("retrans-timer", "0")
		advert.SetLeaf("send-advert", "true")
		ethernet.SetLeaf("speed", "auto")
	}
	interfaces.Tag("loopback", "lo")
	interfaces.Tag("openvpn", "vtun1").SetLeaf("config-file", routerConfig.GetManagementVpnConfigFile())

	// protocols
	static := root.Child("protocols").Child("static")
	static.Tag("route6", "::/0").Tag("next-hop", routerConfig.WanGatewayIpv6).SetLeaf("interface", routerConfig.WanInterface)

	// service
	service := root.Child("service")
	dhcp := service.Child("dhcp-server")
	dhcp.SetLeaf("disabled", "false")
	dhcp.SetLeaf("hostfile-update", "disable")
	lanNetwork := lanIpv4.Masked()
	lanBytes := lanNetwork.Addr().As4()
	dhcpStart, dhcpStop := lanBytes, lanBytes
	dhcpStart[3] = 38
	dhcpStop[3] = 243
	subnet := dhcp.Tag("shared-network-name", "LAN_BR")
	subnet.SetLeaf("authoritative", "enable")
	subnetNode := subnet.Tag("subnet", lanNetwork.String())
	subnetNode.SetLeaf("default-router", lanIpv4.Addr().String())
	subnetNode.SetLeaf("dns-server", lanIpv4.Addr().String())
	subnetNode.SetLeaf("lease", "86400")
	subnetNode.Tag("start", netip.AddrFrom4(dhcpStart).String()).SetLeaf("stop", netip.AddrFrom4(dhcpStop).String())
	dhcp.SetLeaf("static-arp", "disable")
	dhcp.SetLeaf("use-dnsmasq", "disable")
	forwarding := service.Child("dns").Child("forwarding")
	forwarding.SetLeaf("cache-size", "10000")
	forwarding.SetLeaf("force-public-dns-boost")
	forwarding.SetLeaf("listen-on", "br0")
	gui := service.Child("gui")
	gui.SetLeaf("http-port", "80")
	gui.SetLeaf("https-port", "443")
	gui.SetLeaf("older-ciphers", "enable")
	nat := service.Child("nat")
	exclude := nat.Tag("rule", "5000")
	exclude.SetLeaf("description", "Exclude local")
	exclude.SetLeaf("exclude")
	exclude.SetLeaf("log", "disable")
	exclude.SetLeaf("outbound-interface", routerConfig.WanInterface)
	exclude.SetLeaf("protocol", "all")
	exclude.Child("source").SetLeaf("address", wanIpv4.Masked().String())
	exclude.SetLeaf("type", "masquerade")
	masquerade := nat.Tag("rule", "5001")
	masquerade.SetLeaf("description", "masquerade for WAN")
	masquerade.SetLeaf("log", "disable")
	masquerade.SetLeaf("outbound-interface", routerConfig.WanInterface)
	masquerade.SetLeaf("protocol", "all")
	masquerade.SetLeaf("type", "masquerade")
	ssh := service.Child("ssh")
	ssh.SetLeaf("port", "22")
	ssh.SetLeaf("protocol-version", "v2")
	if routerConfig.Unms != "" {
		service.Child("unms").SetLeaf("connection", routerConfig.Unms)
	}

	// system
	system := root.Child("system")
	system.Child("analytics-handler").SetLeaf("send-analytics-report", "true")
	// conntrack helpers can be abused to open ports from inside the lan
	// (nat slipstreaming); none of them are needed here
	modules := system.Child("conntrack").Child("modules")
	for _, module := range []string{"ftp", "gre", "h323", "pptp", "sip", "tftp"} {
		modules.Child(module).SetLeaf("disable")
	}
	system.Child("crash-handler").SetLeaf("send-crash-report", "true")
	system.SetLeaf("gateway-address", routerConfig.WanGatewayIpv4)
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
	syslog := system.Child("syslog").Child("global")
	syslog.Tag("facility", "all").SetLeaf("level", "notice")
	syslog.Tag("facility", "protocols").SetLeaf("level", "debug")
	system.SetLeaf("time-zone", "UTC")

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

	return &vyos.Config{
		Root: root,
		Comments: []string{
			"/* Warning: Do not remove the following line. */",
			fmt.Sprintf("/* === vyatta-config-version: \"%s\" === */", routerConfig.EdgeosConfigVersion),
			fmt.Sprintf("/* Release version: %s */", routerConfig.EdgeosRelease),
		},
	}, nil
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
