package main

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/exp/maps"

	"github.com/coreos/go-semver/semver"
	"gopkg.in/yaml.v3"
)

type ServicesConfig struct {
	Domain           string   `yaml:"domain,omitempty"`
	Domains          []string `yaml:"domains,omitempty"`
	HiddenPrefixes   []string `yaml:"hidden_prefixes,omitempty"`
	LbHiddenPrefixes []string `yaml:"lb_hidden_prefixes,omitempty"`
	// TlsWildcard      *bool                    `yaml:"tls_wildcard,omitempty"`
	Versions []*ServicesConfigVersion `yaml:"versions,omitempty"`
}

func (self *ServicesConfig) domains() []string {
	domains := []string{}
	if self.Domain != "" {
		domains = append(domains, self.Domain)
	}
	domains = append(domains, self.Domains...)
	return domains
}

func (self *ServicesConfig) hostnames(env string, envAliases []string) []string {
	serviceConfigs := self.Versions[0].Services
	services := maps.Keys(serviceConfigs)
	sort.Strings(services)

	hosts := []string{}
	hosts = append(hosts, self.domains()...)

	for _, domain := range self.domains() {
		lbHost := fmt.Sprintf("%s-lb.%s", env, domain)
		hosts = append(hosts, lbHost)

		for _, envAlias := range envAliases {
			lbHostAlias := fmt.Sprintf("%s-lb.%s", envAlias, domain)
			hosts = append(hosts, lbHostAlias)
		}

		for _, service := range services {
			serviceConfig := serviceConfigs[service]
			if !serviceConfig.isExposed() {
				continue
			}

			serviceHost := fmt.Sprintf("%s-%s.%s", env, service, domain)
			hosts = append(hosts, serviceHost)

			for _, envAlias := range envAliases {
				serviceHostAlias := fmt.Sprintf("%s-%s.%s", envAlias, service, domain)
				hosts = append(hosts, serviceHostAlias)
			}
		}
	}
	for _, service := range services {
		serviceConfig := serviceConfigs[service]
		if !serviceConfig.isExposed() {
			continue
		}

		hosts = append(hosts, serviceConfig.ExposeAliases...)
		hosts = append(hosts, serviceConfig.ExposeDomains...)
	}

	return hosts
}

func (self *ServicesConfig) getHiddenPrefix() string {
	prefixes := self.getHiddenPrefixes()
	if 0 < len(prefixes) {
		return prefixes[0]
	}
	return ""
}

func (self *ServicesConfig) getHiddenPrefixes() []string {
	return self.HiddenPrefixes
}

func (self *ServicesConfig) getLbHiddenPrefix() string {
	prefixes := self.getLbHiddenPrefixes()
	if 0 < len(prefixes) {
		return prefixes[0]
	}
	return ""
}

func (self *ServicesConfig) getLbHiddenPrefixes() []string {
	if 0 < len(self.LbHiddenPrefixes) {
		return self.LbHiddenPrefixes
	}
	return self.HiddenPrefixes
}

// func (self *ServicesConfig) isTlsWildcard() bool {
//  if self.TlsWildcard != nil {
//      return *self.TlsWildcard
//  }
//  return true
// }

type ServicesConfigVersion struct {
	ExternalPorts         any       `yaml:"external_ports,omitempty"`
	InternalPorts         any       `yaml:"internal_ports,omitempty"`
	RoutingTables         any       `yaml:"routing_tables,omitempty"`
	ParallelBlockCount    int       `yaml:"parallel_block_count,omitempty"`
	ServicesDockerNetwork string    `yaml:"services_docker_network,omitempty"`
	Lb                    *LbConfig `yaml:"lb,omitempty"`
	// LbStream              *LbConfig  `yaml:"lb_stream,omitempty"`
	Services map[string]*ServiceConfig `yaml:"services,omitempty"`
}

type StreamPortServiceConfig struct {
	TcpStreamPortServices map[int]string `yaml:"tcp_stream_port_services,omitempty"`
	UdpStreamPortServices map[int]string `yaml:"udp_stream_port_services,omitempty"`
}

func (self *StreamPortServiceConfig) AllPortServices() map[string]map[int]string {
	return map[string]map[int]string{
		"tcp": self.TcpStreamPortServices,
		"udp": self.UdpStreamPortServices,
	}
}

func (self *StreamPortServiceConfig) SetDefaultStreamPortServices(defaults *StreamPortServiceConfig) {
	for port, service := range defaults.TcpStreamPortServices {
		if _, ok := self.TcpStreamPortServices[port]; !ok {
			if self.TcpStreamPortServices == nil {
				self.TcpStreamPortServices = map[int]string{}
			}
			self.TcpStreamPortServices[port] = service
		}
	}
	for port, service := range defaults.UdpStreamPortServices {
		if _, ok := self.UdpStreamPortServices[port]; !ok {
			if self.UdpStreamPortServices == nil {
				self.UdpStreamPortServices = map[int]string{}
			}
			self.UdpStreamPortServices[port] = service
		}
	}
}

// func (self *StreamPortServiceConfig) AllPorts() map[string][]int {
//  return map[string][]int{
//      "tcp": maps.Keys(self.TcpPortServices),
//      "udp": maps.Keys(self.UdpPortServices),
//  }
// }

// func (self *StreamPortServiceConfig) Ports() []int {
//  return maps.Keys(self.TcpPortServices)
// }

// func (self *StreamPortServiceConfig) UdpPorts() []int {
//  return maps.Keys(self.UdpPortServices)
// }

// type StreamPortConfig struct {
//  TcpPortSpecs    []string `yaml:"tcp_stream_ports,omitempty"`
//  UdpPortSpecs    []string `yaml:"udp_stream_ports,omitempty"`
// }

// func (self *StreamPortConfig) AllPorts() map[string][]int {
//  return map[string][]int{
//      "tcp": expandPortConfigPorts(self.TcpPortSpecs...),
//      "udp": expandPortConfigPorts(self.UdpPortSpecs...),
//  }
// }

// func (self *StreamPortConfig) Ports() []int {
//  return expandPortConfigPorts(self.TcpPortSpecs...)
// }

// func (self *StreamPortConfig) UdpPorts() []int {
//  return expandPortConfigPorts(self.UdpPortSpecs...)
// }

// a port can be either:
//   - <int port>
//   - <int port>+<int n>, where n is the number of additional consecutive ports starting at the int value
//     note that <i>+0 is the same as <i>
//   - <int port>-<int port> an inclusive range
type PortConfig struct {
	PortSpecs []string `yaml:"ports,omitempty"`
	// FIXME this is not used
	// UdpPortSpecs []string `yaml:"udp_ports,omitempty"`
	TcpStreamPortSpecs []string `yaml:"tcp_stream_ports,omitempty"`
	UdpStreamPortSpecs []string `yaml:"udp_stream_ports,omitempty"`
}

// func (self *PortConfig) HasHttpPorts() bool {
//  return 0 < len(self.HttpTcpPorts()) || 0 < len(self.HttpUdpPorts())
// }

// func (self *PortConfig) HasStreamPorts() bool {
//  return 0 < len(self.StreamTcpPorts()) || 0 < len(self.StreamUdpPorts())
// }

func (self *PortConfig) AllPorts() map[string][]int {
	return map[string][]int{
		"tcp": self.TcpPorts(),
		"udp": self.UdpPorts(),
	}
}

func (self *PortConfig) Ports() []int {
	return self.TcpPorts()
}

func (self *PortConfig) TcpPorts() []int {
	return append(
		self.HttpTcpPorts(),
		self.StreamTcpPorts()...,
	)
}

func (self *PortConfig) UdpPorts() []int {
	// return append(
	// self.HttpUdpPorts(),
	// self.StreamUdpPorts()...,
	// )
	return self.StreamUdpPorts()
}

func (self *PortConfig) AllHttpPorts() map[string][]int {
	return map[string][]int{
		"tcp": self.HttpTcpPorts(),
		// "udp": self.HttpUdpPorts(),
	}
}

func (self *PortConfig) AllStreamPorts() map[string][]int {
	return map[string][]int{
		"tcp": self.StreamTcpPorts(),
		"udp": self.StreamUdpPorts(),
	}
}

func (self *PortConfig) HttpTcpPorts() []int {
	return expandPortConfigPorts(self.PortSpecs...)
}

// func (self *PortConfig) HttpUdpPorts() []int {
//  return expandPortConfigPorts(self.UdpPortSpecs...)
// }

func (self *PortConfig) StreamTcpPorts() []int {
	return expandPortConfigPorts(self.TcpStreamPortSpecs...)
}

func (self *PortConfig) StreamUdpPorts() []int {
	return expandPortConfigPorts(self.UdpStreamPortSpecs...)
}

func expandPortConfigPorts(portSpecs ...string) []int {
	ports := map[int]bool{}
	stablePorts := []int{}

	addPort := func(port int) {
		if _, ok := ports[port]; !ok {
			ports[port] = true
			stablePorts = append(stablePorts, port)
		}
	}

	portRe := regexp.MustCompile("^(\\d+)$")
	portPlusRe := regexp.MustCompile("^(\\d+)\\s*\\+\\s*(\\d+)$")
	portRangeRe := regexp.MustCompile("^(\\d+)\\s*-\\s*(\\d+)$")
	for _, portSpec := range portSpecs {
		portSpec = strings.TrimSpace(portSpec)
		if groups := portRe.FindStringSubmatch(portSpec); groups != nil {
			port, _ := strconv.Atoi(groups[1])
			addPort(port)
		} else if groups := portPlusRe.FindStringSubmatch(portSpec); groups != nil {
			port, _ := strconv.Atoi(groups[1])
			n, _ := strconv.Atoi(groups[2])
			for i := 0; i <= n; i += 1 {
				addPort(port + i)
			}
		} else if groups := portRangeRe.FindStringSubmatch(portSpec); groups != nil {
			port, _ := strconv.Atoi(groups[1])
			endPort, _ := strconv.Atoi(groups[2])
			for i := 0; port+i <= endPort; i += 1 {
				addPort(port + i)
			}
		} else {
			panic(fmt.Errorf("Unknown port spec: %s", portSpec))
		}
	}

	return stablePorts
}

type LbConfig struct {
	Interfaces map[string]map[string]*LbBlock `yaml:"interfaces,omitempty"`
	// see https://github.com/go-yaml/yaml/issues/63
	PortConfig              `yaml:",inline"`
	StreamPortServiceConfig `yaml:",inline"`
}

// type LbStreamConfig struct {
//  StreamInterfaces map[string]map[string]*LbStreamBlock `yaml:"interfaces,omitempty"`
//  // see https://github.com/go-yaml/yaml/issues/63
//  StreamPortServiceConfig `yaml:",inline"`
// }

type ServiceConfig struct {
	CorsOrigins    []string          `yaml:"cors_origins,omitempty"`
	Status         string            `yaml:"status,omitempty"`
	HiddenPrefixes []string          `yaml:"hidden_prefixes,omitempty"`
	ExposeAliases  []string          `yaml:"expose_aliases,omitempty"`
	ExposeDomains  []string          `yaml:"expose_domains,omitempty"`
	Exposed        *bool             `yaml:"exposed,omitempty"`
	LbExposed      *bool             `yaml:"lb_exposed,omitempty"`
	Websocket      *bool             `yaml:"websocket,omitempty"`
	Hosts          []string          `yaml:"hosts,omitempty"`
	EnvVars        map[string]string `yaml:"env_vars,omitempty"`
	Mount          map[string]string `yaml:"mount,omitempty"`
	Blocks         []map[string]int  `yaml:"blocks,omitempty"`
	Keepalive      *Keepalive        `yaml:"keepalive,omitempty"`
	// see https://github.com/go-yaml/yaml/issues/63
	PortConfig `yaml:",inline"`
}

func (self *ServiceConfig) getStatusMode() string {
	if self.Status != "" {
		return self.Status
	}
	return "standard"
}

func (self *ServiceConfig) isStandardStatus() bool {
	return self.getStatusMode() == "standard"
}

func (self *ServiceConfig) isExposed() bool {
	// default true
	return self.Exposed == nil || *self.Exposed
}

func (self *ServiceConfig) isLbExposed() bool {
	return self.LbExposed == nil || *self.LbExposed
}

func (self *ServiceConfig) includesHost(host string) bool {
	return len(self.Hosts) == 0 || slices.Contains(self.Hosts, host)
}

func (self *ServiceConfig) getHiddenPrefix() string {
	prefixes := self.getHiddenPrefixes()
	if 0 < len(prefixes) {
		return prefixes[0]
	}
	return ""
}

func (self *ServiceConfig) getHiddenPrefixes() []string {
	return self.HiddenPrefixes
}

func (self *ServiceConfig) isWebsocket() bool {
	// default false
	return self.Websocket != nil && *self.Websocket
}

// type LbStreamBlock struct {
//  DockerNetwork     string      `yaml:"docker_network,omitempty"`
//  ExternalPorts     map[int]int `yaml:"external_ports,omitempty"`
//  PortServiceConfig `yaml:",inline"`
// }

type LbBlock struct {
	DockerNetwork                string      `yaml:"docker_network,omitempty"`
	ConcurrentClients            int         `yaml:"concurrent_clients,omitempty"`
	ExpectedConnectionsPerClient int         `yaml:"expected_connections_per_client,omitempty"`
	Cores                        int         `yaml:"cores,omitempty"`
	ExternalPorts                map[int]int `yaml:"external_ports,omitempty"`
	RateLimit                    *RateLimit  `yaml:"rate_limit,omitempty"`
	Keepalive                    *Keepalive  `yaml:"keepalive,omitempty"`
	StreamPortServiceConfig      `yaml:",inline"`
}

func (self *LbBlock) getRateLimit() *RateLimit {
	if self.RateLimit != nil {
		return self.RateLimit
	}
	// rate defaults
	return DefaultRateLimit()
}

type RateLimit struct {
	RequestsPerSecond int `yaml:"requests_per_second,omitempty"`
	RequestsPerMinute int `yaml:"requests_per_minute,omitempty"`
	Burst             int `yaml:"burst,omitempty"`
	Delay             int `yaml:"delay,omitempty"`
}

func DefaultRateLimit() *RateLimit {
	return &RateLimit{
		RequestsPerMinute: 120,
		Burst:             120,
		Delay:             30,
	}
}

// see https://nginx.org/en/docs/http/ngx_http_upstream_module.html
type Keepalive struct {
	Keepalive         int    `yaml:"keepalive,omitempty"`
	KeepaliveRequests int    `yaml:"keepalive_requests,omitempty"`
	KeepaliveTime     string `yaml:"keepalive_time,omitempty"`
	KeepaliveTimeout  string `yaml:"keepalive_timeout,omitempty"`
}

func DefaultKeepalive() *Keepalive {
	return &Keepalive{
		Keepalive:         1024,
		KeepaliveRequests: 128,
		KeepaliveTime:     "5m",
		KeepaliveTimeout:  "30s",
	}
}

func getServicesConfig(env string) *ServicesConfig {
	state := getWarpState()

	servicesConfigPath := filepath.Join(
		state.warpSettings.RequireVaultHome(),
		env,
		"services.yml",
	)
	data, err := os.ReadFile(servicesConfigPath)
	if err != nil {
		panic(err)
	}

	var servicesConfig ServicesConfig
	err = yaml.Unmarshal(data, &servicesConfig)
	if err != nil {
		panic(err)
	}

	// add a default config-updater if not defined
	if _, ok := servicesConfig.Versions[0].Services["config-updater"]; !ok {
		exposed := false
		lbExposed := false
		servicesConfig.Versions[0].Services["config-updater"] = &ServiceConfig{
			Exposed:   &exposed,
			LbExposed: &lbExposed,
			Blocks: []map[string]int{
				map[string]int{"main": 1},
			},
		}
	}

	return &servicesConfig
}

// union lb and service blocks
type BlockInfo struct {
	service string
	block   string
	weight  int

	host          string
	interfaceName string
	lbBlock       *LbBlock
}

// service -> block -> blockinfo
func getBlockInfos(env string) map[string]map[string]*BlockInfo {
	servicesConfig := getServicesConfig(env)

	blockInfos := map[string]map[string]*BlockInfo{}

	lbBlockInfos := map[string]*BlockInfo{}
	lbConfig := servicesConfig.Versions[0].Lb
	for host, lbBlocks := range lbConfig.Interfaces {
		for interfaceName, lbBlock := range lbBlocks {
			// merge the port services from the lb config to the lb block
			lbBlock.SetDefaultStreamPortServices(&lbConfig.StreamPortServiceConfig)

			block := fmt.Sprintf("%s-%s", host, interfaceName)
			blockInfo := &BlockInfo{
				service:       "lb",
				block:         block,
				host:          host,
				interfaceName: interfaceName,
				lbBlock:       lbBlock,
			}
			lbBlockInfos[block] = blockInfo
		}
	}
	blockInfos["lb"] = lbBlockInfos

	for service, serviceConfig := range servicesConfig.Versions[0].Services {
		serviceBlockInfos := map[string]*BlockInfo{}
		for _, blockWeights := range serviceConfig.Blocks {
			blocks := maps.Keys(blockWeights)
			sort.Strings(blocks)
			for _, block := range blocks {
				weight := blockWeights[block]
				blockInfo := &BlockInfo{
					service: service,
					block:   block,
					weight:  weight,
				}
				serviceBlockInfos[block] = blockInfo
			}
		}
		blockInfos[service] = serviceBlockInfos
	}

	return blockInfos
}

func getBlocks(env string, service string) []string {
	blockInfos := getBlockInfos(env)
	blocks := []string{}
	for block, _ := range blockInfos[service] {
		blocks = append(blocks, block)
	}
	return blocks
}

type PortBlock struct {
	service           string
	block             string
	port              int
	externalPort      int
	externalPortTypes map[string]bool
	// port type -> lb type
	lbTypes       map[string]string
	internalPorts []int
	routingTable  int
	version       int
}

func (self *PortBlock) eq(service string, block string, port int) bool {
	return self.service == service && self.block == block && self.port == port
}

// host -> service -> block -> port -> block
// port block is external port:service port:internal port range
func getPortBlocks(env string) map[string]map[string]map[string]map[int]*PortBlock {
	/*
	   RULES:
	   1. Once an internal port is associated to a service-block, it can never be associated to another service-block.
	   2. Each service-block-<serviceport> has a fixed external port that will never change.
	      If the port is removed from the exteral ports list, that is a config error.
	   3. An lb-block has a fixed routing table that will never change
	   4. An internal port can't use a port ever used by as an external; and vice-versa
	*/

	servicesConfig := getServicesConfig(env)

	hostPortBlocks := map[string]map[string]map[string]map[int]*PortBlock{}
	hostAssignedExternalPorts := map[string]map[int]*PortBlock{}
	hostAssignedInternalPorts := map[string]map[int]*PortBlock{}
	hostAssignedLbRoutingTables := map[string]map[int]string{}

	// portBlocks := func(host string) map[string]map[string]map[int]*PortBlock {
	// 	b, ok := hostPortBlocks[host]
	// 	if !ok {
	// 		b = map[string]map[string]map[int]*PortBlock{}
	// 		hostPortBlocks[host] = b
	// 	}
	// 	return b
	// }
	assignedExternalPorts := func(host string) map[int]*PortBlock {
		b := map[int]*PortBlock{}
		if assigned, ok := hostAssignedExternalPorts[host]; ok {
			maps.Copy(b, assigned)
		}
		if host != "" {
			if shared, ok := hostAssignedExternalPorts[""]; ok {
				maps.Copy(b, shared)
			}
		}
		return b
	}
	assignedInternalPorts := func(host string) map[int]*PortBlock {
		b := map[int]*PortBlock{}
		if assigned, ok := hostAssignedInternalPorts[host]; ok {
			maps.Copy(b, assigned)
		}
		if host != "" {
			if shared, ok := hostAssignedInternalPorts[""]; ok {
				maps.Copy(b, shared)
			}
		}
		return b
	}
	assignedLbRoutingTables := func(host string) map[int]string {
		b := map[int]string{}
		if assigned, ok := hostAssignedLbRoutingTables[host]; ok {
			maps.Copy(b, assigned)
		}
		return b
	}

	setExternalPort := func(host string, port int, portBlock *PortBlock) {
		b, ok := hostAssignedExternalPorts[host]
		if !ok {
			b = map[int]*PortBlock{}
			hostAssignedExternalPorts[host] = b
		}
		b[port] = portBlock
	}
	setInternalPort := func(host string, port int, portBlock *PortBlock) {
		b, ok := hostAssignedInternalPorts[host]
		if !ok {
			b = map[int]*PortBlock{}
			hostAssignedInternalPorts[host] = b
		}
		b[port] = portBlock
	}
	setLbRoutingTable := func(host string, rt int, block string) {
		b, ok := hostAssignedLbRoutingTables[host]
		if !ok {
			b = map[int]string{}
			hostAssignedLbRoutingTables[host] = b
		}
		b[rt] = block
	}

	assignPortBlock := func(host string, service string, block string, port int) *PortBlock {
		Err.Printf("Assign port block %s %s %d\n", service, block, port)
		// portBlocks := portBlocks(host)
		portBlocks, ok := hostPortBlocks[host]
		if !ok {
			portBlocks = map[string]map[string]map[int]*PortBlock{}
			hostPortBlocks[host] = portBlocks
		}

		if portBlock, ok := portBlocks[service][block][port]; ok {
			return portBlock
		}
		portBlock := &PortBlock{
			service:           service,
			block:             block,
			port:              port,
			externalPortTypes: map[string]bool{},
			lbTypes:           map[string]string{},
		}
		if _, ok := portBlocks[service]; !ok {
			portBlocks[service] = map[string]map[int]*PortBlock{}
		}
		if _, ok := portBlocks[service][block]; !ok {
			portBlocks[service][block] = map[int]*PortBlock{}
		}
		portBlocks[service][block][port] = portBlock
		return portBlock
	}

	assignExternalPort := func(
		host string,
		service string,
		block string,
		port int,
		externalPorts []int,
		force map[int]int,
		externalPortType string,
		lbType string,
		version int,
	) {
		portBlock := assignPortBlock(host, service, block, port)
		assignedExternalPorts := assignedExternalPorts(host)
		assignedInternalPorts := assignedInternalPorts(host)

		p := portBlock.externalPort
		if p == 0 {
			p = func() int {
				for p, servicePort := range force {
					if port == servicePort {
						// fmt.Printf("FORCE\n")
						return p
					}
				}

				// find an already assigned port
				// for _, p := range externalPorts {
				// 	if assignedPortBlock, ok := assignedExternalPorts[p]; ok {
				// 		if assignedPortBlock.eq(service, block, port) {
				// 			fmt.Printf("ASSIGNED\n")
				// 			return p
				// 		}
				// 	}
				// }

				// find a free port
				for _, p := range externalPorts {
					if _, ok := assignedExternalPorts[p]; !ok {
						if _, ok := assignedInternalPorts[p]; !ok {
							// fmt.Printf("FREE\n")
							return p
						}
					}
				}

				panic("No more external ports to assign. Increase the external port range.")
			}()
		}

		// if portBlock.externalPort != 0 && portBlock.externalPort != p {
		// 	panic(fmt.Errorf("The external port of a port block cannot change (%d: %d <> %d %v)", port, portBlock.externalPort, p, assignedExternalPorts))
		// }
		//
		// if portBlock.externalPortType != "" && portBlock.externalPortType != externalPortType {
		//  panic("The external port type of a port block cannot change.")
		// }

		if portBlock.lbTypes[externalPortType] != "" && portBlock.lbTypes[externalPortType] != lbType {
			panic("The lb type of a port block cannot change.")
		}

		// if assignedPortBlock, ok := assignedExternalPorts[p]; ok {
		// 	if !assignedPortBlock.eq(service, block, port) {
		// 		panic("Cannot overwrite the external port of another port block.")
		// 	}
		// }
		// if _, ok := assignedInternalPorts[p]; ok {
		// 	panic("Cannot use an internal port as an external port.")
		// }

		setExternalPort(host, p, portBlock)
		portBlock.externalPort = p
		portBlock.externalPortTypes[externalPortType] = true
		portBlock.lbTypes[externalPortType] = lbType
		portBlock.version = version

		Err.Printf("Assigned external port %s %s %d -> %d\n", service, block, port, p)
	}
	assignInternalPorts := func(
		host string,
		service string,
		block string,
		port int,
		internalPorts []int,
		count int,
		version int,
	) {
		portBlock := assignPortBlock(host, service, block, port)
		assignedExternalPorts := assignedExternalPorts(host)
		assignedInternalPorts := assignedInternalPorts(host)

		ps := []int{}

		// find already assigned ports
		for _, p := range internalPorts {
			if count <= len(ps) {
				break
			}
			if assignedPortBlock, ok := assignedInternalPorts[p]; ok {
				if assignedPortBlock.eq(service, block, port) {
					ps = append(ps, p)
				}
			}
		}

		// find free ports
		for _, p := range internalPorts {
			if count <= len(ps) {
				break
			}
			if _, ok := assignedExternalPorts[p]; !ok {
				if _, ok := assignedInternalPorts[p]; !ok {
					ps = append(ps, p)
				}
			}
		}

		if len(ps) < count {
			panic("No more internal ports to assign. Increase the internal port range.")
		}

		for _, p := range ps {
			setInternalPort(host, p, portBlock)
			Err.Printf("Assigned internal port %s %s %d -> %d\n", service, block, port, p)
		}
		portBlock.internalPorts = ps
		portBlock.version = version
	}
	assignLbRoutingTable := func(
		host string,
		block string,
		routingTables []int,
	) {
		assignedLbRoutingTables := assignedLbRoutingTables(host)

		// find an already routing table
		for _, rt := range routingTables {
			if assignedBlock, ok := assignedLbRoutingTables[rt]; ok {
				if assignedBlock == block {
					return
				}
			}
		}

		rt := func() int {
			// find a free routing table
			for _, rt := range routingTables {
				if _, ok := assignedLbRoutingTables[rt]; !ok {
					return rt
				}
			}

			panic("No more routing tables to assign. Increase the routing table range.")
		}()

		// search all the routing tables
		// for assignedRt, assignedBlock := range assignedLbRoutingTables {
		// 	if assignedBlock == block {
		// 		if assignedRt != rt {
		// 			panic("The routing table of a block cannot change.")
		// 		}
		// 	}
		// }

		setLbRoutingTable(host, rt, block)
	}

	// interate versions from last to first
	for version := len(servicesConfig.Versions) - 1; 0 <= version; version -= 1 {
		serviceConfigVersion := servicesConfig.Versions[version]
		externalPorts, err := expandAnyPorts(serviceConfigVersion.ExternalPorts)
		if err != nil {
			panic(err)
		}
		internalPorts, err := expandAnyPorts(serviceConfigVersion.InternalPorts)
		if err != nil {
			panic(err)
		}
		routingTables, err := expandAnyPorts(serviceConfigVersion.RoutingTables)
		if err != nil {
			panic(err)
		}

		slices.Sort(externalPorts)
		slices.Sort(internalPorts)
		slices.Sort(routingTables)

		// iteration for port assignment must have a stable order
		// when iterating map keys always sort the keys and iterate the sorted keys

		lbConfig := serviceConfigVersion.Lb
		// process forced external ports first
		for _, includeForcedExternalPorts := range []bool{true, false} {
			orderedHosts := maps.Keys(lbConfig.Interfaces)
			sort.Strings(orderedHosts)
			for _, host := range orderedHosts {
				lbBlocks := lbConfig.Interfaces[host]
				orderedInterfaceNames := maps.Keys(lbBlocks)
				sort.Strings(orderedInterfaceNames)
				for _, interfaceName := range orderedInterfaceNames {
					lbBlock := lbBlocks[interfaceName]

					// merge the port services from the lb config to the lb block
					lbBlock.SetDefaultStreamPortServices(&lbConfig.StreamPortServiceConfig)

					hasForcedExternalPorts := 0 < len(lbBlock.ExternalPorts)
					if hasForcedExternalPorts != includeForcedExternalPorts {
						continue
					}

					block := fmt.Sprintf("%s-%s", host, interfaceName)

					assignLbRoutingTable(
						host,
						block,
						routingTables,
					)

					lbTypeAllPorts := map[string]map[string][]int{}
					lbTypeAllPorts["http"] = lbConfig.AllHttpPorts()
					// merge the ports and service ports
					mergedStreamPorts := lbConfig.AllStreamPorts()
					for portType, portServices := range lbBlock.AllPortServices() {
						for port, _ := range portServices {
							if !slices.Contains(mergedStreamPorts[portType], port) {
								mergedStreamPorts[portType] = append(mergedStreamPorts[portType], port)
							}
						}
					}
					lbTypeAllPorts["stream"] = mergedStreamPorts

					orderedLbTypes := maps.Keys(lbTypeAllPorts)
					slices.Sort(orderedLbTypes)

					for _, lbType := range orderedLbTypes {
						allPorts := lbTypeAllPorts[lbType]

						orderedPortTypes := maps.Keys(allPorts)
						slices.Sort(orderedPortTypes)

						for _, portType := range orderedPortTypes {
							ports := allPorts[portType]
							slices.Sort(ports)

							Err.Printf(
								"Assigning %s ports %s %s (%s)\n",
								lbType,
								portType,
								collapsePorts(ports),
								mapStr(lbBlock.ExternalPorts),
							)
							for _, port := range ports {
								assignExternalPort(
									host,
									"lb",
									block,
									port,
									externalPorts,
									lbBlock.ExternalPorts,
									portType,
									lbType,
									version,
								)
								assignInternalPorts(
									host,
									"lb",
									block,
									port,
									internalPorts,
									serviceConfigVersion.ParallelBlockCount,
									version,
								)
							}
						}
					}
				}
			}
		}

		// join back the lb routing tables
		for host, assignedLbRoutingTables := range hostAssignedLbRoutingTables {
			for routingTable, block := range assignedLbRoutingTables {
				for _, portBlock := range hostPortBlocks[host]["lb"][block] {
					portBlock.routingTable = routingTable
				}
			}
		}

		orderedServices := maps.Keys(serviceConfigVersion.Services)
		sort.Strings(orderedServices)
		for _, service := range orderedServices {
			serviceConfig := serviceConfigVersion.Services[service]
			for _, blockWeights := range serviceConfig.Blocks {
				orderedBlocks := maps.Keys(blockWeights)
				slices.Sort(orderedBlocks)

				for _, block := range orderedBlocks {
					allHttpPorts := serviceConfig.AllHttpPorts()
					orderedHttpPortTypes := maps.Keys(allHttpPorts)
					slices.Sort(orderedHttpPortTypes)

					for _, portType := range orderedHttpPortTypes {
						ports := allHttpPorts[portType]
						slices.Sort(ports)

						for _, port := range ports {
							assignExternalPort(
								"",
								service,
								block,
								port,
								externalPorts,
								map[int]int{},
								portType,
								"http",
								version,
							)
							assignInternalPorts(
								"",
								service,
								block,
								port,
								internalPorts,
								serviceConfigVersion.ParallelBlockCount,
								version,
							)
						}
					}

					allStreamPorts := serviceConfig.AllStreamPorts()
					orderedStreamPortTypes := maps.Keys(allStreamPorts)
					slices.Sort(orderedStreamPortTypes)

					for _, portType := range orderedStreamPortTypes {
						ports := allStreamPorts[portType]
						slices.Sort(ports)

						for _, port := range ports {
							assignExternalPort(
								"",
								service,
								block,
								port,
								externalPorts,
								map[int]int{},
								portType,
								"stream",
								version,
							)
							assignInternalPorts(
								"",
								service,
								block,
								port,
								internalPorts,
								serviceConfigVersion.ParallelBlockCount,
								version,
							)
						}
					}
				}
			}
		}
	}

	// removed blocks not used in the latest version
	for _, serviceBlockPortBlocks := range hostPortBlocks {
		for _, blockPortBlocks := range serviceBlockPortBlocks {
			for _, portBlocks := range blockPortBlocks {
				for port, portBlock := range portBlocks {
					if portBlock.version != 0 {
						delete(portBlocks, port)
					}
				}
			}
		}
	}

	return hostPortBlocks
}

func getDomain(env string) string {
	servicesConfig := getServicesConfig(env)
	return servicesConfig.domains()[0]
}

func getHostnames(env string, envAliases []string) []string {
	servicesConfig := getServicesConfig(env)
	return servicesConfig.hostnames(env, envAliases)
}

func isExposed(env string, service string) bool {
	if service == "lb" {
		return true
	}
	servicesConfig := getServicesConfig(env)
	serviceConfig, ok := servicesConfig.Versions[0].Services[service]
	if !ok {
		// doesn't exist
		return false
	}
	return serviceConfig.isExposed()
}

func isLbExposed(env string, service string) bool {
	if service == "lb" {
		return false
	}
	servicesConfig := getServicesConfig(env)
	serviceConfig, ok := servicesConfig.Versions[0].Services[service]
	if !ok {
		// doesn't exist
		return false
	}
	return serviceConfig.isLbExposed()
}

func isStandardStatus(env string, service string) bool {
	if service == "lb" {
		return true
	}
	servicesConfig := getServicesConfig(env)
	serviceConfig, ok := servicesConfig.Versions[0].Services[service]
	if !ok {
		// doesn't exist
		return false
	}
	return serviceConfig.isStandardStatus()
}

func getHiddenPrefix(env string) string {
	servicesConfig := getServicesConfig(env)
	return servicesConfig.getHiddenPrefix()
}

func getLbHiddenPrefix(env string) string {
	servicesConfig := getServicesConfig(env)
	return servicesConfig.getLbHiddenPrefix()
}

type NginxConfig struct {
	env            string
	envAliases     []string
	servicesConfig *ServicesConfig
	// host -> service -> block -> port -> block
	portBlocks map[string]map[string]map[string]map[int]*PortBlock
	blockInfos map[string]map[string]*BlockInfo

	// tlsKey *TlsKey
	domainTlsKeys map[string]*TlsKey

	indent int

	lbBlockInfo *BlockInfo
	configParts []string
}

type TlsKey struct {
	relativeTlsPemPath string
	relativeTlsKeyPath string
}

func NewNginxConfig(env string, envAliases []string) (*NginxConfig, error) {
	servicesConfig := getServicesConfig(env)

	// find keys for the service expose domains
	domainTlsKeys := map[string]*TlsKey{}
	for _, host := range servicesConfig.hostnames(env, envAliases) {
		var tlsKey *TlsKey
		var err error

		// fmt.Printf("PROCESS HOST %s\n", host)

		if strings.HasPrefix(host, "*.") {
			tlsKey, err = findLatestTls(
				env,
				host[len("*."):],
				true,
			)
			if err != nil {
				return nil, err
			}
		} else {
			// key resolution order:
			// 1. exact host
			// 2. wildcard top host
			// 3. top host assuming exact host is a SAN of the top host
			tlsKey, err = findLatestTls(
				env,
				host,
				false,
			)
			if err != nil {
				hostParts := strings.Split(host, ".")
				if 2 < len(hostParts) {
					topHost := strings.Join(hostParts[1:], ".")
					tlsKey, err = findLatestTls(
						env,
						topHost,
						true,
					)
					if err != nil {
						// assume there are SANs for all needed domains on the top domain cert
						// TODO we currently do not verify the SANs on the cert
						tlsKey, err = findLatestTls(
							env,
							topHost,
							false,
						)
						if err != nil {
							return nil, err
						}
					}
				}
			}
		}
		domainTlsKeys[host] = tlsKey
	}

	nginxConfig := &NginxConfig{
		env:            env,
		envAliases:     envAliases,
		servicesConfig: servicesConfig,
		portBlocks:     getPortBlocks(env),
		blockInfos:     getBlockInfos(env),
		// tlsKey:             tlsKey,
		domainTlsKeys: domainTlsKeys,
	}
	return nginxConfig, nil
}

func findLatestTls(env string, domain string, wildcard bool) (tlsKey *TlsKey, err error) {
	state := getWarpState()

	find := func(home string) error {
		var keyDirName string
		var pemFileName string
		var keyFileName string
		if wildcard {
			keyDirName = fmt.Sprintf("star.%s", domain)
			pemFileName = fmt.Sprintf("star.%s.pem", domain)
			keyFileName = fmt.Sprintf("star.%s.key", domain)
		} else {
			keyDirName = domain
			pemFileName = fmt.Sprintf("%s.pem", domain)
			keyFileName = fmt.Sprintf("%s.key", domain)
		}

		hasTlsFiles := func(dirPath string) bool {
			Err.Printf("Tls searching dir %s\n", dirPath)
			for _, fileName := range []string{pemFileName, keyFileName} {
				if _, err := os.Stat(filepath.Join(dirPath, keyDirName, fileName)); errors.Is(err, os.ErrNotExist) {
					return false
				}
			}
			return true
		}

		if entries, err := os.ReadDir(filepath.Join(home, "tls")); err == nil {
			versionDirNames := map[semver.Version]string{}
			for _, entry := range entries {
				if entry.IsDir() {
					if version, err := semver.NewVersion(entry.Name()); err == nil {
						if hasTlsFiles(filepath.Join(home, "tls", entry.Name())) {
							versionDirNames[*version] = entry.Name()
						}
					}
				}
			}

			versions := maps.Keys(versionDirNames)
			semverSortWithBuild(versions)
			if 0 < len(versions) {
				version := versions[len(versions)-1]
				versionDirName := versionDirNames[version]
				tlsKey = &TlsKey{
					relativeTlsPemPath: filepath.Join("tls", versionDirName, keyDirName, pemFileName),
					relativeTlsKeyPath: filepath.Join("tls", versionDirName, keyDirName, keyFileName),
				}
				return nil
			}

			// no version
			if hasTlsFiles(home) {
				tlsKey = &TlsKey{
					relativeTlsPemPath: pemFileName,
					relativeTlsKeyPath: keyFileName,
				}
				return nil
			}
		}

		return errors.New(fmt.Sprintf("TLS files %s and %s not found.", pemFileName, keyFileName))
	}

	// resolve relative to
	// - vault/<env>
	// - vault/all
	vaultHome := state.warpSettings.RequireVaultHome()
	err = find(filepath.Join(vaultHome, env))
	if err == nil {
		return
	}
	err = find(filepath.Join(vaultHome, "all"))
	if err == nil {
		return
	}

	return
}

func (self *NginxConfig) hasUdp443Stream() bool {
	allPortServices := self.lbBlockInfo.lbBlock.AllPortServices()

	for portType, portServices := range allPortServices {
		for port, _ := range portServices {
			if portType == "udp" && port == 443 {
				return true
			}
		}
	}

	for _, service := range self.services() {
		serviceConfig := self.servicesConfig.Versions[0].Services[service]
		if !serviceConfig.isExposed() {
			continue
		}

		for portType, ports := range serviceConfig.AllStreamPorts() {
			for _, port := range ports {
				if allPortServices[portType][port] == service {
					if portType == "udp" && port == 443 {
						return true
					}
				}
			}
		}
	}
	return false
}

// service -> block -> port -> port block
func (self *NginxConfig) httpPortBlocks() map[string]map[string]map[int]*PortBlock {
	httpPortBlocks := map[string]map[string]map[int]*PortBlock{}

	addForHost := func(h string) {
		for service, blockPortBlocks := range self.portBlocks[h] {
			for block, portBlocks := range blockPortBlocks {
				for port, portBlock := range portBlocks {
					if portBlock.lbTypes["tcp"] == "http" {
						blockPortBlocks, ok := httpPortBlocks[service]
						if !ok {
							blockPortBlocks = map[string]map[int]*PortBlock{}
							httpPortBlocks[service] = blockPortBlocks
						}
						portBlocks, ok := blockPortBlocks[block]
						if !ok {
							portBlocks = map[int]*PortBlock{}
							blockPortBlocks[block] = portBlocks

						}
						portBlocks[port] = portBlock
					}
				}
			}
		}
	}

	addForHost(self.lbBlockInfo.host)
	if 0 < len(httpPortBlocks) {
		addForHost("")
	}

	return httpPortBlocks
}

// service -> block -> port -> port block
func (self *NginxConfig) streamPortBlocks() map[string]map[string]map[int]*PortBlock {
	streamPortBlocks := map[string]map[string]map[int]*PortBlock{}

	addForHost := func(h string) {

		Err.Printf("[DEBUG]port blocks[%s] = %s", h, self.portBlocks[h])

		// allPortsExposed := func(service string)(bool) {
		//  for block, portBlocks := range self.portBlocks[h][service] {
		//      for port, portBlock := range portBlocks {
		//          if portBlock.lbType == "stream" {
		//              exposedPortTypes := map[string]bool{}
		//              for portType, _ := range portBlock.externalPortTypes {
		//                  var s string
		//                  var ok bool
		//                  switch portType {
		//                  case "udp":
		//                      s, ok = self.lbBlockInfo.lbBlock.UdpStreamPortServices[port]
		//                  default:
		//                      s, ok = self.lbBlockInfo.lbBlock.TcpStreamPortServices[port]
		//                  }
		//                  if (s == service || ok && service == "lb") {
		//                      exposedPortTypes[portType] = true
		//                  }
		//              }

		//              if !maps.Equal(exposedPortTypes, portBlock.externalPortTypes) {
		//                  fmt.Printf("Warning: %s-%s %s:%d expected port types %s but found %s\n", service, block, self.lbBlockInfo.block, port, maps.Keys(portBlock.externalPortTypes), maps.Keys(exposedPortTypes))
		//                  return false
		//              }
		//              // for udp, the http lb automatically turns off udp support if it detects a conflict

		//              return true
		//          }
		//      }
		//  }
		//  return true
		// }

		for service, blockPortBlocks := range self.portBlocks[h] {
			// if !allPortsExposed(service) {
			//  continue
			// }

			for block, portBlocks := range blockPortBlocks {
				for port, portBlock := range portBlocks {
					if portBlock.lbTypes["tcp"] == "stream" || portBlock.lbTypes["udp"] == "stream" {
						blockPortBlocks, ok := streamPortBlocks[service]
						if !ok {
							blockPortBlocks = map[string]map[int]*PortBlock{}
							streamPortBlocks[service] = blockPortBlocks
						}
						portBlocks, ok := blockPortBlocks[block]
						if !ok {
							portBlocks = map[int]*PortBlock{}
							blockPortBlocks[block] = portBlocks
						}
						portBlocks[port] = portBlock
					}
				}
			}
		}
	}

	addForHost(self.lbBlockInfo.host)
	if 0 < len(streamPortBlocks) {
		// add stream services if there are stream lb ports
		addForHost("")
	}

	// fmt.Printf("FOUND STREAM PORT BLOCKS %v\n", streamPortBlocks)

	return streamPortBlocks
}

func (self *NginxConfig) services() []string {
	// filter services based on which ones are exposed to the lbBlockInfo.host

	services := []string{}
	for service, serviceConfig := range self.servicesConfig.Versions[0].Services {
		if serviceConfig.includesHost(self.lbBlockInfo.host) {
			services = append(services, service)
		}
	}
	sort.Strings(services)
	return services
}

func (self *NginxConfig) raw(text string, data ...map[string]any) {
	configPart := indentAndTrimString(templateString(text, data...), self.indent)
	self.configParts = append(self.configParts, configPart)
}

func (self *NginxConfig) block(tag string, body func()) {
	open := indentAndTrimString(fmt.Sprintf("%s {", tag), self.indent)
	close := indentAndTrimString("}", self.indent)
	self.configParts = append(self.configParts, open)
	self.indent += 4
	body()
	self.indent -= 4
	self.configParts = append(self.configParts, close)
}

// lb block -> config
func (self *NginxConfig) Generate() map[string]string {
	blockConfigParts := map[string][]string{}

	for block, blockInfo := range self.blockInfos["lb"] {
		Err.Printf("Generating for block %s\n", block)
		self.indent = 0
		self.configParts = []string{}
		self.lbBlockInfo = blockInfo

		if len(blockConfigParts[block]) == 0 {
			self.raw(`
            user www-data;
            pid /run/nginx.pid;
            include /etc/nginx/modules-enabled/*.conf;
            `)
		}
		self.addNginxConfig()
		blockConfigParts[block] = append(blockConfigParts[block], self.configParts...)

		self.configParts = nil
		self.lbBlockInfo = nil
	}

	blockConfigs := map[string]string{}
	for block, configParts := range blockConfigParts {
		blockConfigs[block] = strings.Join(configParts, "\n")
	}
	return blockConfigs
}

func (self *NginxConfig) addNginxConfig() {

	concurrentClients := self.lbBlockInfo.lbBlock.ConcurrentClients
	connectionsPerClient := self.lbBlockInfo.lbBlock.ExpectedConnectionsPerClient
	if connectionsPerClient == 0 {
		connectionsPerClient = 32
	}
	cores := self.lbBlockInfo.lbBlock.Cores
	if 0 < concurrentClients && 0 < cores {
		// round up
		workersPerCore := connectionsPerClient * (concurrentClients + cores - 1) / cores

		self.raw(`
        # target concurrent users (from services.yml): {{.concurrentClients}}
        # https://www.nginx.com/blog/tuning-nginx/
        worker_processes {{.cores}};
        events {
            worker_connections {{.workersPerCore}};
            multi_accept on;
        }
        `, map[string]any{
			"concurrentClients": concurrentClients,
			"cores":             cores,
			"workersPerCore":    workersPerCore,
		})
	}

	Err.Printf("[config]http port blocks: %s\n", self.httpPortBlocks())
	Err.Printf("[config]stream port blocks: %s\n", self.streamPortBlocks())

	hasHttp := 0 < len(self.httpPortBlocks())
	// greater than 1 because there is always an lb, but an lb without services isn't needed
	hasStream := 1 < len(self.streamPortBlocks())

	if !hasHttp && !hasStream {
		panic(fmt.Sprintf("Lb has neither http or stream: %s", self.lbBlockInfo.block))
	}

	if hasHttp {
		self.block("http", func() {
			self.raw(`
            ##
            # Basic Settings
            ##

            sendfile on;
            # minimize latency
            tcp_nodelay on;
            tcp_nopush off;
            types_hash_max_size 2048;
            server_tokens off;

            include /etc/nginx/mime.types;
            default_type application/octet-stream;

            ##
            # SSL Settings
            ##
            # see https://syslink.pl/cipherlist/

            ssl_protocols TLSv1.2 TLSv1.3;
            ssl_prefer_server_ciphers on;
            ssl_dhparam /etc/nginx/dhparam.pem; # openssl dhparam -out /etc/nginx/dhparam.pem 4096
            ssl_ciphers EECDH+AESGCM:EDH+AESGCM;
            ssl_ecdh_curve secp384r1; # Requires nginx >= 1.1.0
            ssl_session_timeout  10m;
            ssl_session_cache shared:SSL:10m;
            ssl_session_tickets off; # Requires nginx >= 1.5.9
            ssl_stapling on; # Requires nginx >= 1.3.7
            ssl_stapling_verify on; # Requires nginx => 1.3.7
            resolver 1.1.1.1 1.0.0.1 valid=300s;
            resolver_timeout 5s;

            ##
            # Logging Settings
            ##

            access_log /dev/stdout;
            error_log stderr;

            ##
            # Gzip Settings
            ##

            gzip on;

            ##
            # Http Settings
            ##

            http2 on;
            http3 on;
            quic_retry on;
            quic_gso on;
            # see https://blog.trailofbits.com/2019/03/25/what-application-developers-need-to-know-about-tls-early-data-0rtt/
            ssl_early_data off;
            `)

			self.addUpstreamBlocks()

			// rate limiters
			rateLimit := self.lbBlockInfo.lbBlock.getRateLimit()

			var requests string
			if 0 < rateLimit.RequestsPerMinute {
				requests = fmt.Sprintf("%dr/m", rateLimit.RequestsPerMinute)
			} else {
				requests = fmt.Sprintf("%dr/s", rateLimit.RequestsPerSecond)
			}

			self.raw(`
            # see https://www.nginx.com/blog/rate-limiting-nginx/
            limit_req_status 429;
            limit_req_zone $binary_remote_addr zone=standardlimit:32m rate={{.requests}};
            limit_req zone=standardlimit burst={{.burst}} delay={{.delay}};
            `, map[string]any{
				"requests": requests,
				"burst":    rateLimit.Burst,
				"delay":    rateLimit.Delay,
			})

			self.block("server", func() {
				self.raw(`
                listen 0.0.0.0:80 default_server;
                listen [::]:80 default_server;
                server_name _;
                `)

				self.block("location /", func() {
					self.raw(`
                    deny all;
                    `)
				})
			})

			self.addLbBlock()

			self.addServiceBlocks()
		})
	}

	if hasStream {
		self.block("stream", func() {
			self.raw(`
            ##
            # Basic Settings
            ##

            proxy_protocol on;
            proxy_timeout 30s;
            `)

			self.addStreamUpstreamBlocks()
			self.addStreamServiceBlocks()
		})
	}
}

func (self *NginxConfig) addUpstreamBlocks() {
	httpPortBlocks := self.httpPortBlocks()

	Out.Printf("PORT BLOCKS %s\n", httpPortBlocks)
	// service-block-<service>
	// service-block-<service>-<block>
	for _, service := range self.services() {
		// only service port 80 is exposed via the html block
		if !slices.Contains(self.servicesConfig.Versions[0].Services[service].TcpPorts(), 80) {
			continue
		}

		blocks := maps.Keys(httpPortBlocks[service])
		sort.Strings(blocks)

		if len(blocks) == 0 {
			continue
		}

		keepalive := self.servicesConfig.Versions[0].Services[service].Keepalive
		if keepalive == nil {
			keepalive = self.lbBlockInfo.lbBlock.Keepalive
			if keepalive == nil {
				keepalive = DefaultKeepalive()
			}
		}

		upstream := templateString(
			`upstream service-block-{{.service}}`,
			map[string]any{
				"service": service,
			},
		)

		self.block(upstream, func() {
			for _, block := range blocks {
				portBlock, ok := httpPortBlocks[service][block][80]
				if !ok {
					panic("Port block for service port 80 should have been defined.")
				}
				blockInfo := self.blockInfos[service][block]

				upstreamServer := templateString("server {{.dockerNetwork}}:{{.externalPort}} weight={{.weight}} max_fails=0;",
					map[string]any{
						"dockerNetwork": self.servicesConfig.Versions[0].ServicesDockerNetwork,
						"externalPort":  portBlock.externalPort,
						"weight":        blockInfo.weight,
					},
				)
				self.raw(upstreamServer)
			}

			if 0 < keepalive.Keepalive {
				self.raw(`
                keepalive {{.keepalive}};
                keepalive_requests {{.keepalive_requests}};
                keepalive_time {{.keepalive_time}};
                keepalive_timeout {{.keepalive_timeout}};
                `, map[string]any{
					"keepalive":          keepalive.Keepalive,
					"keepalive_requests": keepalive.KeepaliveRequests,
					"keepalive_time":     keepalive.KeepaliveTime,
					"keepalive_timeout":  keepalive.KeepaliveTimeout,
				})
			}
		})

		for _, block := range blocks {
			portBlock, ok := httpPortBlocks[service][block][80]
			if !ok {
				panic("Port block for service port 80 should have been defined.")
			}

			blockUpstream := templateString(
				`upstream service-block-{{.service}}-{{.block}}`,
				map[string]any{
					"service": service,
					"block":   block,
				},
			)

			self.block(blockUpstream, func() {
				self.raw(`
                    server {{.dockerNetwork}}:{{.externalPort}};
                `, map[string]any{
					"dockerNetwork": self.servicesConfig.Versions[0].ServicesDockerNetwork,
					"externalPort":  portBlock.externalPort,
				})

				if 0 < keepalive.Keepalive {
					self.raw(`
                        keepalive {{.keepalive}};
                        keepalive_requests {{.keepalive_requests}};
                        keepalive_time {{.keepalive_time}};
                        keepalive_timeout {{.keepalive_timeout}};
                    `, map[string]any{
						"keepalive":          keepalive.Keepalive,
						"keepalive_requests": keepalive.KeepaliveRequests,
						"keepalive_time":     keepalive.KeepaliveTime,
						"keepalive_timeout":  keepalive.KeepaliveTimeout,
					})
				}
			})
		}
	}
}

// func (self *NginxConfig) TlsCertDomains() []string {
//  domains := []string{}

//  // lb
//  domains = append(
//      domains,
//      fmt.Sprintf("%s-lb.%s", self.env, self.servicesConfig.Domain),
//  )

//  for _, env := range self.envAliases {
//      domains = append(
//          domains,
//          fmt.Sprintf("%s-lb.%s", env, self.servicesConfig.Domain),
//      )
//  }

//  for _, service := range self.services() {
//      serviceConfig := self.servicesConfig.Versions[0].Services[service]
//      if !serviceConfig.isExposed() {
//          continue
//      }

//      // service
//      domains = append(
//          domains,
//          fmt.Sprintf("%s-%s.%s", self.env, service, self.servicesConfig.Domain),
//      )

//      for _, env := range self.envAliases {
//          domains = append(
//              domains,
//              fmt.Sprintf("%s-%s.%s", env, service, self.servicesConfig.Domain),
//          )
//      }

//      domains = append(domains, serviceConfig.ExposeAliases...)
//      domains = append(domains, serviceConfig.ExposeDomains...)
//  }

//  return domains
// }

func (self *NginxConfig) addLbBlock() {
	httpPortBlocks := self.httpPortBlocks()

	lbHosts := []string{}

	for _, domain := range self.servicesConfig.domains() {
		lbHost := fmt.Sprintf("%s-lb.%s", self.env, domain)
		lbHosts = append(lbHosts, lbHost)

		for _, env := range self.envAliases {
			lbHostAlias := fmt.Sprintf("%s-lb.%s", env, domain)
			lbHosts = append(lbHosts, lbHostAlias)
		}
	}

	self.block("server", func() {
		self.raw(`
        listen 0.0.0.0:80;
        listen [::]:80;
        server_name {{.lbHostList}};
        `, map[string]any{
			"lbHostList": strings.Join(lbHosts, " "),
		})

		// the run controller expects services to expose /status on http
		for _, routePrefix := range self.getLbRoutePrefixes() {
			statusLocation := templateString(
				"location ={{.routePrefix}}/status",
				map[string]any{
					"routePrefix": routePrefix,
				},
			)

			self.block(statusLocation, func() {
				self.raw(`
                alias /srv/warp/status/status.json;
                add_header 'Content-Type' 'application/json';
                `)
			})

			// expose each block status via http so that an exact ip-service-block can be monitored
			for _, service := range self.services() {
				serviceConfig := self.servicesConfig.Versions[0].Services[service]

				blocks := maps.Keys(httpPortBlocks[service])
				sort.Strings(blocks)

				serviceHost := fmt.Sprintf("%s-%s.%s", self.env, service, self.servicesConfig.domains()[0])

				for _, block := range blocks {
					blockLocation := templateString(
						`location ={{.routePrefix}}/by/b/{{.service}}/{{.block}}/status`,
						map[string]any{
							"routePrefix": routePrefix,
							"service":     service,
							"block":       block,
						},
					)

					self.block(blockLocation, func() {
						self.raw(`
                        proxy_pass http://service-block-{{.service}}-{{.block}}/status;
                        proxy_set_header X-Forwarded-For $remote_addr:$remote_port;
                        proxy_set_header Host {{.serviceHost}};
                        proxy_set_header X-Forwarded-Host $host;
                        proxy_set_header Early-Data $ssl_early_data;
                        add_header 'Content-Type' 'application/json';
                        `, map[string]any{
							"service":     service,
							"block":       block,
							"serviceHost": serviceHost,
						})

						if serviceConfig.isWebsocket() {
							self.raw(`
                            # support websocket upgrade
                            proxy_http_version 1.1;
                            proxy_set_header Upgrade $http_upgrade;
                            proxy_set_header Connection 'upgrade';
                            `)
						}
					})
				}
			}
		}

		self.block("location /", func() {
			self.raw(`
            return 301 https://$host$request_uri;
            `)
		})
	})

	for lbHostIndex, lbHost := range lbHosts {
		self.block("server", func() {
			self.raw(`
            listen 0.0.0.0:443 ssl;
            listen [::]:443 ssl;
            `)

			if !self.hasUdp443Stream() {
				// important: `443 quic reuseport` can only be declared once in the nginx config.
				//            Use it in the first lb config only.
				if 0 == lbHostIndex {
					self.raw(`
                    listen 0.0.0.0:443 quic reuseport;
                    listen [::]:443 quic reuseport;
                    `)
				} else {
					self.raw(`
                    listen 0.0.0.0:443 quic;
                    listen [::]:443 quic;
                    `)
				}
			}

			self.raw(`
            server_name {{.lbHostList}};
            `, map[string]any{
				"lbHostList": lbHost,
			})

			lbTlsKey, ok := self.domainTlsKeys[lbHost]
			if !ok {
				panic(fmt.Errorf("Missing TLS key for %s", lbHost))
			}

			// important: nginx can handle only one ssl_certificate/ssl_certificate_key pair per server block
			self.raw(`
                ssl_certificate     /srv/warp/vault/{{.relativeTlsPemPath}};
                ssl_certificate_key /srv/warp/vault/{{.relativeTlsKeyPath}};
            `, map[string]any{
				"relativeTlsPemPath": lbTlsKey.relativeTlsPemPath,
				"relativeTlsKeyPath": lbTlsKey.relativeTlsKeyPath,
			})

			for _, routePrefix := range self.getLbRoutePrefixes() {
				location := templateString(
					"location {{.routePrefix}}/",
					map[string]any{
						"routePrefix": routePrefix,
					},
				)

				if !self.hasUdp443Stream() {
					self.block(location, func() {
						self.raw(`
                        # required for browsers to direct them to quic port
                        add_header 'Alt-Svc' 'h3=":443"; ma=86400';
                        `)
					})
				}
			}

			for _, routePrefix := range self.getLbRoutePrefixes() {
				statusLocation := templateString(
					"location ={{.routePrefix}}/status",
					map[string]any{
						"routePrefix": routePrefix,
					},
				)

				self.block(statusLocation, func() {
					self.raw(`
                    alias /srv/warp/status/status.json;
                    add_header 'Content-Type' 'application/json';
                    `)

					if !self.hasUdp443Stream() {
						self.raw(`
                        # required for browsers to direct them to quic port
                        add_header 'Alt-Svc' 'h3=":443"; ma=86400';
                        `)
					}
				})
			}

			// /by/service/{service}/
			// /by/b/{service}/{name}/

			for _, service := range self.services() {
				if !self.servicesConfig.Versions[0].Services[service].isLbExposed() {
					continue
				}

				blocks := maps.Keys(httpPortBlocks[service])
				sort.Strings(blocks)

				serviceHost := fmt.Sprintf("%s-%s.%s", self.env, service, self.servicesConfig.domains()[0])

				for _, routePrefix := range self.getLbRoutePrefixes() {
					location := templateString(
						`location {{.routePrefix}}/by/service/{{.service}}/`,
						map[string]any{
							"routePrefix": routePrefix,
							"service":     service,
						},
					)

					self.block(location, func() {
						self.raw(`
                        proxy_pass http://service-block-{{.service}}/;
                        proxy_set_header X-Forwarded-For $remote_addr:$remote_port;
                        proxy_set_header Host {{.serviceHost}};
                        proxy_set_header X-Forwarded-Host $host;
                        proxy_set_header Early-Data $ssl_early_data;
                        `, map[string]any{
							"service":     service,
							"serviceHost": serviceHost,
						})
					})

					for _, block := range blocks {
						blockLocation := templateString(
							`location {{.routePrefix}}/by/b/{{.service}}/{{.block}}/`,
							map[string]any{
								"routePrefix": routePrefix,
								"service":     service,
								"block":       block,
							},
						)

						self.block(blockLocation, func() {
							self.raw(`
                            proxy_pass http://service-block-{{.service}}-{{.block}}/;
                            proxy_set_header X-Forwarded-For $remote_addr:$remote_port;
                            proxy_set_header Host {{.serviceHost}};
                            proxy_set_header X-Forwarded-Host $host;
                            proxy_set_header Early-Data $ssl_early_data;
                            `, map[string]any{
								"service":     service,
								"block":       block,
								"serviceHost": serviceHost,
							})
						})
					}
				}
			}
		})
	}
}

func (self *NginxConfig) addServiceBlocks() {
	for _, service := range self.services() {
		serviceConfig := self.servicesConfig.Versions[0].Services[service]
		if !serviceConfig.isExposed() {
			continue
		}

		if !slices.Contains(serviceConfig.HttpTcpPorts(), 80) {
			return
		}

		// add the main service block
		serviceHosts := []string{}

		for _, domain := range self.servicesConfig.domains() {
			serviceHost := fmt.Sprintf("%s-%s.%s", self.env, service, domain)
			serviceHosts = append(serviceHosts, serviceHost)

			for _, env := range self.envAliases {
				serviceHostAlias := fmt.Sprintf("%s-%s.%s", env, service, domain)
				serviceHosts = append(serviceHosts, serviceHostAlias)
			}
		}

		serviceHosts = append(serviceHosts, serviceConfig.ExposeAliases...)
		serviceHosts = append(serviceHosts, serviceConfig.ExposeDomains...)

		if slices.Contains(self.servicesConfig.Versions[0].Lb.HttpTcpPorts(), 80) {
			self.block("server", func() {
				self.raw(`
                listen 0.0.0.0:80;
                listen [::]:80;
                server_name {{.serviceHostList}};
                return 301 https://$host$request_uri;
                `, map[string]any{
					"serviceHostList": strings.Join(serviceHosts, " "),
				})
			})
		}

		if slices.Contains(self.servicesConfig.Versions[0].Lb.HttpTcpPorts(), 443) {
			for _, serviceHost := range serviceHosts {
				self.block("server", func() {
					self.raw(`
                    listen 0.0.0.0:443 ssl;
                    listen [::]:443 ssl;
                    `)

					if !self.hasUdp443Stream() {
						self.raw(`
                        listen 0.0.0.0:443 quic;
                        listen [::]:443 quic;
                        `)
					}

					self.raw(`
                    server_name {{.serviceHostList}};
                    `, map[string]any{
						"serviceHostList": serviceHost,
					})

					serviceTlsKey, ok := self.domainTlsKeys[serviceHost]
					if !ok {
						panic(fmt.Errorf("Missing TLS key for %s", serviceHost))
					}

					// important: nginx can handle only one ssl_certificate/ssl_certificate_key pair per server block
					self.raw(`
                        ssl_certificate     /srv/warp/vault/{{.relativeTlsPemPath}};
                        ssl_certificate_key /srv/warp/vault/{{.relativeTlsKeyPath}};
                    `, map[string]any{
						"relativeTlsPemPath": serviceTlsKey.relativeTlsPemPath,
						"relativeTlsKeyPath": serviceTlsKey.relativeTlsKeyPath,
					})

					for _, routePrefix := range self.getRoutePrefixes(service) {
						if serviceConfig.isStandardStatus() {
							statusLocation := templateString(
								"location ={{.routePrefix}}/status",
								map[string]any{
									"routePrefix": routePrefix,
								},
							)

							self.block(statusLocation, func() {
								self.raw(`
                                deny all;
                                `)
							})
						}

						location := templateString(
							"location {{.routePrefix}}/",
							map[string]any{
								"routePrefix": routePrefix,
							},
						)

						self.block(location, func() {
							self.raw(`
                            proxy_pass http://service-block-{{.service}}/;
                            proxy_set_header X-Forwarded-For $remote_addr:$remote_port;
                            proxy_set_header X-Forwarded-Host $host;
                            proxy_set_header Early-Data $ssl_early_data;
                            `, map[string]any{
								"service": service,
							})

							if !self.hasUdp443Stream() {
								self.raw(`
                                # required for browsers to direct them to quic port
                                add_header 'Alt-Svc' 'h3=":443"; ma=86400';
                                `)
							}

							if serviceConfig.isWebsocket() {
								self.raw(`
                                # support websocket upgrade
                                proxy_http_version 1.1;
                                proxy_set_header Upgrade $http_upgrade;
                                proxy_set_header Connection 'upgrade';
                                `)
							}

							addSecurityHeaders := func() {
								self.raw(`
                                # see https://syslink.pl/cipherlist/
                                add_header Strict-Transport-Security 'max-age=63072000; includeSubDomains; preload' always;
                                add_header X-Frame-Options 'SAMEORIGIN' always;
                                add_header X-Content-Type-Options 'nosniff' always;
                                add_header X-XSS-Protection '1; mode=block' always;
                                `)
							}

							initCorsHeaders := func() {
								if 0 < len(serviceConfig.CorsOrigins) {
									if slices.Contains(serviceConfig.CorsOrigins, "*") {
										self.raw(`
                                        set $cors_origin '*';
                                        `)
									} else {
										// return the origin for the specific client making the request, per
										// https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Allow-Origin
										self.raw(`
                                        set $cors_origin '';
                                        `)
										for _, corsOrigin := range serviceConfig.CorsOrigins {
											self.raw(`
                                            if ($http_origin = '{{.corsOrigin}}') {
                                                set $cors_origin '{{.corsOrigin}}';
                                            }
                                            `, map[string]any{
												"corsOrigin": corsOrigin,
											})
										}
									}
								}
							}

							addCorsHeaders := func() {
								// initCorsHeaders must have been added before this in the block
								if 0 < len(serviceConfig.CorsOrigins) {
									self.raw(`
                                    # see https://enable-cors.org/server_nginx.html
                                    add_header 'Access-Control-Allow-Origin' $cors_origin always;
                                    add_header 'Access-Control-Allow-Methods' 'GET, POST, OPTIONS' always;
                                    add_header 'Access-Control-Allow-Headers' 'DNT,User-Agent,X-Requested-With,If-Modified-Since,Cache-Control,Content-Type,Range,X-Client-Version,Authorization' always;
                                    add_header 'Access-Control-Expose-Headers' 'Content-Length,Content-Range' always;
                                    `)
								}
							}

							initCorsHeaders()
							if 0 < len(serviceConfig.CorsOrigins) {
								self.block("if ($request_method = 'OPTIONS')", func() {
									// nginx inheritance model does not inheret `add_header` into a block where another `add_header` is defined
									// add all the headers inside a block where another `add_header` is defined
									addSecurityHeaders()
									addCorsHeaders()
									self.raw(`
                                    add_header 'Access-Control-Max-Age' 1728000;
                                    add_header 'Content-Type' 'text/plain; charset=utf-8';
                                    add_header 'Content-Length' 0;
                                    return 204;
                                    `)
								})
							}
							addSecurityHeaders()
							addCorsHeaders()
						})
					}
				})
			}
		}
	}
}

func (self *NginxConfig) addStreamUpstreamBlocks() {
	streamPortBlocks := self.streamPortBlocks()
	allPortServices := self.lbBlockInfo.lbBlock.AllPortServices()

	Out.Printf("STREAM PORT BLOCKS %s\n", streamPortBlocks)
	// stream-service-block-<service>
	for _, service := range self.services() {
		blocks := maps.Keys(streamPortBlocks[service])
		sort.Strings(blocks)

		if len(blocks) == 0 {
			continue
		}

		serviceConfig := self.servicesConfig.Versions[0].Services[service]

		for portType, ports := range serviceConfig.AllStreamPorts() {
			for _, port := range ports {
				if allPortServices[portType][port] == service {

					upstream := templateString(
						`upstream stream-service-block-{{.service}}-{{.port}}`,
						map[string]any{
							"service": service,
							"port":    port,
						},
					)

					self.block(upstream, func() {
						for _, block := range blocks {
							for _, portBlock := range streamPortBlocks[service][block] {
								if portBlock.port == port {
									blockInfo := self.blockInfos[service][block]
									upstreamServer := templateString("server {{.dockerNetwork}}:{{.externalPort}} weight={{.weight}} max_fails=0;",
										map[string]any{
											"dockerNetwork": self.servicesConfig.Versions[0].ServicesDockerNetwork,
											"externalPort":  portBlock.externalPort,
											"weight":        blockInfo.weight,
										},
									)
									self.raw(upstreamServer)
								}
							}
						}

						// see https://nginx.org/en/docs/stream/ngx_stream_upstream_module.html
						self.raw(`
                        random two least_conn;
                        `)
					})

				}
			}
		}
	}
}

func (self *NginxConfig) addStreamServiceBlocks() {
	allPortServices := self.lbBlockInfo.lbBlock.AllPortServices()

	for _, service := range self.services() {
		serviceConfig := self.servicesConfig.Versions[0].Services[service]
		if !serviceConfig.isExposed() {
			continue
		}

		for portType, ports := range serviceConfig.AllStreamPorts() {
			for _, port := range ports {
				if allPortServices[portType][port] == service {
					self.block("server", func() {
						if portType == "udp" {
							self.raw(`
                            listen 0.0.0.0:{{.port}} udp;
                            listen [::]:{{.port}} udp;
                            `, map[string]any{
								"port": port,
							})
						} else {
							self.raw(`
                            listen 0.0.0.0:{{.port}};
                            listen [::]:{{.port}};
                            `, map[string]any{
								"port": port,
							})
						}

						self.raw(`
                        proxy_pass stream-service-block-{{.service}}-{{.port}};
                        `, map[string]any{
							"service": service,
							"port":    port,
						})
					})
				}
			}
		}
	}
}

func (self *NginxConfig) getLbRoutePrefixes() []string {
	routePrefixes := []string{}
	for _, prefix := range self.servicesConfig.getLbHiddenPrefixes() {
		routePrefix := fmt.Sprintf("/%s", prefix)
		routePrefixes = append(routePrefixes, routePrefix)
	}
	if len(routePrefixes) == 0 {
		routePrefixes = append(routePrefixes, "")
	}
	return routePrefixes
}

func (self *NginxConfig) getRoutePrefixes(service string) []string {
	routePrefixes := []string{}
	for _, prefix := range self.servicesConfig.getHiddenPrefixes() {
		routePrefix := fmt.Sprintf("/%s", prefix)
		routePrefixes = append(routePrefixes, routePrefix)
	}
	for _, prefix := range self.servicesConfig.Versions[0].Services[service].getHiddenPrefixes() {
		routePrefix := fmt.Sprintf("/%s", prefix)
		routePrefixes = append(routePrefixes, routePrefix)
	}
	if len(routePrefixes) == 0 {
		routePrefixes = append(routePrefixes, "")
	}
	return routePrefixes
}

type SystemdUnits struct {
	env            string
	targetWarpHome string
	targetWarpctl  string
	hostNetworking bool
	servicesConfig *ServicesConfig
	portBlocks     map[string]map[string]map[string]map[int]*PortBlock
	blockInfos     map[string]map[string]*BlockInfo
}

func NewSystemdUnits(
	env string,
	targetWarpHome string,
	targetWarpctl string,
	hostNetworking bool,
) *SystemdUnits {
	servicesConfig := getServicesConfig(env)

	return &SystemdUnits{
		env:            env,
		targetWarpHome: targetWarpHome,
		targetWarpctl:  targetWarpctl,
		hostNetworking: hostNetworking,
		servicesConfig: servicesConfig,
		portBlocks:     getPortBlocks(env),
		blockInfos:     getBlockInfos(env),
	}
}

// host -> service -> block -> unit
func (self *SystemdUnits) Generate() map[string]map[string]map[string]*Units {
	hosts := maps.Keys(self.servicesConfig.Versions[0].Lb.Interfaces)

	hostsServicesUnits := map[string]map[string]map[string]*Units{}
	for _, host := range hosts {
		hostsServicesUnits[host] = self.generateForHost(host)
	}

	return hostsServicesUnits
}

type Units struct {
	serviceUnit string
	drainUnit   string
	shortBlock  string
}

func (self *SystemdUnits) generateForHost(host string) map[string]map[string]*Units {
	servicesUnits := map[string]map[string]*Units{}

	// generate:
	// - lb
	// - config updater
	// - services

	lbUnits := map[string]*Units{}
	for block, blockInfo := range self.blockInfos["lb"] {
		if blockInfo.host != host {
			continue
		}

		parts := []string{}
		// parts = append(parts, fmt.Sprintf(`WARP_HOME="%s"`, self.targetWarpHome))

		parts = append(parts, []string{
			self.targetWarpctl,
			"service",
			"run",
			self.env,
			"lb",
			block,
		}...)

		routingTablesMap := map[int]bool{}
		if portBlocks, ok := self.portBlocks[host]["lb"][block]; ok {
			for _, portBlock := range portBlocks {
				routingTablesMap[portBlock.routingTable] = true
			}
		}
		routingTables := maps.Keys(routingTablesMap)
		if 1 != len(routingTables) {
			panic("Each lb block must have one routing table.")
		}
		routingTable := routingTables[0]

		parts = append(parts, []string{
			fmt.Sprintf(`--rttable="%s:%d"`, blockInfo.interfaceName, routingTable),
			fmt.Sprintf("--dockernet=%s", blockInfo.lbBlock.DockerNetwork),
		}...)

		if portBlocks, ok := self.portBlocks[host]["lb"][block]; ok {
			// add port block strs in ascending port order
			orderedPorts := maps.Keys(portBlocks)
			slices.Sort(orderedPorts)
			portBlockParts := []string{}
			for _, port := range orderedPorts {
				portBlock := portBlocks[port]
				portBlockPart := fmt.Sprintf(
					"%d:%d:%s",
					portBlock.port,
					portBlock.externalPort,
					collapsePorts(portBlock.internalPorts),
				)
				portBlockParts = append(portBlockParts, portBlockPart)
			}
			part := fmt.Sprintf(`--portblocks="%s"`, strings.Join(portBlockParts, ";"))
			parts = append(parts, part)
		}

		parts = append(parts, fmt.Sprintf("--services_dockernet=%s", self.servicesConfig.Versions[0].ServicesDockerNetwork))

		vaultMode := "yes"
		configMode := "no"
		siteMode := "no"

		parts = append(parts, fmt.Sprintf("--mount_vault=%s", vaultMode))
		parts = append(parts, fmt.Sprintf("--mount_config=%s", configMode))
		parts = append(parts, fmt.Sprintf("--mount_site=%s", siteMode))

		statusMode := "standard"

		parts = append(parts, fmt.Sprintf("--status=%s", statusMode))
		// status are only exposed via the lb using the lb routes
		lbHiddenPrefix := self.servicesConfig.getLbHiddenPrefix()
		if lbHiddenPrefix != "" {
			parts = append(parts, fmt.Sprintf("--status-prefix=%s", lbHiddenPrefix))
		}

		parts = append(parts, fmt.Sprintf("--domain=%s", self.servicesConfig.domains()[0]))

		hostNetworking := "no"
		if self.hostNetworking {
			hostNetworking = "yes"
		}
		parts = append(parts, fmt.Sprintf("--host_networking=%s", hostNetworking))

		lbUnits[block] = &Units{
			serviceUnit: self.serviceUnit("lb", block, blockInfo.interfaceName, parts),
			drainUnit:   self.drainUnit("lb", block, parts),
			shortBlock:  blockInfo.interfaceName,
		}
	}
	servicesUnits["lb"] = lbUnits

	// config-updater
	// enforce zero exposed ports for the config-updater
	configUpdaterUnits := map[string]*Units{}
	for block, _ := range self.blockInfos["config-updater"] {
		parts := []string{}
		// parts = append(parts, fmt.Sprintf(`WARP_HOME="%s"`, self.targetWarpHome))

		parts = append(parts, []string{
			self.targetWarpctl,
			"service",
			"run",
			self.env,
			"config-updater",
			block,
		}...)

		parts = append(parts, fmt.Sprintf("--services_dockernet=%s", self.servicesConfig.Versions[0].ServicesDockerNetwork))

		vaultMode := "no"
		configMode := "root"
		siteMode := "no"

		parts = append(parts, fmt.Sprintf("--mount_vault=%s", vaultMode))
		parts = append(parts, fmt.Sprintf("--mount_config=%s", configMode))
		parts = append(parts, fmt.Sprintf("--mount_site=%s", siteMode))

		statusMode := "no"

		parts = append(parts, fmt.Sprintf("--status=%s", statusMode))

		parts = append(parts, fmt.Sprintf("--domain=%s", self.servicesConfig.domains()[0]))

		hostNetworking := "no"
		if self.hostNetworking {
			hostNetworking = "yes"
		}
		parts = append(parts, fmt.Sprintf("--host_networking=%s", hostNetworking))

		configUpdaterUnits[block] = &Units{
			serviceUnit: self.serviceUnit("config-updater", block, block, parts),
			drainUnit:   self.drainUnit("config-updater", block, parts),
			shortBlock:  block,
		}
	}
	servicesUnits["config-updater"] = configUpdaterUnits

	// services
	for service, serviceBlockInfos := range self.blockInfos {
		switch service {
		case "lb", "config-updater":
			continue
		}

		serviceConfig := self.servicesConfig.Versions[0].Services[service]

		if !serviceConfig.includesHost(host) {
			continue
		}

		serviceUnits := map[string]*Units{}
		for block, _ := range serviceBlockInfos {
			parts := []string{}
			// parts = append(parts, fmt.Sprintf(`WARP_HOME="%s"`, self.targetWarpHome))

			parts = append(parts, []string{
				self.targetWarpctl,
				"service",
				"run",
				self.env,
				service,
				block,
			}...)

			// fmt.Printf("PORT BLOCKS RAW %v\n", self.portBlocks)
			// fmt.Printf("PORT BLOCKS RAW[%s][%s][%s] %v\n", "", service, block, self.portBlocks[""][service][block])

			if portBlocks, ok := self.portBlocks[""][service][block]; ok {
				// add port block strs

				orderedPorts := maps.Keys(portBlocks)
				slices.Sort(orderedPorts)
				portBlockParts := []string{}
				for _, port := range orderedPorts {
					portBlock := portBlocks[port]
					portBlockPart := fmt.Sprintf(
						"%d:%d:%s",
						portBlock.port,
						portBlock.externalPort,
						collapsePorts(portBlock.internalPorts),
					)
					portBlockParts = append(portBlockParts, portBlockPart)
				}
				part := fmt.Sprintf("--portblocks=%s", strings.Join(portBlockParts, ";"))
				parts = append(parts, part)
			}

			parts = append(parts, fmt.Sprintf("--services_dockernet=%s", self.servicesConfig.Versions[0].ServicesDockerNetwork))

			var vaultMode string
			if mode, ok := serviceConfig.Mount["vault"]; ok {
				vaultMode = mode
			} else {
				vaultMode = "yes"
			}

			var configMode string
			if mode, ok := serviceConfig.Mount["config"]; ok {
				configMode = mode
			} else {
				configMode = "yes"
			}

			var siteMode string
			if mode, ok := serviceConfig.Mount["site"]; ok {
				siteMode = mode
			} else {
				siteMode = "yes"
			}

			parts = append(parts, fmt.Sprintf("--mount_vault=%s", vaultMode))
			parts = append(parts, fmt.Sprintf("--mount_config=%s", configMode))
			parts = append(parts, fmt.Sprintf("--mount_site=%s", siteMode))

			statusMode := serviceConfig.getStatusMode()

			parts = append(parts, fmt.Sprintf("--status=%s", statusMode))

			parts = append(parts, fmt.Sprintf("--domain=%s", self.servicesConfig.domains()[0]))

			hostNetworking := "no"
			if self.hostNetworking {
				hostNetworking = "yes"
			}
			parts = append(parts, fmt.Sprintf("--host_networking=%s", hostNetworking))

			for key, value := range serviceConfig.EnvVars {
				parts = append(parts, fmt.Sprintf("--envvar=%s:%s", key, value))
			}

			serviceUnits[block] = &Units{
				serviceUnit: self.serviceUnit(service, block, block, parts),
				drainUnit:   self.drainUnit(service, block, parts),
				shortBlock:  block,
			}
		}
		servicesUnits[service] = serviceUnits
	}

	return servicesUnits
}

func (self *SystemdUnits) serviceUnit(service string, block string, shortBlock string, cmdArgs []string) string {
	unit := templateString(`
    [Unit]
    Description=Warpctl {{.env}} {{.service}} {{.block}}
    Requires=network-online.target
    After=network-online.target
    Requires=docker.service
    After=docker.service
    ReloadPropagatedFrom=network-online.target docker.service

    [Service]
    Type=simple
    Environment="WARP_HOME={{.warpHome}}"
    ExecStart={{.cmd}}
    ExecStop=/bin/kill -s TERM $MAINPID
    TimeoutStopSec=60
    Restart=always
    StandardOutput=append:/var/log/warp/{{.env}}-{{.service}}-{{.shortBlock}}.out
    StandardError=append:/var/log/warp/{{.env}}-{{.service}}-{{.shortBlock}}.err

    [Install]
    WantedBy=multi-user.target
    `, map[string]any{
		"env":        self.env,
		"service":    service,
		"block":      block,
		"shortBlock": shortBlock,
		"warpHome":   self.targetWarpHome,
		"cmd":        strings.Join(cmdArgs, " "),
	})

	return unit
}

func (self *SystemdUnits) drainUnit(service string, block string, cmdArgs []string) string {
	// FIXME
	return ""
}

// host -> commands
func getDockerNetworkCommands(env string) map[string][][]string {
	/*
	   # LB block network
	   docker network create --attachable --opt 'com.docker.network.bridge.name=warp1' --opt 'com.docker.network.bridge.enable_ip_masquerade=false' warp1 --ipv6 --subnet fd00:X::/64
	   # services network
	   docker network create --attachable --opt 'com.docker.network.bridge.name=warpsservices' warpsservices
	*/

	servicesConfig := getServicesConfig(env)

	hostNetworkCommands := map[string][][]string{}

	for host, lbBlocks := range servicesConfig.Versions[0].Lb.Interfaces {
		networkCommands := [][]string{}

		// services network
		servicesDockerNetwork := servicesConfig.Versions[0].ServicesDockerNetwork
		servicesNetworkCommand := []string{
			"docker", "network", "create", "--attachable",
			// interface name should be equal to the network name
			"--opt", fmt.Sprintf("com.docker.network.bridge.name=%s", servicesDockerNetwork),
			servicesDockerNetwork,
		}
		networkCommands = append(networkCommands, servicesNetworkCommand)

		for _, lbBlock := range lbBlocks {
			// block network

			// the ipv6 subnet is a hash of the docker network
			h := sha256.New()
			h.Write([]byte(lbBlock.DockerNetwork))
			b := h.Sum(nil)
			ipv6Subnet := fmt.Sprintf("fd00:%x:%x:%x::/64", b[0:2], b[2:4], b[4:6])

			blockNetworkCommand := []string{
				"docker", "network", "create", "--attachable",
				// interface name should be equal to the network name
				"--opt", fmt.Sprintf("com.docker.network.bridge.name=%s", lbBlock.DockerNetwork),
				// disable masquerade (snat) to preserve the source ip
				"--opt", "com.docker.network.bridge.enable_ip_masquerade=false",
				"--ipv6", "--subnet", ipv6Subnet,
				lbBlock.DockerNetwork,
			}
			networkCommands = append(networkCommands, blockNetworkCommand)
		}

		hostNetworkCommands[host] = networkCommands
	}

	return hostNetworkCommands
}
