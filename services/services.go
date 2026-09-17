// Package services holds the parseable warp services/grafana configuration types,
// their loaders, and pure discovery helpers.
//
// This package is intentionally free of any warpctl runtime state
// (getWarpState/RequireVaultHome). It may use the common utilities in the
// parent `warp` package (which must never import this package), and it must
// not import `warpctl`, so it can be imported by warpctl and other consumers
// without cycles.
package services

import (
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"sort"
	"strings"

	"golang.org/x/exp/maps"

	"github.com/urnetwork/warp"
)

type ServicesConfig struct {
	Domain string `yaml:"domain,omitempty"`
	// domain to registrar map
	Domains          map[string]string `yaml:"domains,omitempty"`
	ExposeAliases    []string          `yaml:"expose_aliases,omitempty"`
	HiddenPrefixes   []string          `yaml:"hidden_prefixes,omitempty"`
	LbHiddenPrefixes []string          `yaml:"lb_hidden_prefixes,omitempty"`
	// The document-level limits the lb blocks alias. Parsed so a service that
	// runs without an lb in front of it can apply the same limits itself.
	DefaultRateLimit *RateLimit `yaml:"default_rate_limit,omitempty"`
	// TlsWildcard      *bool                    `yaml:"tls_wildcard,omitempty"`
	Versions []*ServicesConfigVersion `yaml:"versions,omitempty"`
	Cores    map[string]int           `yaml:"cores,omitempty"`
}

// GetDefaultRateLimit returns the document-level block, or the same defaults
// an lb block with no rate limit of its own gets.
func (self *ServicesConfig) GetDefaultRateLimit() *RateLimit {
	if self.DefaultRateLimit != nil {
		return self.DefaultRateLimit
	}
	return DefaultRateLimit()
}

// Latest returns the current (index 0) services config version.
func (self *ServicesConfig) Latest() *ServicesConfigVersion {
	return self.Versions[0]
}

// DomainNames returns the ordered list of domains.
// DomainNames[0] will be used as the primary domain.
func (self *ServicesConfig) DomainNames() []string {
	domains := map[string]bool{}
	if self.Domain != "" {
		domains[self.Domain] = true
	}
	for domain, _ := range self.Domains {
		domains[domain] = true
	}
	orderedDomains := maps.Keys(domains)
	slices.SortFunc(orderedDomains, func(a string, b string) int {
		if a == b {
			return 0
		}
		if a == self.Domain {
			return -1
		}
		if b == self.Domain {
			return 1
		}
		return strings.Compare(a, b)
	})
	return orderedDomains
}

// GetDomain returns the primary domain.
func (self *ServicesConfig) GetDomain() string {
	return self.DomainNames()[0]
}

func (self *ServicesConfig) DomainRegistrars() map[string]string {
	return maps.Clone(self.Domains)
}

func (self *ServicesConfig) Hostnames(env string, envAliases []string) []string {
	serviceConfigs := self.Versions[0].Services
	services := maps.Keys(serviceConfigs)
	sort.Strings(services)

	hosts := []string{}
	hosts = append(hosts, self.DomainNames()...)
	hosts = append(hosts, self.ExposeAliases...)

	for _, domain := range self.DomainNames() {
		lbHost := fmt.Sprintf("%s-lb.%s", env, domain)
		hosts = append(hosts, lbHost)

		for _, envAlias := range envAliases {
			lbHostAlias := fmt.Sprintf("%s-lb.%s", envAlias, domain)
			hosts = append(hosts, lbHostAlias)
		}

		for _, service := range services {
			serviceConfig := serviceConfigs[service]
			if !serviceConfig.IsExposed() {
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
		if !serviceConfig.IsExposed() {
			continue
		}

		hosts = append(hosts, serviceConfig.ExposeAliases...)
		hosts = append(hosts, serviceConfig.ExposeDomains...)
	}

	return hosts
}

func (self *ServicesConfig) GetHiddenPrefix() string {
	prefixes := self.GetHiddenPrefixes()
	if 0 < len(prefixes) {
		return prefixes[0]
	}
	return ""
}

func (self *ServicesConfig) GetHiddenPrefixes() []string {
	return self.HiddenPrefixes
}

func (self *ServicesConfig) GetLbHiddenPrefix() string {
	prefixes := self.GetLbHiddenPrefixes()
	if 0 < len(prefixes) {
		return prefixes[0]
	}
	return ""
}

func (self *ServicesConfig) GetLbHiddenPrefixes() []string {
	if 0 < len(self.LbHiddenPrefixes) {
		return self.LbHiddenPrefixes
	}
	return self.HiddenPrefixes
}

// IsExposed reports whether the named service is externally exposed.
// The lb service is always exposed. Unknown services are not exposed.
func (self *ServicesConfig) IsExposed(service string) bool {
	if service == "lb" {
		return true
	}
	serviceConfig, ok := self.Versions[0].Services[service]
	if !ok {
		// doesn't exist
		return false
	}
	return serviceConfig.IsExposed()
}

// IsLbExposed reports whether the named service is exposed through the lb.
func (self *ServicesConfig) IsLbExposed(service string) bool {
	if service == "lb" {
		return false
	}
	serviceConfig, ok := self.Versions[0].Services[service]
	if !ok {
		// doesn't exist
		return false
	}
	return serviceConfig.IsLbExposed()
}

// IsStandardStatus reports whether the named service uses the standard status mode.
func (self *ServicesConfig) IsStandardStatus(service string) bool {
	if service == "lb" {
		return true
	}
	serviceConfig, ok := self.Versions[0].Services[service]
	if !ok {
		// doesn't exist
		return false
	}
	return serviceConfig.IsStandardStatus()
}

type ServicesConfigVersion struct {
	ExternalPorts         any       `yaml:"external_ports,omitempty"`
	InternalPorts         any       `yaml:"internal_ports,omitempty"`
	RoutingTables         any       `yaml:"routing_tables,omitempty"`
	ParallelBlockCount    int       `yaml:"parallel_block_count,omitempty"`
	ServicesDockerNetwork string    `yaml:"services_docker_network,omitempty"`
	Lb                    *LbConfig `yaml:"lb,omitempty"`
	// LbStream              *LbConfig  `yaml:"lb_stream,omitempty"`
	HostServices map[string][]string       `yaml:"host_services,omitempty"`
	Services     map[string]*ServiceConfig `yaml:"services,omitempty"`
}

// HostsForService returns the sorted set of hosts the given service is placed on.
//
// The placement rule (reproduced exactly from the block allocation):
//   - seed with every host that has an lb interface (v.Lb.Interfaces)
//   - drop any host whose host_services list does not include the service
//   - drop any host the service's own `hosts` restriction excludes
func HostsForService(v *ServicesConfigVersion, service string) []string {
	// an unknown service is placed nowhere. callers of this discovery api may pass
	// any name, so return empty instead of nil-dereferencing the absent ServiceConfig
	serviceConfig, ok := v.Services[service]
	if !ok {
		return nil
	}
	serviceHosts := map[string]bool{}
	// a version with no lb places nothing; config load validates every version,
	// including historical ones that may predate the lb block
	if v.Lb != nil {
		for host, _ := range v.Lb.Interfaces {
			serviceHosts[host] = true
		}
	}
	for host, services := range v.HostServices {
		if !slices.Contains(services, service) {
			delete(serviceHosts, host)
		}
	}
	for host, _ := range serviceHosts {
		if !serviceConfig.IncludesHost(host) {
			delete(serviceHosts, host)
		}
	}
	hosts := maps.Keys(serviceHosts)
	sort.Strings(hosts)
	return hosts
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

// ForwardPortConfig declares public aliases for load-balancer service ports.
// The map key is the port received on the interface and the value is the
// logical lb service port. warpctl resolves that service port to the active
// internal binding for a host-networked lb (or the container service port for
// an isolated lb). Targets remain ordinary stream service ports so NGINX owns
// PPv2 emission and backend selection; warpctl owns only the scoped DNAT.
// Forward aliases are currently IPv4-only by policy.
type ForwardPortConfig struct {
	TcpForwardPorts map[int]int `yaml:"tcp_forward_ports,omitempty"`
	UdpForwardPorts map[int]int `yaml:"udp_forward_ports,omitempty"`
}

func (self *ForwardPortConfig) AllForwardPorts() map[string]map[int]int {
	return map[string]map[int]int{
		"tcp": self.TcpForwardPorts,
		"udp": self.UdpForwardPorts,
	}
}

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
	return self.StreamUdpPorts()
}

func (self *PortConfig) AllHttpPorts() map[string][]int {
	return map[string][]int{
		"tcp": self.HttpTcpPorts(),
	}
}

func (self *PortConfig) AllStreamPorts() map[string][]int {
	return map[string][]int{
		"tcp": self.StreamTcpPorts(),
		"udp": self.StreamUdpPorts(),
	}
}

func (self *PortConfig) HttpTcpPorts() []int {
	return warp.ExpandPortConfigPorts(self.PortSpecs...)
}

func (self *PortConfig) StreamTcpPorts() []int {
	return warp.ExpandPortConfigPorts(self.TcpStreamPortSpecs...)
}

func (self *PortConfig) StreamUdpPorts() []int {
	return warp.ExpandPortConfigPorts(self.UdpStreamPortSpecs...)
}

type LbConfig struct {
	Interfaces map[string]map[string]*LbBlock `yaml:"interfaces,omitempty"`
	// see https://github.com/go-yaml/yaml/issues/63
	PortConfig              `yaml:",inline"`
	StreamPortServiceConfig `yaml:",inline"`
	ForwardPortConfig       `yaml:",inline"`
}

type ServiceConfig struct {
	CorsOrigins     []string          `yaml:"cors_origins,omitempty"`
	CorsOriginsFrom string            `yaml:"cors_origins_from,omitempty"`
	Status          string            `yaml:"status,omitempty"`
	HiddenPrefixes  []string          `yaml:"hidden_prefixes,omitempty"`
	ExposeAliases   []string          `yaml:"expose_aliases,omitempty"`
	RedirectAliases map[string]string `yaml:"redirect_aliases,omitempty"`
	ExposeDomains   []string          `yaml:"expose_domains,omitempty"`
	Exposed         *bool             `yaml:"exposed,omitempty"`
	LbExposed       *bool             `yaml:"lb_exposed,omitempty"`
	Websocket       *bool             `yaml:"websocket,omitempty"`
	Streamable      *bool             `yaml:"streamable,omitempty"`
	// service-relative path patterns whose request body the lb streams
	// through to the service as it arrives, while every other path of the
	// service keeps the buffered default, which the lb can retry on a
	// sibling block. The syntax is the api router's route pattern: a regex
	// matched against the whole service-relative path (implicitly anchored
	// at both ends), beginning with /. The lb marks a streamed request with
	// `X-UR-Request-Buffering: off`. Redundant with `streamable`, which
	// streams every path.
	StreamablePaths []string `yaml:"streamable_paths,omitempty"`
	Stateful        *bool    `yaml:"stateful,omitempty"`
	Hosts           []string `yaml:"hosts,omitempty"`
	// public udp ports the service owns directly on each host it is pinned to.
	// warp allocates a host port per entry exactly as it does for `ports`, so the
	// container reads the mapping from WARP_PORTS and binds only the allocated
	// port, while the public port reaches it through the same interface dnat warp
	// applies to the lb. Only a host-pinned service (`hosts`) may declare these.
	ExternalUdpPorts []int             `yaml:"external_udp_ports,omitempty"`
	EnvVars          map[string]string `yaml:"env_vars,omitempty"`
	Mount            map[string]string `yaml:"mount,omitempty"`
	CapNetAdmin      bool              `yaml:"cap_net_admin,omitempty"`
	User             string            `yaml:"user,omitempty"`
	SecretFiles      []string          `yaml:"secret_files,omitempty"`
	Blocks           []map[string]int  `yaml:"blocks,omitempty"`
	Keepalive        *Keepalive        `yaml:"keepalive,omitempty"`
	MemoryLimit      string            `yaml:"memory_limit,omitempty"`
	Cores            int               `yaml:"cores,omitempty"`
	RateLimit        *RateLimit        `yaml:"rate_limit,omitempty"`
	// see https://github.com/go-yaml/yaml/issues/63
	PortConfig `yaml:",inline"`
}

// ResolveCorsOrigins returns the effective allowlist for service. A service can
// inherit another service's list so related browser surfaces cannot drift.
func (self *ServicesConfigVersion) ResolveCorsOrigins(service string) ([]string, error) {
	visited := map[string]bool{}
	currentService := service
	for {
		if visited[currentService] {
			return nil, fmt.Errorf("cors_origins_from cycle at service %q", currentService)
		}
		visited[currentService] = true

		serviceConfig, ok := self.Services[currentService]
		if !ok || serviceConfig == nil {
			return nil, fmt.Errorf("cors origin source service %q does not exist", currentService)
		}
		if serviceConfig.CorsOriginsFrom != "" && 0 < len(serviceConfig.CorsOrigins) {
			return nil, fmt.Errorf("service %q sets both cors_origins and cors_origins_from", currentService)
		}
		if serviceConfig.CorsOriginsFrom == "" {
			return slices.Clone(serviceConfig.CorsOrigins), nil
		}
		currentService = serviceConfig.CorsOriginsFrom
	}
}

func (self *ServiceConfig) GetStatusMode() string {
	if self.Status != "" {
		return self.Status
	}
	return "standard"
}

func (self *ServiceConfig) IsStandardStatus() bool {
	return self.GetStatusMode() == "standard"
}

func (self *ServiceConfig) IsExposed() bool {
	// default true
	return self.Exposed == nil || *self.Exposed
}

func (self *ServiceConfig) IsLbExposed() bool {
	return self.LbExposed == nil || *self.LbExposed
}

func (self *ServiceConfig) IncludesHost(host string) bool {
	return len(self.Hosts) == 0 || slices.Contains(self.Hosts, host)
}

// The public ports the service publishes itself, keyed by port type. These are
// not lb ports: the lb never fronts them and no lb stream mapping refers to
// them. The returned slices are copies so a caller may sort them in place, as
// the port allocator does.
func (self *ServiceConfig) AllExternalPorts() map[string][]int {
	return map[string][]int{
		"udp": slices.Clone(self.ExternalUdpPorts),
	}
}

func (self *ServiceConfig) GetHiddenPrefix() string {
	prefixes := self.GetHiddenPrefixes()
	if 0 < len(prefixes) {
		return prefixes[0]
	}
	return ""
}

func (self *ServiceConfig) GetHiddenPrefixes() []string {
	return self.HiddenPrefixes
}

func (self *ServiceConfig) IsWebsocket() bool {
	// default false
	return self.Websocket != nil && *self.Websocket
}

func (self *ServiceConfig) IsStreamable() bool {
	// default false
	return self.Streamable != nil && *self.Streamable
}

// GetStreamablePaths returns the service-relative patterns whose request
// body the lb streams; empty when the service buffers every path or, as a
// `streamable` service, streams every path.
func (self *ServiceConfig) GetStreamablePaths() []string {
	return self.StreamablePaths
}

// ValidateStreamablePath checks one `streamable_paths` pattern. It is the
// api router's route pattern syntax, matched against the whole
// service-relative path with the anchors implied, so it begins with /
// rather than ^. It is compiled here as a Go (RE2) regex, which the PCRE
// nginx runs accepts as well; nginx checks the composed location itself
// when the lb loads its config.
func ValidateStreamablePath(streamablePath string) error {
	if !strings.HasPrefix(streamablePath, "/") {
		return fmt.Errorf("streamable path %q must begin with /", streamablePath)
	}
	for _, r := range streamablePath {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("streamable path %q contains a control character", streamablePath)
		}
	}
	if _, err := regexp.Compile("^(?:" + streamablePath + ")$"); err != nil {
		return fmt.Errorf("streamable path %q: %w", streamablePath, err)
	}
	return nil
}

func (self *ServiceConfig) IsStateful() bool {
	// default false
	return self.Stateful != nil && *self.Stateful
}

// MemoryLimitBytes parses the MemoryLimit string into a byte count.
// Returns 0 when no limit is set. Panics on an unparseable value.
func (self *ServiceConfig) MemoryLimitBytes() (memoryLimit int64) {
	if self.MemoryLimit == "" {
		return
	}
	var err error
	memoryLimit, err = warp.ParseByteCount(self.MemoryLimit)
	if err != nil {
		panic(err)
	}
	return
}

type LbBlock struct {
	Transparent                  bool        `yaml:"transparent,omitempty"`
	DockerNetwork                string      `yaml:"docker_network,omitempty"`
	ConcurrentClients            int         `yaml:"concurrent_clients,omitempty"`
	ExpectedConnectionsPerClient int         `yaml:"expected_connections_per_client,omitempty"`
	Cores                        int         `yaml:"cores,omitempty"`
	ExternalPorts                map[int]int `yaml:"external_ports,omitempty"`
	RateLimit                    *RateLimit  `yaml:"rate_limit,omitempty"`
	Keepalive                    *Keepalive  `yaml:"keepalive,omitempty"`
	StreamPortServiceConfig      `yaml:",inline"`
}

func (self *LbBlock) GetRateLimit() *RateLimit {
	if self.RateLimit != nil {
		return self.RateLimit
	}
	// rate defaults
	return DefaultRateLimit()
}

type RateLimit struct {
	RequestsPerSecond int      `yaml:"requests_per_second,omitempty"`
	RequestsPerMinute int      `yaml:"requests_per_minute,omitempty"`
	Burst             int      `yaml:"burst,omitempty"`
	Delay             int      `yaml:"delay,omitempty"`
	NetConnections    int      `yaml:"net_connections,omitempty"`
	ExcludeSubnets    []string `yaml:"exclude_subnets,omitempty"`
}

func (self *RateLimit) ExcludePrefixes() []netip.Prefix {
	prefixes := []netip.Prefix{}
	for _, subnet := range self.ExcludeSubnets {
		prefix := netip.MustParsePrefix(subnet)
		prefixes = append(prefixes, prefix)
	}
	return prefixes
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
		KeepaliveRequests: 8192,
		KeepaliveTime:     "15m",
		KeepaliveTimeout:  "1m",
	}
}

// Service identities/roles come from config; passwords come from vault.
type GrafanaConfig struct {
	Users []*GrafanaServiceUser `yaml:"users,omitempty"`
}

// One service identity whose authorization and password have separate sources.
type GrafanaServiceUser struct {
	Name     string   `yaml:"name,omitempty"`
	Password string   `yaml:"password,omitempty"`
	Roles    []string `yaml:"roles,omitempty"`
}

// Reports whether ordinary config grants the requested authorization role.
func (self *GrafanaServiceUser) hasRole(role string) bool {
	return slices.Contains(self.Roles, role)
}

// Selects the configured query identity, preferring the warpctl-specific user.
func (self *GrafanaConfig) QueryUser() (*GrafanaServiceUser, error) {
	var queryUser *GrafanaServiceUser
	for _, user := range self.Users {
		if !user.hasRole("query") || user.Password == "" {
			continue
		}
		if user.Name == "warpctl" {
			return user, nil
		}
		if queryUser == nil {
			queryUser = user
		}
	}
	if queryUser == nil {
		return nil, errors.New("No user with the query role in grafana.yml")
	}
	return queryUser, nil
}
