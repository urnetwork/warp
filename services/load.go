package services

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/coreos/go-semver/semver"
	"github.com/urnetwork/warp"
	"golang.org/x/exp/maps"
	"gopkg.in/yaml.v3"
)

// DefaultWarpHome mirrors server/env.go DefaultWarpHome.
var DefaultWarpHome = "/srv/warp"

// warpHome replicates server/env.go WarpHome (this package deliberately does not
// import github.com/urnetwork/server, which is a different module).
func warpHome() string {
	if warpHome := os.Getenv("WARP_HOME"); warpHome != "" {
		return warpHome
	}
	return DefaultWarpHome
}

// vaultHomeRoot replicates server/env.go VaultHomeRoot.
func vaultHomeRoot() string {
	if warpVaultHome := os.Getenv("WARP_VAULT_HOME"); warpVaultHome != "" {
		return warpVaultHome
	}
	return filepath.Join(warpHome(), "vault")
}

// Mirrors the warpctl config-root convention without importing that child
// package into its parent service/config package.
func configHomeRoot() string {
	if warpConfigHome := os.Getenv("WARP_CONFIG_HOME"); warpConfigHome != "" {
		return warpConfigHome
	}
	return filepath.Join(warpHome(), "config")
}

// resolveVaultPath returns <vaultDir>/<env>/<name> when that env-specific file
// exists (local dev layout), else <vaultDir>/<name> (a warp container mounts the
// env-specific vault directly at the root).
func resolveVaultPath(vaultDir string, env string, name string) string {
	envPath := filepath.Join(vaultDir, env, name)
	if _, err := os.Stat(envPath); err == nil {
		return envPath
	}
	return filepath.Join(vaultDir, name)
}

// No config file of that name in any layout resolveConfigPath reads.
var ErrConfigNotFound = errors.New("config file not found")

// Supports source-tree, container-root, and host version-directory layouts,
// choosing the newest semantic config version in the latter case.
func resolveConfigPath(configDir string, env string, name string) (string, error) {
	for _, configPath := range []string{
		filepath.Join(configDir, env, name),
		filepath.Join(configDir, name),
	} {
		if configInfo, err := os.Stat(configPath); err == nil && configInfo.Mode().IsRegular() {
			return configPath, nil
		}
	}

	entries, err := os.ReadDir(configDir)
	if err != nil {
		return "", err
	}
	versionNames := []string{}
	for _, entry := range entries {
		if entry.IsDir() {
			if _, err := semver.NewVersion(entry.Name()); err == nil {
				versionNames = append(versionNames, entry.Name())
			}
		}
	}
	slices.SortFunc(versionNames, func(a string, b string) int {
		aVersion, _ := semver.NewVersion(a)
		bVersion, _ := semver.NewVersion(b)
		if aVersion.LessThan(*bVersion) {
			return -1
		}
		if bVersion.LessThan(*aVersion) {
			return 1
		}
		return strings.Compare(a, b)
	})
	for versionIndex := len(versionNames) - 1; 0 <= versionIndex; versionIndex -= 1 {
		configPath := filepath.Join(configDir, versionNames[versionIndex], name)
		if configInfo, err := os.Stat(configPath); err == nil && configInfo.Mode().IsRegular() {
			return configPath, nil
		}
	}
	return "", fmt.Errorf("%w: %q beneath %s", ErrConfigNotFound, name, configDir)
}

// ServicesConfigPath is where LoadServicesConfigFrom reads env's services.yml in vaultDir.
func ServicesConfigPath(vaultDir string, env string) string {
	return resolveVaultPath(vaultDir, env, "services.yml")
}

// LoadServicesConfigFrom reads and parses the services config for env out of vaultDir.
func LoadServicesConfigFrom(vaultDir string, env string) (*ServicesConfig, error) {
	servicesConfigPath := ServicesConfigPath(vaultDir, env)
	data, err := os.ReadFile(servicesConfigPath)
	if err != nil {
		return nil, err
	}
	return ParseServicesConfig(data, servicesConfigPath)
}

// ParseServicesConfig parses a services.yml's text, with every check LoadServicesConfigFrom makes, and
// adds the default config-updater to the latest version as it does. servicesConfigPath names the text
// in errors.
func ParseServicesConfig(data []byte, servicesConfigPath string) (*ServicesConfig, error) {
	var servicesConfig ServicesConfig
	if err := yaml.Unmarshal(data, &servicesConfig); err != nil {
		return nil, err
	}

	if len(servicesConfig.Versions) == 0 {
		return nil, fmt.Errorf("services config %s has no versions", servicesConfigPath)
	}

	// add a default config-updater if not defined
	if servicesConfig.Versions[0].Services == nil {
		servicesConfig.Versions[0].Services = map[string]*ServiceConfig{}
	}
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

	if err := validateRouters(&servicesConfig); err != nil {
		return nil, fmt.Errorf("services config %s: %w", servicesConfigPath, err)
	}
	if err := validateNoAccessLog(&servicesConfig); err != nil {
		return nil, fmt.Errorf("services config %s: %w", servicesConfigPath, err)
	}
	if err := validateDnsRecords(&servicesConfig); err != nil {
		return nil, fmt.Errorf("services config %s: %w", servicesConfigPath, err)
	}
	if err := validateDnsUnproxied(&servicesConfig); err != nil {
		return nil, fmt.Errorf("services config %s: %w", servicesConfigPath, err)
	}

	for versionIndex, version := range servicesConfig.Versions {
		if err := validateForwardPorts(version); err != nil {
			return nil, fmt.Errorf("services config %s version %d: %w", servicesConfigPath, versionIndex, err)
		}
		if err := validateExternalPorts(version); err != nil {
			return nil, fmt.Errorf("services config %s version %d: %w", servicesConfigPath, versionIndex, err)
		}
		if err := validatePublicPorts(version); err != nil {
			return nil, fmt.Errorf("services config %s version %d: %w", servicesConfigPath, versionIndex, err)
		}
		if err := validateRouterInterfaces(&servicesConfig, version); err != nil {
			return nil, fmt.Errorf("services config %s version %d: %w", servicesConfigPath, versionIndex, err)
		}
		if err := validateExternalUdpForwardPorts(version); err != nil {
			return nil, fmt.Errorf("services config %s version %d: %w", servicesConfigPath, versionIndex, err)
		}
		if err := validateDnsAliases(version); err != nil {
			return nil, err
		}
		if err := validateRouterForwards(version); err != nil {
			return nil, fmt.Errorf("services config %s version %d: %w", servicesConfigPath, versionIndex, err)
		}
		if err := validateTlsSplit(version); err != nil {
			return nil, fmt.Errorf("services config %s version %d: %w", servicesConfigPath, versionIndex, err)
		}
		if err := validateTlsEdgePorts(version); err != nil {
			return nil, fmt.Errorf("services config %s version %d: %w", servicesConfigPath, versionIndex, err)
		}
		for service, serviceConfig := range version.Services {
			if _, err := version.ResolveCorsOrigins(service); err != nil {
				return nil, fmt.Errorf("services config %s version %d: %w", servicesConfigPath, versionIndex, err)
			}
			if serviceConfig.CapNetAdmin && service != "proxy" {
				return nil, fmt.Errorf("services config %s version %d: service %q grants cap_net_admin; only proxy may request it", servicesConfigPath, versionIndex, service)
			}
			if serviceConfig.Mount["docker"] == "yes" {
				return nil, fmt.Errorf("services config %s version %d: service %q requests the forbidden Docker API mount", servicesConfigPath, versionIndex, service)
			}
			seenSecretFiles := map[string]bool{}
			for _, secretFile := range serviceConfig.SecretFiles {
				if secretFile == "" || filepath.Base(secretFile) != secretFile || !filepath.IsLocal(secretFile) {
					return nil, fmt.Errorf("services config %s version %d: service %q has unsafe secret file %q", servicesConfigPath, versionIndex, service, secretFile)
				}
				if seenSecretFiles[secretFile] {
					return nil, fmt.Errorf("services config %s version %d: service %q repeats secret file %q", servicesConfigPath, versionIndex, service, secretFile)
				}
				seenSecretFiles[secretFile] = true
			}
			if !slices.IsSorted(serviceConfig.SecretFiles) {
				return nil, fmt.Errorf("services config %s version %d: service %q secret_files must be sorted", servicesConfigPath, versionIndex, service)
			}
			if err := ValidateRouteRateLimits(service, serviceConfig); err != nil {
				return nil, fmt.Errorf("services config %s version %d: service %q: %w", servicesConfigPath, versionIndex, service, err)
			}
			if err := ValidateServiceRateLimit(serviceConfig); err != nil {
				return nil, fmt.Errorf("services config %s version %d: service %q: %w", servicesConfigPath, versionIndex, service, err)
			}
			if 0 < len(serviceConfig.StreamablePaths) {
				if serviceConfig.IsStreamable() {
					return nil, fmt.Errorf("services config %s version %d: service %q streams every path already (streamable); streamable_paths is redundant", servicesConfigPath, versionIndex, service)
				}
				if serviceConfig.IsWebsocket() {
					return nil, fmt.Errorf("services config %s version %d: service %q is a websocket service; streamable_paths needs a plain http service", servicesConfigPath, versionIndex, service)
				}
				for _, streamablePath := range serviceConfig.StreamablePaths {
					if err := ValidateStreamablePath(streamablePath); err != nil {
						return nil, fmt.Errorf("services config %s version %d: service %q: %w", servicesConfigPath, versionIndex, service, err)
					}
				}
			}
		}
	}

	return &servicesConfig, nil
}

// Checks the public ports a service publishes on its own hosts. warp dnats each
// one to the port it allocated for that service port, so the claim is only
// meaningful for a host-pinned service, the port cannot also be an lb-fronted
// stream port of the same service (one port key cannot carry two lb types), and
// two services pinned to the same host cannot claim the same public port.
func validateExternalPorts(version *ServicesConfigVersion) error {
	if version == nil {
		return nil
	}

	type publicPortClaim struct {
		host     string
		portType string
		port     int
	}
	claimingServices := map[publicPortClaim]string{}

	orderedServices := maps.Keys(version.Services)
	sort.Strings(orderedServices)

	for _, service := range orderedServices {
		serviceConfig := version.Services[service]
		if serviceConfig == nil {
			continue
		}
		allExternalPorts := serviceConfig.AllExternalPorts()
		externalPortCount := 0
		for _, ports := range allExternalPorts {
			externalPortCount += len(ports)
		}
		if externalPortCount == 0 {
			continue
		}
		if len(serviceConfig.Hosts) == 0 {
			return fmt.Errorf("service %q declares external ports without a hosts list", service)
		}
		serviceHosts := HostsForService(version, service)

		orderedPortTypes := maps.Keys(allExternalPorts)
		sort.Strings(orderedPortTypes)
		for _, portType := range orderedPortTypes {
			streamPorts := serviceConfig.AllStreamPorts()[portType]
			httpPorts := serviceConfig.AllHttpPorts()[portType]
			claimedPorts := map[int]bool{}
			for _, publicPort := range allExternalPorts[portType] {
				if publicPort < 1 || 65535 < publicPort {
					return fmt.Errorf("service %q external %s port %d is outside 1..65535", service, portType, publicPort)
				}
				if claimedPorts[publicPort] {
					return fmt.Errorf("service %q repeats external %s port %d", service, portType, publicPort)
				}
				claimedPorts[publicPort] = true
				if slices.Contains(streamPorts, publicPort) || slices.Contains(httpPorts, publicPort) {
					return fmt.Errorf("service %q declares %s port %d as both an lb port and an external port", service, portType, publicPort)
				}

				// the same public port on two blocks of one host has no single owner
				for _, host := range serviceHosts {
					claim := publicPortClaim{host: host, portType: portType, port: publicPort}
					if claimingService, claimed := claimingServices[claim]; claimed {
						return fmt.Errorf("services %q and %q both claim external %s port %d on %s", claimingService, service, portType, publicPort, host)
					}
					claimingServices[claim] = service
				}
			}
		}
	}
	return nil
}

// Checks the public udp aliases a host-pinned service adds to its own dnat:
// each targets one of the service's external udp ports, rewrites a port the
// service does not already own, and claims a public udp port no other
// service owns or aliases on the same host.
func validateExternalUdpForwardPorts(version *ServicesConfigVersion) error {
	if version == nil {
		return nil
	}
	type publicPortClaim struct {
		host string
		port int
	}
	claimingServices := map[publicPortClaim]string{}

	orderedServices := maps.Keys(version.Services)
	sort.Strings(orderedServices)
	for _, service := range orderedServices {
		serviceConfig := version.Services[service]
		if serviceConfig == nil {
			continue
		}
		for _, host := range HostsForService(version, service) {
			for _, publicPort := range serviceConfig.ExternalUdpPorts {
				claimingServices[publicPortClaim{host: host, port: publicPort}] = service
			}
		}
	}
	for _, service := range orderedServices {
		serviceConfig := version.Services[service]
		if serviceConfig == nil || len(serviceConfig.ExternalUdpForwardPorts) == 0 {
			continue
		}
		if len(serviceConfig.Hosts) == 0 {
			return fmt.Errorf("service %q declares external udp forward ports without a hosts list", service)
		}
		serviceHosts := HostsForService(version, service)
		publicPorts := maps.Keys(serviceConfig.ExternalUdpForwardPorts)
		sort.Ints(publicPorts)
		for _, publicPort := range publicPorts {
			targetPort := serviceConfig.ExternalUdpForwardPorts[publicPort]
			if err := validateForwardPair("udp", publicPort, targetPort); err != nil {
				return fmt.Errorf("service %q external udp forward: %w", service, err)
			}
			if !slices.Contains(serviceConfig.ExternalUdpPorts, targetPort) {
				return fmt.Errorf("service %q external udp forward %d->%d targets a port that is not one of its external_udp_ports", service, publicPort, targetPort)
			}
			if slices.Contains(serviceConfig.ExternalUdpPorts, publicPort) {
				return fmt.Errorf("service %q external udp forward %d->%d rewrites a port the service already owns", service, publicPort, targetPort)
			}
			for _, host := range serviceHosts {
				claim := publicPortClaim{host: host, port: publicPort}
				if claimingService, claimed := claimingServices[claim]; claimed {
					return fmt.Errorf("services %q and %q both claim public udp port %d on %s", claimingService, service, publicPort, host)
				}
				claimingServices[claim] = service
			}
		}
	}
	return nil
}

func validateForwardPorts(version *ServicesConfigVersion) error {
	if version == nil || version.Lb == nil {
		return nil
	}

	lb := version.Lb
	allForwardPorts := lb.AllForwardPorts()
	hasForwardPorts := false
	for _, forwardPorts := range allForwardPorts {
		hasForwardPorts = hasForwardPorts || 0 < len(forwardPorts)
	}
	allocatedExternalPorts := map[int]bool{}
	if hasForwardPorts && version.ExternalPorts != nil {
		externalPorts, err := warp.ExpandAnyPorts(version.ExternalPorts)
		if err != nil {
			return fmt.Errorf("resolve external port pool for forward ports: %w", err)
		}
		for _, externalPort := range externalPorts {
			allocatedExternalPorts[externalPort] = true
		}
	}
	allPortServices := lb.AllPortServices()
	allDirectPorts := lb.AllStreamPorts()
	for protocol, forwardPorts := range allForwardPorts {
		portServices := allPortServices[protocol]
		directPorts := allDirectPorts[protocol]
		for publicPort, servicePort := range forwardPorts {
			if publicPort < 1 || 65535 < publicPort || servicePort < 1 || 65535 < servicePort {
				return fmt.Errorf("%s forward %d->%d uses a port outside 1..65535", protocol, publicPort, servicePort)
			}
			if publicPort == servicePort {
				return fmt.Errorf("%s forward %d->%d is an identity mapping", protocol, publicPort, servicePort)
			}
			if _, chained := forwardPorts[servicePort]; chained {
				return fmt.Errorf("%s forward %d->%d targets another forward port", protocol, publicPort, servicePort)
			}
			if _, directlyServed := portServices[publicPort]; directlyServed || slices.Contains(directPorts, publicPort) {
				return fmt.Errorf("%s forward port %d conflicts with a directly served lb port", protocol, publicPort)
			}
			if allocatedExternalPorts[publicPort] {
				return fmt.Errorf("%s forward port %d conflicts with the allocatable external port pool", protocol, publicPort)
			}

			service, ok := portServices[servicePort]
			if !ok || service == "" {
				return fmt.Errorf("%s forward %d->%d has no lb stream service target", protocol, publicPort, servicePort)
			}
			serviceConfig, ok := version.Services[service]
			if !ok || serviceConfig == nil || !slices.Contains(serviceConfig.AllStreamPorts()[protocol], servicePort) {
				return fmt.Errorf("%s forward %d->%d targets service %q without that stream port", protocol, publicPort, servicePort, service)
			}

			for host, lbBlocks := range lb.Interfaces {
				for interfaceName, lbBlock := range lbBlocks {
					if lbBlock == nil {
						continue
					}
					blockPortServices := lbBlock.AllPortServices()[protocol]
					if blockService, overridden := blockPortServices[servicePort]; overridden && blockService != service {
						return fmt.Errorf("%s forward %d->%d targets %q globally but %s/%s overrides it with %q", protocol, publicPort, servicePort, service, host, interfaceName, blockService)
					}
					if _, conflict := blockPortServices[publicPort]; conflict {
						return fmt.Errorf("%s forward port %d conflicts with directly served port on %s/%s", protocol, publicPort, host, interfaceName)
					}
					if forcedServicePort, conflict := lbBlock.ExternalPorts[publicPort]; conflict {
						return fmt.Errorf("%s forward port %d conflicts with forced external mapping to service port %d on %s/%s", protocol, publicPort, forcedServicePort, host, interfaceName)
					}
				}
			}
		}
	}
	return nil
}

// LoadServicesConfig reads and parses the services config for env, resolving the
// vault dir from the environment (WARP_VAULT_HOME, else WARP_HOME/vault, else
// /srv/warp/vault).
func LoadServicesConfig(env string) (*ServicesConfig, error) {
	return LoadServicesConfigFrom(vaultHomeRoot(), env)
}

// Loads names/roles from ordinary config and overlays only matching passwords
// from the scoped vault file.
func LoadGrafanaConfigFrom(configDir string, vaultDir string, env string) (*GrafanaConfig, error) {
	grafanaConfigPath, err := resolveConfigPath(configDir, env, "grafana.yml")
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(grafanaConfigPath)
	if err != nil {
		return nil, err
	}

	var grafanaConfig GrafanaConfig
	if err := yaml.Unmarshal(data, &grafanaConfig); err != nil {
		return nil, err
	}
	secretPath := resolveVaultPath(vaultDir, env, "grafana.yml")
	secretData, err := os.ReadFile(secretPath)
	if err != nil {
		return nil, err
	}
	var secretConfig GrafanaConfig
	if err := yaml.Unmarshal(secretData, &secretConfig); err != nil {
		return nil, err
	}

	configUsers := map[string]*GrafanaServiceUser{}
	for _, configUser := range grafanaConfig.Users {
		if configUser == nil || configUser.Name == "" {
			return nil, fmt.Errorf("Grafana config %s has an unnamed service user", grafanaConfigPath)
		}
		if configUser.Password != "" {
			return nil, fmt.Errorf("Grafana config %s contains password for %q", grafanaConfigPath, configUser.Name)
		}
		if configUsers[configUser.Name] != nil {
			return nil, fmt.Errorf("Grafana config %s repeats service user %q", grafanaConfigPath, configUser.Name)
		}
		configUsers[configUser.Name] = configUser
	}
	secretUsers := map[string]bool{}
	for _, secretUser := range secretConfig.Users {
		if secretUser == nil || secretUser.Name == "" {
			return nil, fmt.Errorf("Grafana secret %s has an unnamed service user", secretPath)
		}
		if 0 < len(secretUser.Roles) {
			return nil, fmt.Errorf("Grafana secret %s contains roles for %q", secretPath, secretUser.Name)
		}
		if secretUsers[secretUser.Name] {
			return nil, fmt.Errorf("Grafana secret %s repeats service user %q", secretPath, secretUser.Name)
		}
		secretUsers[secretUser.Name] = true
		configUser := configUsers[secretUser.Name]
		if configUser == nil {
			return nil, fmt.Errorf("Grafana secret user %q is absent from ordinary config", secretUser.Name)
		}
		configUser.Password = secretUser.Password
	}

	return &grafanaConfig, nil
}

// Resolves both ordinary config and vault roots from the environment.
func LoadGrafanaConfig(env string) (*GrafanaConfig, error) {
	return LoadGrafanaConfigFrom(configHomeRoot(), vaultHomeRoot(), env)
}

// Checks §13.4's split block (W1). Its roots are exact DNS names, none under
// another, so one wildcard each covers them. Its service declares tcp stream
// port 443 and runs on every lb host, since every interface renders the
// split's upstream to it and a variable proxy_pass to an upstream that is not
// there fails per connection while `nginx -t` passes. TCP 443 stays among the
// lb's http ports, whose servers the split moves to the socket, and no stream
// port or tcp_stream_port_services entry claims it, since the split's stream
// server listens there. Its sizes are positive.
func validateTlsSplit(version *ServicesConfigVersion) error {
	if version == nil || version.Lb == nil || version.Lb.TlsSplit == nil {
		return nil
	}
	split := version.Lb.TlsSplit
	roots := split.GetRoots()
	if len(roots) == 0 {
		return fmt.Errorf("tls_split names no roots")
	}
	for i, root := range roots {
		if !noAccessLogHostRegex.MatchString(root) {
			return fmt.Errorf("tls_split root %q is not a lowercase dns name", root)
		}
		for j, other := range roots {
			if i != j && (root == other || strings.HasSuffix(root, "."+other)) {
				return fmt.Errorf("tls_split root %q repeats or is under root %q", root, other)
			}
		}
	}

	service := split.GetService()
	serviceConfig, ok := version.Services[service]
	if !ok || serviceConfig == nil {
		return fmt.Errorf("tls_split service %q is not a service", service)
	}
	if !slices.Contains(serviceConfig.StreamTcpPorts(), 443) {
		return fmt.Errorf("tls_split service %q declares no tcp stream port 443", service)
	}
	serviceHosts := HostsForService(version, service)
	lbHosts := maps.Keys(version.Lb.Interfaces)
	sort.Strings(lbHosts)
	for _, host := range lbHosts {
		if !slices.Contains(serviceHosts, host) {
			return fmt.Errorf("tls_split service %q does not run on lb host %s, whose split would send to nothing", service, host)
		}
	}

	if !slices.Contains(version.Lb.HttpTcpPorts(), 443) {
		return fmt.Errorf("tls_split needs 443 among the lb's ports, whose servers it moves to the socket")
	}
	if slices.Contains(version.Lb.StreamTcpPorts(), 443) {
		return fmt.Errorf("tls_split owns tcp 443, which the lb's tcp_stream_ports also claims")
	}
	if claimingService, claimed := version.Lb.TcpStreamPortServices[443]; claimed {
		return fmt.Errorf("tls_split owns tcp 443, which tcp_stream_port_services gives %q", claimingService)
	}
	for _, host := range lbHosts {
		interfaceNames := maps.Keys(version.Lb.Interfaces[host])
		sort.Strings(interfaceNames)
		for _, interfaceName := range interfaceNames {
			lbBlock := version.Lb.Interfaces[host][interfaceName]
			if lbBlock == nil {
				continue
			}
			if claimingService, claimed := lbBlock.TcpStreamPortServices[443]; claimed {
				return fmt.Errorf("tls_split owns tcp 443, which %s %s's tcp_stream_port_services gives %q", host, interfaceName, claimingService)
			}
		}
	}

	if split.ProxyBufferSize != "" {
		byteCount, err := split.GetProxyBufferByteCount()
		if err != nil || byteCount <= 0 {
			return fmt.Errorf("tls_split proxy_buffer_size %q is not a positive byte count", split.ProxyBufferSize)
		}
	}
	if split.ClientHello != nil && (split.ClientHello.TimeoutSeconds < 0 || split.ClientHello.MaxBytes < 0) {
		return fmt.Errorf("tls_split client_hello bounds must be positive")
	}
	return nil
}

// Holds the tls edge to its ports (§13.4, §19 W7, R-TLS-9; owner decisions 34,
// 68, 121): tcp 443 through the split, and 8443, 8883 and 5671 unsplit as
// stream ports, and nothing else, so no other port of the shared addresses
// reaches a user's listener (§22.5). The tls edge is tlsedge, and the split's
// service when it names another. Its tcp stream ports are those four, it has
// no udp stream port or public port of its own, and no lb or interface
// stream port service entry gives it any port outside them.
func validateTlsEdgePorts(version *ServicesConfigVersion) error {
	if version == nil {
		return nil
	}
	edgeServices := []string{TlsEdgeService}
	if version.Lb != nil && version.Lb.TlsSplit != nil && version.Lb.TlsSplit.GetService() != TlsEdgeService {
		edgeServices = append(edgeServices, version.Lb.TlsSplit.GetService())
	}
	for _, service := range edgeServices {
		serviceConfig, ok := version.Services[service]
		if !ok || serviceConfig == nil {
			continue
		}
		for _, port := range serviceConfig.StreamTcpPorts() {
			if !slices.Contains(TlsEdgePorts, port) {
				return fmt.Errorf("tls edge %q declares tcp stream port %d, outside %v", service, port, TlsEdgePorts)
			}
		}
		if ports := serviceConfig.StreamUdpPorts(); 0 < len(ports) {
			return fmt.Errorf("tls edge %q declares udp stream ports %v, and takes tcp only", service, ports)
		}
		for portType, ports := range serviceConfig.AllExternalPorts() {
			if 0 < len(ports) {
				return fmt.Errorf("tls edge %q declares external %s ports %v, and takes only lb ports", service, portType, ports)
			}
		}
		if version.Lb == nil {
			continue
		}
		checkPortServices := func(where string, streamPortServiceConfig *StreamPortServiceConfig) error {
			for portType, portServices := range streamPortServiceConfig.AllPortServices() {
				ports := maps.Keys(portServices)
				sort.Ints(ports)
				for _, port := range ports {
					if portServices[port] != service {
						continue
					}
					if portType != "tcp" || !slices.Contains(TlsEdgePorts, port) {
						return fmt.Errorf("%s gives tls edge %q %s port %d, outside tcp %v", where, service, portType, port, TlsEdgePorts)
					}
				}
			}
			return nil
		}
		if err := checkPortServices("the lb", &version.Lb.StreamPortServiceConfig); err != nil {
			return err
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
				if err := checkPortServices(host+" "+interfaceName, &lbBlock.StreamPortServiceConfig); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// config/<env>/sidecar.yml's one key warp reads (§19.11; D-OPS-10): the lb
// interfaces the split's rollout holds out of DNS answers (W1).
type sidecarGatesConfig struct {
	Sidecar struct {
		Drained []string `yaml:"drained"`
	} `yaml:"sidecar"`
}

// config/<env>/sidecar.yml's `drained` (W1; plan-TLS-small-readings#16): the
// lb interfaces `warpctl dns` leaves out of the <env>-lb sets and the dns
// edges leave out of their answers, one list for both. The file is optional
// and inert when absent, so none is drained then; one that does not parse, or
// an entry empty or listed twice, is an error, since a drain that silently
// failed would put an interface under test into answers.
func LoadSidecarDrainedFrom(configDir string, env string) ([]string, error) {
	sidecarConfigPath, err := resolveConfigPath(configDir, env, "sidecar.yml")
	if errors.Is(err, ErrConfigNotFound) || errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(sidecarConfigPath)
	if err != nil {
		return nil, err
	}
	var gates sidecarGatesConfig
	if err := yaml.Unmarshal(data, &gates); err != nil {
		return nil, fmt.Errorf("sidecar config %s: %w", sidecarConfigPath, err)
	}
	seen := map[string]bool{}
	for _, name := range gates.Sidecar.Drained {
		if strings.TrimSpace(name) == "" || seen[name] {
			return nil, fmt.Errorf("sidecar config %s: drained entry %q is empty or repeated", sidecarConfigPath, name)
		}
		seen[name] = true
	}
	return gates.Sidecar.Drained, nil
}

// a lowercase dns name whose labels may begin with _ (_dmarc, _report), with
// an optional leading *. for a wildcard
var dnsRecordNameRegex = regexp.MustCompile(`^(\*\.)?([a-z0-9_]([a-z0-9_-]*[a-z0-9])?\.)+[a-z0-9]([a-z0-9-]*[a-z0-9])?$`)

// an mx value: a preference and an exchange host
var dnsRecordMxRegex = regexp.MustCompile(`^([0-9]{1,5}) ([a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+)$`)

// Checks dns.records (W11): each name a lowercase dns name, listed once, with
// something to publish; each interface one of the latest version's lb
// interfaces, with an ipv4 address, since its A record holds that; each mx a
// preference of at most 65535 and an exchange host; each txt one
// character-string of printable ascii that needs no quoting rule beyond its
// quotes. A record no registrar domain covers is reported by warpctl dns, as
// other names are, not refused here.
func validateDnsRecords(servicesConfig *ServicesConfig) error {
	records := servicesConfig.DnsRecords()
	if len(records) == 0 {
		return nil
	}
	var latest *ServicesConfigVersion
	if 0 < len(servicesConfig.Versions) {
		latest = servicesConfig.Versions[0]
	}
	names := map[string]bool{}
	for _, record := range records {
		if record == nil {
			return fmt.Errorf("dns records has an empty entry")
		}
		if !dnsRecordNameRegex.MatchString(record.Name) || 253 < len(record.Name) {
			return fmt.Errorf("dns record %q is not a lowercase dns name", record.Name)
		}
		if names[record.Name] {
			return fmt.Errorf("dns record %q is listed twice", record.Name)
		}
		names[record.Name] = true
		if len(record.Interfaces) == 0 && len(record.Mx) == 0 && len(record.Txt) == 0 {
			return fmt.Errorf("dns record %q publishes nothing", record.Name)
		}
		seenInterfaces := map[DnsRecordInterface]bool{}
		for _, recordInterface := range record.Interfaces {
			if recordInterface == nil {
				return fmt.Errorf("dns record %q has an empty interface", record.Name)
			}
			if seenInterfaces[*recordInterface] {
				return fmt.Errorf("dns record %q names %s %s twice", record.Name, recordInterface.Host, recordInterface.Interface)
			}
			seenInterfaces[*recordInterface] = true
			var lbBlock *LbBlock
			if latest != nil && latest.Lb != nil {
				lbBlock = latest.Lb.Interfaces[recordInterface.Host][recordInterface.Interface]
			}
			if lbBlock == nil {
				return fmt.Errorf("dns record %q names %s %s, which is no lb interface of the latest version", record.Name, recordInterface.Host, recordInterface.Interface)
			}
			if lbBlock.Ipv4 == "" {
				return fmt.Errorf("dns record %q names %s %s, which has no ipv4 address", record.Name, recordInterface.Host, recordInterface.Interface)
			}
		}
		for _, mx := range record.Mx {
			match := dnsRecordMxRegex.FindStringSubmatch(mx)
			if match == nil {
				return fmt.Errorf("dns record %q mx %q is not a preference and a lowercase host", record.Name, mx)
			}
			preference, err := strconv.Atoi(match[1])
			if err != nil || 65535 < preference {
				return fmt.Errorf("dns record %q mx %q has a preference past 65535", record.Name, mx)
			}
		}
		for _, txt := range record.Txt {
			if txt == "" || 255 < len(txt) {
				return fmt.Errorf("dns record %q txt %q is empty or past 255 bytes", record.Name, txt)
			}
			for _, b := range []byte(txt) {
				if b < 0x20 || 0x7e < b || b == '"' || b == '\\' {
					return fmt.Errorf("dns record %q txt %q holds a byte that is not printable ascii, or a quote or backslash", record.Name, txt)
				}
			}
		}
		if hasDuplicate(record.Mx) || hasDuplicate(record.Txt) {
			return fmt.Errorf("dns record %q repeats a value", record.Name)
		}
	}
	return nil
}

// Whether a list holds one value twice.
func hasDuplicate(values []string) bool {
	seen := map[string]bool{}
	for _, value := range values {
		if seen[value] {
			return true
		}
		seen[value] = true
	}
	return false
}
