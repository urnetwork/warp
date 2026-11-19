package services

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
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
	return "", fmt.Errorf("config file %q not found beneath %s", name, configDir)
}

// LoadServicesConfigFrom reads and parses the services config for env out of vaultDir.
func LoadServicesConfigFrom(vaultDir string, env string) (*ServicesConfig, error) {
	servicesConfigPath := resolveVaultPath(vaultDir, env, "services.yml")
	data, err := os.ReadFile(servicesConfigPath)
	if err != nil {
		return nil, err
	}

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

	requestBodySettings := DefaultRequestBodySettings()
	lbAltVersions := lbAltDeclaringVersions(&servicesConfig)
	for versionIndex, version := range servicesConfig.Versions {
		if err := validateTransparentInterfaces(version); err != nil {
			return nil, fmt.Errorf("services config %s version %d: %w", servicesConfigPath, versionIndex, err)
		}
		if err := validateForwardPorts(version); err != nil {
			return nil, fmt.Errorf("services config %s version %d: %w", servicesConfigPath, versionIndex, err)
		}
		if err := validateLbAlt(version, env); err != nil {
			return nil, fmt.Errorf("services config %s version %d: %w", servicesConfigPath, versionIndex, err)
		}
		if err := validateLbAltTlsServicePort(version, lbAltVersions); err != nil {
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
			if err := ValidateNoSuccessAccessLog(serviceConfig); err != nil {
				return nil, fmt.Errorf("services config %s version %d: service %q: %w", servicesConfigPath, versionIndex, service, err)
			}
			if err := ValidateRouteRequestBodies(serviceConfig, requestBodySettings); err != nil {
				return nil, fmt.Errorf("services config %s version %d: service %q: %w", servicesConfigPath, versionIndex, service, err)
			}
			if err := validateBlockOverrides(serviceConfig); err != nil {
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
	if err := validatePortBlockLbTypes(&servicesConfig); err != nil {
		return nil, fmt.Errorf("services config %s: %w", servicesConfigPath, err)
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

// Checks that a transparent interface sets none of the lb front settings. No
// lb runs on a transparent interface (LbBlock.Transparent), so such a setting
// would apply to nothing. The forced external ports and the stream port
// services would also still take ports from the allocation.
func validateTransparentInterfaces(version *ServicesConfigVersion) error {
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
			if lbBlock == nil || !lbBlock.Transparent {
				continue
			}
			frontSettings := []struct {
				name string
				set  bool
			}{
				{"cores", lbBlock.Cores != 0},
				{"concurrent_clients", lbBlock.ConcurrentClients != 0},
				{"expected_connections_per_client", lbBlock.ExpectedConnectionsPerClient != 0},
				{"rate_limit", lbBlock.RateLimit != nil},
				{"keepalive", lbBlock.Keepalive != nil},
				{"dns_weight", lbBlock.DnsWeight != 0},
				{"external_ports", 0 < len(lbBlock.ExternalPorts)},
				{"tcp_stream_port_services", 0 < len(lbBlock.TcpStreamPortServices)},
				{"udp_stream_port_services", 0 < len(lbBlock.UdpStreamPortServices)},
				{"lb_alt", lbBlock.LbAlt != nil},
			}
			for _, frontSetting := range frontSettings {
				if frontSetting.set {
					return fmt.Errorf("%s %s is transparent, so no lb runs on it, but it sets the lb setting %s", host, interfaceName, frontSetting.name)
				}
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

// Checks the lb_alt setting (server/LBALT.md D2 and D4). One service may
// declare it, and only connect. An interface may override it, but not a
// transparent interface, and may turn it on only when a service declares it.
// On each interface where lb_alt is in effect (IsLbAltInterface):
//   - the lb_alt service is placed on the host, with blocks weighted so the
//     split can give each positive weight a bucket (LbAltBucketBlocks);
//   - no tcp stream is mapped, no udp stream is mapped to another service,
//     and the lb_alt service declares no tcp stream port, since lb_alt
//     forwards no streams;
//   - no other service claims one of its public udp ports (LbAltPublicPorts)
//     on the host, as an external udp port or an external udp forward port;
//   - each of its public ports is a row of LbAltPublicPortTable, since no
//     connect socket serves any other.
//
// And beyond single interfaces, on a host where lb_alt is enabled
// (IsLbAltHost), whose connect blocks write a chain on each of its
// non-transparent lb interfaces:
//   - no lb interface name holds a '-': the split's chain names,
//     WARP-<ENV>-LBA-<IFACE>-<BLOCK>, are split on it;
//   - each block chain name, for env, fits iptables' lbAltChainNameLimit, so
//     the shorter split and lb chain names fit too. warpctl resolves the
//     names only when a block promotes or an lb unit reconciles, and a name
//     over the limit would leave every connect block of the host with a
//     promotion that never completes;
//   - the interfaces give a service that sets no keepalive of its own the
//     same keepalive as nginx applies it (Keepalive.Resolve, which the route
//     render compares by too, so 15m and 900s are one time), when the
//     service has tcp port 80 and is placed on the host: the route file
//     holds one keepalive per service, so connect's route render would fail
//     on the host, and no connect generation could start there.
//
// And no service is named lba or lbt, or starts with either and a '-', whose
// block chains would be named like an interface's split chain or like the
// split's block chains.
//
// The lb_alt service's tcp port 443 is checked across versions, by
// validateLbAltTlsServicePort.
//
// An override to false on a front interface is never refused, so the rollback
// edit always loads. The lb front settings (cores, rate_limit, dns_weight,
// keepalive and the rest) stay allowed on an lb_alt interface, since a
// rollback puts them back in use, and the front and DNS read some of them.
func validateLbAlt(version *ServicesConfigVersion, env string) error {
	if version == nil {
		return nil
	}
	services := maps.Keys(version.Services)
	sort.Strings(services)
	for _, service := range services {
		name := strings.ToLower(service)
		for _, token := range []string{lbAltSplitChainToken, lbAltReplacementSplitChainToken} {
			if name == token || strings.HasPrefix(name, token+"-") {
				return fmt.Errorf("service %q is named like the lb_alt split chains (%s or %s, alone or before a '-'); its block chains would be taken for an interface's split chain or the split's block chains", service, lbAltSplitChainToken, lbAltReplacementSplitChainToken)
			}
		}
	}
	declaringServices := lbAltDeclaringServices(version)
	if 1 < len(declaringServices) {
		return fmt.Errorf("services %q and %q both declare lb_alt, but one service fronts the lb_alt interfaces", declaringServices[0], declaringServices[1])
	}
	lbAltService, declared := LbAltService(version)
	if declared && lbAltService != lbAltConnectService {
		return fmt.Errorf("service %q declares lb_alt, but only %s may front the lb interfaces", lbAltService, lbAltConnectService)
	}
	if version.Lb == nil {
		return nil
	}

	hosts := maps.Keys(version.Lb.Interfaces)
	sort.Strings(hosts)
	for _, host := range hosts {
		interfaceNames := maps.Keys(version.Lb.Interfaces[host])
		sort.Strings(interfaceNames)
		lbAltHost := IsLbAltHost(version, host)
		for _, interfaceName := range interfaceNames {
			if lbAltHost && strings.Contains(interfaceName, "-") {
				return fmt.Errorf("%s %s: lb_alt is enabled on %s, whose lb interface names must hold no '-', since the lb_alt chain names split on it", host, interfaceName, host)
			}
			lbBlock := version.Lb.Interfaces[host][interfaceName]
			if lbBlock == nil || lbBlock.LbAlt == nil {
				continue
			}
			if lbBlock.Transparent {
				return fmt.Errorf("%s %s is transparent, so no lb runs on it, but it sets lb_alt", host, interfaceName)
			}
			if *lbBlock.LbAlt && !declared {
				return fmt.Errorf("%s %s sets lb_alt: true, but no service declares lb_alt", host, interfaceName)
			}
		}
		if !lbAltHost {
			continue
		}

		// the chains connect's blocks write, one per block on each front
		// interface, as warpctl names them; an interface's split and lb
		// chains are shorter than any of its block chains
		frontInterfaceNames := LbInterfaceNames(version, host)
		for _, interfaceName := range frontInterfaceNames {
			for _, blockWeight := range ServiceBlockWeights(version.Services[lbAltService]) {
				chain := strings.ToUpper(fmt.Sprintf("WARP-%s-%s-%s-%s", env, lbAltSplitChainToken, interfaceName, blockWeight.Block))
				if lbAltChainNameLimit < len(chain) {
					return fmt.Errorf("%s %s: lb_alt is enabled on %s, and block %s of %q would write the chain %s there, over iptables' %d characters; shorten the interface or block name", host, interfaceName, host, blockWeight.Block, lbAltService, chain, lbAltChainNameLimit)
				}
			}
		}

		// The keepalive an interface gives a service with none of its own, as
		// nginx resolves it per interface: the interface's, else
		// DefaultKeepalive. The route file holds one per service (warpctl's
		// renderLbAltRouteTable), for the services nginx would front on the
		// host, those of host_services or else every service that includes
		// the host, with tcp port 80.
		interfaceKeepalive := func(interfaceName string) *Keepalive {
			if lbBlock := version.Lb.Interfaces[host][interfaceName]; lbBlock != nil && lbBlock.Keepalive != nil {
				return lbBlock.Keepalive
			}
			return DefaultKeepalive()
		}
		// Whether two interfaces' keepalives are one as nginx applies them
		// (Keepalive.Resolve), the comparison of the route render: 2m and
		// 120s are one time, and every keepalive without connections is
		// none. Keepalives whose times do not resolve are compared as
		// written, since the route render refuses them whatever the other
		// interfaces give, as nginx does.
		sameKeepalive := func(keepalive *Keepalive, otherKeepalive *Keepalive) bool {
			resolvedKeepalive, err := keepalive.Resolve()
			otherResolvedKeepalive, otherErr := otherKeepalive.Resolve()
			if err == nil && otherErr == nil {
				return resolvedKeepalive == otherResolvedKeepalive
			}
			return *keepalive == *otherKeepalive
		}
		hostServices, listed := version.HostServices[host]
		if !listed {
			hostServices = []string{}
			for service, serviceConfig := range version.Services {
				if serviceConfig != nil && serviceConfig.IncludesHost(host) {
					hostServices = append(hostServices, service)
				}
			}
		}
		hostServices = slices.Sorted(slices.Values(hostServices))
		// an lb_alt host has a front interface (IsLbAltHost)
		for _, interfaceName := range frontInterfaceNames[1:] {
			if sameKeepalive(interfaceKeepalive(interfaceName), interfaceKeepalive(frontInterfaceNames[0])) {
				continue
			}
			for _, service := range hostServices {
				serviceConfig := version.Services[service]
				if serviceConfig == nil || serviceConfig.Keepalive != nil || !slices.Contains(serviceConfig.TcpPorts(), LbAltHttpServicePort) {
					continue
				}
				return fmt.Errorf("%s: lb_alt is enabled on %s, and its lb interfaces %s and %s give service %q, which sets no keepalive of its own, different keepalives; the lb_alt route file holds one per service", host, host, frontInterfaceNames[0], interfaceName, service)
			}
		}
	}

	hostInterfaceNames := LbAltInterfaces(version)
	if len(hostInterfaceNames) == 0 {
		return nil
	}
	// lb_alt is in effect somewhere, so a service declares it
	serviceConfig := version.Services[lbAltService]
	serviceHosts := HostsForService(version, lbAltService)
	_, splitErr := LbAltBucketBlocks(ServiceBlockWeights(serviceConfig), LbAltBucketCount)
	tcpStreamPorts := serviceConfig.StreamTcpPorts()

	otherServices := []string{}
	otherServiceHosts := map[string][]string{}
	for service, otherServiceConfig := range version.Services {
		if service == lbAltService || otherServiceConfig == nil {
			continue
		}
		otherServices = append(otherServices, service)
		otherServiceHosts[service] = HostsForService(version, service)
	}
	sort.Strings(otherServices)

	lbAltHosts := maps.Keys(hostInterfaceNames)
	sort.Strings(lbAltHosts)
	for _, host := range lbAltHosts {
		for _, interfaceName := range hostInterfaceNames[host] {
			if !slices.Contains(serviceHosts, host) {
				return fmt.Errorf("%s %s is lb_alt, but the lb_alt service %q is not placed on %s", host, interfaceName, lbAltService, host)
			}
			if splitErr != nil {
				return fmt.Errorf("%s %s is lb_alt, but the blocks of the lb_alt service %q cannot split its clients: %w", host, interfaceName, lbAltService, splitErr)
			}
			if 0 < len(tcpStreamPorts) {
				return fmt.Errorf("%s %s is lb_alt, but the lb_alt service %q declares the tcp stream ports %v, and lb_alt forwards no tcp stream", host, interfaceName, lbAltService, tcpStreamPorts)
			}

			effectivePortServices := EffectivePortServices(version.Lb, version.Lb.Interfaces[host][interfaceName])
			tcpPorts := maps.Keys(effectivePortServices["tcp"])
			sort.Ints(tcpPorts)
			if 0 < len(tcpPorts) {
				return fmt.Errorf("%s %s is lb_alt, but it maps the tcp stream port %d to %q, and lb_alt forwards no tcp stream", host, interfaceName, tcpPorts[0], effectivePortServices["tcp"][tcpPorts[0]])
			}
			udpPorts := maps.Keys(effectivePortServices["udp"])
			sort.Ints(udpPorts)
			for _, port := range udpPorts {
				if service := effectivePortServices["udp"][port]; service != lbAltService {
					return fmt.Errorf("%s %s is lb_alt, but it maps the udp stream port %d to %q, and only the lb_alt service %q serves udp there", host, interfaceName, port, service, lbAltService)
				}
			}

			publicPorts := LbAltPublicPorts(version, host, interfaceName)
			for _, protocol := range []string{"tcp", "udp"} {
				for _, publicPort := range publicPorts[protocol] {
					if _, ok := LbAltPublicPortServicePort(protocol, publicPort); !ok {
						return fmt.Errorf("%s %s is lb_alt, but it would publish the %s port %d, which no connect socket serves; an lb_alt interface publishes only tcp 80 and 443, and udp 443, 4053 and 53", host, interfaceName, protocol, publicPort)
					}
				}
			}

			for _, publicPort := range publicPorts["udp"] {
				for _, otherService := range otherServices {
					if !slices.Contains(otherServiceHosts[otherService], host) {
						continue
					}
					otherServiceConfig := version.Services[otherService]
					if slices.Contains(otherServiceConfig.ExternalUdpPorts, publicPort) {
						return fmt.Errorf("%s %s is lb_alt and publishes the udp port %d, which service %q also claims on %s as an external udp port", host, interfaceName, publicPort, otherService, host)
					}
					if _, claimed := otherServiceConfig.ExternalUdpForwardPorts[publicPort]; claimed {
						return fmt.Errorf("%s %s is lb_alt and publishes the udp port %d, which service %q also claims on %s as an external udp forward port", host, interfaceName, publicPort, otherService, host)
					}
				}
			}
		}
	}
	return nil
}

// The services that declare lb_alt, true or false, in any version of the
// file, each with the newest version that does.
func lbAltDeclaringVersions(servicesConfig *ServicesConfig) map[string]int {
	serviceVersions := map[string]int{}
	for versionIndex, version := range servicesConfig.Versions {
		for _, service := range lbAltDeclaringServices(version) {
			if _, ok := serviceVersions[service]; !ok {
				serviceVersions[service] = versionIndex
			}
		}
	}
	return serviceVersions
}

// Checks, in one version, the tcp port 443 of each service that declares
// lb_alt in any version of the file (lbAltDeclaringVersions). The lb_alt
// front's tls socket takes service port 443 on tcp, which warpctl allocates
// with an lb type of its own, beside quic on udp. warpctl allocates a
// service's ports from every version of the file and keeps one lb type for a
// port across them, so the service may not list 443 as an http port or a tcp
// stream port in any version, whether or not that version declares lb_alt.
// The file would load, and then every port allocation and route render would
// fail on it.
func validateLbAltTlsServicePort(version *ServicesConfigVersion, lbAltVersions map[string]int) error {
	if version == nil {
		return nil
	}
	lbAltServices := maps.Keys(lbAltVersions)
	sort.Strings(lbAltServices)
	for _, service := range lbAltServices {
		serviceConfig := version.Services[service]
		if serviceConfig == nil {
			continue
		}
		servicePortLists := []struct {
			kind  string
			ports []int
		}{
			{kind: "http", ports: serviceConfig.HttpTcpPorts()},
			{kind: "tcp stream", ports: serviceConfig.StreamTcpPorts()},
		}
		for _, servicePortList := range servicePortLists {
			if slices.Contains(servicePortList.ports, LbAltHttpsServicePort) {
				return fmt.Errorf(
					"service %q lists the %s port %d, which the tls socket of its lb_alt front takes; version %d declares lb_alt for it, and warpctl keeps one lb type for a service port across every version",
					service,
					servicePortList.kind,
					LbAltHttpsServicePort,
					lbAltVersions[service],
				)
			}
		}
	}
	return nil
}

// Checks that each port of warpctl's port allocation keeps one lb type, in
// each version and across them. warpctl allocates, from every version, oldest
// first, a port block for each lb interface's ports and each service block's
// ports, and keeps a block's external and internal ports, and the port's lb
// type for each of tcp and udp, across versions (portBlocksOf): http, stream,
// external, or the lb_alt service's tls port. It panics on a port whose lb
// type would change, and such a file loaded before: units, the nginx and VyOS
// configs, the lb readiness poll and every lb_alt route render panicked.
//
// A port block belongs to one lb interface or one service block, so a port may
// take another lb type on a block the other versions do not list. The lb_alt
// service's tcp 443 is refused more broadly, and first, by
// validateLbAltTlsServicePort.
func validatePortBlockLbTypes(servicesConfig *ServicesConfig) error {
	const (
		httpLbType     = "an http port"
		streamLbType   = "a stream port"
		externalLbType = "an external port"
		lbAltTlsLbType = "the lb_alt front's tls port"
	)
	// a port of one port block, keyed as warpctl keys its port blocks: an lb
	// interface's by its host and interface, a service's by its service and
	// block alone
	type portBlockPort struct {
		host     string
		service  string
		block    string
		portType string
		port     int
	}
	type portBlockLbType struct {
		lbType       string
		versionIndex int
	}
	// the ports a service block lists of one port type and lb type
	type servicePortList struct {
		portType string
		ports    []int
		lbType   string
	}
	portBlockLbTypes := map[portBlockPort]portBlockLbType{}

	// oldest first, as warpctl allocates
	for versionIndex := len(servicesConfig.Versions) - 1; 0 <= versionIndex; versionIndex -= 1 {
		version := servicesConfig.Versions[versionIndex]
		if version == nil {
			continue
		}
		assign := func(owner string, port portBlockPort, lbType string) error {
			assigned, ok := portBlockLbTypes[port]
			if !ok {
				portBlockLbTypes[port] = portBlockLbType{lbType: lbType, versionIndex: versionIndex}
				return nil
			}
			if assigned.lbType == lbType {
				return nil
			}
			if assigned.versionIndex == versionIndex {
				return fmt.Errorf(
					"%s lists the %s port %d as both %s and %s in version %d, and warpctl gives a port one lb type",
					owner,
					port.portType,
					port.port,
					assigned.lbType,
					lbType,
					versionIndex,
				)
			}
			return fmt.Errorf(
				"%s lists the %s port %d as %s in version %d and as %s in version %d, and warpctl keeps one lb type for a port across every version of the file",
				owner,
				port.portType,
				port.port,
				assigned.lbType,
				assigned.versionIndex,
				lbType,
				versionIndex,
			)
		}

		if lb := version.Lb; lb != nil {
			hosts := maps.Keys(lb.Interfaces)
			sort.Strings(hosts)
			for _, host := range hosts {
				interfaceNames := maps.Keys(lb.Interfaces[host])
				sort.Strings(interfaceNames)
				for _, interfaceName := range interfaceNames {
					owner := fmt.Sprintf("lb interface %s %s", host, interfaceName)
					block := fmt.Sprintf("%s-%s", host, interfaceName)
					for _, port := range lb.HttpTcpPorts() {
						if err := assign(owner, portBlockPort{host: host, service: "lb", block: block, portType: "tcp", port: port}, httpLbType); err != nil {
							return err
						}
					}
					// the lb's stream ports and the stream port services in
					// effect on the interface, as warpctl merges them
					streamPorts := lb.AllStreamPorts()
					for portType, portServices := range EffectivePortServices(lb, lb.Interfaces[host][interfaceName]) {
						for port := range portServices {
							if !slices.Contains(streamPorts[portType], port) {
								streamPorts[portType] = append(streamPorts[portType], port)
							}
						}
					}
					portTypes := maps.Keys(streamPorts)
					sort.Strings(portTypes)
					for _, portType := range portTypes {
						ports := slices.Sorted(slices.Values(streamPorts[portType]))
						for _, port := range ports {
							if err := assign(owner, portBlockPort{host: host, service: "lb", block: block, portType: portType, port: port}, streamLbType); err != nil {
								return err
							}
						}
					}
				}
			}
		}

		lbAltService, lbAltDeclared := LbAltService(version)
		services := maps.Keys(version.Services)
		sort.Strings(services)
		for _, service := range services {
			serviceConfig := version.Services[service]
			if serviceConfig == nil {
				continue
			}
			blocks := []string{}
			for _, blockWeights := range serviceConfig.Blocks {
				for block := range blockWeights {
					if !slices.Contains(blocks, block) {
						blocks = append(blocks, block)
					}
				}
			}
			sort.Strings(blocks)
			servicePortLists := []servicePortList{
				{portType: "tcp", ports: serviceConfig.HttpTcpPorts(), lbType: httpLbType},
				{portType: "tcp", ports: serviceConfig.StreamTcpPorts(), lbType: streamLbType},
				{portType: "udp", ports: serviceConfig.StreamUdpPorts(), lbType: streamLbType},
				{portType: "udp", ports: serviceConfig.ExternalUdpPorts, lbType: externalLbType},
			}
			if lbAltDeclared && lbAltService == service {
				servicePortLists = append(servicePortLists, servicePortList{portType: "tcp", ports: []int{LbAltHttpsServicePort}, lbType: lbAltTlsLbType})
			}
			for _, block := range blocks {
				owner := fmt.Sprintf("service %q block %q", service, block)
				for _, servicePortList := range servicePortLists {
					for _, port := range servicePortList.ports {
						if err := assign(owner, portBlockPort{service: service, block: block, portType: servicePortList.portType, port: port}, servicePortList.lbType); err != nil {
							return err
						}
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
