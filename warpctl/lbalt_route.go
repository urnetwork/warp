package main

// Rendering and writing the lb_alt route file (server/LBALT-IMPL.md §2.1, §2.2,
// §5; LBALT.md D5). A connect worker on an lb_alt host renders the file when it
// starts a generation, from the same services.yml inputs and functions the nginx
// generator uses, writes it once under WARP_HOME with mode 0444, and bind-mounts
// it read-only into the container. The file is removed with its container.
//
// The renderer runs the nginx generator's own helpers for the host it renders:
// NginxConfig.services, serviceHosts, lbHosts, the route prefixes,
// httpPortBlocks, routeRateLimits and noSuccessAccessLogs. So an interface's lb
// config and the route file can't disagree about what is fronted, by which
// names, or on which block ports. What the generator leaves to nginx's own
// defaults or to its inline code is resolved here, so connect applies no
// services.yml default:
//   - DefaultRateLimit for an interface without one;
//   - a requests_per_second rate as a minute rate;
//   - the server-wide request body settings for a value a route leaves unset;
//   - the keepalive fallback, service then interface then DefaultKeepalive,
//     with nginx's time strings as seconds.
//
// Every list is in its contract order, so the bytes, and with them the
// revision, depend only on the inputs. The renderer then checks the table
// against the rules connect's strict parser enforces (§5), so a table connect
// would refuse fails the render, before the generation starts. No error carries
// a route prefix, which is secret.
//
// Owner: unit w-route.

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode"

	"github.com/urnetwork/warp/services"
)

// The service ports a connect generation's WARP_PORTS maps to its listen ports
// (§2.1 listen): 80 to the port-80 front, 443 to both the tls front and quic,
// and 4053 to whodis. Service port 80 is also the http port nginx proxies, so
// each block's upstream port is its external port for it.
const (
	lbAltHttpServicePort   = 80
	lbAltHttpsServicePort  = 443
	lbAltWhodisServicePort = 4053
)

// The service whose names the front forwards and also admits on h3 and whodis
// (front.api_service).
const lbAltApiService = "api"

// The whodis tld connect's trusted h3dns listener decodes today, hard-coded in
// the server repo's connect/transport.go. A route file whose inputs name no
// whodis tld carries it, so the front decodes what that listener does.
const lbAltDefaultWhodisTld = "ur.xyz."

// The mode of a generation's route directory. The route file holds the lb's
// hidden route prefixes, so only the worker that writes it, and docker, which
// bind-mounts it, look inside. The file itself is world-readable
// (lbAltRouteFileMode) so the container's user can read it at the mount.
const lbAltRouteDirMode = 0700

// DNS bounds on a whole name and on each of its labels, in bytes, as connect's
// parser applies them to the route file's names.
const (
	lbAltRouteMaxNameBytes  = 253
	lbAltRouteMaxLabelBytes = 63
)

// One lb interface of the host as the worker sees it when it starts a connect
// generation: its name, whether lb_alt is effective on it (informational for
// connect), and its docker network's bridge addresses. An empty address means
// the family is absent.
type lbAltRouteInterfaceInput struct {
	name  string
	lbAlt bool
	ipv4  string
	ipv6  string
}

// What a worker knows when it starts a connect generation on an lb_alt host.
type lbAltRouteInputs struct {
	// versions[0] of this is what is rendered
	servicesConfig *services.ServicesConfig
	env            string
	host           string
	// the container name of the generation, also its generation id
	generation string
	// every non-transparent lb interface on the host, as --lbaltnets lists them
	interfaces []lbAltRouteInterfaceInput
	// this generation's WARP_PORTS: service port -> internal port
	servicePorts map[int]int
	// the warpservices bridge address the upstream blocks listen on
	upstreamIpv4 string
	// the whodis tlds the config names, each ending in "."; none renders
	// connect's current one, lbAltDefaultWhodisTld
	whodisTlds []string
}

// Renders the generation's route table. It fails, and the generation does not
// start, if any input is missing or the table would not validate on the server.
//
// The interfaces must be exactly the host's non-transparent lb interfaces
// (services.LbInterfaceNames), each with a bridge address, and WARP_PORTS
// must map service ports 80, 443 and 4053. The block ports come from
// getPortBlocks for inputs.env, which reads the env's services.yml from the
// vault, as NewNginxConfig does. The production lb image is built without env
// aliases (`warpctl lb create-config <env>`), so the names carry none either.
func renderLbAltRouteTable(inputs *lbAltRouteInputs) (*LbAltRouteTable, error) {
	if inputs == nil {
		return nil, errors.New("lbalt route: no inputs")
	}
	servicesConfig := inputs.servicesConfig
	if servicesConfig == nil || len(servicesConfig.Versions) == 0 || servicesConfig.Versions[0] == nil {
		return nil, errors.New("lbalt route: no services config")
	}
	version := servicesConfig.Versions[0]
	if version.Lb == nil {
		return nil, errors.New("lbalt route: the services config has no lb")
	}
	connectService, ok := services.LbAltService(version)
	if !ok {
		return nil, errors.New("lbalt route: no single service declares lb_alt")
	}

	listenPort := func(servicePort int) (int, error) {
		internalPort, ok := inputs.servicePorts[servicePort]
		if !ok {
			return 0, fmt.Errorf("lbalt route: WARP_PORTS has no internal port for service port %d", servicePort)
		}
		return internalPort, nil
	}
	httpPort, err := listenPort(lbAltHttpServicePort)
	if err != nil {
		return nil, err
	}
	httpsPort, err := listenPort(lbAltHttpsServicePort)
	if err != nil {
		return nil, err
	}
	whodisPort, err := listenPort(lbAltWhodisServicePort)
	if err != nil {
		return nil, err
	}

	// an address of one family as netip writes it, which is how connect reports
	// its sockets (X-UR-Front-Sockets); empty stays empty
	canonicalAddr := func(name string, value string, ipv6 bool) (string, error) {
		if value == "" {
			return "", nil
		}
		family := "ipv4"
		if ipv6 {
			family = "ipv6"
		}
		addr, err := netip.ParseAddr(value)
		if err != nil || addr.Zone() != "" || (ipv6 && (!addr.Is6() || addr.Is4In6())) || (!ipv6 && !addr.Is4()) {
			return "", fmt.Errorf("lbalt route: %s %q is not an %s address", name, value, family)
		}
		return addr.String(), nil
	}
	upstreamIpv4, err := canonicalAddr("the services bridge", inputs.upstreamIpv4, false)
	if err != nil {
		return nil, err
	}
	if upstreamIpv4 == "" {
		return nil, errors.New("lbalt route: the services bridge has no ipv4 address")
	}

	// a minute rate from a per-second one, as nginx's r/s is the same limit
	minuteSeconds := float64(time.Minute / time.Second)

	interfaceNames := services.LbInterfaceNames(version, inputs.host)
	if len(interfaceNames) == 0 {
		return nil, fmt.Errorf("lbalt route: %s has no non-transparent lb interface", inputs.host)
	}
	lbBlocks := version.Lb.Interfaces[inputs.host]
	inputInterfaces := map[string]lbAltRouteInterfaceInput{}
	for _, inputInterface := range inputs.interfaces {
		if _, ok := inputInterfaces[inputInterface.name]; ok {
			return nil, fmt.Errorf("lbalt route: interface %q is given twice", inputInterface.name)
		}
		if !slices.Contains(interfaceNames, inputInterface.name) {
			return nil, fmt.Errorf("lbalt route: %q is not a non-transparent lb interface of %s", inputInterface.name, inputs.host)
		}
		inputInterfaces[inputInterface.name] = inputInterface
	}
	routeInterfaces := []LbAltRouteInterface{}
	for _, interfaceName := range interfaceNames {
		inputInterface, ok := inputInterfaces[interfaceName]
		if !ok {
			return nil, fmt.Errorf("lbalt route: the inputs leave out lb interface %s of %s and its bridge", interfaceName, inputs.host)
		}
		ipv4, err := canonicalAddr(interfaceName+" bridge", inputInterface.ipv4, false)
		if err != nil {
			return nil, err
		}
		ipv6, err := canonicalAddr(interfaceName+" bridge", inputInterface.ipv6, true)
		if err != nil {
			return nil, err
		}
		if ipv4 == "" && ipv6 == "" {
			return nil, fmt.Errorf("lbalt route: lb interface %s of %s has no bridge address", interfaceName, inputs.host)
		}

		// nginx's shared zones of the interface (addRateLimits): the rate is
		// requests_per_minute when set, else requests_per_second, else there
		// is no request limit and so no burst; a burst or connection cap that
		// is not positive is none
		rateLimit := services.DefaultRateLimit()
		if lbBlock := lbBlocks[interfaceName]; lbBlock != nil {
			rateLimit = lbBlock.GetRateLimit()
		}
		routeRateLimit := LbAltRouteRateLimit{
			RequestsPerMinute: 0,
			Burst:             0,
			NetConnections:    max(rateLimit.NetConnections, 0),
			ExcludeSubnets:    []string{},
		}
		if 0 < rateLimit.RequestsPerMinute {
			routeRateLimit.RequestsPerMinute = float64(rateLimit.RequestsPerMinute)
			routeRateLimit.Burst = max(rateLimit.Burst, 0)
		} else if 0 < rateLimit.RequestsPerSecond {
			routeRateLimit.RequestsPerMinute = float64(rateLimit.RequestsPerSecond) * minuteSeconds
			routeRateLimit.Burst = max(rateLimit.Burst, 0)
		}
		for _, excludeSubnet := range rateLimit.ExcludeSubnets {
			// as RateLimit.ExcludePrefixes writes it into nginx's geo, with a
			// refusal in place of its panic
			prefix, err := netip.ParsePrefix(excludeSubnet)
			if err != nil {
				return nil, fmt.Errorf("lbalt route: lb interface %s of %s excludes %q, which is not a cidr prefix", interfaceName, inputs.host, excludeSubnet)
			}
			routeRateLimit.ExcludeSubnets = append(routeRateLimit.ExcludeSubnets, prefix.String())
		}
		routeRateLimit.ExcludeSubnets = lbAltSortedUnique(routeRateLimit.ExcludeSubnets)

		routeInterfaces = append(routeInterfaces, LbAltRouteInterface{
			Name:      interfaceName,
			Block:     fmt.Sprintf("%s-%s", inputs.host, interfaceName),
			LbAlt:     inputInterface.lbAlt,
			Ipv4:      ipv4,
			Ipv6:      ipv6,
			RateLimit: routeRateLimit,
		})
	}

	// the nginx generator's view of one interface of the host. The helpers
	// called below read only its services config, env, host and port blocks.
	nginxConfig := &NginxConfig{
		env:                 inputs.env,
		servicesConfig:      servicesConfig,
		portBlocks:          getPortBlocks(inputs.env),
		requestBodySettings: services.DefaultRequestBodySettings(),
		lbBlockInfo: &BlockInfo{
			service: "lb",
			host:    inputs.host,
		},
	}
	// the helpers below read the config of every service the host fronts
	frontedServices := nginxConfig.services()
	for _, service := range frontedServices {
		if version.Services[service] == nil {
			return nil, fmt.Errorf("lbalt route: %s fronts service %q, which the services config does not define", inputs.host, service)
		}
	}
	httpPortBlocks := nginxConfig.httpPortBlocks()
	serviceRouteRateLimits := nginxConfig.routeRateLimits()
	serviceNoSuccessAccessLogs := nginxConfig.noSuccessAccessLogs()
	// nginx serves a service's names on port 80, with a 301, and on 443
	lbHttpPorts := version.Lb.HttpTcpPorts()
	lbServesNames := slices.Contains(lbHttpPorts, lbAltHttpServicePort) || slices.Contains(lbHttpPorts, lbAltHttpsServicePort)

	// a time nginx reads as keepalive_time or keepalive_timeout, in seconds
	keepaliveSeconds := func(service string, name string, value string) (int, error) {
		seconds, err := parseNginxTimeSeconds(value)
		if err != nil {
			return 0, fmt.Errorf("lbalt route: service %q %s: %w", service, name, err)
		}
		return seconds, nil
	}
	// nginx resolves an upstream's keepalive per interface: the service's
	// own, else the interface's, else DefaultKeepalive, and renders none for
	// connections 0 (addUpstreamBlocks). The table holds one per service, so
	// every interface of the host must resolve the same one.
	resolveKeepalive := func(service string, serviceConfig *services.ServiceConfig) (LbAltRouteKeepalive, error) {
		keepalives := []LbAltRouteKeepalive{}
		for _, interfaceName := range interfaceNames {
			keepalive := serviceConfig.Keepalive
			if keepalive == nil {
				if lbBlock := lbBlocks[interfaceName]; lbBlock != nil {
					keepalive = lbBlock.Keepalive
				}
				if keepalive == nil {
					keepalive = services.DefaultKeepalive()
				}
			}
			routeKeepalive := LbAltRouteKeepalive{
				Connections:    0,
				Requests:       0,
				TimeSeconds:    0,
				TimeoutSeconds: 0,
			}
			if 0 < keepalive.Keepalive {
				timeSeconds, err := keepaliveSeconds(service, "keepalive_time", keepalive.KeepaliveTime)
				if err != nil {
					return routeKeepalive, err
				}
				timeoutSeconds, err := keepaliveSeconds(service, "keepalive_timeout", keepalive.KeepaliveTimeout)
				if err != nil {
					return routeKeepalive, err
				}
				routeKeepalive = LbAltRouteKeepalive{
					Connections:    keepalive.Keepalive,
					Requests:       keepalive.KeepaliveRequests,
					TimeSeconds:    timeSeconds,
					TimeoutSeconds: timeoutSeconds,
				}
			}
			if 0 < len(keepalives) && routeKeepalive != keepalives[0] {
				return routeKeepalive, fmt.Errorf(
					"lbalt route: service %q has no keepalive of its own, and lb interfaces %s and %s of %s give it different ones; the route file holds one per service",
					service,
					interfaceNames[0],
					interfaceName,
					inputs.host,
				)
			}
			keepalives = append(keepalives, routeKeepalive)
		}
		return keepalives[0], nil
	}

	routeServices := []LbAltRouteService{}
	for _, service := range frontedServices {
		serviceConfig := version.Services[service]

		// nginx serves the names of a service it proxies over http
		// (addServiceBlocks). A redirect alias's server answers only its 301,
		// so its name moves out of names.
		names := []string{}
		redirectAliases := []LbAltRouteRedirectAlias{}
		if lbServesNames && serviceConfig.IsExposed() && slices.Contains(serviceConfig.HttpTcpPorts(), lbAltHttpServicePort) {
			for _, serviceHost := range nginxConfig.serviceHosts(service) {
				// nginx matches server names in lowercase
				name := strings.ToLower(serviceHost)
				if target, ok := serviceConfig.RedirectAliases[serviceHost]; ok {
					redirectAliases = append(redirectAliases, LbAltRouteRedirectAlias{
						Name:   name,
						Target: strings.ToLower(target),
					})
				} else {
					names = append(names, name)
				}
			}
		}
		slices.SortFunc(redirectAliases, func(a LbAltRouteRedirectAlias, b LbAltRouteRedirectAlias) int {
			return strings.Compare(a.Name, b.Name)
		})
		redirectAliases = slices.CompactFunc(redirectAliases, func(a LbAltRouteRedirectAlias, b LbAltRouteRedirectAlias) bool {
			return a.Name == b.Name
		})

		corsOrigins, err := version.ResolveCorsOrigins(service)
		if err != nil {
			return nil, fmt.Errorf("lbalt route: service %q: %w", service, err)
		}

		// the routes nginx limits in their own zone, on the service's names
		routeRateLimits := []LbAltRoutePathRateLimit{}
		for _, serviceRouteRateLimit := range serviceRouteRateLimits {
			if serviceRouteRateLimit.service != service {
				continue
			}
			routeRateLimit := serviceRouteRateLimit.routeRateLimit
			// as RouteRateLimit.NginxRate: requests_per_minute when set, else
			// requests_per_second
			requestsPerMinute := float64(routeRateLimit.RequestsPerMinute)
			if routeRateLimit.RequestsPerMinute <= 0 {
				requestsPerMinute = float64(routeRateLimit.RequestsPerSecond) * minuteSeconds
			}
			routeRateLimits = append(routeRateLimits, LbAltRoutePathRateLimit{
				Path:              routeRateLimit.Path,
				RequestsPerMinute: requestsPerMinute,
				Burst:             max(routeRateLimit.Burst, 0),
			})
		}
		slices.SortFunc(routeRateLimits, func(a LbAltRoutePathRateLimit, b LbAltRoutePathRateLimit) int {
			return strings.Compare(a.Path, b.Path)
		})
		routeRateLimits = slices.CompactFunc(routeRateLimits, func(a LbAltRoutePathRateLimit, b LbAltRoutePathRateLimit) bool {
			return a.Path == b.Path
		})

		// a value the entry leaves unset is the server-wide one, which nginx's
		// location inherits (addRouteRequestBody)
		routeRequestBodies := []LbAltRoutePathRequestBody{}
		for _, routeRequestBody := range serviceConfig.RouteRequestBodies {
			if routeRequestBody == nil {
				return nil, fmt.Errorf("lbalt route: service %q has an empty route_request_bodies entry", service)
			}
			clientBodyBufferSize, err := routeRequestBody.ClientBodyBufferSizeBytes()
			if err != nil {
				return nil, fmt.Errorf("lbalt route: service %q route request body %q: %w", service, routeRequestBody.Path, err)
			}
			if clientBodyBufferSize <= 0 {
				clientBodyBufferSize = nginxConfig.requestBodySettings.ClientBodyBufferSize
			}
			clientBodyTimeout, err := routeRequestBody.ClientBodyTimeoutDuration()
			if err != nil {
				return nil, fmt.Errorf("lbalt route: service %q route request body %q: %w", service, routeRequestBody.Path, err)
			}
			if clientBodyTimeout <= 0 {
				clientBodyTimeout = nginxConfig.requestBodySettings.ClientBodyTimeout
			}
			routeRequestBodies = append(routeRequestBodies, LbAltRoutePathRequestBody{
				Path:                     routeRequestBody.Path,
				ClientBodyBufferSize:     clientBodyBufferSize,
				ClientBodyTimeoutSeconds: int(clientBodyTimeout / time.Second),
			})
		}
		slices.SortFunc(routeRequestBodies, func(a LbAltRoutePathRequestBody, b LbAltRoutePathRequestBody) int {
			return strings.Compare(a.Path, b.Path)
		})
		routeRequestBodies = slices.CompactFunc(routeRequestBodies, func(a LbAltRoutePathRequestBody, b LbAltRoutePathRequestBody) bool {
			return a.Path == b.Path
		})

		// the paths nginx leaves unlogged on a 2xx, on the service's names
		noSuccessAccessLog := []string{}
		for _, serviceNoSuccessAccessLog := range serviceNoSuccessAccessLogs {
			if serviceNoSuccessAccessLog.service == service {
				noSuccessAccessLog = append(noSuccessAccessLog, serviceNoSuccessAccessLog.paths...)
			}
		}

		keepalive, err := resolveKeepalive(service, serviceConfig)
		if err != nil {
			return nil, err
		}

		// nginx's upstream of the service: each block's external port for
		// service port 80 (addUpstreamBlocks). A service without port 80 has
		// no upstream, and neither has any service on an lb without an http
		// port, whose http port blocks hold none of the services'.
		blocks := []LbAltRouteBlock{}
		if slices.Contains(serviceConfig.TcpPorts(), lbAltHttpServicePort) && 0 < len(httpPortBlocks[service]) {
			for _, blockWeight := range services.ServiceBlockWeights(serviceConfig) {
				portBlock, ok := httpPortBlocks[service][blockWeight.Block][lbAltHttpServicePort]
				if !ok {
					return nil, fmt.Errorf("lbalt route: service %q block %q has no external port for service port %d", service, blockWeight.Block, lbAltHttpServicePort)
				}
				blocks = append(blocks, LbAltRouteBlock{
					Name:   blockWeight.Block,
					Weight: blockWeight.Weight,
					Port:   portBlock.externalPort,
				})
			}
		}

		routeServices = append(routeServices, LbAltRouteService{
			Name:               service,
			Exposed:            serviceConfig.IsExposed(),
			LbExposed:          serviceConfig.IsLbExposed(),
			Status:             serviceConfig.GetStatusMode(),
			Names:              lbAltSortedUnique(names),
			RedirectAliases:    redirectAliases,
			CorsOrigins:        lbAltSortedUnique(corsOrigins),
			Websocket:          serviceConfig.IsWebsocket(),
			Streamable:         serviceConfig.IsStreamable(),
			StreamablePaths:    lbAltSortedUnique(serviceConfig.GetStreamablePaths()),
			Stateful:           serviceConfig.IsStateful(),
			RoutePrefixes:      lbAltSortedUnique(nginxConfig.getRoutePrefixes(service)),
			RouteRateLimits:    routeRateLimits,
			RouteRequestBodies: routeRequestBodies,
			NoSuccessAccessLog: lbAltSortedUnique(noSuccessAccessLog),
			Keepalive:          keepalive,
			Blocks:             blocks,
		})
	}

	// a no_access_log host the lb does not serve is most likely a misspelling,
	// which would leave the host that was meant logged; NewNginxConfig refuses
	// it too
	servedHostnames := map[string]bool{}
	for _, hostname := range servicesConfig.Hostnames(inputs.env, nil) {
		servedHostnames[strings.TrimSuffix(strings.ToLower(hostname), ".")] = true
	}
	noAccessLog := servicesConfig.NoAccessLogHosts()
	for _, hostname := range noAccessLog {
		if !servedHostnames[hostname] {
			return nil, fmt.Errorf("lbalt route: no_access_log names %s, which the lb does not serve", hostname)
		}
	}

	// the primary domain first, then the rest sorted, as DomainNames orders
	// them; the lb names follow the domains, so the first is the default server
	domains := []string{}
	for _, domain := range servicesConfig.DomainNames() {
		domains = append(domains, strings.ToLower(domain))
	}
	lbNames := []string{}
	for _, lbHost := range nginxConfig.lbHosts() {
		lbNames = append(lbNames, strings.ToLower(lbHost))
	}

	whodisTlds := lbAltSortedUnique(inputs.whodisTlds)
	if len(whodisTlds) == 0 {
		whodisTlds = []string{lbAltDefaultWhodisTld}
	}

	table := &LbAltRouteTable{
		SchemaVersion: LbAltRouteSchemaVersion,
		Env:           inputs.env,
		Host:          inputs.host,
		Generation:    inputs.generation,
		Domains:       domains,
		Upstream: LbAltRouteUpstream{
			Host: version.ServicesDockerNetwork,
			Ipv4: upstreamIpv4,
		},
		Lb: LbAltRouteLb{
			Names:         lbNames,
			RoutePrefixes: lbAltSortedUnique(nginxConfig.getLbRoutePrefixes()),
		},
		NoAccessLog: lbAltSortedUnique(noAccessLog),
		Interfaces:  routeInterfaces,
		Listen: LbAltRouteListen{
			HttpPort:   httpPort,
			HttpsPort:  httpsPort,
			QuicPort:   httpsPort,
			WhodisPort: whodisPort,
		},
		Front: LbAltRouteFront{
			ConnectService: connectService,
			ApiService:     lbAltApiService,
			WhodisTlds:     whodisTlds,
		},
		Services: routeServices,
	}
	if err := validateLbAltRouteTable(table); err != nil {
		return nil, err
	}
	return table, nil
}

// A sorted copy of values without repeats. Never nil, so an empty list encodes
// as [].
func lbAltSortedUnique(values []string) []string {
	sortedValues := slices.Clone(values)
	if sortedValues == nil {
		sortedValues = []string{}
	}
	slices.Sort(sortedValues)
	return slices.Compact(sortedValues)
}

// Checks the table against the rules connect's strict parser enforces (the
// server repo's nginx/route.go; LBALT-IMPL.md §5), so a table connect would
// refuse fails here, before its generation starts:
//   - identities (env, host, generation, the upstream network, interface,
//     block and service names) are letters, digits, '.', '-' and '_';
//   - names are lowercase dns labels, a service's and a redirect alias's may
//     lead with one wildcard label, and each served name appears once across
//     the lb names, the services' names and the redirect aliases;
//   - addresses are canonical and of their family, every interface has one,
//     and none is another interface's or the services bridge's;
//   - ports are 1-65535, http differs from https and quic from whodis, and
//     no two blocks share an upstream port;
//   - counts are not negative, a route's rate and body settings are positive;
//   - the required lists are not empty, and listed values do not repeat;
//   - the front names two different services of the table.
//
// A refusal names the field by its json path from the root, and never a route
// prefix, which is secret.
func validateLbAltRouteTable(table *LbAltRouteTable) error {
	if table == nil {
		return errors.New("lbalt route table is missing")
	}
	fieldErrorf := func(fieldPath string, format string, a ...any) error {
		return fmt.Errorf("lbalt route %s: %s", fieldPath, fmt.Sprintf(format, a...))
	}
	checkIdentity := func(fieldPath string, value string) error {
		if value == "" {
			return fieldErrorf(fieldPath, "must not be empty")
		}
		for _, r := range value {
			if !('a' <= r && r <= 'z' || 'A' <= r && r <= 'Z' || '0' <= r && r <= '9' || r == '.' || r == '-' || r == '_') {
				return fieldErrorf(fieldPath, "may hold only letters, digits, '.', '-' and '_' (got %q)", value)
			}
		}
		return nil
	}
	checkName := func(fieldPath string, name string, allowWildcard bool) error {
		exactName, wildcard := strings.CutPrefix(name, "*.")
		if wildcard && !allowWildcard {
			return fieldErrorf(fieldPath, "must be an exact name, not a wildcard (got %q)", name)
		}
		if exactName == "" {
			return fieldErrorf(fieldPath, "must name a host (got %q)", name)
		}
		if lbAltRouteMaxNameBytes < len(exactName) {
			return fieldErrorf(fieldPath, "must be at most %d bytes", lbAltRouteMaxNameBytes)
		}
		for _, label := range strings.Split(exactName, ".") {
			if label == "" {
				return fieldErrorf(fieldPath, "has an empty label (got %q)", name)
			}
			if lbAltRouteMaxLabelBytes < len(label) {
				return fieldErrorf(fieldPath, "has a label over %d bytes", lbAltRouteMaxLabelBytes)
			}
			for _, r := range label {
				if !('a' <= r && r <= 'z' || '0' <= r && r <= '9' || r == '-' || r == '_') {
					return fieldErrorf(fieldPath, "must be dot-separated labels of lowercase letters, digits, '-' and '_' (got %q)", name)
				}
			}
		}
		return nil
	}
	checkAddr := func(fieldPath string, value string, ipv6 bool) error {
		addr, err := netip.ParseAddr(value)
		if err != nil {
			return fieldErrorf(fieldPath, "must be an ip address (got %q)", value)
		}
		if ipv6 {
			if !addr.Is6() || addr.Is4In6() {
				return fieldErrorf(fieldPath, "must be an ipv6 address (got %q)", value)
			}
		} else if !addr.Is4() {
			return fieldErrorf(fieldPath, "must be an ipv4 address (got %q)", value)
		}
		if addr.Zone() != "" {
			return fieldErrorf(fieldPath, "must not carry a zone (got %q)", value)
		}
		if addr.String() != value {
			return fieldErrorf(fieldPath, "must be written %s (got %q)", addr.String(), value)
		}
		return nil
	}
	checkPort := func(fieldPath string, port int) error {
		if port < 1 || math.MaxUint16 < port {
			return fieldErrorf(fieldPath, "must be in 1-%d (got %d)", math.MaxUint16, port)
		}
		return nil
	}
	checkCount := func(fieldPath string, count int) error {
		if count < 0 {
			return fieldErrorf(fieldPath, "must not be negative (got %d)", count)
		}
		return nil
	}
	isSpaceOrControl := func(r rune) bool {
		return unicode.IsSpace(r) || unicode.IsControl(r)
	}
	checkPath := func(fieldPath string, routePath string) error {
		if !strings.HasPrefix(routePath, "/") {
			return fieldErrorf(fieldPath, "must start with / (got %q)", routePath)
		}
		if strings.ContainsFunc(routePath, isSpaceOrControl) {
			return fieldErrorf(fieldPath, "must not hold whitespace or control characters (got %q)", routePath)
		}
		return nil
	}
	// records the first field path of each value, to refuse a repeat; the
	// refusal names both fields and never the value, which may be secret
	newValuePaths := func() func(fieldPath string, value string) error {
		valuePaths := map[string]string{}
		return func(fieldPath string, value string) error {
			if firstPath, ok := valuePaths[value]; ok {
				return fieldErrorf(fieldPath, "duplicates %s", firstPath)
			}
			valuePaths[value] = fieldPath
			return nil
		}
	}
	checkUnique := func(fieldPath string, values []string) error {
		addValue := newValuePaths()
		for i, value := range values {
			if err := addValue(fmt.Sprintf("%s[%d]", fieldPath, i), value); err != nil {
				return err
			}
		}
		return nil
	}
	checkPrefixes := func(fieldPath string, routePrefixes []string) error {
		if len(routePrefixes) == 0 {
			return fieldErrorf(fieldPath, "must list at least one prefix, [\"\"] when there is none")
		}
		for i, routePrefix := range routePrefixes {
			if routePrefix != "" && !strings.HasPrefix(routePrefix, "/") {
				return fieldErrorf(fmt.Sprintf("%s[%d]", fieldPath, i), "must be empty or start with /")
			}
		}
		return checkUnique(fieldPath, routePrefixes)
	}

	if table.SchemaVersion != LbAltRouteSchemaVersion {
		return fieldErrorf("schema_version", "must be %d", LbAltRouteSchemaVersion)
	}
	identities := []struct {
		fieldPath string
		value     string
	}{
		{fieldPath: "env", value: table.Env},
		{fieldPath: "host", value: table.Host},
		{fieldPath: "generation", value: table.Generation},
		{fieldPath: "upstream.host", value: table.Upstream.Host},
	}
	for _, identity := range identities {
		if err := checkIdentity(identity.fieldPath, identity.value); err != nil {
			return err
		}
	}

	if len(table.Domains) == 0 {
		return fieldErrorf("domains", "must list at least the primary domain")
	}
	for i, domain := range table.Domains {
		if err := checkName(fmt.Sprintf("domains[%d]", i), domain, false); err != nil {
			return err
		}
	}
	if err := checkUnique("domains", table.Domains); err != nil {
		return err
	}
	if err := checkAddr("upstream.ipv4", table.Upstream.Ipv4, false); err != nil {
		return err
	}

	// each served name routes one way
	addServedName := newValuePaths()
	if len(table.Lb.Names) == 0 {
		return fieldErrorf("lb.names", "must list at least one name, the default server")
	}
	for i, name := range table.Lb.Names {
		namePath := fmt.Sprintf("lb.names[%d]", i)
		if err := checkName(namePath, name, false); err != nil {
			return err
		}
		if err := addServedName(namePath, name); err != nil {
			return err
		}
	}
	if err := checkPrefixes("lb.route_prefixes", table.Lb.RoutePrefixes); err != nil {
		return err
	}
	for i, name := range table.NoAccessLog {
		if err := checkName(fmt.Sprintf("no_access_log[%d]", i), name, false); err != nil {
			return err
		}
	}
	if err := checkUnique("no_access_log", table.NoAccessLog); err != nil {
		return err
	}

	if len(table.Interfaces) == 0 {
		return fieldErrorf("interfaces", "must list at least one interface")
	}
	addInterfaceName := newValuePaths()
	addInterfaceBlock := newValuePaths()
	// each interface has a bridge of its own
	addInterfaceAddr := newValuePaths()
	for i, routeInterface := range table.Interfaces {
		interfacePath := fmt.Sprintf("interfaces[%d]", i)
		if err := checkIdentity(interfacePath+".name", routeInterface.Name); err != nil {
			return err
		}
		if err := addInterfaceName(interfacePath+".name", routeInterface.Name); err != nil {
			return err
		}
		if err := checkIdentity(interfacePath+".block", routeInterface.Block); err != nil {
			return err
		}
		if err := addInterfaceBlock(interfacePath+".block", routeInterface.Block); err != nil {
			return err
		}
		if routeInterface.Ipv4 == "" && routeInterface.Ipv6 == "" {
			return fieldErrorf(interfacePath, "needs an ipv4 or ipv6 address")
		}
		interfaceAddrs := []struct {
			fieldPath string
			value     string
			ipv6      bool
		}{
			{fieldPath: interfacePath + ".ipv4", value: routeInterface.Ipv4, ipv6: false},
			{fieldPath: interfacePath + ".ipv6", value: routeInterface.Ipv6, ipv6: true},
		}
		for _, interfaceAddr := range interfaceAddrs {
			if interfaceAddr.value == "" {
				continue
			}
			if err := checkAddr(interfaceAddr.fieldPath, interfaceAddr.value, interfaceAddr.ipv6); err != nil {
				return err
			}
			// public sockets bind interface addresses; the services bridge
			// holds the trusted listeners, which clients must never reach
			if interfaceAddr.value == table.Upstream.Ipv4 {
				return fieldErrorf(interfaceAddr.fieldPath, "must not be the services bridge address, upstream.ipv4")
			}
			if err := addInterfaceAddr(interfaceAddr.fieldPath, interfaceAddr.value); err != nil {
				return err
			}
		}

		rateLimitPath := interfacePath + ".rate_limit"
		rateLimit := routeInterface.RateLimit
		if !(0 <= rateLimit.RequestsPerMinute) || math.IsInf(rateLimit.RequestsPerMinute, 0) {
			return fieldErrorf(rateLimitPath+".requests_per_minute", "must not be negative (got %v)", rateLimit.RequestsPerMinute)
		}
		if err := checkCount(rateLimitPath+".burst", rateLimit.Burst); err != nil {
			return err
		}
		if err := checkCount(rateLimitPath+".net_connections", rateLimit.NetConnections); err != nil {
			return err
		}
		for j, excludeSubnet := range rateLimit.ExcludeSubnets {
			if _, err := netip.ParsePrefix(excludeSubnet); err != nil {
				return fieldErrorf(fmt.Sprintf("%s.exclude_subnets[%d]", rateLimitPath, j), "must be a cidr prefix")
			}
		}
		if err := checkUnique(rateLimitPath+".exclude_subnets", rateLimit.ExcludeSubnets); err != nil {
			return err
		}
	}

	listenPorts := []struct {
		fieldPath string
		port      int
	}{
		{fieldPath: "listen.http_port", port: table.Listen.HttpPort},
		{fieldPath: "listen.https_port", port: table.Listen.HttpsPort},
		{fieldPath: "listen.quic_port", port: table.Listen.QuicPort},
		{fieldPath: "listen.whodis_port", port: table.Listen.WhodisPort},
	}
	for _, listenPort := range listenPorts {
		if err := checkPort(listenPort.fieldPath, listenPort.port); err != nil {
			return err
		}
	}
	if table.Listen.HttpsPort == table.Listen.HttpPort {
		return fieldErrorf("listen.https_port", "must differ from listen.http_port, since both are tcp")
	}
	if table.Listen.WhodisPort == table.Listen.QuicPort {
		return fieldErrorf("listen.whodis_port", "must differ from listen.quic_port, since both are udp")
	}

	addServiceName := newValuePaths()
	// every block of every service has an external port of its own
	addBlockPort := newValuePaths()
	for i, service := range table.Services {
		servicePath := fmt.Sprintf("services[%d]", i)
		if err := checkIdentity(servicePath+".name", service.Name); err != nil {
			return err
		}
		if err := addServiceName(servicePath+".name", service.Name); err != nil {
			return err
		}
		if service.Status == "" {
			return fieldErrorf(servicePath+".status", "must not be empty")
		}

		for j, name := range service.Names {
			namePath := fmt.Sprintf("%s.names[%d]", servicePath, j)
			if err := checkName(namePath, name, true); err != nil {
				return err
			}
			if err := addServedName(namePath, name); err != nil {
				return err
			}
		}
		for j, redirectAlias := range service.RedirectAliases {
			redirectAliasPath := fmt.Sprintf("%s.redirect_aliases[%d]", servicePath, j)
			if err := checkName(redirectAliasPath+".name", redirectAlias.Name, true); err != nil {
				return err
			}
			if err := addServedName(redirectAliasPath+".name", redirectAlias.Name); err != nil {
				return err
			}
			if err := checkName(redirectAliasPath+".target", redirectAlias.Target, false); err != nil {
				return err
			}
		}

		for j, corsOrigin := range service.CorsOrigins {
			corsOriginPath := fmt.Sprintf("%s.cors_origins[%d]", servicePath, j)
			if corsOrigin == "" {
				return fieldErrorf(corsOriginPath, "must not be empty")
			}
			if strings.ContainsFunc(corsOrigin, isSpaceOrControl) {
				return fieldErrorf(corsOriginPath, "must not hold whitespace or control characters (got %q)", corsOrigin)
			}
		}
		if err := checkUnique(servicePath+".cors_origins", service.CorsOrigins); err != nil {
			return err
		}

		for j, streamablePath := range service.StreamablePaths {
			streamablePathPath := fmt.Sprintf("%s.streamable_paths[%d]", servicePath, j)
			if !strings.HasPrefix(streamablePath, "/") {
				return fieldErrorf(streamablePathPath, "must start with / (got %q)", streamablePath)
			}
			for _, r := range streamablePath {
				if r < 0x20 || r == 0x7f {
					return fieldErrorf(streamablePathPath, "must not hold a control character (got %q)", streamablePath)
				}
			}
			if _, err := regexp.Compile("^(?:" + streamablePath + ")$"); err != nil {
				return fieldErrorf(streamablePathPath, "must compile as an anchored regular expression: %s", err)
			}
		}
		if err := checkUnique(servicePath+".streamable_paths", service.StreamablePaths); err != nil {
			return err
		}

		if err := checkPrefixes(servicePath+".route_prefixes", service.RoutePrefixes); err != nil {
			return err
		}

		addRouteRateLimitPath := newValuePaths()
		for j, routeRateLimit := range service.RouteRateLimits {
			routeRateLimitPath := fmt.Sprintf("%s.route_rate_limits[%d]", servicePath, j)
			if err := checkPath(routeRateLimitPath+".path", routeRateLimit.Path); err != nil {
				return err
			}
			if err := addRouteRateLimitPath(routeRateLimitPath+".path", routeRateLimit.Path); err != nil {
				return err
			}
			// a route zone always has a rate: nginx refuses a zero one
			if !(0 < routeRateLimit.RequestsPerMinute) || math.IsInf(routeRateLimit.RequestsPerMinute, 0) {
				return fieldErrorf(routeRateLimitPath+".requests_per_minute", "must be positive (got %v)", routeRateLimit.RequestsPerMinute)
			}
			if err := checkCount(routeRateLimitPath+".burst", routeRateLimit.Burst); err != nil {
				return err
			}
		}

		addRouteRequestBodyPath := newValuePaths()
		for j, routeRequestBody := range service.RouteRequestBodies {
			routeRequestBodyPath := fmt.Sprintf("%s.route_request_bodies[%d]", servicePath, j)
			if err := checkPath(routeRequestBodyPath+".path", routeRequestBody.Path); err != nil {
				return err
			}
			if err := addRouteRequestBodyPath(routeRequestBodyPath+".path", routeRequestBody.Path); err != nil {
				return err
			}
			if routeRequestBody.ClientBodyBufferSize <= 0 {
				return fieldErrorf(routeRequestBodyPath+".client_body_buffer_size", "must be positive (got %d)", routeRequestBody.ClientBodyBufferSize)
			}
			if routeRequestBody.ClientBodyTimeoutSeconds <= 0 {
				return fieldErrorf(routeRequestBodyPath+".client_body_timeout_seconds", "must be positive (got %d)", routeRequestBody.ClientBodyTimeoutSeconds)
			}
		}

		for j, noSuccessAccessLogPath := range service.NoSuccessAccessLog {
			if err := checkPath(fmt.Sprintf("%s.no_success_access_log[%d]", servicePath, j), noSuccessAccessLogPath); err != nil {
				return err
			}
		}
		if err := checkUnique(servicePath+".no_success_access_log", service.NoSuccessAccessLog); err != nil {
			return err
		}

		keepalivePath := servicePath + ".keepalive"
		keepaliveCounts := []struct {
			fieldPath string
			count     int
		}{
			{fieldPath: keepalivePath + ".connections", count: service.Keepalive.Connections},
			{fieldPath: keepalivePath + ".requests", count: service.Keepalive.Requests},
			{fieldPath: keepalivePath + ".time_seconds", count: service.Keepalive.TimeSeconds},
			{fieldPath: keepalivePath + ".timeout_seconds", count: service.Keepalive.TimeoutSeconds},
		}
		for _, keepaliveCount := range keepaliveCounts {
			if err := checkCount(keepaliveCount.fieldPath, keepaliveCount.count); err != nil {
				return err
			}
		}

		addBlockName := newValuePaths()
		for j, block := range service.Blocks {
			blockPath := fmt.Sprintf("%s.blocks[%d]", servicePath, j)
			if err := checkIdentity(blockPath+".name", block.Name); err != nil {
				return err
			}
			if err := addBlockName(blockPath+".name", block.Name); err != nil {
				return err
			}
			if err := checkCount(blockPath+".weight", block.Weight); err != nil {
				return err
			}
			if err := checkPort(blockPath+".port", block.Port); err != nil {
				return err
			}
			if err := addBlockPort(blockPath+".port", fmt.Sprintf("%d", block.Port)); err != nil {
				return err
			}
		}
	}

	hasService := func(name string) bool {
		return slices.ContainsFunc(table.Services, func(service LbAltRouteService) bool {
			return service.Name == name
		})
	}
	if !hasService(table.Front.ConnectService) {
		return fieldErrorf("front.connect_service", "must name a service in services (got %q)", table.Front.ConnectService)
	}
	if !hasService(table.Front.ApiService) {
		return fieldErrorf("front.api_service", "must name a service in services (got %q)", table.Front.ApiService)
	}
	if table.Front.ApiService == table.Front.ConnectService {
		return fieldErrorf("front.api_service", "must differ from front.connect_service")
	}
	if len(table.Front.WhodisTlds) == 0 {
		return fieldErrorf("front.whodis_tlds", "must list at least one tld")
	}
	for i, whodisTld := range table.Front.WhodisTlds {
		whodisTldPath := fmt.Sprintf("front.whodis_tlds[%d]", i)
		name, ok := strings.CutSuffix(whodisTld, ".")
		if !ok {
			return fieldErrorf(whodisTldPath, "must end with . (got %q)", whodisTld)
		}
		if err := checkName(whodisTldPath, name, false); err != nil {
			return err
		}
	}
	return checkUnique("front.whodis_tlds", table.Front.WhodisTlds)
}

// The whole seconds of an nginx time as a millisecond directive such as
// keepalive_time reads it (nginx's ngx_parse_time): numbers with the units w,
// d, h, m, s and ms, largest first and each at most once, spaces allowed after
// a unit, and a trailing number with no unit counting seconds, as in 15m,
// 1h 30m or 60. Months and years are refused there, as nginx refuses them for
// these directives. A time that is not whole seconds is refused, since the
// route file holds seconds.
func parseNginxTimeSeconds(value string) (int, error) {
	total := time.Duration(0)
	add := func(count int64, unit time.Duration) bool {
		if count != 0 && int64(math.MaxInt64-total)/int64(unit) < count {
			return false
		}
		total += time.Duration(count) * unit
		return true
	}
	number := int64(0)
	hasDigit := false
	// the rank of the last unit, so the units come largest first
	lastUnitRank := 0
	for i := 0; i < len(value); {
		c := value[i]
		if '0' <= c && c <= '9' {
			digit := int64(c - '0')
			if (math.MaxInt64-digit)/10 < number {
				return 0, fmt.Errorf("nginx time %q is too large", value)
			}
			number = number*10 + digit
			hasDigit = true
			i += 1
			continue
		}
		var unit time.Duration
		var unitRank int
		switch {
		case c == 'w':
			unit, unitRank = 7*24*time.Hour, 1
		case c == 'd':
			unit, unitRank = 24*time.Hour, 2
		case c == 'h':
			unit, unitRank = time.Hour, 3
		case c == 'm' && i+1 < len(value) && value[i+1] == 's':
			unit, unitRank = time.Millisecond, 6
			i += 1
		case c == 'm':
			unit, unitRank = time.Minute, 4
		case c == 's':
			unit, unitRank = time.Second, 5
		default:
			return 0, fmt.Errorf("%q is not an nginx time", value)
		}
		i += 1
		if unitRank <= lastUnitRank {
			return 0, fmt.Errorf("nginx time %q repeats a unit or puts a smaller one first", value)
		}
		lastUnitRank = unitRank
		if !add(number, unit) {
			return 0, fmt.Errorf("nginx time %q is too large", value)
		}
		number = 0
		for i < len(value) && value[i] == ' ' {
			i += 1
		}
	}
	if !hasDigit {
		return 0, fmt.Errorf("%q is not an nginx time", value)
	}
	if !add(number, time.Second) {
		return 0, fmt.Errorf("nginx time %q is too large", value)
	}
	if total%time.Second != 0 {
		return 0, fmt.Errorf("nginx time %q is not a whole number of seconds", value)
	}
	return int(total / time.Second), nil
}

// The directory of a generation's route file, <warpHome>/lbalt/<containerName>.
// The container name must be one path element of a docker name's characters,
// so neither a write nor a removal reaches outside the generation's own
// directory.
func lbAltRouteDirPath(warpHome string, containerName string) (string, error) {
	if warpHome == "" {
		return "", errors.New("lbalt route file: no warp home")
	}
	if containerName == "" || containerName == "." || containerName == ".." {
		return "", fmt.Errorf("lbalt route file: %q is not a container name", containerName)
	}
	for _, r := range containerName {
		if !('a' <= r && r <= 'z' || 'A' <= r && r <= 'Z' || '0' <= r && r <= '9' || r == '.' || r == '-' || r == '_') {
			return "", fmt.Errorf("lbalt route file: %q is not a container name", containerName)
		}
	}
	return filepath.Join(warpHome, lbAltRouteHostDirName, containerName), nil
}

// Writes the encoded table to <warpHome>/lbalt/<containerName>/route.json with
// mode 0444, never over an existing file, and returns the host path and the
// revision (lowercase hex sha256 of the bytes written).
//
// The table's generation must be the container name, which connect reports
// back in X-UR-Front-Generation. The directory is created with mode 0700. A
// write that fails part way removes its file, so no container starts from a
// partial one.
func writeLbAltRouteFile(warpHome string, containerName string, table *LbAltRouteTable) (hostPath string, revision string, err error) {
	routeDirPath, err := lbAltRouteDirPath(warpHome, containerName)
	if err != nil {
		return "", "", err
	}
	data, err := encodeLbAltRouteTable(table)
	if err != nil {
		return "", "", err
	}
	if table.Generation != containerName {
		return "", "", fmt.Errorf("lbalt route file: the table is of generation %q, not of the container %q", table.Generation, containerName)
	}
	if err := os.MkdirAll(routeDirPath, lbAltRouteDirMode); err != nil {
		return "", "", fmt.Errorf("lbalt route file: %w", err)
	}
	routeFilePath := filepath.Join(routeDirPath, lbAltRouteFileName)
	// O_EXCL: a generation's file is written once and never replaced
	routeFile, err := os.OpenFile(routeFilePath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, lbAltRouteFileMode)
	if err != nil {
		return "", "", fmt.Errorf("lbalt route file: %w", err)
	}
	writeErr := func() error {
		if _, err := routeFile.Write(data); err != nil {
			return err
		}
		return routeFile.Sync()
	}()
	closeErr := routeFile.Close()
	if writeErr == nil {
		writeErr = closeErr
	}
	// the create asked for the mode under the process umask; set it exactly
	if writeErr == nil {
		writeErr = os.Chmod(routeFilePath, lbAltRouteFileMode)
	}
	if writeErr != nil {
		os.Remove(routeFilePath)
		return "", "", fmt.Errorf("lbalt route file: %w", writeErr)
	}
	digest := sha256.Sum256(data)
	return routeFilePath, hex.EncodeToString(digest[:]), nil
}

// Removes <warpHome>/lbalt/<containerName>/, once the container is gone. A
// directory that is already gone is not an error.
func removeLbAltRouteFile(warpHome string, containerName string) error {
	routeDirPath, err := lbAltRouteDirPath(warpHome, containerName)
	if err != nil {
		return err
	}
	if err := os.RemoveAll(routeDirPath); err != nil {
		return fmt.Errorf("lbalt route file: %w", err)
	}
	return nil
}
