package main

// The public port contract of an lb_alt interface (server/LBALT.md §4.1 and
// its review amendments; server/LBALT-IMPL.md §2.3): which connect socket each
// public (protocol, port) reaches. The host's dnat (the block chains of the
// lb_alt split) and the router firewall (VyosGenerator) both read it, so the
// two agree on one list.
//
// An lb_alt interface publishes exactly services.LbAltPublicPorts, and each of
// those ports reaches the connect service port the fixed map below names. The
// socket connect binds on the interface's bridge address listens on that
// service port's internal port (WARP_PORTS):
//   - tcp 80: service port 80, the front's port-80 handler (listen.http_port);
//   - tcp 443: service port 443, the tls front (listen.https_port);
//   - udp 443: service port 443, quic (listen.quic_port);
//   - udp 4053 and udp 53: service port 4053, whodis (listen.whodis_port).
//
// Nothing else has a front socket, so no other (protocol, port) is published:
// not udp 80, and not tcp 53 or 4053. This is where an lb_alt interface
// differs from an nginx one, whose map (publicPortServiceTargets) publishes
// every lb port on both protocols and keeps the forward target 4053 private;
// on an lb_alt interface whodis answers on 4053 as well as on 53, at the host
// and at the router.

import (
	"fmt"
	"slices"
	"sort"

	"golang.org/x/exp/maps"
)

// The public ports of the lb_alt front (server/LBALT-IMPL.md §2.3). Each is
// also the connect service port whose internal port the socket behind it
// listens on, except the dns port, which whodis answers on its own service
// port. These are protocol values: the route file's listen ports are defined
// by them.
const (
	lbAltHttpPort   = 80
	lbAltHttpsPort  = 443
	lbAltWhodisPort = 4053
	lbAltDnsPort    = 53
)

// The connect service port behind a public (protocol, port) of an lb_alt
// interface, by the fixed map of server/LBALT-IMPL.md §2.3. False for every
// other (protocol, port): no front socket answers there.
func lbAltPublicPortServicePort(protocol string, publicPort int) (int, bool) {
	switch {
	case protocol == "tcp" && publicPort == lbAltHttpPort:
		// the front's port-80 handler
		return lbAltHttpPort, true
	case protocol == "tcp" && publicPort == lbAltHttpsPort:
		// the tls front
		return lbAltHttpsPort, true
	case protocol == "udp" && publicPort == lbAltHttpsPort:
		// quic
		return lbAltHttpsPort, true
	case protocol == "udp" && publicPort == lbAltWhodisPort:
		// whodis
		return lbAltWhodisPort, true
	case protocol == "udp" && publicPort == lbAltDnsPort:
		// whodis, on the dns port
		return lbAltWhodisPort, true
	}
	return 0, false
}

// Checks an lb_alt interface's public port list (services.LbAltPublicPorts)
// against the front's sockets: tcp and udp only, and each port one the fixed
// map names. A port the list adds beyond the map, from a wider lb `ports`
// list or another udp forward, has no socket to reach, so the host and the
// router refuse to publish it rather than open a port nothing answers.
func lbAltCheckPublicPorts(publicPorts map[string][]int) error {
	protocols := maps.Keys(publicPorts)
	sort.Strings(protocols)
	for _, protocol := range protocols {
		if protocol != "tcp" && protocol != "udp" {
			return fmt.Errorf("lb_alt public ports name the protocol %q; only tcp and udp have front sockets", protocol)
		}
		for _, publicPort := range publicPorts[protocol] {
			if _, ok := lbAltPublicPortServicePort(protocol, publicPort); !ok {
				return fmt.Errorf("lb_alt public %s port %d has no front socket; an lb_alt interface publishes only tcp 80 and 443, and udp 443, 4053 and 53", protocol, publicPort)
			}
		}
	}
	return nil
}

// The public ports of an lb_alt interface on one protocol, each mapped to the
// connect service port behind it: public port -> service port, the shape of
// publicPortServiceTargets, whose service port the caller resolves to the
// generation's internal port. publicPorts is the interface's
// services.LbAltPublicPorts.
//
// An error when a listed port has no front socket (lbAltCheckPublicPorts) or
// the service port behind it is not one of the generation's
// (servicePortsToInternalPort), so a dnat never points at a port nothing
// binds.
func lbAltPublicPortServiceTargets(
	protocol string,
	publicPorts map[string][]int,
	servicePortsToInternalPort map[int]int,
) (map[int]int, error) {
	if protocol != "tcp" && protocol != "udp" {
		return nil, fmt.Errorf("invalid lb_alt protocol %q", protocol)
	}
	if err := lbAltCheckPublicPorts(publicPorts); err != nil {
		return nil, err
	}
	publicTargets := map[int]int{}
	for _, publicPort := range publicPorts[protocol] {
		// checked above
		servicePort, _ := lbAltPublicPortServicePort(protocol, publicPort)
		if _, ok := servicePortsToInternalPort[servicePort]; !ok {
			return nil, fmt.Errorf("lb_alt public %s port %d reaches service port %d, which the generation does not allocate", protocol, publicPort, servicePort)
		}
		publicTargets[publicPort] = servicePort
	}
	return publicTargets, nil
}

// The dnat targets of an lb_alt block chain (server/LBALT-IMPL.md §2.5): each
// public port of the interface, ordered by protocol then port, to the
// internal port of the connect service port behind it in the generation's
// WARP_PORTS (servicePortsToInternalPort). udp 53 and udp 4053 both reach
// whodis, so they share one internal port. The block worker hands these to
// writeLbAltBlockChains once its candidate generation is ready.
func lbAltBlockTargets(publicPorts map[string][]int, servicePortsToInternalPort map[int]int) ([]lbAltBlockTarget, error) {
	blockTargets := []lbAltBlockTarget{}
	for _, protocol := range []string{"tcp", "udp"} {
		publicTargets, err := lbAltPublicPortServiceTargets(protocol, publicPorts, servicePortsToInternalPort)
		if err != nil {
			return nil, err
		}
		orderedPublicPorts := maps.Keys(publicTargets)
		slices.Sort(orderedPublicPorts)
		for _, publicPort := range orderedPublicPorts {
			blockTargets = append(blockTargets, lbAltBlockTarget{
				protocol:     protocol,
				publicPort:   publicPort,
				internalPort: servicePortsToInternalPort[publicTargets[publicPort]],
			})
		}
	}
	return blockTargets, nil
}
