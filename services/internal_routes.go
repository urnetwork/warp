package services

import (
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"strings"
)

// Path prefixes of an lb service that the lb serves only to the site's own
// sources: api's /internal/gate/, the read surface the sidecar's blocks with no
// database reach with a bearer, and the dns API's /dns/internal/, which the dns
// edges, the monitors, certs and lbmap reach with theirs (sidecar DESIGN §8.9,
// §19.4, §19.5's W8; QD-027, QD-680). The bearers stay the routes' own check;
// this keeps a bearer that leaked from being used from outside the site.
//
// On every name the lb serves the service by, its own hosts and aliases behind
// each of its route prefixes and the lb hosts' /by/ routes, a request under
// one of the prefixes from an address outside allow_subnets is answered 403
// and never reaches the service, and one from inside is proxied as the
// service's other paths are, its path unchanged. nginx normalizes a path before
// it matches one (percent-decoding, dot segments, merged slashes), so a
// spelling of the prefix that the service would route alike matches it too.
// The address is the client's as the lb sees it, the PROXY header's behind the
// tls split, so a header a client sends changes nothing. An empty
// allow_subnets lets no source through the lb.
//
// The site's blocks reach such a route through the lb, by the service's
// public name, from the addresses the site's hosts send from, and those
// requests count in the lb's per-address limits as any other's do unless the
// interface's rate_limit exclude_subnets cover them.
type InternalRoutes struct {
	// each a path of unreserved characters beginning and ending with /, such
	// as /internal/gate/
	Prefixes []string `yaml:"prefixes,omitempty"`
	// the sources let through, each a cidr block with no host bits set, such
	// as 192.0.2.0/24 or 2001:db8::/32; a single address is a /32 or /128
	AllowSubnets []string `yaml:"allow_subnets,omitempty"`
}

// a path of unreserved url path characters beginning and ending with /, so it
// needs no quoting or escaping in an nginx location or proxy_pass, with no
// empty segment
var internalRoutePrefixRegex = regexp.MustCompile(`^(/[A-Za-z0-9._~-]+)+/$`)

// The service's internal route prefixes, none for a service without
// internal_routes.
func (self *ServiceConfig) GetInternalRoutePrefixes() []string {
	if self.InternalRoutes == nil {
		return nil
	}
	return self.InternalRoutes.Prefixes
}

// The sources the lb lets through to the service's internal routes, in the
// order listed. The loader has checked each parses.
func (self *ServiceConfig) GetInternalRouteAllowSubnets() []netip.Prefix {
	if self.InternalRoutes == nil {
		return nil
	}
	prefixes := []netip.Prefix{}
	for _, subnet := range self.InternalRoutes.AllowSubnets {
		prefixes = append(prefixes, netip.MustParsePrefix(subnet))
	}
	return prefixes
}

// Whether path, a service-relative path, is under one of the service's
// internal route prefixes.
func (self *ServiceConfig) IsInternalRoutePath(path string) bool {
	for _, prefix := range self.GetInternalRoutePrefixes() {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}

// ValidateInternalRoutes checks a service's `internal_routes`: at least one
// prefix, each a path beginning and ending with /, with no dot segment, listed
// once; each allowed source a cidr block with no host bits, listed once; a
// service the lb has http server blocks for, since on any other the routes
// would quietly be refused nowhere; and no exact route_rate_limits route under
// a prefix, whose exact location nginx would take before the prefix's, letting
// every source through.
func ValidateInternalRoutes(serviceConfig *ServiceConfig) error {
	internalRoutes := serviceConfig.InternalRoutes
	if internalRoutes == nil {
		return nil
	}
	if len(internalRoutes.Prefixes) == 0 {
		return fmt.Errorf("internal_routes lists no prefix")
	}
	prefixes := map[string]bool{}
	for _, prefix := range internalRoutes.Prefixes {
		if !internalRoutePrefixRegex.MatchString(prefix) {
			return fmt.Errorf("internal route prefix %q is not a path of unreserved characters beginning and ending with /", prefix)
		}
		for _, segment := range strings.Split(strings.Trim(prefix, "/"), "/") {
			if segment == "." || segment == ".." {
				return fmt.Errorf("internal route prefix %q has a dot segment", prefix)
			}
		}
		if prefixes[prefix] {
			return fmt.Errorf("internal route prefix %q is listed more than once", prefix)
		}
		prefixes[prefix] = true
	}
	subnets := map[netip.Prefix]bool{}
	for _, subnet := range internalRoutes.AllowSubnets {
		prefix, err := netip.ParsePrefix(subnet)
		if err != nil || prefix.Masked() != prefix || prefix.Addr().Is4In6() {
			return fmt.Errorf("internal routes allow subnet %q is not a cidr block with no host bits set", subnet)
		}
		if subnets[prefix] {
			return fmt.Errorf("internal routes allow subnet %q is listed more than once", subnet)
		}
		subnets[prefix] = true
	}
	if !serviceConfig.IsExposed() || !slices.Contains(serviceConfig.HttpTcpPorts(), 80) {
		return fmt.Errorf("internal_routes is on a service the lb serves no http server block for (exposed, with port 80)")
	}
	for _, routeRateLimit := range serviceConfig.RouteRateLimits {
		if routeRateLimit != nil && serviceConfig.IsInternalRoutePath(routeRateLimit.Path) {
			return fmt.Errorf("route rate limit path %q is under an internal route prefix, and its exact location would let every source through", routeRateLimit.Path)
		}
	}
	return nil
}
