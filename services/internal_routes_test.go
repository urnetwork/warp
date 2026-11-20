package services

import (
	"net/netip"
	"slices"
	"strings"
	"testing"
)

// The fragment base with internal_routes on api, which the loader reads with every other check.
func internalRoutesServicesYaml(t *testing.T, internalRoutes string) string {
	t.Helper()
	// the first api is the latest version's
	header := "        api: &api\n"
	if !strings.Contains(fragmentBaseYaml, header) {
		t.Fatal("the fragment base lacks api")
	}
	return strings.Replace(fragmentBaseYaml, header, header+internalRoutes, 1)
}

// internal_routes as the loader reads it: its prefixes and allowed sources in the order written, and which paths
// fall under a prefix.
func TestInternalRoutesLoad(t *testing.T) {
	servicesConfig := mustParseServicesConfig(t, internalRoutesServicesYaml(t, ""+
		"            internal_routes:\n"+
		"                prefixes:\n"+
		"                    - /internal/gate/\n"+
		"                    - /other/internal/\n"+
		"                allow_subnets:\n"+
		"                    - 198.51.100.0/24\n"+
		"                    - \"2001:db8:1234::/48\"\n"+
		"                    - 203.0.113.7/32\n"))
	api := servicesConfig.Versions[0].Services["api"]
	if got := api.GetInternalRoutePrefixes(); !slices.Equal(got, []string{"/internal/gate/", "/other/internal/"}) {
		t.Errorf("prefixes %q", got)
	}
	want := []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24"), netip.MustParsePrefix("2001:db8:1234::/48"), netip.MustParsePrefix("203.0.113.7/32")}
	if got := api.GetInternalRouteAllowSubnets(); !slices.Equal(got, want) {
		t.Errorf("allow subnets %v", got)
	}
	for path, inside := range map[string]bool{
		"/internal/gate/projection/x": true,
		"/internal/gate/":             true,
		"/internal/gate":              false,
		"/internal/gateway/x":         false,
		"/x/internal/gate/y":          false,
		"/other/internal/x":           true,
	} {
		if api.IsInternalRoutePath(path) != inside {
			t.Errorf("%s under a prefix: %v, want %v", path, !inside, inside)
		}
	}
	// a service with none has none
	mcp := servicesConfig.Versions[0].Services["mcp"]
	if mcp.GetInternalRoutePrefixes() != nil || mcp.GetInternalRouteAllowSubnets() != nil || mcp.IsInternalRoutePath("/internal/gate/x") {
		t.Error("a service without internal_routes has some")
	}
	// an empty allow list loads, and lets no source through
	none := mustParseServicesConfig(t, internalRoutesServicesYaml(t, ""+
		"            internal_routes:\n"+
		"                prefixes:\n"+
		"                    - /internal/gate/\n"))
	if got := none.Versions[0].Services["api"].GetInternalRouteAllowSubnets(); len(got) != 0 {
		t.Errorf("an empty allow list holds %v", got)
	}
}

// The loader refuses internal_routes that would refuse nothing or the wrong thing: no prefix, a prefix that is no
// path ending in /, one with a dot segment or listed twice, a source that is no cidr block with its host bits clear
// or is listed twice, a service the lb serves no http server block for, and an exact route_rate_limits route under a
// prefix, whose exact location nginx would take first, letting every source through.
func TestInternalRoutesRefusals(t *testing.T) {
	for _, c := range []struct {
		name string
		text string
		want string
	}{
		{name: "no prefix", text: "            internal_routes:\n                allow_subnets:\n                    - 198.51.100.0/24\n", want: "lists no prefix"},
		{name: "no trailing slash", text: "            internal_routes:\n                prefixes:\n                    - /internal/gate\n", want: "beginning and ending with /"},
		{name: "no leading slash", text: "            internal_routes:\n                prefixes:\n                    - internal/gate/\n", want: "beginning and ending with /"},
		{name: "the root", text: "            internal_routes:\n                prefixes:\n                    - /\n", want: "beginning and ending with /"},
		{name: "an empty segment", text: "            internal_routes:\n                prefixes:\n                    - /internal//gate/\n", want: "beginning and ending with /"},
		{name: "a character to escape", text: "            internal_routes:\n                prefixes:\n                    - \"/internal gate/\"\n", want: "beginning and ending with /"},
		{name: "a dot segment", text: "            internal_routes:\n                prefixes:\n                    - /internal/../gate/\n", want: "dot segment"},
		{name: "a prefix twice", text: "            internal_routes:\n                prefixes:\n                    - /internal/gate/\n                    - /internal/gate/\n", want: "more than once"},
		{name: "a placeholder source", text: "            internal_routes:\n                prefixes:\n                    - /internal/gate/\n                allow_subnets:\n                    - fill-in-site-ipv4-range\n", want: "not a cidr block"},
		{name: "an address with no length", text: "            internal_routes:\n                prefixes:\n                    - /internal/gate/\n                allow_subnets:\n                    - 198.51.100.7\n", want: "not a cidr block"},
		{name: "host bits", text: "            internal_routes:\n                prefixes:\n                    - /internal/gate/\n                allow_subnets:\n                    - 198.51.100.7/24\n", want: "not a cidr block"},
		{name: "a mapped address", text: "            internal_routes:\n                prefixes:\n                    - /internal/gate/\n                allow_subnets:\n                    - \"::ffff:198.51.100.0/120\"\n", want: "not a cidr block"},
		{name: "a source twice", text: "            internal_routes:\n                prefixes:\n                    - /internal/gate/\n                allow_subnets:\n                    - 198.51.100.0/24\n                    - 198.51.100.0/24\n", want: "more than once"},
		{name: "an exact route under a prefix", text: "            internal_routes:\n                prefixes:\n                    - /internal/gate/\n            route_rate_limits:\n                -   path: /internal/gate/over-limit\n                    requests_per_minute: 60\n", want: "let every source through"},
	} {
		_, err := ParseServicesConfig([]byte(internalRoutesServicesYaml(t, c.text)), "services.yml")
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %q", c.name, err, c.want)
		}
	}

	// taskworker is not exposed, so the lb has no server block to refuse anything in
	header := "        taskworker: &taskworker\n"
	if !strings.Contains(fragmentBaseYaml, header) {
		t.Fatal("the fragment base lacks taskworker")
	}
	text := strings.Replace(fragmentBaseYaml, header, header+"            internal_routes:\n                prefixes:\n                    - /internal/gate/\n", 1)
	if _, err := ParseServicesConfig([]byte(text), "services.yml"); err == nil || !strings.Contains(err.Error(), "no http server block") {
		t.Errorf("an unexposed service's internal routes: %v", err)
	}
}
