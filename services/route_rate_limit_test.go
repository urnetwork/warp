package services

import (
	"fmt"
	"strings"
	"testing"
)

// a services document whose api lists the given route_rate_limits entries
func routeRateLimitServicesYaml(status string, entries string) string {
	return fmt.Sprintf(`
versions:
-   services:
        api:
%s            route_rate_limits:
%s            ports:
                - 80
            blocks:
                - g1: 1
`, status, entries)
}

// The api's /connect/control route is parsed with its own rate and burst and
// named for its nginx zone (support inbox 8093, 8077).
func TestLoadServicesConfigParsesRouteRateLimits(t *testing.T) {
	servicesConfig, err := loadInlineServicesConfig(t, routeRateLimitServicesYaml("", `
                -   path: /connect/control
                    requests_per_minute: 12000
                    burst: 6000
                -   path: /other/route-1
                    requests_per_second: 5
`))
	if err != nil {
		t.Fatal(err)
	}
	routeRateLimits := servicesConfig.Latest().Services["api"].RouteRateLimits
	if len(routeRateLimits) != 2 {
		t.Fatalf("route rate limits = %d, want 2", len(routeRateLimits))
	}
	connectControl := routeRateLimits[0]
	if connectControl.Path != "/connect/control" || connectControl.RequestsPerMinute != 12000 || connectControl.Burst != 6000 {
		t.Fatalf("/connect/control = %+v", connectControl)
	}
	if rate := connectControl.NginxRate(); rate != "12000r/m" {
		t.Fatalf("/connect/control rate = %s, want 12000r/m", rate)
	}
	if zone := RouteRateLimitZoneName("api", connectControl.Path); zone != "route_api_connect_control" {
		t.Fatalf("/connect/control zone = %s, want route_api_connect_control", zone)
	}
	if rate := routeRateLimits[1].NginxRate(); rate != "5r/s" {
		t.Fatalf("/other/route-1 rate = %s, want 5r/s", rate)
	}
	if zone := RouteRateLimitZoneName("api", routeRateLimits[1].Path); zone != "route_api_other_route_1" {
		t.Fatalf("/other/route-1 zone = %s", zone)
	}
}

// A route the lb could not render as one exact location, or could render
// only as a duplicate location or zone, is refused when the document loads,
// before any lb config is generated.
func TestLoadServicesConfigRejectsInvalidRouteRateLimits(t *testing.T) {
	for _, test := range []struct {
		name    string
		status  string
		entries string
		message string
	}{
		{"relative path", "", `
                -   path: connect/control
                    requests_per_minute: 1
`, "not an exact path"},
		{"regex path", "", `
                -   path: /connect/.*
                    requests_per_minute: 1
`, "not an exact path"},
		{"space", "", `
                -   path: "/connect/control x"
                    requests_per_minute: 1
`, "not an exact path"},
		{"nginx variable", "", `
                -   path: /connect/$host
                    requests_per_minute: 1
`, "not an exact path"},
		{"empty segment", "", `
                -   path: /connect//control
                    requests_per_minute: 1
`, "not an exact path"},
		{"dot segment", "", `
                -   path: /connect/../control
                    requests_per_minute: 1
`, "dot segment"},
		{"status route", "", `
                -   path: /status
                    requests_per_minute: 1
`, "generated status route"},
		{"repeated path", "", `
                -   path: /connect/control
                    requests_per_minute: 1
                -   path: /connect/control
                    requests_per_minute: 2
`, "more than once"},
		{"shared zone name", "", `
                -   path: /connect/control
                    requests_per_minute: 1
                -   path: /connect-control
                    requests_per_minute: 1
`, "share the zone name"},
		{"no rate", "", `
                -   path: /connect/control
                    burst: 10
`, "has no rate"},
		{"negative rate", "", `
                -   path: /connect/control
                    requests_per_minute: -1
`, "negative rate"},
		{"negative burst", "", `
                -   path: /connect/control
                    requests_per_minute: 1
                    burst: -1
`, "negative burst"},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := loadInlineServices(t, routeRateLimitServicesYaml(test.status, test.entries))
			if err == nil || !strings.Contains(err.Error(), test.message) {
				t.Fatalf("err = %v, want %q", err, test.message)
			}
		})
	}

	// without the generated status route, /status is an ordinary route
	if err := loadInlineServices(t, routeRateLimitServicesYaml("            status: \"no\"\n", `
                -   path: /status
                    requests_per_minute: 1
`)); err != nil {
		t.Fatalf("a /status route of a service without the generated status route: %s", err)
	}
}
