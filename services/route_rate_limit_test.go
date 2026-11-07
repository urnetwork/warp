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

// a services document whose evs carries the given service_rate_limit lines
func serviceRateLimitServicesYaml(serviceRateLimit string, extra string) string {
	return fmt.Sprintf(`
versions:
-   services:
        evs:
%s            service_rate_limit:
%s            ports:
                - 80
            blocks:
                - g1: 1
`, extra, serviceRateLimit)
}

// evs's whole-service limit is parsed with its rate and burst, and named for
// its nginx zone, apart from every route zone of the service.
func TestLoadServicesConfigParsesServiceRateLimit(t *testing.T) {
	servicesConfig, err := loadInlineServicesConfig(t, serviceRateLimitServicesYaml(`
                requests_per_minute: 3000
                burst: 1000
`, ""))
	if err != nil {
		t.Fatal(err)
	}
	serviceRateLimit := servicesConfig.Latest().Services["evs"].ServiceRateLimit
	if serviceRateLimit == nil {
		t.Fatal("evs has no service rate limit")
	}
	if serviceRateLimit.RequestsPerMinute != 3000 || serviceRateLimit.Burst != 1000 {
		t.Fatalf("evs = %+v", serviceRateLimit)
	}
	if rate := serviceRateLimit.NginxRate(); rate != "3000r/m" {
		t.Fatalf("evs rate = %s, want 3000r/m", rate)
	}
	if zone := ServiceRateLimitZoneName("evs"); zone != "service_evs" {
		t.Fatalf("evs zone = %s, want service_evs", zone)
	}
	if zone := RouteRateLimitZoneName("evs", "/x"); zone == ServiceRateLimitZoneName("evs") {
		t.Fatalf("a route of evs shares the service's zone %s", zone)
	}
}

// gkm's limit names a rate and no burst, which is valid.
func TestLoadServicesConfigAcceptsAServiceRateLimitWithoutABurst(t *testing.T) {
	servicesConfig, err := loadInlineServicesConfig(t, serviceRateLimitServicesYaml(`
                requests_per_minute: 1200
`, ""))
	if err != nil {
		t.Fatal(err)
	}
	if burst := servicesConfig.Latest().Services["evs"].ServiceRateLimit.Burst; burst != 0 {
		t.Fatalf("burst = %d, want 0", burst)
	}
}

// A limit that could not render, or that would render into nothing, is refused
// when the document loads, before any lb config is generated.
func TestLoadServicesConfigRejectsInvalidServiceRateLimits(t *testing.T) {
	for _, test := range []struct {
		name    string
		yaml    string
		message string
	}{
		{"zero rate", serviceRateLimitServicesYaml(`
                requests_per_minute: 0
                burst: 10
`, ""), "has no rate"},
		{"no rate", serviceRateLimitServicesYaml(`
                burst: 10
`, ""), "has no rate"},
		// the whole-service form counts per minute, so a per-second rate is
		// not a rate it reads
		{"per second rate", serviceRateLimitServicesYaml(`
                requests_per_second: 50
`, ""), "has no rate"},
		{"negative rate", serviceRateLimitServicesYaml(`
                requests_per_minute: -1
`, ""), "negative rate"},
		{"negative burst", serviceRateLimitServicesYaml(`
                requests_per_minute: 1
                burst: -1
`, ""), "negative burst"},
		{"unexposed service", serviceRateLimitServicesYaml(`
                requests_per_minute: 1
`, "            exposed: false\n"), "no http server block"},
		{"no port 80", `
versions:
-   services:
        evs:
            service_rate_limit:
                requests_per_minute: 1
            ports:
                - 8080
            blocks:
                - g1: 1
`, "no http server block"},
	} {
		err := loadInlineServices(t, test.yaml)
		if err == nil || !strings.Contains(err.Error(), test.message) {
			t.Errorf("%s: err = %v, want %q", test.name, err, test.message)
		}
	}
}
