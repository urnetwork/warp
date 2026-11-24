// Tests of parsing and validating services.yml route_request_bodies against
// the lb's request body settings.
package services

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// A services document whose api lists the given route_request_bodies
// entries. `extra` is inserted among the api's own settings, e.g. to
// unexpose it or change its ports.
func routeRequestBodyServicesYaml(extra string, entries string) string {
	ports := "            ports:\n                - 80\n"
	if strings.Contains(extra, "ports:") {
		ports = ""
	}
	return fmt.Sprintf(`
versions:
-   services:
        api:
%s            route_request_bodies:
%s%s            blocks:
                - g1: 1
`, extra, entries, ports)
}

// The api's upload route is parsed with its own body buffer and stall
// timeout, and a value an entry leaves unset reads as zero, which keeps the
// server-wide one.
func TestLoadServicesConfigParsesRouteRequestBodies(t *testing.T) {
	servicesConfig, err := loadInlineServicesConfig(t, routeRequestBodyServicesYaml("", `
                -   path: /sn/attempt-artifact
                    client_body_buffer_size: 1mib
                    client_body_timeout: 60s
                -   path: /other/route-1
                    client_body_timeout: 1m
`))
	if err != nil {
		t.Fatal(err)
	}
	routeRequestBodies := servicesConfig.Latest().Services["api"].RouteRequestBodies
	if len(routeRequestBodies) != 2 {
		t.Fatalf("route request bodies = %d, want 2", len(routeRequestBodies))
	}

	attemptArtifact := routeRequestBodies[0]
	if attemptArtifact.Path != "/sn/attempt-artifact" {
		t.Fatalf("path = %s, want /sn/attempt-artifact", attemptArtifact.Path)
	}
	clientBodyBufferSize, err := attemptArtifact.ClientBodyBufferSizeBytes()
	if err != nil || clientBodyBufferSize != 1024*1024 {
		t.Fatalf("/sn/attempt-artifact buffer = %d (%v), want %d", clientBodyBufferSize, err, 1024*1024)
	}
	clientBodyTimeout, err := attemptArtifact.ClientBodyTimeoutDuration()
	if err != nil || clientBodyTimeout != 60*time.Second {
		t.Fatalf("/sn/attempt-artifact timeout = %s (%v), want 60s", clientBodyTimeout, err)
	}

	other := routeRequestBodies[1]
	clientBodyBufferSize, err = other.ClientBodyBufferSizeBytes()
	if err != nil || clientBodyBufferSize != 0 {
		t.Fatalf("/other/route-1 buffer = %d (%v), want 0 (unset)", clientBodyBufferSize, err)
	}
	clientBodyTimeout, err = other.ClientBodyTimeoutDuration()
	if err != nil || clientBodyTimeout != time.Minute {
		t.Fatalf("/other/route-1 timeout = %s (%v), want 1m", clientBodyTimeout, err)
	}
}

// An entry the lb could not render as one exact location, a value that does
// not parse or lies outside the server-wide value up to the route maximum,
// an entry that sets nothing, and a service the lb never proxies are refused
// when the document loads, before any lb config is generated. The document
// is parsed leniently, so each would otherwise leave a route the setting
// silently does not reach.
func TestLoadServicesConfigRejectsInvalidRouteRequestBodies(t *testing.T) {
	for _, test := range []struct {
		name    string
		extra   string
		entries string
		message string
	}{
		{name: "relative path", entries: `
                -   path: sn/attempt-artifact
                    client_body_timeout: 60s
`, message: "not an exact path"},
		{name: "regex path", entries: `
                -   path: /sn/.*
                    client_body_timeout: 60s
`, message: "not an exact path"},
		{name: "nginx variable", entries: `
                -   path: /sn/$host
                    client_body_timeout: 60s
`, message: "not an exact path"},
		{name: "empty segment", entries: `
                -   path: /sn//attempt-artifact
                    client_body_timeout: 60s
`, message: "not an exact path"},
		{name: "dot segment", entries: `
                -   path: /sn/../attempt-artifact
                    client_body_timeout: 60s
`, message: "dot segment"},
		{name: "status route", entries: `
                -   path: /status
                    client_body_timeout: 60s
`, message: "generated status route"},
		{name: "repeated path", entries: `
                -   path: /sn/attempt-artifact
                    client_body_timeout: 60s
                -   path: /sn/attempt-artifact
                    client_body_buffer_size: 1mib
`, message: "more than once"},
		{name: "empty entry", entries: `
                -
`, message: "empty entry"},
		{name: "sets nothing", entries: `
                -   path: /sn/attempt-artifact
`, message: "sets nothing"},
		{name: "misspelled setting", entries: `
                -   path: /sn/attempt-artifact
                    client_body_timout: 60s
`, message: "sets nothing"},
		{name: "nginx size", entries: `
                -   path: /sn/attempt-artifact
                    client_body_buffer_size: 1m
`, message: "not a byte count"},
		{name: "size word", entries: `
                -   path: /sn/attempt-artifact
                    client_body_buffer_size: large
`, message: "not a byte count"},
		{name: "spaced size", entries: `
                -   path: /sn/attempt-artifact
                    client_body_buffer_size: 1 mib
`, message: "not a byte count"},
		{name: "unitless timeout", entries: `
                -   path: /sn/attempt-artifact
                    client_body_timeout: 60
`, message: "not a duration"},
		{name: "timeout word", entries: `
                -   path: /sn/attempt-artifact
                    client_body_timeout: forever
`, message: "not a duration"},
		{name: "fractional timeout", entries: `
                -   path: /sn/attempt-artifact
                    client_body_timeout: 60.5s
`, message: "not a whole number of seconds"},
		{name: "buffer below the server-wide size", entries: `
                -   path: /sn/attempt-artifact
                    client_body_buffer_size: 32kib
`, message: "outside 64kib..1mib"},
		{name: "buffer above the route maximum", entries: `
                -   path: /sn/attempt-artifact
                    client_body_buffer_size: 2mib
`, message: "outside 64kib..1mib"},
		{name: "zero buffer", entries: `
                -   path: /sn/attempt-artifact
                    client_body_buffer_size: 0
`, message: "outside 64kib..1mib"},
		{name: "negative buffer", entries: `
                -   path: /sn/attempt-artifact
                    client_body_buffer_size: -1mib
`, message: "outside 64kib..1mib"},
		{name: "timeout below the server-wide timeout", entries: `
                -   path: /sn/attempt-artifact
                    client_body_timeout: 10s
`, message: "outside 15s..2m0s"},
		{name: "timeout above the route maximum", entries: `
                -   path: /sn/attempt-artifact
                    client_body_timeout: 121s
`, message: "outside 15s..2m0s"},
		{name: "zero timeout", entries: `
                -   path: /sn/attempt-artifact
                    client_body_timeout: 0s
`, message: "outside 15s..2m0s"},
		{name: "negative timeout", entries: `
                -   path: /sn/attempt-artifact
                    client_body_timeout: -60s
`, message: "outside 15s..2m0s"},
		{name: "unexposed service", extra: "            exposed: false\n", entries: `
                -   path: /sn/attempt-artifact
                    client_body_timeout: 60s
`, message: "the lb does not proxy the service"},
		{name: "service without http port 80", extra: "            ports:\n                - 8080\n", entries: `
                -   path: /sn/attempt-artifact
                    client_body_timeout: 60s
`, message: "no http port 80"},
	} {
		err := loadInlineServices(t, routeRequestBodyServicesYaml(test.extra, test.entries))
		if err == nil || !strings.Contains(err.Error(), test.message) {
			t.Errorf("%s: err = %v, want %q", test.name, err, test.message)
		}
	}

	// without the generated status route, /status is an ordinary route
	if err := loadInlineServices(t, routeRequestBodyServicesYaml("            status: \"no\"\n", `
                -   path: /status
                    client_body_timeout: 60s
`)); err != nil {
		t.Fatalf("a /status route of a service without the generated status route: %s", err)
	}
}

// The bounds are inclusive: a route may set exactly the server-wide values
// and exactly the route maximums.
func TestLoadServicesConfigAcceptsRouteRequestBodyBounds(t *testing.T) {
	for _, entries := range []string{`
                -   path: /sn/attempt-artifact
                    client_body_buffer_size: 64kib
                    client_body_timeout: 15s
`, `
                -   path: /sn/attempt-artifact
                    client_body_buffer_size: 1mib
                    client_body_timeout: 2m
`, `
                -   path: /sn/attempt-artifact
                    client_body_buffer_size: 1048576
                    client_body_timeout: 120s
`} {
		if err := loadInlineServices(t, routeRequestBodyServicesYaml("", entries)); err != nil {
			t.Errorf("bounds %s: %s", entries, err)
		}
	}
}

// The bounds are the given settings' server-wide values and route
// maximums, not numbers of the validator's own.
func TestValidateRouteRequestBodiesReadsTheGivenSettings(t *testing.T) {
	serviceConfig := &ServiceConfig{
		PortConfig: PortConfig{PortSpecs: []string{"80"}},
		RouteRequestBodies: []*RouteRequestBody{
			{Path: "/sn/attempt-artifact", ClientBodyBufferSize: "512kib", ClientBodyTimeout: "30s"},
		},
	}

	if err := ValidateRouteRequestBodies(serviceConfig, DefaultRequestBodySettings()); err != nil {
		t.Fatalf("default settings: %s", err)
	}

	settings := DefaultRequestBodySettings()
	settings.ClientBodyBufferSize = 1024 * 1024
	settings.MaxRouteClientBodyBufferSize = 2 * 1024 * 1024
	if err := ValidateRouteRequestBodies(serviceConfig, settings); err == nil || !strings.Contains(err.Error(), "outside 1mib..2mib") {
		t.Fatalf("a buffer under a larger server-wide size: err = %v", err)
	}

	settings = DefaultRequestBodySettings()
	settings.MaxRouteClientBodyTimeout = 20 * time.Second
	if err := ValidateRouteRequestBodies(serviceConfig, settings); err == nil || !strings.Contains(err.Error(), "outside 15s..20s") {
		t.Fatalf("a timeout over a smaller route maximum: err = %v", err)
	}
}

// Each call returns its own instance, so a caller that tunes the settings it
// was given cannot change another's.
func TestDefaultRequestBodySettingsReturnsANewInstance(t *testing.T) {
	settings := DefaultRequestBodySettings()
	settings.ClientBodyBufferSize = 1
	settings.ClientBodyTimeout = time.Second
	settings.MaxRouteClientBodyBufferSize = 1
	settings.MaxRouteClientBodyTimeout = time.Second

	defaultSettings := DefaultRequestBodySettings()
	if defaultSettings.ClientBodyBufferSize != 64*1024 ||
		defaultSettings.ClientBodyTimeout != 15*time.Second ||
		defaultSettings.MaxRouteClientBodyBufferSize != 1024*1024 ||
		defaultSettings.MaxRouteClientBodyTimeout != 2*time.Minute {
		t.Fatalf("default settings changed with another instance: %+v", defaultSettings)
	}
}
