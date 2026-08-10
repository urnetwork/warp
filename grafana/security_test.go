package main

// Regression tests cover the configuration split, exact peer boundary, and
// authenticated bounded ingestion used to close the observability findings.

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"
)

// Scoped secrets may populate credentials but cannot replace ordinary ports or
// storage topology from config.
func TestMergeGrafanaConfigOverlaysCredentialsOnly(t *testing.T) {
	ordinary := GrafanaConfig{
		LocalPort: 3100,
		Postgres:  &PostgresConfig{Port: 5432, User: "grafana", Database: "grafana"},
		Users: []*ServiceUser{
			{Name: "fluent-bit", Roles: []string{"push"}},
		},
	}
	secrets := GrafanaConfig{
		LocalPort: 9999,
		Postgres:  &PostgresConfig{Port: 9999, Password: "database-secret"},
		Users: []*ServiceUser{
			{Name: "fluent-bit", Password: "push-secret"},
		},
	}

	merged, err := mergeGrafanaConfig(ordinary, secrets)
	if err != nil {
		t.Fatal(err)
	}
	if merged.LocalPort != 3100 || merged.Postgres.Port != 5432 {
		t.Fatalf("secret file replaced ordinary topology: %+v", merged)
	}
	if merged.Postgres.Password != "database-secret" {
		t.Fatal("postgres credential was not overlaid")
	}
	if merged.Users[0].Password != "push-secret" || len(merged.Users[0].Roles) != 1 || merged.Users[0].Roles[0] != "push" {
		t.Fatalf("service user merge = %+v", merged.Users[0])
	}
}

// Credentials in broadly mounted ordinary config fail instead of becoming an
// accidental second secret source.
func TestMergeGrafanaConfigRejectsCredentialInOrdinaryConfig(t *testing.T) {
	ordinary := GrafanaConfig{Postgres: &PostgresConfig{Password: "misplaced-secret"}}
	if _, err := mergeGrafanaConfig(ordinary, GrafanaConfig{}); err == nil {
		t.Fatal("expected an ordinary-config credential to fail")
	}
}

// Authorization roles in the secret document are rejected rather than merged.
func TestMergeGrafanaConfigRejectsSecretRole(t *testing.T) {
	ordinary := GrafanaConfig{Users: []*ServiceUser{{Name: "reader", Roles: []string{"query"}}}}
	secrets := GrafanaConfig{Users: []*ServiceUser{{Name: "reader", Password: "secret", Roles: []string{"push"}}}}
	if _, err := mergeGrafanaConfig(ordinary, secrets); err == nil {
		t.Fatal("expected a secret-owned role to fail")
	}
}

// A secret-only identity cannot create a new push/query principal.
func TestMergeGrafanaConfigRejectsSecretOnlyUser(t *testing.T) {
	ordinary := GrafanaConfig{Users: []*ServiceUser{{Name: "reader", Roles: []string{"query"}}}}
	secrets := GrafanaConfig{Users: []*ServiceUser{{Name: "attacker", Password: "secret", Roles: []string{"query"}}}}
	if _, err := mergeGrafanaConfig(ordinary, secrets); err == nil {
		t.Fatal("expected a secret-only service user to fail")
	}
}

// An authorized identity cannot fall back to an empty Basic Auth password.
func TestMergeGrafanaConfigRequiresAuthorizedUserPassword(t *testing.T) {
	ordinary := GrafanaConfig{Users: []*ServiceUser{{Name: "reader", Roles: []string{"query"}}}}
	if _, err := mergeGrafanaConfig(ordinary, GrafanaConfig{}); err == nil {
		t.Fatal("expected an authorized user without a password to fail")
	}
}

// Ring ingress accepts an exact configured route source and rejects adjacent
// private addresses that previously reached an all-interface listener.
func TestRingRemoteAllowedUsesExactSourceIp(t *testing.T) {
	allowedIps := map[netip.Addr]bool{netip.MustParseAddr("10.10.0.4"): true}
	allowedAddr := &net.TCPAddr{IP: net.ParseIP("10.10.0.4"), Port: 41000}
	deniedAddr := &net.TCPAddr{IP: net.ParseIP("10.10.0.5"), Port: 41000}
	if !ringRemoteAllowed(allowedAddr, allowedIps) {
		t.Fatal("configured ring peer was rejected")
	}
	if ringRemoteAllowed(deniedAddr, allowedIps) {
		t.Fatal("unconfigured private source was accepted")
	}
}

// Missing topology routes fail closed instead of falling back to every route.
func TestRingAllowedIpsRejectsMissingRoute(t *testing.T) {
	hostSettings := &HostSettings{Routes: map[string]string{"edge-a": "10.10.0.4"}}
	if _, err := ringAllowedIps(hostSettings, []string{"edge-a", "edge-b"}); err == nil {
		t.Fatal("expected a missing ring route to fail")
	}
}

// Local ingestion uses the same role authentication as public ingestion.
func TestAuthenticatedPushHandlerRejectsMissingCredential(t *testing.T) {
	called := false
	handler := authenticatedPushHandler(
		[]*ServiceUser{{Name: "writer", Password: "secret", Roles: []string{"push"}}},
		1024,
		http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }),
	)
	request := httptest.NewRequest(http.MethodPost, "/loki/api/v1/push", strings.NewReader("log"))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized || called {
		t.Fatalf("response = %d, backend called = %t", response.Code, called)
	}
}

// An empty stored password never authorizes an explicitly empty credential.
func TestRequireRoleRejectsEmptyStoredPassword(t *testing.T) {
	called := false
	handler := requireRole(
		[]*ServiceUser{{Name: "writer", Roles: []string{"push"}}},
		"push",
		http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }),
	)
	request := httptest.NewRequest(http.MethodPost, "/loki/api/v1/push", strings.NewReader("log"))
	request.SetBasicAuth("writer", "")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized || called {
		t.Fatalf("response = %d, backend called = %t", response.Code, called)
	}
}

// An authenticated request above the route cap deterministically reaches a
// MaxBytesError before a backend can process the oversized payload.
func TestAuthenticatedPushHandlerLimitsBody(t *testing.T) {
	handler := authenticatedPushHandler(
		[]*ServiceUser{{Name: "writer", Password: "secret", Roles: []string{"push"}}},
		4,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if _, err := io.ReadAll(r.Body); err != nil {
				http.Error(w, "too large", http.StatusRequestEntityTooLarge)
			}
		}),
	)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/push", strings.NewReader("12345"))
	request.SetBasicAuth("writer", "secret")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("response = %d, want %d", response.Code, http.StatusRequestEntityTooLarge)
	}
}

// All bundled third-party child listeners use loopback behind the Go front.
func TestChildListenAddressIsLoopback(t *testing.T) {
	if childListenAddress != "127.0.0.1" {
		t.Fatalf("child listen address = %q", childListenAddress)
	}
}

// The old non-host-networking fallback cannot restore a wildcard public bind.
func TestValidateExactListenAddrsRejectsWildcard(t *testing.T) {
	for _, listenAddrs := range [][]string{{":80"}, {"0.0.0.0:80"}, {"[::]:80"}} {
		if err := validateExactListenAddrs(listenAddrs); err == nil {
			t.Errorf("listen addresses %v were accepted", listenAddrs)
		}
	}
}

// Concrete IPv4 and IPv6 service addresses remain valid.
func TestValidateExactListenAddrsAcceptsConcreteIps(t *testing.T) {
	listenAddrs := []string{"192.0.2.4:8080", "[2001:db8::4]:8080"}
	if err := validateExactListenAddrs(listenAddrs); err != nil {
		t.Fatal(err)
	}
}

// A full TCP limiter rejects immediately and admits again after release.
func TestRingSessionLimiterBoundsConcurrency(t *testing.T) {
	limiter := newRingSessionLimiter(2)
	if !limiter.tryAcquire() || !limiter.tryAcquire() {
		t.Fatal("limiter rejected an available slot")
	}
	if limiter.tryAcquire() {
		t.Fatal("limiter admitted a session above capacity")
	}
	limiter.release()
	if !limiter.tryAcquire() {
		t.Fatal("limiter did not return a released slot")
	}
}

// UDP source rate windows reject excess datagrams and reset on a deterministic
// one-second boundary.
func TestRingDatagramRateBoundsAndResets(t *testing.T) {
	rate := &ringDatagramRate{}
	start := time.Unix(100, 0)
	if !rate.allow(start, 2) || !rate.allow(start, 2) {
		t.Fatal("rate rejected an in-limit datagram")
	}
	if rate.allow(start, 2) {
		t.Fatal("rate admitted a datagram above the window limit")
	}
	if !rate.allow(start.Add(time.Second), 2) {
		t.Fatal("rate did not reset at the next window")
	}
}

// UDP session creation stops at the fixed aggregate capacity.
func TestRingUdpSessionAvailableAtBoundary(t *testing.T) {
	if !ringUdpSessionAvailable(maxRingUdpSessions - 1) {
		t.Fatal("last available UDP session slot was rejected")
	}
	if ringUdpSessionAvailable(maxRingUdpSessions) {
		t.Fatal("UDP session cap admitted an extra source")
	}
}
