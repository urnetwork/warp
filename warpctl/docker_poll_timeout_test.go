package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// Exercise the actual HTTP sampler and target-version poll. A completed poll
// cannot imply convergence when every responding instance is still old.
func TestPollStatusUntilReportsUnconvergedDeployment(t *testing.T) {
	const desired = "2026.10.4-new+2"
	for _, test := range []struct {
		name, version, status, target string
		timeout                       time.Duration
		wantError                     bool
	}{
		{"old_zero_budget", "2026.10.4-old+1", "ok", desired, 0, true},
		{"old_expired_budget", "2026.10.4-old+1", "ok", desired, time.Nanosecond, true},
		{"desired_but_not_ready", desired, "error not ready: pg", desired, 0, true},
		{"desired_ready", desired, "ok", desired, 0, false},
		{"status_listing_has_no_target", "2026.10.4-old+1", "ok", "", 0, false},
		{"status_listing_preserves_errors", desired, "error not ready: pg", "", 0, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if err := json.NewEncoder(w).Encode(map[string]any{"version": test.version, "status": test.status}); err != nil {
					t.Error(err)
				}
			}))
			defer server.Close()
			err := pollStatusUntil("synthetic", "api", 1, []string{server.URL + "/private-route"}, test.target, test.timeout)
			if (err != nil) != test.wantError {
				t.Fatalf("poll convergence error=%v, want error=%t", err, test.wantError)
			}
			if err != nil && (strings.Contains(err.Error(), server.URL) || strings.Contains(err.Error(), "private-route")) {
				t.Fatal("poll timeout exposed its private status route")
			}
		})
	}
}

func TestPollStatusUntilDoesNotAcceptMissingOrMixedVersions(t *testing.T) {
	const desired = "2026.10.4-new+2"
	if err := pollStatusUntil("synthetic", "api", 1, nil, desired, 0); err == nil {
		t.Fatal("empty sample cannot establish target convergence")
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		version := desired
		if r.URL.Path == "/old" {
			version = "2026.10.4-old+1"
		}
		if err := json.NewEncoder(w).Encode(map[string]any{"version": version, "status": "ok"}); err != nil {
			t.Error(err)
		}
	}))
	defer server.Close()
	if err := pollStatusUntil("synthetic", "api", 1, []string{server.URL + "/old", server.URL + "/new"}, desired, 0); err == nil {
		t.Fatal("mixed fleet cannot establish target convergence")
	}
}
