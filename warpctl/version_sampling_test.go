package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coreos/go-semver/semver"
)

func setupTransparentStatusTestVault(t *testing.T) string {
	t.Helper()
	return setupTestVault(t, []byte(`
domain: example.com
domains:
    example.com: route53

versions:
-   external_ports: 7000-7200,7443-7449
    internal_ports: 7201-7442,7450-10000
    routing_tables: 100-120
    parallel_block_count: 30
    services_docker_network: testservices
    lb:
        ports:
            - 80
            - 443
        interfaces:
            edge-0.example.com:
                eth0:
                    docker_network: warpeth0
                    ipv4: 10.0.0.1
                    ipv6: "fd00::1"
            metrics-0.example.com:
                eth0:
                    transparent: true
                    docker_network: warpeth0
                    ipv4: 10.0.0.2
                    ipv6: "fd00::2"
    host_services:
        metrics-0.example.com:
            - svc-direct
    services:
        svc-direct:
            hosts:
                - metrics-0.example.com
            ports:
                - 80
            blocks:
                - g1: 1
        svc-normal:
            ports:
                - 80
            blocks:
                - g1: 1
`))
}

func TestTransparentVersionListingDoesNotPollMissingLbRoute(t *testing.T) {
	env := setupTransparentStatusTestVault(t)
	previousOutput := Out.Writer()
	output := &bytes.Buffer{}
	Out.SetOutput(output)
	t.Cleanup(func() { Out.SetOutput(previousOutput) })

	pollCalls := 0
	err := sampleListedBlockVersions(
		env,
		"svc-direct",
		[]string{"g1"},
		func(string) bool { return true },
		func(string, string, []string, string, time.Duration) { pollCalls++ },
	)
	if err == nil || !strings.Contains(err.Error(), "transparent") {
		t.Fatalf("transparent status sampling error = %v", err)
	}
	if pollCalls != 0 {
		t.Fatalf("transparent service issued %d status polls, want 0", pollCalls)
	}
	if output.Len() != 0 {
		t.Fatalf("transparent service emitted sampled block output %q", output.String())
	}
}

func TestTransparentOnlyOlderSamplingFailsClosed(t *testing.T) {
	env := setupTransparentStatusTestVault(t)
	versions, err := sampleBlockCurrentVersions(env, "svc-direct", "g1")
	if err == nil || !strings.Contains(err.Error(), "transparent") {
		t.Fatalf("transparent current-version sampling error = %v", err)
	}
	if versions != nil {
		t.Fatalf("transparent current-version sampling = %v, want nil", versions)
	}
}

func TestOnlyOlderFailsClosedWithoutObservedVersion(t *testing.T) {
	_, err := filterOlderDeployBlocks(
		"2026.8.31+2",
		[]string{"g1"},
		map[string]map[semver.Version]float32{},
	)
	if err == nil || !strings.Contains(err.Error(), "no observed running version") {
		t.Fatalf("missing live version error = %v", err)
	}
}

func TestOnlyOlderSelectsEntirelyOlderBlocks(t *testing.T) {
	older := *semver.New("2026.8.31+1")
	equal := *semver.New("2026.8.31+2")
	blocks, err := filterOlderDeployBlocks(
		"2026.8.31+2",
		[]string{"g1", "g2"},
		map[string]map[semver.Version]float32{
			"g1": {older: 100},
			"g2": {equal: 100},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(blocks) != 1 || blocks[0] != "g1" {
		t.Fatalf("selected blocks = %v, want [g1]", blocks)
	}
}

// A stale LB generation can still rate-limit its control-plane path during a
// rollout. Sampling must preserve that 429 as an error instead of parsing its
// body, reporting an old version, or silently retrying and adding more load.
func TestVersionSamplingPreservesHttpRateLimitFailure(t *testing.T) {
	requestCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requestCount++
		http.Error(w, "rate limited", http.StatusTooManyRequests)
	}))
	defer server.Close()

	statusVersions := sampleStatusVersions(1, []string{server.URL})
	if requestCount != 1 {
		t.Fatalf("rate-limited sample issued %d requests, want 1", requestCount)
	}
	if len(statusVersions.versions) != 0 || len(statusVersions.configVersions) != 0 {
		t.Fatalf(
			"rate-limited sample reported versions=%v config_versions=%v",
			statusVersions.versions,
			statusVersions.configVersions,
		)
	}

	errorCount := 0
	for message, count := range statusVersions.errors {
		errorCount += count
		if !strings.HasPrefix(message, "error http status 429 -> ") {
			t.Errorf("rate-limit error = %q, want HTTP status and selected peer", message)
		}
	}
	if errorCount != 1 {
		t.Fatalf("rate-limit error count = %d, want 1", errorCount)
	}
}

// An application readiness error is different from a synthetic transport
// failure: its parsed version remains useful rollout evidence even though the
// status must still fail the sample.
func TestVersionSamplingRetainsVersionFromErrorStatusPayload(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"version":"2026.9.3+1","status":"error not ready"}`))
	}))
	defer server.Close()

	statusVersions := sampleStatusVersions(1, []string{server.URL})
	versionCount := 0
	for _, count := range statusVersions.versions {
		versionCount += count
	}
	if versionCount != 1 {
		t.Fatalf("readiness-error version count = %d, want 1", versionCount)
	}
	if count := statusVersions.errors["error not ready"]; count != 1 {
		t.Fatalf("readiness-error count = %d, want 1", count)
	}
}
