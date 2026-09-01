package main

import (
	"bytes"
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
