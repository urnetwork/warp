package main

import (
	"testing"
)

// minio.hostname may thread `{{ env:BRINGYOUR_MINIO_HOSTNAME }}` (the vault
// value convention) and must resolve through the settings routes to the lan
// ip before it is written into the loki/mimir s3 configs.
func TestResolveMinioEndpointEnvAndRoutes(t *testing.T) {
	hostSettings := &HostSettings{
		Routes: map[string]string{
			"test-minio-host": "192.168.1.3",
		},
	}

	// literal hostname routes to the lan ip; default port applies
	ip, port := resolveMinioEndpoint(hostSettings, &GrafanaConfig{
		Minio: &MinioConfig{Hostname: "test-minio-host"},
	})
	if ip != "192.168.1.3" || port != defaultMinioPort {
		t.Fatalf("literal hostname: %s:%d", ip, port)
	}

	// env-interpolated hostname resolves then routes
	t.Setenv("BRINGYOUR_MINIO_HOSTNAME", "test-minio-host")
	ip, port = resolveMinioEndpoint(hostSettings, &GrafanaConfig{
		Minio: &MinioConfig{Hostname: "{{ env:BRINGYOUR_MINIO_HOSTNAME }}", Port: 23900},
	})
	if ip != "192.168.1.3" || port != 23900 {
		t.Fatalf("env hostname: %s:%d", ip, port)
	}

	// a hostname not in routes passes through unchanged
	ip, _ = resolveMinioEndpoint(hostSettings, &GrafanaConfig{
		Minio: &MinioConfig{Hostname: "10.1.2.3"},
	})
	if ip != "10.1.2.3" {
		t.Fatalf("passthrough: %s", ip)
	}

	// the production shape: the env var holds a raw lan ip — interpolates,
	// misses routes, passes through
	t.Setenv("BRINGYOUR_MINIO_HOSTNAME_IP", "192.168.1.2")
	ip, port = resolveMinioEndpoint(hostSettings, &GrafanaConfig{
		Minio: &MinioConfig{Hostname: "{{ env:BRINGYOUR_MINIO_HOSTNAME_IP }}"},
	})
	if ip != "192.168.1.2" || port != defaultMinioPort {
		t.Fatalf("env ip passthrough: %s:%d", ip, port)
	}

	// a bare ipv6 literal is bracketed so the callers' host:port formatting
	// yields a valid endpoint
	ip, _ = resolveMinioEndpoint(hostSettings, &GrafanaConfig{
		Minio: &MinioConfig{Hostname: "fd00::93"},
	})
	if ip != "[fd00::93]" {
		t.Fatalf("ipv6 bracket: %s", ip)
	}

	// an unset env var panics (a literal template endpoint would fail far
	// less legibly at loki/mimir runtime)
	defer func() {
		if recover() == nil {
			t.Fatal("unset env var must panic")
		}
	}()
	resolveMinioEndpoint(hostSettings, &GrafanaConfig{
		Minio: &MinioConfig{Hostname: "{{ env:BRINGYOUR_MINIO_HOSTNAME_UNSET }}"},
	})
}
