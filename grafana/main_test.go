package main

import (
	"testing"

	"gopkg.in/yaml.v3"
)

// minio.hostname may thread `{{ env:BRINGYOUR_MINIO_HOSTNAME }}` (the vault
// value convention) and must resolve through the settings routes to the lan
// ip before it is written into the loki/mimir s3 configs. This covers routing
// and the process-environment fallback; settings.yml env_vars, the carrier
// that production actually uses, is covered below.
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

// settings.yml env_vars is the only carrier of the BRINGYOUR_* values into
// this container: warpctl emits `--envvar=` for services.yml env_vars only, so
// the process environment never holds them (the server binary sees them solely
// because server env.go replays settings env_vars through os.Setenv at init).
// Resolving `{{ env:... }}` from the process environment alone panicked every
// grafana container at startup on 2026-08-11 once grafana.yml threaded the
// minio hostname that way — a fleet-wide crash loop that took down the hosts
// which had already dropped their previous container.
func TestResolveMinioEndpointFromSettingsEnvVars(t *testing.T) {
	hostSettings := &HostSettings{
		EnvVars: map[string]string{
			"BRINGYOUR_MINIO_HOSTNAME": "192.168.1.77",
		},
		Routes: map[string]string{
			"test-minio-host": "192.168.1.77",
		},
	}

	// the production shape: a raw lan ip in settings env_vars, nothing in the
	// process environment
	ip, port := resolveMinioEndpoint(hostSettings, &GrafanaConfig{
		Minio: &MinioConfig{Hostname: "{{ env:BRINGYOUR_MINIO_HOSTNAME }}", Port: 23900},
	})
	if ip != "192.168.1.77" || port != 23900 {
		t.Fatalf("settings env_vars: %s:%d", ip, port)
	}

	// settings env_vars win over the process environment, matching the server,
	// where os.Setenv overwrites whatever the process inherited
	t.Setenv("BRINGYOUR_MINIO_HOSTNAME", "10.9.9.9")
	ip, _ = resolveMinioEndpoint(hostSettings, &GrafanaConfig{
		Minio: &MinioConfig{Hostname: "{{ env:BRINGYOUR_MINIO_HOSTNAME }}"},
	})
	if ip != "192.168.1.77" {
		t.Fatalf("settings env_vars must win over the process environment: %s", ip)
	}
}

// The provisioned datasources must address the stable local publish port.
// Grafana's datasource rows are shared fleet-wide through the env postgres and
// upserted by uid, so a warp allocated child port here (those differ per host
// and per deploy) leaves every host except the one that wrote the row dialing a
// dead port. That is the 2026-08-11 "no data" public dashboard: mimir was
// healthy on 14579 while the shared row still pointed at another host's 14578.
func TestRenderDatasourcesYamlUsesStableLocalPort(t *testing.T) {
	// a distinctive port, so the assertion cannot pass on the default
	datasourcesYaml := renderDatasourcesYaml(9999)

	var parsed struct {
		Datasources []struct {
			Uid string `yaml:"uid"`
			Url string `yaml:"url"`
		} `yaml:"datasources"`
	}
	if err := yaml.Unmarshal([]byte(datasourcesYaml), &parsed); err != nil {
		t.Fatalf("unmarshal: %s", err)
	}

	urls := map[string]string{}
	for _, datasource := range parsed.Datasources {
		urls[datasource.Uid] = datasource.Url
	}
	if urls["warp-loki"] != "http://127.0.0.1:9999" {
		t.Fatalf("loki url: %s", urls["warp-loki"])
	}
	// grafana appends the prometheus api path to this base
	if urls["warp-mimir"] != "http://127.0.0.1:9999/prometheus" {
		t.Fatalf("mimir url: %s", urls["warp-mimir"])
	}
}
