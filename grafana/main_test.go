package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/urnetwork/warp"
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

// A container whose loki or mimir never finished starting must not pass the
// deploy poll. The front used to answer /status ok the moment it bound, so on
// 2026-08-17 edge-4 installed a loki whose query modules stayed in Starting
// and the deploy reported success: front=200 graf=200 up=1 restarts=0 while
// every log query on that host 503'd for 16 hours (SIGNALS.md 11.2, 11.13).
func TestNotReadyStatusFailsTheWarpctlDeployPoll(t *testing.T) {
	statusJson := notReadyStatusJson(errors.New("loki: 503 Starting: 4 Running: 12"))

	var parsed struct {
		Status string `json:"status"`
	}
	if err := json.Unmarshal(statusJson, &parsed); err != nil {
		t.Fatalf("unmarshal: %s", err)
	}

	// the contract with warpctl WarpStatusResponse.IsError, which is the only
	// thing that fails a poll. The http status code is not read there
	warpctlIsError := regexp.MustCompile(`^(?i)error(\s|:)`)
	if !warpctlIsError.MatchString(parsed.Status) {
		t.Fatalf("status does not fail the warpctl poll: %q", parsed.Status)
	}
	// and it has to name the child, so the failing poll in the journal says
	// which one
	if !strings.Contains(parsed.Status, "loki") {
		t.Fatalf("status does not name the unready child: %q", parsed.Status)
	}
}

// The probe's diagnostic value is the body: loki answers 503 with the modules
// that have not started, and that is what distinguishes a wedged query path
// from a child that is simply still booting.
func TestCheckChildReadyReportsTheUnreadyBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		w.Write([]byte("Some services are not Running:\nStarting: 4\nRunning: 12\n"))
	}))
	defer server.Close()

	err := checkChildReady(
		context.Background(),
		newChildReadyClient(),
		childReadyCheck{name: "loki", url: server.URL},
	)
	if err == nil {
		t.Fatalf("503 must not read as ready")
	}
	for _, want := range []string{"loki", "503", "Starting: 4"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error %q missing %q", err, want)
		}
	}
}

// The latch is one way. It must wait for every child, tolerate a check that
// flaps while the fleet cycles (loki and mimir gate /ready on their rings), and
// never un-ready an already serving container: the deploy poll's job is to
// stop a broken container taking over, not to pull a live one out of rotation.
func TestReadinessLatchWaitsForEveryChildThenLatches(t *testing.T) {
	var lokiReady atomic.Bool
	newChild := func(ready *atomic.Bool) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if ready == nil || ready.Load() {
				w.Write([]byte("ready"))
				return
			}
			w.WriteHeader(http.StatusServiceUnavailable)
			w.Write([]byte("Starting: 4"))
		}))
	}

	loki := newChild(&lokiReady)
	defer loki.Close()
	mimir := newChild(nil)
	defer mimir.Close()
	grafana := newChild(nil)
	defer grafana.Close()

	checks := []childReadyCheck{
		{name: "loki", url: loki.URL},
		{name: "mimir", url: mimir.URL},
		{name: "grafana", url: grafana.URL},
	}

	event := warp.NewEvent()
	defer event.Set()

	latch := newReadinessLatch()
	go latch.watch(event, checks)

	// loki is not ready, so the container must not take over
	time.Sleep(readinessCheckInterval + 500*time.Millisecond)
	if ready, err := latch.status(); ready {
		t.Fatalf("latched ready while loki was 503")
	} else if !strings.Contains(err.Error(), "loki") {
		t.Fatalf("unready error does not name loki: %s", err)
	}

	lokiReady.Store(true)
	deadline := time.Now().Add(10 * time.Second)
	for {
		if ready, _ := latch.status(); ready {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("never latched ready after loki came up")
		}
		time.Sleep(50 * time.Millisecond)
	}

	// a later blip must not pull the serving container back out
	lokiReady.Store(false)
	time.Sleep(2 * readinessCheckInterval)
	if ready, _ := latch.status(); !ready {
		t.Fatalf("latch un-readied a container that had already taken over")
	}
}

// The env has exactly one redis and it is clustered, where grafana's remote
// cache fails every write with "ERR SELECT is not allowed in cluster mode".
// The shared postgres is the only store a fleet-wide cache can use here.
func TestRemoteCacheUsesTheGrafanaDatabaseNotTheClusteredRedis(t *testing.T) {
	section := renderRemoteCacheSection(&GrafanaConfig{
		Postgres: &PostgresConfig{Password: "test"},
		// still configured, and still must not be used
		Redis: &RedisConfig{Hostname: "redis.test", Port: 6379, Database: 8},
	})

	if !strings.Contains(section, "type = database") {
		t.Fatalf("remote cache is not the state database: %q", section)
	}
	for _, unwanted := range []string{"redis", "connstr", "db=8"} {
		if strings.Contains(section, unwanted) {
			t.Fatalf("remote cache still addresses redis (%q): %q", unwanted, section)
		}
	}
}
