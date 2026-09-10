package main

import (
	"context"
	"encoding/json"
	"errors"
	"net"
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
			Uid  string `yaml:"uid"`
			Type string `yaml:"type"`
			Url  string `yaml:"url"`
		} `yaml:"datasources"`
	}
	if err := yaml.Unmarshal([]byte(datasourcesYaml), &parsed); err != nil {
		t.Fatalf("unmarshal: %s", err)
	}

	urls := map[string]string{}
	types := map[string]string{}
	for _, datasource := range parsed.Datasources {
		urls[datasource.Uid] = datasource.Url
		types[datasource.Uid] = datasource.Type
	}
	if urls["warp-loki"] != "http://127.0.0.1:9999" {
		t.Fatalf("loki url: %s", urls["warp-loki"])
	}
	if types["warp-loki"] != "loki" {
		t.Fatalf("Logs Drilldown datasource type: %q", types["warp-loki"])
	}
	// grafana appends the prometheus api path to this base
	if urls["warp-mimir"] != "http://127.0.0.1:9999/prometheus" {
		t.Fatalf("mimir url: %s", urls["warp-mimir"])
	}
}

// Mimir enables query-frontend statistics by default and emits a successful
// info line per request. Keep query execution and metrics unchanged while
// making the rendered opt-out explicit. The streaming evaluator has a separate
// unconditional info path covered by TestMimirRoutineLogsStayAtSource.
func TestMimirFrontendDisablesPerQueryStatistics(t *testing.T) {
	frontend := mimirFrontendConfig("192.0.2.10", 6491)

	queryStatsEnabled, ok := frontend["query_stats_enabled"].(bool)
	if !ok {
		t.Fatalf("query_stats_enabled is not a boolean: %#v", frontend["query_stats_enabled"])
	}
	if queryStatsEnabled {
		t.Fatal("Mimir per-query statistics remain enabled")
	}
	if frontend["address"] != "192.0.2.10" || frontend["port"] != 6491 {
		t.Fatalf("frontend ring identity changed: %#v", frontend)
	}

	rendered, err := yaml.Marshal(map[string]any{"frontend": frontend})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(rendered), "query_stats_enabled: false") {
		t.Fatalf("rendered Mimir config omitted explicit query-stats opt-out:\n%s", rendered)
	}
}

// Mimir 3.1.1 does not gate streamingpromql's `evaluation stats` line on the
// frontend query-statistics option. In the single-binary fleet, alert rules
// therefore produced hundreds of routine info records per minute even after
// query_stats_enabled=false was deployed. Keep warning/error evidence while
// stopping those records at their source. A one-minute bucket-index refresh
// also bounds the independently jittered store-gateway version gap that was
// observed emitting the same warning for 882 seconds on every query.
func TestMimirRoutineLogsStayAtSource(t *testing.T) {
	server := mimirServerConfig(3201, 16491)
	if server["log_level"] != "warn" {
		t.Fatalf("Mimir routine info logging remains enabled: %#v", server)
	}
	if server["http_listen_address"] != childListenAddress || server["http_listen_port"] != 3201 {
		t.Fatalf("Mimir HTTP listener changed: %#v", server)
	}
	if server["grpc_listen_address"] != childListenAddress || server["grpc_listen_port"] != 16491 {
		t.Fatalf("Mimir gRPC listener changed: %#v", server)
	}

	bucketStore := mimirBucketStoreConfig()
	if bucketStore["sync_dir"] != "/var/lib/mimir/tsdb-sync" {
		t.Fatalf("Mimir bucket sync directory changed: %#v", bucketStore)
	}
	if bucketStore["sync_interval"] != "1m" {
		t.Fatalf("Mimir bucket-index skew remains near the 15-minute default: %#v", bucketStore)
	}

	rendered, err := yaml.Marshal(map[string]any{
		"server": server,
		"blocks_storage": map[string]any{
			"bucket_store": bucketStore,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		"log_level: warn",
		"sync_interval: 1m",
	} {
		if !strings.Contains(string(rendered), required) {
			t.Fatalf("rendered Mimir config omitted %q:\n%s", required, rendered)
		}
	}
}

// Mimir normally expects its incomplete TSDB head to survive a restart. The
// Grafana bundle intentionally uses an ephemeral data directory because old
// and new deploy generations overlap, so that default erased the recent head
// on every fleet restart. The clean-shutdown flush is the persistence boundary.
func TestMimirTSDBFlushesEphemeralHeadOnShutdown(t *testing.T) {
	tsdb := mimirTSDBConfig()

	if tsdb["dir"] != "/var/lib/mimir/tsdb" {
		t.Fatalf("Mimir TSDB directory changed: %#v", tsdb)
	}
	flush, ok := tsdb["flush_blocks_on_shutdown"].(bool)
	if !ok || !flush {
		t.Fatalf("Mimir can discard its ephemeral head on shutdown: %#v", tsdb)
	}

	rendered, err := yaml.Marshal(map[string]any{"blocks_storage": map[string]any{"tsdb": tsdb}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(rendered), "flush_blocks_on_shutdown: true") {
		t.Fatalf("rendered Mimir config omitted the shutdown flush:\n%s", rendered)
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

func TestCheckChildReadyExecutesBothGrafanaDatasources(t *testing.T) {
	const adminPassword = "test-admin-password"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/ds/query" {
			t.Errorf("datasource request = %s %s", r.Method, r.URL.Path)
		}
		username, password, ok := r.BasicAuth()
		if !ok || username != "admin" || password != adminPassword {
			t.Errorf("datasource basic auth = %q/%q/%t", username, password, ok)
		}
		var payload struct {
			Queries []struct {
				RefID      string `json:"refId"`
				Expr       string `json:"expr"`
				Datasource struct {
					UID  string `json:"uid"`
					Type string `json:"type"`
				} `json:"datasource"`
			} `json:"queries"`
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Errorf("decode datasource payload: %s", err)
		}
		if len(payload.Queries) != 2 {
			t.Errorf("datasource query count = %d", len(payload.Queries))
		} else {
			if payload.Queries[0].RefID != "M" || payload.Queries[0].Datasource.UID != "warp-mimir" || payload.Queries[0].Datasource.Type != "prometheus" || payload.Queries[0].Expr != "vector(1)" {
				t.Errorf("Mimir readiness query = %+v", payload.Queries[0])
			}
			if payload.Queries[1].RefID != "L" || payload.Queries[1].Datasource.UID != "warp-loki" || payload.Queries[1].Datasource.Type != "loki" || payload.Queries[1].Expr != `sum(count_over_time({service="web"}[1m]))` {
				t.Errorf("Loki readiness query = %+v", payload.Queries[1])
			}
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"results":{"M":{"status":200,"frames":[]},"L":{"status":200,"frames":[]}}}`))
	}))
	defer server.Close()

	checks := childReadyChecks(3101, 3201, 3000, adminPassword)
	check := requireChildReadyCheck(checks, "grafana-datasources")
	check.url = server.URL + "/api/ds/query"
	if err := checkChildReady(context.Background(), newChildReadyClient(), check); err != nil {
		t.Fatalf("healthy datasource readiness query: %s", err)
	}
}

func TestCheckChildReadyRejectsGrafanaDatasourcePluginFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"statusCode":404,"messageId":"plugin.notRegistered","message":"Plugin not registered"}`))
	}))
	defer server.Close()

	check := childReadyCheck{
		name:                       "grafana-datasources",
		url:                        server.URL,
		method:                     http.MethodPost,
		body:                       `{}`,
		username:                   "admin",
		password:                   "must-not-leak",
		requireDatasourceQueryBody: true,
	}
	err := checkChildReady(context.Background(), newChildReadyClient(), check)
	if err == nil {
		t.Fatal("plugin.notRegistered must fail readiness")
	}
	for _, want := range []string{"grafana-datasources", "404", "plugin.notRegistered"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("readiness error %q missing %q", err, want)
		}
	}
	if strings.Contains(err.Error(), check.password) {
		t.Fatalf("readiness error leaked the Grafana password: %q", err)
	}
}

func TestValidateDatasourceQueryResponseRejectsEmbeddedFailure(t *testing.T) {
	err := validateDatasourceQueryResponse(
		[]byte(`{"results":{"M":{"status":200,"frames":[]},"L":{"status":500,"error":"plugin not registered"}}}`),
		"M",
		"L",
	)
	if err == nil || !strings.Contains(err.Error(), "query L: plugin not registered") {
		t.Fatalf("embedded datasource failure = %v", err)
	}
}

// A candidate must not join the stable publisher pool until every direct
// child check passes. The datasource check runs afterward because Grafana's
// provisioned datasource deliberately traverses that stable loopback front.
// Even then /status must not latch ready until activation and the second phase
// are complete.
func TestReadinessWaitsForChildrenThenPublisherAndLatches(t *testing.T) {
	var lokiReady atomic.Bool
	var publisherActive atomic.Bool
	var publisherChecks atomic.Int32
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
	publisherCheck := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		publisherChecks.Add(1)
		if publisherActive.Load() {
			w.Write([]byte("ready"))
			return
		}
		w.WriteHeader(http.StatusServiceUnavailable)
		w.Write([]byte("publisher inactive"))
	}))
	defer publisherCheck.Close()

	checks := []childReadyCheck{
		{name: "loki", url: loki.URL},
		{name: "mimir", url: mimir.URL},
		{name: "grafana-datasources", url: publisherCheck.URL, requiresPublisher: true},
	}

	event := warp.NewEvent()
	defer event.Set()

	latch := newReadinessLatch()
	serveErrors := make(chan error, 1)
	activationStarted := make(chan struct{})
	finishActivation := make(chan struct{})
	type activationResult struct {
		active bool
		err    error
	}
	result := make(chan activationResult, 1)
	go func() {
		active, err := activatePublishersWhenReady(event, latch, checks, serveErrors, func() error {
			close(activationStarted)
			<-finishActivation
			publisherActive.Store(true)
			return nil
		})
		result <- activationResult{active: active, err: err}
	}()

	// Loki is not ready, so neither publisher activation nor the dependent
	// datasource check may begin.
	time.Sleep(readinessCheckInterval + 500*time.Millisecond)
	if ready, err := latch.status(); ready {
		t.Fatalf("latched ready while loki was 503")
	} else if !strings.Contains(err.Error(), "loki") {
		t.Fatalf("unready error does not name loki: %s", err)
	}
	select {
	case <-activationStarted:
		t.Fatal("publisher activated before every direct child was ready")
	default:
	}
	if got := publisherChecks.Load(); got != 0 {
		t.Fatalf("publisher-dependent checks ran before activation: %d", got)
	}

	lokiReady.Store(true)
	select {
	case <-activationStarted:
	case <-time.After(2*readinessCheckInterval + time.Second):
		t.Fatal("publisher was not activated after every direct child became ready")
	}
	if ready, _ := latch.status(); ready {
		t.Fatal("latched ready before publisher activation completed")
	}

	close(finishActivation)
	select {
	case got := <-result:
		if got.err != nil {
			t.Fatal(got.err)
		}
		if !got.active {
			t.Fatal("startup completed without active publishers")
		}
	case <-time.After(time.Second):
		t.Fatal("readiness did not complete after publisher activation")
	}
	if got := publisherChecks.Load(); got == 0 {
		t.Fatal("publisher-dependent check did not run after activation")
	}
	if ready, _ := latch.status(); !ready {
		t.Fatal("did not latch ready after both readiness phases")
	}

	// The latch remains one-way after the candidate has taken over.
	latch.setUnready(errors.New("later child blip"))
	if ready, _ := latch.status(); !ready {
		t.Fatalf("latch un-readied a container that had already taken over")
	}
}

func TestPublisherActivationFailureDoesNotLatchReady(t *testing.T) {
	event := warp.NewEvent()
	defer event.Set()
	latch := newReadinessLatch()
	wantErr := errors.New("synthetic publisher bind failure")

	active, err := activatePublishersWhenReady(
		event,
		latch,
		nil,
		make(chan error, 1),
		func() error { return wantErr },
	)
	if active {
		t.Fatal("publisher activation reported success after bind failure")
	}
	if !errors.Is(err, wantErr) {
		t.Fatalf("activation error = %v, want %v", err, wantErr)
	}
	if ready, _ := latch.status(); ready {
		t.Fatal("bind failure latched the candidate ready")
	}
}

func TestDatasourceReadinessIsTheOnlyPostPublisherCheck(t *testing.T) {
	beforePublisher, afterPublisher := partitionReadyChecks(childReadyChecks(3101, 3201, 3000, "synthetic-admin-password"))
	if len(beforePublisher) != 3 {
		t.Fatalf("direct readiness checks = %d, want 3", len(beforePublisher))
	}
	for _, check := range beforePublisher {
		if check.name == "grafana-datasources" {
			t.Fatal("datasource check would create a pre-publisher readiness cycle")
		}
	}
	if len(afterPublisher) != 1 || afterPublisher[0].name != "grafana-datasources" {
		t.Fatalf("post-publisher checks = %#v, want only grafana-datasources", afterPublisher)
	}
}

func TestCancelledStartupDoesNotActivatePublisher(t *testing.T) {
	event := warp.NewEvent()
	checkObserved := make(chan struct{}, 1)
	unready := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case checkObserved <- struct{}{}:
		default:
		}
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer unready.Close()
	called := make(chan struct{}, 1)
	result := make(chan bool, 1)
	go func() {
		active, err := activatePublishersWhenReady(
			event,
			newReadinessLatch(),
			[]childReadyCheck{{name: "not-ready", url: unready.URL}},
			make(chan error, 1),
			func() error {
				called <- struct{}{}
				return nil
			},
		)
		result <- active || err != nil
	}()
	select {
	case <-checkObserved:
	case <-time.After(time.Second):
		t.Fatal("readiness check did not start")
	}
	event.Set()
	select {
	case failed := <-result:
		if failed {
			t.Fatal("cancelled startup returned an error or active publisher")
		}
	case <-time.After(time.Second):
		t.Fatal("cancelled readiness did not return")
	}
	select {
	case <-called:
		t.Fatal("cancelled candidate joined the publisher pool")
	default:
	}
}

func TestListenerFailureBeforeReadinessDoesNotActivatePublisher(t *testing.T) {
	event := warp.NewEvent()
	defer event.Set()
	unready := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer unready.Close()
	wantErr := errors.New("synthetic main listener failure")
	serveErrors := make(chan error, 1)
	serveErrors <- wantErr
	called := false

	active, err := activatePublishersWhenReady(
		event,
		newReadinessLatch(),
		[]childReadyCheck{{name: "not-ready", url: unready.URL}},
		serveErrors,
		func() error {
			called = true
			return nil
		},
	)
	if active || called {
		t.Fatal("candidate joined the publisher pool after its main listener failed")
	}
	if !errors.Is(err, wantErr) {
		t.Fatalf("startup error = %v, want %v", err, wantErr)
	}
}

func TestPreloadedReadinessSuccessCannotBeatBufferedListenerFailure(t *testing.T) {
	event := warp.NewEvent()
	defer event.Set()
	checksReady := make(chan bool, 1)
	checksReady <- true
	wantErr := errors.New("synthetic simultaneous listener failure")
	serveErrors := make(chan error, 1)
	serveErrors <- wantErr

	ready, err := waitForReadinessResult(event, checksReady, serveErrors)
	if ready {
		t.Fatal("readiness success beat an already-buffered listener failure")
	}
	if !errors.Is(err, wantErr) {
		t.Fatalf("readiness boundary error = %v, want %v", err, wantErr)
	}
}

type syntheticNetListener struct {
	closed atomic.Bool
}

func (self *syntheticNetListener) Accept() (net.Conn, error) {
	return nil, net.ErrClosed
}

func (self *syntheticNetListener) Close() error {
	self.closed.Store(true)
	return nil
}

func (self *syntheticNetListener) Addr() net.Addr {
	return syntheticNetAddr("publisher-a.example:3100")
}

type syntheticNetAddr string

func (self syntheticNetAddr) Network() string { return "tcp" }
func (self syntheticNetAddr) String() string  { return string(self) }

func TestPublisherBindFailureClosesEveryAcquiredSocket(t *testing.T) {
	first := &syntheticNetListener{}
	wantErr := errors.New("synthetic second bind failure")
	calls := 0
	err := activatePublishListeners(
		[]publishListener{
			{listenAddr: "publisher-a.example:3100", server: &http.Server{}},
			{listenAddr: "publisher-b.example:3100", server: &http.Server{}},
		},
		make(chan error, 2),
		func(string) (net.Listener, error) {
			calls++
			if calls == 1 {
				return first, nil
			}
			return nil, wantErr
		},
	)
	if !errors.Is(err, wantErr) {
		t.Fatalf("activation error = %v, want %v", err, wantErr)
	}
	if !first.closed.Load() {
		t.Fatal("first publisher socket remained open after the second bind failed")
	}
}

// A rolling replacement shares the stable publisher with SO_REUSEPORT. The
// retiring front must finish accepting and draining requests before its own
// Mimir/Loki children receive their stop event; otherwise the old front can
// accept a valid push after the matching child listener has disappeared.
func TestServeBeforeStoppingChildrenDrainsFrontFirst(t *testing.T) {
	frontEvent := warp.NewEvent()
	childEvent := warp.NewEvent()
	drainStarted := make(chan struct{})
	finishDrain := make(chan struct{})
	done := make(chan error, 1)

	go func() {
		done <- serveBeforeStoppingChildren(frontEvent, childEvent, func() error {
			<-frontEvent.Ctx.Done()
			close(drainStarted)
			<-finishDrain
			return nil
		})
	}()

	frontEvent.Set()
	select {
	case <-drainStarted:
	case <-time.After(time.Second):
		t.Fatal("front did not begin draining")
	}
	if childEvent.IsSet() {
		t.Fatal("child stop became visible before the front drained")
	}

	close(finishDrain)
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("ordered shutdown did not complete")
	}
	if !childEvent.IsSet() {
		t.Fatal("children remained live after the front drained")
	}
}

type syntheticShutdownServer struct {
	called      chan struct{}
	release     <-chan struct{}
	shutdownErr error
	closed      chan struct{}
}

func (self *syntheticShutdownServer) Shutdown(ctx context.Context) error {
	close(self.called)
	if self.shutdownErr != nil {
		return self.shutdownErr
	}
	if self.release == nil {
		return nil
	}
	select {
	case <-self.release:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (self *syntheticShutdownServer) Close() error {
	if self.closed != nil {
		close(self.closed)
	}
	return nil
}

func TestServeFailureDrainsEveryFrontBeforeStoppingChildren(t *testing.T) {
	frontEvent := warp.NewEvent()
	childEvent := warp.NewEvent()
	wantErr := errors.New("synthetic listener failure")
	serveErrors := make(chan error, 1)
	releaseFirst := make(chan struct{})
	fronts := []*syntheticShutdownServer{
		{called: make(chan struct{}), release: releaseFirst},
		{called: make(chan struct{})},
		{called: make(chan struct{})},
	}
	done := make(chan error, 1)

	go func() {
		done <- serveBeforeStoppingChildren(frontEvent, childEvent, func() error {
			return waitAndDrainFronts(frontEvent, serveErrors, fronts[0], fronts[1], fronts[2])
		})
	}()
	serveErrors <- wantErr
	for _, front := range []*syntheticShutdownServer{fronts[0], fronts[2]} {
		select {
		case <-front.called:
		case <-time.After(time.Second):
			t.Fatal("a blocked first front prevented another listener from closing")
		}
	}
	if !frontEvent.IsSet() {
		t.Fatal("listener failure did not retire the remaining front goroutines")
	}
	if childEvent.IsSet() {
		t.Fatal("children stopped while the first front was still draining")
	}

	close(releaseFirst)
	var gotErr error
	select {
	case gotErr = <-done:
	case <-time.After(time.Second):
		t.Fatal("listener-failure shutdown did not complete")
	}
	if !errors.Is(gotErr, wantErr) {
		t.Fatalf("serve error = %v, want %v", gotErr, wantErr)
	}
	if !childEvent.IsSet() {
		t.Fatal("children remained live after every front drained")
	}
}

func TestDrainFrontsClosesAFrontThatCannotDrain(t *testing.T) {
	wantErr := errors.New("synthetic drain deadline")
	front := &syntheticShutdownServer{
		called:      make(chan struct{}),
		shutdownErr: wantErr,
		closed:      make(chan struct{}),
	}

	drainFronts(context.Background(), front)
	select {
	case <-front.called:
	default:
		t.Fatal("front shutdown was not attempted")
	}
	select {
	case <-front.closed:
	default:
		t.Fatal("front remained active after graceful drain failed")
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
