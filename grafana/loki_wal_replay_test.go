package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// One scrape of a loki's WAL replay metrics.
type lokiReplayReading struct {
	active           bool
	recoveredBytes   float64
	recoveredEntries float64
	flushedChunks    float64
	flushFailures    float64
}

// exposition renders the reading the way loki 3.7's /metrics does, with the
// flushed chunks split over two reasons.
func (self lokiReplayReading) exposition() string {
	active := 0
	if self.active {
		active = 1
	}
	return fmt.Sprintf(`# HELP loki_ingester_chunks_flush_failures_total Total number of flush failures.
# TYPE loki_ingester_chunks_flush_failures_total counter
loki_ingester_chunks_flush_failures_total %g
# HELP loki_ingester_chunks_flushed_total Total flushed chunks per reason.
# TYPE loki_ingester_chunks_flushed_total counter
loki_ingester_chunks_flushed_total{reason="forced"} %g
loki_ingester_chunks_flushed_total{reason="full"} 0
# HELP loki_ingester_wal_duplicate_entries_total Entries discarded during WAL replay due to existing in checkpoints.
# TYPE loki_ingester_wal_duplicate_entries_total counter
loki_ingester_wal_duplicate_entries_total 0
# HELP loki_ingester_wal_recovered_bytes_total Total number of bytes recovered from the WAL.
# TYPE loki_ingester_wal_recovered_bytes_total counter
loki_ingester_wal_recovered_bytes_total %g
# HELP loki_ingester_wal_recovered_entries_total Total number of entries recovered from the WAL.
# TYPE loki_ingester_wal_recovered_entries_total counter
loki_ingester_wal_recovered_entries_total %g
# HELP loki_ingester_wal_replay_active Whether the WAL is replaying
# TYPE loki_ingester_wal_replay_active gauge
loki_ingester_wal_replay_active %d
`, self.flushFailures, self.flushedChunks, self.recoveredBytes, self.recoveredEntries, active)
}

// newFakeLoki answers /ready with readyStatus (503 names a Starting module)
// and /metrics with the next reading, repeating the last one. It returns the
// supervisor settings main gives loki on this server's port, and the number
// of scrapes so far.
func newFakeLoki(t *testing.T, readyStatus int, metricsStatus int, readings ...lokiReplayReading) (func(context.Context) error, *atomic.Int32) {
	t.Helper()
	var scrapes atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ready":
			if readyStatus == http.StatusOK {
				w.Write([]byte("ready\n"))
				return
			}
			w.WriteHeader(readyStatus)
			w.Write([]byte("Some services are not Running:\nStarting: 1\nRunning: 20\n"))
		case "/metrics":
			i := int(scrapes.Add(1)) - 1
			if metricsStatus != http.StatusOK {
				w.WriteHeader(metricsStatus)
				return
			}
			if len(readings) <= i {
				i = len(readings) - 1
			}
			w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8; escaping=underscores")
			w.Write([]byte(readings[i].exposition()))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)

	serverUrl, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("parse server url: %s", err)
	}
	host, portString, err := net.SplitHostPort(serverUrl.Host)
	if err != nil {
		t.Fatalf("split server address: %s", err)
	}
	if host != childListenAddress {
		t.Fatalf("test server on %s, children listen on %s", host, childListenAddress)
	}
	port, err := strconv.Atoi(portString)
	if err != nil {
		t.Fatalf("server port: %s", err)
	}

	settings := lokiChildSettings(childReadyChecks(port, 0, 0, "test-admin-password"), port)
	// the probe may pass more often, but a stalled or wedged loki still has
	// to be restarted on the same schedule as before
	if settings.HealthCheckInterval != childHealthCheckInterval || settings.UnhealthyTimeout != childUnhealthyTimeout {
		t.Fatalf(
			"loki supervision interval/timeout = %s/%s, want %s/%s",
			settings.HealthCheckInterval,
			settings.UnhealthyTimeout,
			childHealthCheckInterval,
			childUnhealthyTimeout,
		)
	}
	if settings.StopTimeout != 120*time.Second {
		t.Fatalf("loki stop timeout = %s, want 120s to flush chunks", settings.StopTimeout)
	}
	return settings.HealthCheck, &scrapes
}

// probe runs one supervisor health check the way warp.Child does.
func probe(healthCheck func(context.Context) error) error {
	ctx, cancel := context.WithTimeout(context.Background(), childHealthCheckInterval)
	defer cancel()
	return healthCheck(ctx)
}

// On 2026-11-06 edge-0's loki restarted with a 33 GB WAL, left behind while
// its flushes failed against the loki bucket's MinIO quota. /ready stays 503
// (ingester Starting) for the whole replay, and the supervisor killed loki at
// 19:04, 19:16 and 19:28, each time 10 minutes into a replay that was still
// reading the WAL and storing chunks. Every restart began the replay again,
// so loki could never finish starting. The probe has to pass while the replay
// advances, through both of its phases: reading the WAL, then a replay flush
// in which only the flushed chunks grow.
func TestLokiProbePassesWhileTheWalReplayAdvances(t *testing.T) {
	healthCheck, scrapes := newFakeLoki(
		t,
		http.StatusServiceUnavailable,
		http.StatusOK,
		lokiReplayReading{active: true, recoveredBytes: 1e9, recoveredEntries: 2e6},
		// reading segments
		lokiReplayReading{active: true, recoveredBytes: 4e9, recoveredEntries: 8e6},
		// a replay flush: the reads wait, the chunks are stored
		lokiReplayReading{active: true, recoveredBytes: 4e9, recoveredEntries: 8e6, flushedChunks: 1200},
		lokiReplayReading{active: true, recoveredBytes: 4e9, recoveredEntries: 8e6, flushedChunks: 3211},
		// reading again after the flush
		lokiReplayReading{active: true, recoveredBytes: 5e9, recoveredEntries: 1e7, flushedChunks: 3211},
	)

	// the first reading is only a baseline
	if err := probe(healthCheck); err == nil {
		t.Fatal("the first replay reading passed without a baseline")
	}
	for i := 1; i < 5; i += 1 {
		if err := probe(healthCheck); err != nil {
			t.Fatalf("probe %d of an advancing WAL replay failed: %s", i+1, err)
		}
	}
	if got := scrapes.Load(); got != 5 {
		t.Fatalf("scrapes = %d, want one per probe", got)
	}
}

// A replay that stops advancing is wedged as far as the supervisor can tell,
// and the probe keeps failing so it is restarted after childUnhealthyTimeout.
// Flush attempts are not progress: before the quota was raised on 2026-11-06,
// every replay flush failed with XMinioAdminBucketQuotaExceeded, the failures
// grew, and nothing else did.
func TestLokiProbeFailsAStalledWalReplay(t *testing.T) {
	healthCheck, _ := newFakeLoki(
		t,
		http.StatusServiceUnavailable,
		http.StatusOK,
		lokiReplayReading{active: true, recoveredBytes: 37300361764, recoveredEntries: 73486524, flushedChunks: 3211},
		lokiReplayReading{active: true, recoveredBytes: 37300361764, recoveredEntries: 73486524, flushedChunks: 3211, flushFailures: 22},
		lokiReplayReading{active: true, recoveredBytes: 37300361764, recoveredEntries: 73486524, flushedChunks: 3211, flushFailures: 61},
	)

	for i := 0; i < 3; i += 1 {
		err := probe(healthCheck)
		if err == nil {
			t.Fatalf("probe %d of a stalled WAL replay passed", i+1)
		}
		for _, want := range []string{"loki", "503", "Starting: 1", "did not advance"} {
			if !strings.Contains(err.Error(), want) {
				t.Fatalf("stalled replay error %q missing %q", err, want)
			}
		}
	}
}

// The supervisor exists for a loki that is up and unready without replaying:
// on 2026-08-17 a loki's query modules sat in Starting for 16 hours
// (SIGNALS.md 11.13). Counters that grow outside a replay do not excuse it.
func TestLokiProbeFailsAnUnreadyLokiThatIsNotReplaying(t *testing.T) {
	healthCheck, _ := newFakeLoki(
		t,
		http.StatusServiceUnavailable,
		http.StatusOK,
		lokiReplayReading{active: false, recoveredBytes: 4e9, flushedChunks: 100},
		lokiReplayReading{active: false, recoveredBytes: 4e9, flushedChunks: 900},
		lokiReplayReading{active: false, recoveredBytes: 4e9, flushedChunks: 1700},
	)

	for i := 0; i < 3; i += 1 {
		err := probe(healthCheck)
		if err == nil {
			t.Fatalf("probe %d of an unready loki that is not replaying passed", i+1)
		}
		if !strings.Contains(err.Error(), "Starting: 1") {
			t.Fatalf("error %q does not carry the readiness body", err)
		}
	}
}

// After a restart the counters start again from zero. Lower counters are a
// new baseline, never progress, and the new process advances from there.
func TestLokiProbeTakesLowerCountersAsARestartedReplay(t *testing.T) {
	healthCheck, _ := newFakeLoki(
		t,
		http.StatusServiceUnavailable,
		http.StatusOK,
		lokiReplayReading{active: true, recoveredBytes: 37300361764, recoveredEntries: 73486524, flushedChunks: 3211},
		// the restarted process: its bytes are lower, its chunks higher than
		// nothing, and that is still not progress
		lokiReplayReading{active: true, recoveredBytes: 1e9, recoveredEntries: 2e6, flushedChunks: 4000},
		lokiReplayReading{active: true, recoveredBytes: 2e9, recoveredEntries: 4e6, flushedChunks: 4000},
	)

	if err := probe(healthCheck); err == nil {
		t.Fatal("the first replay reading passed without a baseline")
	}
	if err := probe(healthCheck); err == nil {
		t.Fatal("a reading with a lower counter passed as progress")
	}
	if err := probe(healthCheck); err != nil {
		t.Fatalf("the restarted replay advanced and failed: %s", err)
	}
}

// A ready loki costs one /ready request per probe, as before: no scrape.
func TestLokiProbePassesAReadyLokiWithoutScraping(t *testing.T) {
	healthCheck, scrapes := newFakeLoki(
		t,
		http.StatusOK,
		http.StatusOK,
		lokiReplayReading{active: true, recoveredBytes: 1e9},
	)

	for i := 0; i < 3; i += 1 {
		if err := probe(healthCheck); err != nil {
			t.Fatalf("probe %d of a ready loki failed: %s", i+1, err)
		}
	}
	if got := scrapes.Load(); got != 0 {
		t.Fatalf("a ready loki was scraped %d times", got)
	}
}

// Without its metrics there is no evidence the replay advances, so an unready
// loki fails the probe and says why.
func TestLokiProbeFailsWhenTheReplayMetricsAreUnreadable(t *testing.T) {
	healthCheck, scrapes := newFakeLoki(
		t,
		http.StatusServiceUnavailable,
		http.StatusInternalServerError,
		lokiReplayReading{active: true, recoveredBytes: 1e9},
	)

	for i := 0; i < 2; i += 1 {
		err := probe(healthCheck)
		if err == nil {
			t.Fatalf("probe %d passed without replay metrics", i+1)
		}
		if !strings.Contains(err.Error(), "WAL replay unknown") || !strings.Contains(err.Error(), "500") {
			t.Fatalf("error %q does not say the replay metrics failed", err)
		}
	}
	if got := scrapes.Load(); got != 2 {
		t.Fatalf("scrapes = %d, want 2", got)
	}
}

// The reading parses loki's real exposition: these lines are edge-0's /metrics
// at 19:29:03Z on 2026-11-06, in a replay flush 10 minutes into its third
// replay, as the supervisor stopped it again.
func TestReadLokiWalReplayParsesEdge0Exposition(t *testing.T) {
	const exposition = `# HELP loki_ingester_chunks_flush_failures_total Total number of flush failures.
# TYPE loki_ingester_chunks_flush_failures_total counter
loki_ingester_chunks_flush_failures_total 0
# HELP loki_ingester_chunks_flushed_total Total flushed chunks per reason.
# TYPE loki_ingester_chunks_flushed_total counter
loki_ingester_chunks_flushed_total{reason="forced"} 3211
# HELP loki_ingester_wal_bytes_in_use Total number of bytes in use by the WAL recovery process.
# TYPE loki_ingester_wal_bytes_in_use gauge
loki_ingester_wal_bytes_in_use 3.1456565839e+10
# HELP loki_ingester_wal_duplicate_entries_total Entries discarded during WAL replay due to existing in checkpoints.
# TYPE loki_ingester_wal_duplicate_entries_total counter
loki_ingester_wal_duplicate_entries_total 0
# HELP loki_ingester_wal_recovered_bytes_total Total number of bytes recovered from the WAL.
# TYPE loki_ingester_wal_recovered_bytes_total counter
loki_ingester_wal_recovered_bytes_total 3.7300361764e+10
# HELP loki_ingester_wal_recovered_entries_total Total number of entries recovered from the WAL.
# TYPE loki_ingester_wal_recovered_entries_total counter
loki_ingester_wal_recovered_entries_total 7.3486524e+07
# HELP loki_ingester_wal_replay_active Whether the WAL is replaying
# TYPE loki_ingester_wal_replay_active gauge
loki_ingester_wal_replay_active 1
# HELP loki_ingester_wal_replay_flushing Whether the wal replay is in a flushing phase due to backpressure
# TYPE loki_ingester_wal_replay_flushing gauge
loki_ingester_wal_replay_flushing 1
`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8; escaping=underscores")
		w.Write([]byte(exposition))
	}))
	defer server.Close()

	replay, err := readLokiWalReplay(context.Background(), newChildReadyClient(), server.URL+"/metrics")
	if err != nil {
		t.Fatalf("read replay: %s", err)
	}
	if !replay.active {
		t.Fatal("loki_ingester_wal_replay_active 1 read as not replaying")
	}
	want := map[string]float64{
		"loki_ingester_wal_recovered_bytes_total":   37300361764,
		"loki_ingester_wal_recovered_entries_total": 73486524,
		"loki_ingester_wal_duplicate_entries_total": 0,
		"loki_ingester_chunks_flushed_total":        3211,
	}
	for name, value := range want {
		if replay.counters[name] != value {
			t.Fatalf("%s = %g, want %g", name, replay.counters[name], value)
		}
	}
	if len(replay.counters) != len(lokiWalReplayProgressMetrics) {
		t.Fatalf("read counters %v, want exactly %v", replay.counters, lokiWalReplayProgressMetrics)
	}
}
