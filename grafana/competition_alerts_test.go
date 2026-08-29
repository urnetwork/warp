package main

import (
	"os"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestCompetitionAlertsCoverFailClosedBoundaries(t *testing.T) {
	data, err := os.ReadFile("alerting/competition.yml")
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := yaml.Unmarshal(data, &document); err != nil {
		t.Fatalf("parse competition alerts: %v", err)
	}
	config := string(data)
	for _, required := range []string{
		"uid: competition-artifact-archive-unready",
		"uid: competition-runner-heartbeat-stale",
		"uid: competition-worker-heartbeat-stale",
		"uid: competition-grading-stalled",
		"uid: competition-operational-errors",
		"uid: competition-minio-capacity-warning",
		"uid: competition-minio-capacity-critical",
		"urnetwork_competition_artifact_archive_ready",
		"urnetwork_competition_runner_heartbeat_timestamp_seconds",
		"urnetwork_competition_worker_heartbeat_age_seconds",
		"urnetwork_competition_metric_refresh_errors_total",
		"urnetwork_competition_artifact_failures_total",
		"urnetwork_competition_evaluations_total",
		"minio_cluster_health_capacity_usable_free_bytes",
	} {
		if !strings.Contains(config, required) {
			t.Errorf("competition alert configuration is missing %q", required)
		}
	}
	if !strings.Contains(config, "interval: 15s") {
		t.Fatal("competition alert group must evaluate at the 15-second heartbeat cadence")
	}
	alertCount := strings.Count(config, "\n      - uid: competition-")
	if alertCount == 0 || strings.Count(config, "service: sim-latency") != alertCount {
		t.Fatalf("service routing labels=%d alerts=%d", strings.Count(config, "service: sim-latency"), alertCount)
	}
	archiveStart := strings.Index(config, "- uid: competition-artifact-archive-unready")
	if archiveStart < 0 {
		t.Fatal("artifact archive alert is missing")
	}
	archiveEnd := len(config)
	if relativeEnd := strings.Index(config[archiveStart+1:], "\n      - uid: "); 0 <= relativeEnd {
		archiveEnd = archiveStart + 1 + relativeEnd
	}
	archiveBlock := config[archiveStart:archiveEnd]
	if !strings.Contains(archiveBlock, "noDataState: Alerting") ||
		!strings.Contains(archiveBlock, "severity: page") {
		t.Fatal("artifact archive alert must page on missing or failed telemetry")
	}
	runnerStart := strings.Index(config, "- uid: competition-runner-heartbeat-stale")
	if runnerStart < 0 {
		t.Fatal("runner heartbeat alert is missing")
	}
	runnerEnd := len(config)
	if relativeEnd := strings.Index(config[runnerStart+1:], "\n      - uid: "); 0 <= relativeEnd {
		runnerEnd = runnerStart + 1 + relativeEnd
	}
	runnerBlock := config[runnerStart:runnerEnd]
	for _, required := range []string{
		"urnetwork_competition_runner_heartbeat_timestamp_seconds",
		"time() - 30",
		"for: 0s",
		"severity: warn",
		"service: sim-latency",
	} {
		if !strings.Contains(runnerBlock, required) {
			t.Errorf("runner heartbeat alert is missing %q", required)
		}
	}
}
