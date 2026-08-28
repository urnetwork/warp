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
		"uid: competition-worker-heartbeat-stale",
		"uid: competition-grading-stalled",
		"uid: competition-operational-errors",
		"uid: competition-minio-capacity-warning",
		"uid: competition-minio-capacity-critical",
		"urnetwork_competition_artifact_archive_ready",
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
}
