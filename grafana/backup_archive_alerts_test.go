package main

import (
	"os"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestBackupArchiveAlertsFailClosedAtFiveDays(t *testing.T) {
	data, err := os.ReadFile("alerting/backup-archives.yml")
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := yaml.Unmarshal(data, &document); err != nil {
		t.Fatalf("parse backup archive alerts: %v", err)
	}
	config := string(data)
	for _, archive := range []string{"pg", "redis", "github-urnetwork", "github-urfoundation"} {
		selector := `archive="` + archive + `"`
		if !strings.Contains(config, selector) {
			t.Errorf("backup archive alerts are missing %s", selector)
		}
	}
	for _, required := range []string{
		"urnetwork_backup_archive_latest_timestamp_seconds",
		"params: [432000]",
		"noDataState: Alerting",
		"execErrState: Error",
		"service: backup-archive",
		"severity: page",
	} {
		if !strings.Contains(config, required) {
			t.Errorf("backup archive alert configuration is missing %q", required)
		}
	}
	if count := strings.Count(config, "\n      - uid: backup-archive-"); count != 4 {
		t.Fatalf("backup archive alert count = %d, want 4", count)
	}
	if count := strings.Count(config, "noDataState: Alerting"); count != 4 {
		t.Fatalf("fail-closed no-data rule count = %d, want 4", count)
	}
}
