package main

import (
	"fmt"
	"os"
	"strings"
	"testing"
)

// Each planetoid archive pages, failing closed on missing data, once its
// newest copy is older than its objective: 7 days for pg (owner, 2026-11-15,
// for edge-6's Sun/Thu runs of 40 to 75 hours and the day-long pull), 5 days
// for the others.
func TestBackupArchiveAlertsFailClosedPastTheirObjective(t *testing.T) {
	data, err := os.ReadFile("alerting/backup-archives.yml")
	if err != nil {
		t.Fatal(err)
	}
	config := string(data)
	const day = 86400
	objectives := map[string]float64{
		"pg":                  7 * day,
		"redis":               5 * day,
		"github-urnetwork":    5 * day,
		"github-urfoundation": 5 * day,
		"router-config":       5 * day,
	}
	groups := loadProvisionedAlertGroups(t, "alerting/backup-archives.yml")
	group, ok := groups["planetoid-backup-archives"]
	if !ok {
		t.Fatal("planetoid-backup-archives group is missing")
	}
	if len(group.Rules) != len(objectives) {
		t.Fatalf("backup archive alert count = %d, want %d", len(group.Rules), len(objectives))
	}
	for archive, objective := range objectives {
		rule := provisionedAlertRuleByUID(t, group, "backup-archive-"+archive+"-stale")
		if len(rule.Data) != 2 || len(rule.Data[1].Model.Conditions) != 1 {
			t.Errorf("%s wants a query and one threshold condition", rule.UID)
			continue
		}
		expr := fmt.Sprintf(`time() - max(urnetwork_backup_archive_latest_timestamp_seconds{env="main",host="planetoid",archive=%q})`, archive)
		if got := rule.Data[0].Model.Expr; got != expr {
			t.Errorf("%s expr = %s, want %s", rule.UID, got, expr)
		}
		evaluator := rule.Data[1].Model.Conditions[0].Evaluator
		if evaluator.Type != "gt" || len(evaluator.Params) != 1 || evaluator.Params[0] != objective {
			t.Errorf("%s threshold = %s %v, want gt %v", rule.UID, evaluator.Type, evaluator.Params, objective)
		}
		if rule.NoDataState != "Alerting" || rule.ExecErrState != "Error" {
			t.Errorf("%s noDataState/execErrState = %s/%s, want Alerting/Error", rule.UID, rule.NoDataState, rule.ExecErrState)
		}
		if rule.Labels["service"] != "backup-archive" || rule.Labels["severity"] != "page" || rule.Labels["archive"] != archive {
			t.Errorf("%s labels = %v", rule.UID, rule.Labels)
		}
		days := map[float64]string{5 * day: "five days", 7 * day: "seven days"}[objective]
		if !strings.Contains(rule.Annotations["summary"], days) {
			t.Errorf("%s summary %q does not say %s", rule.UID, rule.Annotations["summary"], days)
		}
	}
	// the dashboard and the monitor keep the same boundaries
	for _, boundary := range []string{"604800 seconds for pg", "432000 for the others", "backup-archives.json", "§11.22"} {
		if !strings.Contains(config, boundary) {
			t.Errorf("backup archive alerts do not name %q", boundary)
		}
	}
}
