package main

import (
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

type dbArchiveRule struct {
	UID  string `yaml:"uid"`
	Data []struct {
		Model struct {
			Expr       string `yaml:"expr"`
			Conditions []struct {
				Evaluator struct {
					Params []float64 `yaml:"params"`
					Type   string    `yaml:"type"`
				} `yaml:"evaluator"`
			} `yaml:"conditions"`
		} `yaml:"model"`
	} `yaml:"data"`
	NoDataState  string            `yaml:"noDataState"`
	ExecErrState string            `yaml:"execErrState"`
	For          string            `yaml:"for"`
	Labels       map[string]string `yaml:"labels"`
}

func readDbArchiveRules(t *testing.T) map[string]dbArchiveRule {
	t.Helper()
	data, err := os.ReadFile("alerting/db-archive.yml")
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Groups []struct {
			Name     string          `yaml:"name"`
			Interval string          `yaml:"interval"`
			Rules    []dbArchiveRule `yaml:"rules"`
		} `yaml:"groups"`
	}
	if err := yaml.Unmarshal(data, &document); err != nil {
		t.Fatalf("parse db archive alerts: %v", err)
	}
	if len(document.Groups) != 1 || document.Groups[0].Name != "edge6-db-archive" {
		t.Fatalf("db archive alerts want one group edge6-db-archive, got %d", len(document.Groups))
	}
	rules := map[string]dbArchiveRule{}
	for _, rule := range document.Groups[0].Rules {
		rules[rule.UID] = rule
	}
	return rules
}

// The edge-6 archive's rules (owner, 2026-11-03): page on a PostgreSQL dump
// more than 4.5 days old, warn on a Redis copy more than 2 days old, the
// /mnt/archive runway to its 3 TB floor, a stale heartbeat, and a run in
// progress more than 30 hours. The series are those Mimir holds from edge-6's
// textfiles and node_exporter.
func TestDbArchiveAlertsWatchTheEdge6Archive(t *testing.T) {
	const (
		selector     = `env="main",host="by-us-fmt-5-edge-6"`
		lastSuccess  = "urnetwork_backup_onsite_last_success_timestamp_seconds"
		heartbeat    = "urnetwork_backup_onsite_heartbeat_timestamp_seconds"
		inProgress   = "urnetwork_backup_onsite_in_progress"
		pool         = `node_filesystem_avail_bytes{` + selector + `,mountpoint="/mnt/archive"}`
		floorBytes   = 3e12
		hour         = 3600
		day          = 24 * hour
		firstDumpDue = "2026-11-04T06:00:00Z"
		firstCopyDue = "2026-11-03T22:00:00Z"
	)
	due := func(when string) int64 {
		parsed, err := time.Parse(time.RFC3339, when)
		if err != nil {
			t.Fatal(err)
		}
		return parsed.Unix()
	}
	want := map[string]struct {
		expr      string
		evaluator string
		threshold float64
		severity  string
		noData    string
	}{
		"db-archive-pg-stale": {
			expr:      fmt.Sprintf(`time() - (max(%s{%s,archive="pg"}) or vector(%d))`, lastSuccess, selector, due(firstDumpDue)),
			evaluator: "gt", threshold: 4.5 * day, severity: "page", noData: "Alerting",
		},
		"db-archive-redis-copy-stale": {
			expr:      fmt.Sprintf(`time() - (max(%s{%s,archive="redis"}) or vector(%d))`, lastSuccess, selector, due(firstCopyDue)),
			evaluator: "gt", threshold: 2 * day, severity: "warn", noData: "Alerting",
		},
		"db-archive-pg-heartbeat-stale": {
			expr:      fmt.Sprintf(`time() - max(%s{%s,archive="pg"})`, heartbeat, selector),
			evaluator: "gt", threshold: 3 * hour, severity: "warn", noData: "Alerting",
		},
		"db-archive-redis-heartbeat-stale": {
			expr:      fmt.Sprintf(`time() - (max(%s{%s,archive="redis"}) or vector(%d))`, heartbeat, selector, due(firstCopyDue)),
			evaluator: "gt", threshold: 30 * hour, severity: "warn", noData: "Alerting",
		},
		"db-archive-run-over-30h": {
			expr: fmt.Sprintf(`min_over_time(max by (archive) (%[1]s{%[2]s})[30h:5m]) and count_over_time(max by (archive) (%[1]s{%[2]s})[30h:5m]) > 288`,
				inProgress, selector),
			evaluator: "gt", threshold: 0, severity: "page", noData: "OK",
		},
		"db-archive-below-floor": {
			expr:      "max(" + pool + ")",
			evaluator: "lt", threshold: floorBytes, severity: "page", noData: "OK",
		},
		"db-archive-runway-short": {
			expr:      "predict_linear(max_over_time(" + pool + "[1d])[7d:1h], 14 * 86400)",
			evaluator: "lt", threshold: floorBytes, severity: "warn", noData: "OK",
		},
		"db-archive-telemetry-missing": {
			expr:      "absent(" + pool + ")",
			evaluator: "gt", threshold: 0, severity: "warn", noData: "OK",
		},
	}

	rules := readDbArchiveRules(t)
	if len(rules) != len(want) {
		t.Errorf("db archive alert count = %d, want %d", len(rules), len(want))
	}
	for uid, expected := range want {
		rule, ok := rules[uid]
		if !ok {
			t.Errorf("missing db archive alert %s", uid)
			continue
		}
		if len(rule.Data) != 2 || len(rule.Data[1].Model.Conditions) != 1 {
			t.Errorf("%s wants a query and one threshold condition", uid)
			continue
		}
		if got := rule.Data[0].Model.Expr; got != expected.expr {
			t.Errorf("%s expr = %s, want %s", uid, got, expected.expr)
		}
		evaluator := rule.Data[1].Model.Conditions[0].Evaluator
		if evaluator.Type != expected.evaluator || len(evaluator.Params) != 1 || evaluator.Params[0] != expected.threshold {
			t.Errorf("%s threshold = %s %v, want %s %v", uid, evaluator.Type, evaluator.Params, expected.evaluator, expected.threshold)
		}
		if rule.Labels["severity"] != expected.severity || rule.Labels["service"] != "db-archive" {
			t.Errorf("%s labels = %v, want service db-archive, severity %s", uid, rule.Labels, expected.severity)
		}
		if rule.NoDataState != expected.noData || rule.ExecErrState != "Error" {
			t.Errorf("%s noDataState/execErrState = %s/%s, want %s/Error", uid, rule.NoDataState, rule.ExecErrState, expected.noData)
		}
		if _, err := time.ParseDuration(rule.For); err != nil {
			t.Errorf("%s for = %q: %v", uid, rule.For, err)
		}
	}
}

// Before the first dump and the first copy their last-success series do not
// exist (the owner: no page on no data before the first dump). A rule that
// alerts on missing data reads either a series that already reports, or a
// fallback to the time its first sample was due, after which missing data
// counts as stale.
func TestDbArchiveAlertsDoNotPageOnNoDataBeforeTheFirstRun(t *testing.T) {
	reportingSince1103 := map[string]bool{"db-archive-pg-heartbeat-stale": true}
	for uid, rule := range readDbArchiveRules(t) {
		if rule.NoDataState != "Alerting" || reportingSince1103[uid] {
			continue
		}
		expr := rule.Data[0].Model.Expr
		if !strings.Contains(expr, ") or vector(") {
			t.Errorf("%s alerts on missing data with no first-due fallback: %s", uid, expr)
		}
	}
	if rule := readDbArchiveRules(t)["db-archive-pg-heartbeat-stale"]; rule.Labels["severity"] != "warn" {
		t.Errorf("the heartbeat rule that alerts on missing data must not page")
	}
}

// The archive's textfiles reached Mimir with job db-archive from a second Fluent
// Bit input, then with job node from the host's one node_exporter_metrics
// input. A rule that selected a job would go silent across that move, so none
// does.
func TestDbArchiveAlertsSelectNoJob(t *testing.T) {
	for uid, rule := range readDbArchiveRules(t) {
		if expr := rule.Data[0].Model.Expr; strings.Contains(expr, "job=") {
			t.Errorf("%s selects a job label: %s", uid, expr)
		}
	}
}
