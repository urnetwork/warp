package main

import (
	"os"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// On 2026-11-01 urnetwork_api_reserved_upload_startup_failed stayed 1 for 22
// hours on one api block, which stopped SN25 steering, and no rule read it. The
// server publishes this gauge from api and alt alike, so the rule groups by the
// job and keeps the block's name in the alert.
func TestSnValidatorApiLaneAlertReadsEveryProcessGauge(t *testing.T) {
	data, err := os.ReadFile("alerting/sn-validator-api.yml")
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Groups []struct {
			Name     string            `yaml:"name"`
			Folder   string            `yaml:"folder"`
			Interval string            `yaml:"interval"`
			Rules    []snValidatorRule `yaml:"rules"`
		} `yaml:"groups"`
	}
	if err := yaml.Unmarshal(data, &document); err != nil {
		t.Fatalf("parse validator api alerts: %v", err)
	}
	if len(document.Groups) != 1 || len(document.Groups[0].Rules) != 1 {
		t.Fatalf("validator api alert groups = %+v, want one group of one rule", document.Groups)
	}
	group := document.Groups[0]
	if group.Name != "sn-validator-api" || group.Folder != "urnetwork alerts" || group.Interval != "1m" {
		t.Fatalf("validator api alert group = %q in %q every %q", group.Name, group.Folder, group.Interval)
	}
	rule := group.Rules[0]
	if rule.UID != "sn-validator-api-lane-off" || rule.Title != "SnValidatorApiLaneOff" {
		t.Errorf("rule = %s %s", rule.UID, rule.Title)
	}
	if rule.Condition != "B" || len(rule.Data) != 2 || rule.Data[0].RefID != "A" || rule.Data[1].RefID != "B" {
		t.Fatalf("%s does not threshold query A in expression B", rule.UID)
	}
	if rule.Data[0].DatasourceUID != "warp-mimir" || rule.Data[1].DatasourceUID != "__expr__" {
		t.Errorf("%s does not query warp-mimir", rule.UID)
	}
	if want := "max by (env, job, host, block) (urnetwork_api_reserved_upload_startup_failed)"; rule.Data[0].Model.Expr != want {
		t.Errorf("%s reads %q, want %q", rule.UID, rule.Data[0].Model.Expr, want)
	}
	conditions := rule.Data[1].Model.Conditions
	if len(conditions) != 1 || conditions[0].Evaluator.Type != "gt" || len(conditions[0].Evaluator.Params) != 1 || conditions[0].Evaluator.Params[0] != 0 {
		t.Errorf("%s threshold = %+v, want gt 0", rule.UID, conditions)
	}
	// A retrying lane comes back by itself; this long off is a persistent cause.
	if rule.For != "5m" {
		t.Errorf("%s holds for %s, want 5m", rule.UID, rule.For)
	}
	if rule.NoDataState != "OK" || rule.ExecErrState != "Error" {
		t.Errorf("%s noDataState %q execErrState %q, want OK and Error", rule.UID, rule.NoDataState, rule.ExecErrState)
	}
	if rule.Labels["service"] != "sn-validator" || rule.Labels["severity"] != "page" {
		t.Errorf("%s labels = %v", rule.UID, rule.Labels)
	}
	for _, name := range []string{"{{ $labels.job }}", "{{ $labels.block }}", "{{ $labels.host }}"} {
		if !strings.Contains(rule.Annotations["summary"], name) {
			t.Errorf("%s summary does not name %s", rule.UID, name)
		}
	}
}
