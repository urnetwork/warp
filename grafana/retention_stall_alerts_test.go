package main

import (
	"fmt"
	"strings"
	"testing"
)

// The retention stall rule (owner, 2026-11-23) reads the due count of the
// newest probe and the deletes of the last 6 hours, only from taskworker
// series, and warns.
func TestRetentionStalledRuleShape(t *testing.T) {
	groups := loadProvisionedAlertGroups(t, "alerting/retention-stall.yml")
	group, ok := groups["retention-stall"]
	if !ok || group.Folder != "urnetwork alerts" || group.Interval != "5m" || len(group.Rules) != 1 {
		t.Fatalf("retention-stall group = %+v", group)
	}
	rule := provisionedAlertRuleByUID(t, group, "retention-stalled")
	if rule.Title != "RetentionStalled" || rule.Labels["service"] != "retention" || rule.Labels["severity"] != "warn" {
		t.Errorf("retention rule title and labels = %s %v", rule.Title, rule.Labels)
	}
	if rule.NoDataState != "OK" || rule.ExecErrState != "Error" || rule.For != "5m" {
		t.Errorf("retention rule noDataState/execErrState/for = %s/%s/%s", rule.NoDataState, rule.ExecErrState, rule.For)
	}
	expr := rule.Data[0].Model.Expr
	for _, part := range []string{
		"urnetwork_retention_due_rows{",
		"urnetwork_retention_due_rows_timestamp_seconds{",
		"topk by (table) (1, ",
		"increase(urnetwork_retention_deleted_rows_total{",
		"[6h]",
	} {
		if !strings.Contains(expr, part) {
			t.Errorf("retention rule does not read %s", part)
		}
	}
	if count := strings.Count(expr, "{"); count != strings.Count(expr, `{env="main",service="taskworker"}`) {
		t.Errorf("a retention selector is not env and service=taskworker: %s", expr)
	}
	if summary := rule.Annotations["summary"]; !strings.Contains(summary, "6 hours") || !strings.Contains(summary, "st_client_key_gone") {
		t.Errorf("retention summary = %q", summary)
	}
}

// The rule on synthetic taskworker series at 1-minute samples, read at 420
// minutes. It fires on the 2026-11-21 stall: a million records due and no
// deletes for 7 hours. It stays quiet while the retention deletes, when
// nothing is due, when the deletes stopped under 6 hours ago, when only an
// older process's probe still counts rows due, and before any taskworker
// probes. It fires when the newest probe, on another process, counts rows due.
func TestRetentionStalledEvaluate(t *testing.T) {
	groups := loadProvisionedAlertGroups(t, "alerting/retention-stall.yml")
	rule := provisionedAlertRuleByUID(t, groups["retention-stall"], "retention-stalled")
	process := func(instance string) string {
		return fmt.Sprintf(`env="main",service="taskworker",block="g1",host="h1",instance="%s",job="taskworker"`, instance)
	}
	const table = `table="st_client_key_gone"`
	// per minute, for 480 minutes
	counter := func(perMinute float64) string { return fmt.Sprintf("0+%gx480", perMinute) }
	gauge := func(value float64) string { return fmt.Sprintf("%gx480", value) }
	// a process that probes every minute until minute last, and then keeps
	// the count of its last probe
	probes := func(last int) string {
		if 480 <= last {
			return "60+60x480"
		}
		return fmt.Sprintf("60+60x%d %dx%d", last, 60+60*last, 480-last)
	}
	type process_ struct {
		instance  string
		due       string
		probed    string
		deleted   string
		noProbing bool
	}
	series := func(processes ...process_) map[string]string {
		values := map[string]string{
			// another table's deletes, with no probe of its own
			`urnetwork_retention_deleted_rows_total{` + process("i0") + `,table="network_user_action_attempt"}`: gauge(0),
			// another service registers the metrics and pushes zeros
			`urnetwork_retention_deleted_rows_total{env="main",service="api",block="g1",host="h1",instance="a1",job="api",` + table + `}`: gauge(0),
		}
		for _, p := range processes {
			values[`urnetwork_retention_deleted_rows_total{`+process(p.instance)+`,`+table+`}`] = p.deleted
			if !p.noProbing {
				values[`urnetwork_retention_due_rows{`+process(p.instance)+`,`+table+`}`] = p.due
				values[`urnetwork_retention_due_rows_timestamp_seconds{`+process(p.instance)+`,`+table+`}`] = p.probed
			}
		}
		return values
	}
	cases := []promtoolAlertCase{
		{name: "the 2026-11-21 stall: a million due and nothing deleted", series: series(process_{instance: "i1", due: gauge(1000000), probed: probes(480), deleted: gauge(42000000)}), evalTime: "420m", fires: true},
		{name: "the fixed retention deletes", series: series(process_{instance: "i1", due: gauge(1000000), probed: probes(480), deleted: counter(39000)}), evalTime: "420m"},
		{name: "caught up: nothing due", series: series(process_{instance: "i1", due: gauge(0), probed: probes(480), deleted: gauge(1000)}), evalTime: "420m"},
		{name: "the deletes stopped 5 hours ago", series: series(process_{instance: "i1", due: gauge(500), probed: probes(480), deleted: "0+600x120 72000x360"}), evalTime: "420m"},
		{name: "the deletes stopped 7 hours ago", series: series(process_{instance: "i1", due: gauge(500), probed: probes(480), deleted: "0+600x60 36000x420"}), evalTime: "480m", fires: true},
		{name: "only an older process's probe counts rows due", series: series(
			process_{instance: "i1", due: gauge(1000), probed: probes(100), deleted: gauge(5000)},
			process_{instance: "i2", due: gauge(0), probed: probes(480), deleted: gauge(0)},
		), evalTime: "420m"},
		{name: "the newest probe, on another process, counts rows due", series: series(
			process_{instance: "i1", due: gauge(0), probed: probes(100), deleted: gauge(5000)},
			process_{instance: "i2", due: gauge(1000), probed: probes(480), deleted: gauge(0)},
		), evalTime: "420m", fires: true},
		{name: "a stopped task keeps its last count", series: series(process_{instance: "i1", due: gauge(1000), probed: probes(30), deleted: gauge(7000)}), evalTime: "420m", fires: true},
		{name: "no taskworker has probed yet", series: series(process_{instance: "i1", noProbing: true, deleted: gauge(0)}), evalTime: "420m"},
	}
	evaluateAlertRuleWithPromtool(t, rule, "1m", map[string]string{"table": "st_client_key_gone"}, cases)
}
