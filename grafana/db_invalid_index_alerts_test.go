package main

import (
	"fmt"
	"strings"
	"testing"
)

// The invalid index rule (owner, 2026-11-26) reads the oldest invalid index's
// age from the newest hot vacuum run, only from taskworker series, and warns
// above 2 hours.
func TestDbInvalidIndexLingeringRuleShape(t *testing.T) {
	groups := loadProvisionedAlertGroups(t, "alerting/db-invalid-index.yml")
	group, ok := groups["db-invalid-index"]
	if !ok || group.Folder != "urnetwork alerts" || group.Interval != "5m" || len(group.Rules) != 1 {
		t.Fatalf("db-invalid-index group = %+v", group)
	}
	rule := provisionedAlertRuleByUID(t, group, "db-invalid-index-lingering")
	if rule.Title != "DbInvalidIndexLingering" || rule.Labels["service"] != "db" || rule.Labels["severity"] != "warn" {
		t.Errorf("invalid index rule title and labels = %s %v", rule.Title, rule.Labels)
	}
	// the age is the hold; missing data is a taskworker without the gauges
	if rule.NoDataState != "OK" || rule.ExecErrState != "Error" || rule.For != "0s" {
		t.Errorf("invalid index rule noDataState/execErrState/for = %s/%s/%s", rule.NoDataState, rule.ExecErrState, rule.For)
	}
	if len(rule.Data) != 2 || rule.Data[0].DatasourceUID != "warp-mimir" || rule.Data[1].DatasourceUID != "__expr__" || len(rule.Data[1].Model.Conditions) != 1 {
		t.Fatalf("invalid index rule wants a mimir query and one threshold")
	}
	expr := rule.Data[0].Model.Expr
	for _, part := range []string{
		"urnetwork_db_invalid_index_max_age_seconds{",
		"and on (env, service, block, host, instance)",
		"topk (1, urnetwork_db_invalid_index_sample_timestamp_seconds{",
	} {
		if !strings.Contains(expr, part) {
			t.Errorf("invalid index rule does not read %s", part)
		}
	}
	if count := strings.Count(expr, "{"); count != strings.Count(expr, `{env="main",service="taskworker"}`) {
		t.Errorf("an invalid index selector is not env and service=taskworker: %s", expr)
	}
	evaluator := rule.Data[1].Model.Conditions[0].Evaluator
	if evaluator.Type != "gt" || len(evaluator.Params) != 1 || evaluator.Params[0] != 7200 {
		t.Errorf("invalid index rule threshold = %s %v, want gt 7200", evaluator.Type, evaluator.Params)
	}
	summary := rule.Annotations["summary"]
	for _, want := range []string{"2 hours", "invalid index(es) no build owns", "DROP INDEX CONCURRENTLY"} {
		if !strings.Contains(summary, want) {
			t.Errorf("invalid index summary does not name %s: %q", want, summary)
		}
	}
}

// The rule on synthetic taskworker series at 1-minute samples. A process that
// runs the chain every minute from minute 1 publishes its sample time and the
// oldest invalid index's age. It fires once an index has been invalid for
// more than 2 hours, and stays quiet with nothing invalid, at an hour and
// three quarters, once the index is dropped, when only an older process's run
// still reports an old index, and before any taskworker runs the chain. It
// fires when the newest run, on another process, reports it, and keeps firing
// on a stopped chain's last report. A series of another service is not read.
func TestDbInvalidIndexLingeringEvaluate(t *testing.T) {
	groups := loadProvisionedAlertGroups(t, "alerting/db-invalid-index.yml")
	rule := provisionedAlertRuleByUID(t, groups["db-invalid-index"], "db-invalid-index-lingering")
	process := func(service string, instance string) string {
		return fmt.Sprintf(`env="main",service="%s",block="g1",host="h1",instance="%s",job="%s"`, service, instance, service)
	}
	// runs every minute until minute last, then keeps the time of its last run
	runs := func(last int) string {
		if 300 <= last {
			return "60+60x300"
		}
		return fmt.Sprintf("60+60x%d %dx%d", last, 60+60*last, 300-last)
	}
	// an index found invalid at minute found and dropped at minute dropped,
	// as each run reports its age, until the process's last run
	ages := func(found int, dropped int, last int) string {
		values := []string{}
		for minute := 0; minute <= 300; minute++ {
			run := min(minute, last)
			age := 0
			if found <= run && run < dropped {
				age = 60 * (run - found)
			}
			values = append(values, fmt.Sprint(age))
		}
		return strings.Join(values, " ")
	}
	type process_ struct {
		service, instance string
		age, sampled      string
	}
	series := func(processes ...process_) map[string]string {
		values := map[string]string{}
		for _, p := range processes {
			values[`urnetwork_db_invalid_index_max_age_seconds{`+process(p.service, p.instance)+`}`] = p.age
			values[`urnetwork_db_invalid_index_sample_timestamp_seconds{`+process(p.service, p.instance)+`}`] = p.sampled
		}
		return values
	}
	taskworker := func(instance string, found int, dropped int, last int) process_ {
		return process_{service: "taskworker", instance: instance, age: ages(found, dropped, last), sampled: runs(last)}
	}
	cases := []promtoolAlertCase{
		{name: "nothing invalid", series: series(taskworker("i1", 1000, 1000, 300)), evalTime: "240m"},
		{name: "invalid for an hour and three quarters", series: series(taskworker("i1", 10, 1000, 300)), evalTime: "115m"},
		{name: "invalid for more than two hours", series: series(taskworker("i1", 10, 1000, 300)), evalTime: "135m", fires: true},
		{name: "the 2026-11-26 leftover, invalid for four hours", series: series(taskworker("i1", 10, 1000, 300)), evalTime: "250m", fires: true},
		{name: "dropped after three hours", series: series(taskworker("i1", 10, 190, 300)), evalTime: "200m"},
		{name: "only an older process's run reports an old index", series: series(
			taskworker("i1", 10, 1000, 150),
			taskworker("i2", 1000, 1000, 300),
		), evalTime: "250m"},
		{name: "the newest run, on another process, reports an old index", series: series(
			taskworker("i1", 1000, 1000, 100),
			taskworker("i2", 10, 1000, 300),
		), evalTime: "250m", fires: true},
		{name: "a stopped chain keeps its last report", series: series(taskworker("i1", 10, 1000, 200)), evalTime: "250m", fires: true},
		{name: "another service pushes the gauges", series: series(
			process_{service: "api", instance: "a1", age: "30000x300", sampled: "60+60x300"},
			taskworker("i1", 1000, 1000, 290),
		), evalTime: "250m"},
		{name: "no taskworker has run the chain yet", series: map[string]string{
			`urnetwork_db_hot_vacuum_attempts_total{` + process("taskworker", "i1") + `,table="pending_task",outcome="vacuumed"}`: "0+1x300",
		}, evalTime: "250m"},
	}
	evaluateAlertRuleWithPromtool(t, rule, "1m", map[string]string{}, cases)
}
