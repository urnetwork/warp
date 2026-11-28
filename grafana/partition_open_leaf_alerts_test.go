package main

import (
	"fmt"
	"strings"
	"testing"
)

// The open leaf rule (2026-11-28) reads, by family, the wait of the oldest
// opened leaf still without statistics from that family's newest pass, only
// from taskworker series, and warns above three minutes, at once.
func TestPartitionOpenLeafUnanalyzedRuleShape(t *testing.T) {
	groups := loadProvisionedAlertGroups(t, "alerting/partition-open-leaf.yml")
	group, ok := groups["partition-open-leaf"]
	if !ok || group.Folder != "urnetwork alerts" || group.Interval != "1m" || len(group.Rules) != 1 {
		t.Fatalf("partition-open-leaf group = %+v", group)
	}
	rule := provisionedAlertRuleByUID(t, group, "partition-open-leaf-unanalyzed")
	if rule.Title != "PartitionOpenLeafUnanalyzed" || rule.Labels["service"] != "db" || rule.Labels["severity"] != "warn" {
		t.Errorf("open leaf rule title and labels = %s %v", rule.Title, rule.Labels)
	}
	// the wait is the hold; missing data is a taskworker without the gauges
	if rule.NoDataState != "OK" || rule.ExecErrState != "Error" || rule.For != "0s" {
		t.Errorf("open leaf rule noDataState/execErrState/for = %s/%s/%s", rule.NoDataState, rule.ExecErrState, rule.For)
	}
	if len(rule.Data) != 2 || rule.Data[0].DatasourceUID != "warp-mimir" || rule.Data[1].DatasourceUID != "__expr__" || len(rule.Data[1].Model.Conditions) != 1 {
		t.Fatalf("open leaf rule wants a mimir query and one threshold")
	}
	expr := rule.Data[0].Model.Expr
	for _, part := range []string{
		"max by (family) (",
		"urnetwork_db_partition_open_leaf_unanalyzed_wait_seconds{",
		"and on (env, service, block, host, instance, family)",
		"topk by (family) (1, urnetwork_db_partition_open_leaf_sample_timestamp_seconds{",
	} {
		if !strings.Contains(expr, part) {
			t.Errorf("open leaf rule does not read %s", part)
		}
	}
	if count := strings.Count(expr, "{"); count != strings.Count(expr, `{env="main",service="taskworker"}`) {
		t.Errorf("an open leaf selector is not env and service=taskworker: %s", expr)
	}
	evaluator := rule.Data[1].Model.Conditions[0].Evaluator
	if evaluator.Type != "gt" || len(evaluator.Params) != 1 || evaluator.Params[0] != 180 {
		t.Errorf("open leaf rule threshold = %s %v, want gt 180", evaluator.Type, evaluator.Params)
	}
	summary := rule.Annotations["summary"]
	for _, want := range []string{"{{ $labels.family }}", "without statistics", "ANALYZE"} {
		if !strings.Contains(summary, want) {
			t.Errorf("open leaf summary does not name %s: %q", want, summary)
		}
	}
}

// The rule on synthetic taskworker series at 1-minute samples. A process that
// passes over a family's opened leaves every minute publishes its sample time
// and the oldest unanalyzed leaf's wait. It warns once that wait is past
// three minutes, from the family's newest pass, also when that pass ran on
// another process than an older one, and stays quiet when every leaf is
// analyzed, at two minutes, when only an older process's pass still reports a
// wait, and on another service's series. Before a taskworker with the gauges
// runs, the series are absent, and it never fires.
func TestPartitionOpenLeafUnanalyzedEvaluate(t *testing.T) {
	groups := loadProvisionedAlertGroups(t, "alerting/partition-open-leaf.yml")
	rule := provisionedAlertRuleByUID(t, groups["partition-open-leaf"], "partition-open-leaf-unanalyzed")
	labels := func(service string, instance string, family string) string {
		return fmt.Sprintf(`env="main",service="%s",block="g1",host="h1",instance="%s",job="%s",family="%s"`, service, instance, service, family)
	}
	// passes every minute until minute last, then keeps the time of its last pass
	passes := func(last int) string {
		if 40 <= last {
			return "60+60x40"
		}
		return fmt.Sprintf("60+60x%d %dx%d", last, 60+60*last, 40-last)
	}
	type pass struct {
		service, instance, family string
		wait                      string
		last                      int
	}
	series := func(passes_ ...pass) map[string]string {
		values := map[string]string{}
		for _, p := range passes_ {
			values[`urnetwork_db_partition_open_leaf_unanalyzed_wait_seconds{`+labels(p.service, p.instance, p.family)+`}`] = p.wait
			values[`urnetwork_db_partition_open_leaf_sample_timestamp_seconds{`+labels(p.service, p.instance, p.family)+`}`] = passes(p.last)
		}
		return values
	}
	contract := func(instance string, wait string, last int) pass {
		return pass{service: "taskworker", instance: instance, family: "transfer_contract", wait: wait, last: last}
	}
	cases := []promtoolAlertCase{
		{name: "the gauges are absent: no taskworker with them runs", series: map[string]string{
			`urnetwork_db_hot_vacuum_attempts_total{env="main",service="taskworker",block="g1",host="h1",instance="i1",job="taskworker",table="pending_task",outcome="vacuumed"}`: "0+1x40",
		}, evalTime: "30m"},
		{name: "every opened leaf analyzed", series: series(contract("i1", "0x40", 40)), evalTime: "30m"},
		{name: "a leaf two minutes past its analyze time", series: series(contract("i1", "120x40", 40)), evalTime: "30m"},
		{name: "a leaf three minutes past its analyze time", series: series(contract("i1", "180x40", 40)), evalTime: "30m"},
		{name: "the leaf of 2026-11-28, eleven minutes past its analyze time", series: series(contract("i1", "660x40", 40)), evalTime: "30m", fires: true},
		{name: "only an older process's pass still reports a wait", series: series(
			contract("i1", "600x40", 10),
			contract("i2", "0x40", 40),
		), evalTime: "30m"},
		{name: "the newest pass, on another process, reports a wait", series: series(
			contract("i1", "0x40", 10),
			contract("i2", "240x40", 40),
		), evalTime: "30m", fires: true},
		{name: "another service pushes the gauges", series: series(
			pass{service: "api", instance: "a1", family: "transfer_contract", wait: "900x40", last: 40},
			contract("i1", "0x40", 40),
		), evalTime: "30m"},
	}
	evaluateAlertRuleWithPromtool(t, rule, "1m", map[string]string{"family": "transfer_contract"}, cases)
	// each family from its own newest pass
	evaluateAlertRuleWithPromtool(t, rule, "1m", map[string]string{"family": "transfer_debit_journal"}, []promtoolAlertCase{
		{name: "another family's leaf waits while the contract leaves are analyzed", series: series(
			contract("i1", "0x40", 40),
			pass{service: "taskworker", instance: "i1", family: "transfer_debit_journal", wait: "300x40", last: 40},
		), evalTime: "30m", fires: true},
	})
}
