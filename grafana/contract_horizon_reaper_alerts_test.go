package main

import (
	"fmt"
	"strings"
	"testing"
)

// The owner's reaper rule (2026-11-15) reads the reaper's counters and the
// current pass's skipped contracts from server branch
// fix/contract-reaper-cursor-1115 (server bdb11f61c), only from taskworker
// series, and warns.
func TestContractReaperStalledRuleShape(t *testing.T) {
	groups := loadProvisionedAlertGroups(t, "alerting/contract-horizon-reaper.yml")
	group, ok := groups["contract-horizon-reaper"]
	if !ok || group.Folder != "urnetwork alerts" || group.Interval != "5m" || len(group.Rules) != 1 {
		t.Fatalf("contract-horizon-reaper group = %+v", group)
	}
	rule := provisionedAlertRuleByUID(t, group, "contract-reaper-stalled")
	if rule.Title != "ContractReaperStalled" || rule.Labels["service"] != "contract-horizon-reaper" || rule.Labels["severity"] != "warn" {
		t.Errorf("reaper rule title and labels = %s %v", rule.Title, rule.Labels)
	}
	if rule.NoDataState != "OK" || rule.ExecErrState != "Error" || rule.For != "5m" {
		t.Errorf("reaper rule noDataState/execErrState/for = %s/%s/%s", rule.NoDataState, rule.ExecErrState, rule.For)
	}
	expr := rule.Data[0].Model.Expr
	for _, metric := range []string{
		"urnetwork_contract_horizon_eligible_contracts_total",
		"urnetwork_contract_horizon_protected_contracts_total",
		"urnetwork_contract_horizon_pass_skipped_contracts",
		"urnetwork_contract_horizon_mode",
		"urnetwork_contract_horizon_horizon_timestamp_seconds",
		"urnetwork_contract_horizon_horizon_seconds",
	} {
		if !strings.Contains(expr, metric) {
			t.Errorf("reaper rule does not read %s", metric)
		}
	}
	if count := strings.Count(expr, "{"); count != strings.Count(expr, `{env="main",service="taskworker"`) {
		t.Errorf("a reaper selector does not start with env and service=taskworker: %s", expr)
	}
}

// The reaper rule on synthetic taskworker series at 1-minute samples, read at
// 100 minutes. It fires on the 11-12..11-15 defect, a caught-up pass that
// reads about 640 contracts a second, keeps 636 as recent_close and deletes
// 4, and on lock contention; it stays quiet while the reaper deletes, while a
// rescan rereads payment holds, and with the mode off or in a dry run. Its
// second arm fires when the current pass moves past more than 10,000
// contracts an hour that it could delete soon.
func TestContractReaperStalledEvaluate(t *testing.T) {
	groups := loadProvisionedAlertGroups(t, "alerting/contract-horizon-reaper.yml")
	rule := provisionedAlertRuleByUID(t, groups["contract-horizon-reaper"], "contract-reaper-stalled")
	const process = `env="main",service="taskworker",block="g1",host="h1",instance="i1",job="taskworker"`
	const horizon = 35 * 86400
	// per second, for 200 minutes
	counter := func(perSecond float64) string { return fmt.Sprintf("0+%gx200", perSecond*60) }
	gauge := func(value float64) string { return fmt.Sprintf("%gx200", value) }
	type reaper struct {
		mode float64
		// the run's clock stops at this minute (0: runs throughout)
		lastRunMinute int
		deleted       float64
		dryRunDeleted float64
		kept          map[string]float64
		// the pass's skipped contracts by reason, a series of values
		skipped map[string]string
	}
	series := func(r reaper) map[string]string {
		run := fmt.Sprintf("%d+60x200", -horizon)
		if r.lastRunMinute != 0 {
			run = fmt.Sprintf("%d+60x%d %dx%d", -horizon, r.lastRunMinute, -horizon+60*r.lastRunMinute, 200-r.lastRunMinute)
		}
		values := map[string]string{
			"urnetwork_contract_horizon_horizon_timestamp_seconds{" + process + "}":               run,
			"urnetwork_contract_horizon_horizon_seconds{" + process + "}":                         gauge(horizon),
			"urnetwork_contract_horizon_mode{" + process + "}":                                    gauge(r.mode),
			"urnetwork_contract_horizon_eligible_contracts_total{" + process + `,mode="on"}`:      counter(r.deleted),
			"urnetwork_contract_horizon_eligible_contracts_total{" + process + `,mode="dry_run"}`: counter(r.dryRunDeleted),
			// another service registers the reaper's metrics and pushes zeros
			`urnetwork_contract_horizon_mode{env="main",service="api",block="g1",host="h1",instance="a1",job="api"}`: gauge(0),
		}
		for _, reason := range []string{"recent_close", "busy", "open", "unsettled", "payment_hold", "payment_review"} {
			values["urnetwork_contract_horizon_protected_contracts_total{"+process+`,reason="`+reason+`"}`] = counter(r.kept[reason])
			if skipped, ok := r.skipped[reason]; ok {
				values["urnetwork_contract_horizon_pass_skipped_contracts{"+process+`,reason="`+reason+`"}`] = skipped
			} else {
				values["urnetwork_contract_horizon_pass_skipped_contracts{"+process+`,reason="`+reason+`"}`] = gauge(0)
			}
		}
		return values
	}
	cases := []promtoolAlertCase{
		{name: "the caught-up pass of 11-15 before the fix", series: series(reaper{mode: 2, deleted: 4, kept: map[string]float64{"recent_close": 636}}), evalTime: "100m", fires: true},
		{name: "lock contention keeps what it reads as busy", series: series(reaper{mode: 2, deleted: 1, kept: map[string]float64{"busy": 50}}), evalTime: "100m", fires: true},
		{name: "the fixed pass caught up", series: series(reaper{mode: 2, deleted: 260, kept: map[string]float64{"recent_close": 0.2}}), evalTime: "100m"},
		{name: "the backlog delete", series: series(reaper{mode: 2, deleted: 2000}), evalTime: "100m"},
		{name: "a rescan rereads payment holds", series: series(reaper{mode: 2, deleted: 0.5, kept: map[string]float64{"payment_hold": 1900, "payment_review": 99}}), evalTime: "100m"},
		{name: "mode off", series: series(reaper{mode: 0}), evalTime: "100m"},
		{name: "a dry run keeps recent closes", series: series(reaper{mode: 1, dryRunDeleted: 4, kept: map[string]float64{"recent_close": 636}}), evalTime: "100m"},
		{name: "no run in the last 30 minutes", series: series(reaper{mode: 2, lastRunMinute: 60, deleted: 4, kept: map[string]float64{"recent_close": 636}}), evalTime: "100m"},
		// 20,000 an hour while it deletes 1,000 a second
		{name: "the pass moves past 20,000 recent closes an hour", series: series(reaper{mode: 2, deleted: 1000, kept: map[string]float64{"recent_close": 5.6},
			skipped: map[string]string{"recent_close": "0+333.4x200"}}), evalTime: "100m", fires: true},
		{name: "the pass moves past 5,000 contracts an hour", series: series(reaper{mode: 2, deleted: 1000, kept: map[string]float64{"busy": 1.4},
			skipped: map[string]string{"busy": "0+83.4x200"}}), evalTime: "100m"},
		{name: "a new pass starts its count at zero", series: series(reaper{mode: 2, deleted: 1000,
			skipped: map[string]string{"recent_close": "50000x70 0+10x129"}}), evalTime: "100m"},
		{name: "the pass moves past payment holds", series: series(reaper{mode: 2, deleted: 1000, kept: map[string]float64{"payment_hold": 300},
			skipped: map[string]string{"payment_hold": "0+18000x200"}}), evalTime: "100m"},
	}
	evaluateAlertRuleWithPromtool(t, rule, "1m", map[string]string{}, cases)
}
