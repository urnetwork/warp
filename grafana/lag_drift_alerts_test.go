package main

import (
	"fmt"
	"regexp"
	"strings"
	"testing"
)

// lag.dev's drift test rules (alerting/lag-drift.yml): a failed test, runs
// stuck in processing at the sweep's newest pass, a sweep that stopped, a
// spike of inconsistent verdicts and a stale calibration (mmm
// lag.dev/DRIFTTEST.md P4, E5, V4, V5, R1; its runbook lag.dev/ops/drift-test.md
// §6, §7, §9). Each warns, reads only main, and reads a drift counter as each
// process's count over the window, as the lag-dev dashboard's drift row does
// (server grafana/lag_dev_drift_dashboard_test.go).

const lagDriftAlertsFile = "alerting/lag-drift.yml"

// One counter's count over a window, per process: the last value in the
// window less the last value before it, or the whole value of a series that
// began within it. Groups: the three selectors and the four windows.
var lagDriftAlertCountPattern = regexp.MustCompile(`\(last_over_time\((urnetwork_lag_drift_[a-z0-9_]+_total\{[^{}\s]*\})\[([0-9]+[hm])\]\)` +
	` - last_over_time\((urnetwork_lag_drift_[a-z0-9_]+_total\{[^{}\s]*\})\[([0-9]+[hm])\] offset ([0-9]+[hm])\)\)` +
	` or last_over_time\((urnetwork_lag_drift_[a-z0-9_]+_total\{[^{}\s]*\})\[([0-9]+[hm])\]\)`)

var lagDriftAlertCounterPattern = regexp.MustCompile(`urnetwork_lag_drift_[a-z0-9_]+_total`)

func TestLagDriftAlertRulesShape(t *testing.T) {
	groups := loadProvisionedAlertGroups(t, lagDriftAlertsFile)
	group, ok := groups["lag-drift"]
	if !ok || group.Folder != "urnetwork alerts" || group.Interval != "1m" || len(group.Rules) != 5 {
		t.Fatalf("lag-drift group = %+v", group)
	}
	// the stuck runs are the newest pass's, and only while a pass is recent
	stuckExpr := provisionedAlertRuleByUID(t, group, "lag-drift-runs-stuck").Data[0].Model.Expr
	for _, part := range []string{
		` and on (env, service, block, host, instance) `,
		`topk(1, urnetwork_lag_drift_sweep_timestamp_seconds{env="main",service="taskworker"} > time() - 300)`,
	} {
		if !strings.Contains(stuckExpr, part) {
			t.Errorf("lag-drift-runs-stuck does not read the newest recent pass (%q): %s", part, stuckExpr)
		}
	}
	for uid, want := range map[string]struct {
		title     string
		hold      string
		threshold float64
		metric    string
		runbook   string
	}{
		"lag-drift-test-failed":        {"LagDriftTestFailed", "0s", 0, "urnetwork_lag_drift_failures_total", "§9.1"},
		"lag-drift-runs-stuck":         {"LagDriftRunsStuck", "5m", 0, "urnetwork_lag_drift_stuck_runs", "§9.1"},
		"lag-drift-sweep-stopped":      {"LagDriftSweepStopped", "0s", 300, "urnetwork_lag_drift_sweep_timestamp_seconds", "§9.1"},
		"lag-drift-inconsistent-spike": {"LagDriftInconsistentSpike", "0s", 5, "urnetwork_lag_drift_verdict_reasons_total", "§9.2"},
		"lag-drift-calibration-stale":  {"LagDriftCalibrationStale", "1h", 15, "urnetwork_stats_lag_drift_calibration_age_seconds", "§6"},
	} {
		rule := provisionedAlertRuleByUID(t, group, uid)
		if rule.Title != want.title || rule.Labels["service"] != "lag-drift" || rule.Labels["severity"] != "warn" {
			t.Errorf("%s title and labels = %s %v", uid, rule.Title, rule.Labels)
		}
		// a metric no process pushes yet, or a quiet hour, is no alert
		if rule.NoDataState != "OK" || rule.ExecErrState != "Error" || rule.For != want.hold {
			t.Errorf("%s noDataState/execErrState/for = %s/%s/%s", uid, rule.NoDataState, rule.ExecErrState, rule.For)
		}
		if len(rule.Data) != 2 || rule.Data[0].DatasourceUID != "warp-mimir" || len(rule.Data[1].Model.Conditions) != 1 {
			t.Fatalf("%s wants a warp-mimir query and one threshold", uid)
		}
		evaluator := rule.Data[1].Model.Conditions[0].Evaluator
		if evaluator.Type != "gt" || len(evaluator.Params) != 1 || evaluator.Params[0] != want.threshold {
			t.Errorf("%s threshold = %s %v, want gt %v", uid, evaluator.Type, evaluator.Params, want.threshold)
		}
		if !strings.Contains(rule.Annotations["summary"], "lag.dev/ops/drift-test.md "+want.runbook) {
			t.Errorf("%s summary does not name the runbook's %s: %s", uid, want.runbook, rule.Annotations["summary"])
		}

		expr := rule.Data[0].Model.Expr
		if !strings.Contains(expr, want.metric+"{") {
			t.Errorf("%s does not read %s: %s", uid, want.metric, expr)
		}
		if count := strings.Count(expr, "{"); count == 0 || count != strings.Count(expr, `{env="main"`) {
			t.Errorf("%s has a selector that does not start with env=\"main\": %s", uid, expr)
		}
		// every counter read is a whole count form, and the forms agree
		forms := lagDriftAlertCountPattern.FindAllStringSubmatch(expr, -1)
		if counters := len(lagDriftAlertCounterPattern.FindAllString(expr, -1)); counters != 3*len(forms) {
			t.Errorf("%s reads a drift counter other than as each process's count over the window: %s", uid, expr)
		}
		for _, form := range forms {
			if form[1] != form[3] || form[1] != form[6] || form[2] != form[4] || form[2] != form[5] || form[2] != form[7] {
				t.Errorf("%s has a count whose selectors or windows differ: %s", uid, form[0])
			}
		}
	}
}

// The labels of one process's series of a drift metric.
func lagDriftProcess(env string, service string, instance string) string {
	return fmt.Sprintf(`env=%q,service=%q,block="g1",host="h1",instance=%q,job=%q`, env, service, instance, service)
}

// Failures on 1-minute samples, read at 120 minutes unless a case says: a
// failure in the hour fires, whether its process still runs, started within
// the hour (its first push already counts one), or has since stopped; none, an
// older failure, or another environment's stays quiet.
func TestLagDriftTestFailedEvaluate(t *testing.T) {
	rule := provisionedAlertRuleByUID(t, loadProvisionedAlertGroups(t, lagDriftAlertsFile)["lag-drift"], "lag-drift-test-failed")
	failures := func(env string, service string, instance string) string {
		return "urnetwork_lag_drift_failures_total{" + lagDriftProcess(env, service, instance) + "}"
	}
	cases := []promtoolAlertCase{
		{name: "a failure 10 minutes ago", series: map[string]string{
			failures("main", "api", "a1"):        "0x109 1x70",
			failures("main", "taskworker", "t1"): "0x180",
		}, evalTime: "120m", fires: true},
		{name: "no failure", series: map[string]string{
			failures("main", "api", "a1"):        "0x180",
			failures("main", "taskworker", "t1"): "0x180",
		}, evalTime: "120m"},
		{name: "a failure two hours before", series: map[string]string{
			failures("main", "api", "a1"): "0x9 1x170",
		}, evalTime: "150m"},
		{name: "a new taskworker's first push counts one", series: map[string]string{
			failures("main", "taskworker", "t1"): "0x180",
			failures("main", "taskworker", "t2"): "_x99 1x80",
		}, evalTime: "120m", fires: true},
		{name: "a failure in a process that has since stopped", series: map[string]string{
			failures("main", "api", "a1"): "0x89 1x10 _x80",
			failures("main", "api", "a2"): "_x89 0x90",
		}, evalTime: "120m", fires: true},
		{name: "another environment's failure", series: map[string]string{
			failures("beta", "api", "a1"): "0x109 1x70",
			failures("main", "api", "a1"): "0x180",
		}, evalTime: "120m"},
	}
	evaluateAlertRuleWithPromtool(t, rule, "1m", map[string]string{}, cases)
}

// A process's series of the drift sweep's two gauges: the runs its last pass
// left stuck, and when that pass ended, unix seconds.
func lagDriftStuck(env string, service string, instance string) string {
	return "urnetwork_lag_drift_stuck_runs{" + lagDriftProcess(env, service, instance) + "}"
}

func lagDriftSweepTimestamp(env string, service string, instance string) string {
	return "urnetwork_lag_drift_sweep_timestamp_seconds{" + lagDriftProcess(env, service, instance) + "}"
}

// The sweep's gauges on 1-minute samples, read at 60 minutes; a taskworker
// ends a pass each minute unless a case says. Runs stuck at the newest pass
// for 5 minutes fire. A taskworker that stopped sweeping keeps the count of
// its own last pass, which a newer pass by another outweighs; stuck for 4
// minutes so far, or for 3 and then completed, stay quiet, as do none,
// another environment's, and a sweep that stopped (LagDriftSweepStopped's).
// The api registers both gauges too and pushes 0.
func TestLagDriftRunsStuckEvaluate(t *testing.T) {
	rule := provisionedAlertRuleByUID(t, loadProvisionedAlertGroups(t, lagDriftAlertsFile)["lag-drift"], "lag-drift-runs-stuck")
	everyMinute := "0+60x70"
	cases := []promtoolAlertCase{
		{name: "2 runs stuck at each pass for 10 minutes", series: map[string]string{
			lagDriftStuck("main", "taskworker", "t1"):          "0x49 2x20",
			lagDriftSweepTimestamp("main", "taskworker", "t1"): everyMinute,
			lagDriftStuck("main", "api", "a1"):                 "0x70",
			lagDriftSweepTimestamp("main", "api", "a1"):        "0x70",
		}, evalTime: "60m", fires: true},
		{name: "both taskworkers find 3 runs stuck", series: map[string]string{
			lagDriftStuck("main", "taskworker", "t1"):          "0x49 3x20",
			lagDriftSweepTimestamp("main", "taskworker", "t1"): "30+60x70",
			lagDriftStuck("main", "taskworker", "t2"):          "0x49 3x20",
			lagDriftSweepTimestamp("main", "taskworker", "t2"): everyMinute,
		}, evalTime: "60m", fires: true},
		{name: "a taskworker that stopped sweeping keeps its old count", series: map[string]string{
			lagDriftStuck("main", "taskworker", "t1"):          "2x70",
			lagDriftSweepTimestamp("main", "taskworker", "t1"): "30+60x20 1230x50",
			lagDriftStuck("main", "taskworker", "t2"):          "0x70",
			lagDriftSweepTimestamp("main", "taskworker", "t2"): everyMinute,
		}, evalTime: "60m"},
		{name: "stuck for 4 minutes so far", series: map[string]string{
			lagDriftStuck("main", "taskworker", "t1"):          "0x55 2x14",
			lagDriftSweepTimestamp("main", "taskworker", "t1"): everyMinute,
		}, evalTime: "60m"},
		{name: "stuck for 3 minutes, then completed", series: map[string]string{
			lagDriftStuck("main", "taskworker", "t1"):          "0x50 2x3 0x16",
			lagDriftSweepTimestamp("main", "taskworker", "t1"): everyMinute,
		}, evalTime: "60m"},
		{name: "the sweep stopped 10 minutes before", series: map[string]string{
			lagDriftStuck("main", "taskworker", "t1"):          "2x70",
			lagDriftSweepTimestamp("main", "taskworker", "t1"): "0+60x50 3000x20",
		}, evalTime: "60m"},
		{name: "none stuck", series: map[string]string{
			lagDriftStuck("main", "taskworker", "t1"):          "0x70",
			lagDriftSweepTimestamp("main", "taskworker", "t1"): everyMinute,
			lagDriftStuck("main", "api", "a1"):                 "0x70",
		}, evalTime: "60m"},
		{name: "another environment's", series: map[string]string{
			lagDriftStuck("beta", "taskworker", "t1"):          "0x49 2x20",
			lagDriftSweepTimestamp("beta", "taskworker", "t1"): everyMinute,
		}, evalTime: "60m"},
	}
	evaluateAlertRuleWithPromtool(t, rule, "1m", map[string]string{}, cases)
}

// The sweep's timestamp on 1-minute samples, read at 60 minutes: no pass for
// 10 minutes fires, and so do 20 minutes without one across a restart, whose
// new taskworker publishes 0 until its first pass. A pass each minute, one
// taskworker's passes while another stopped, a pass that took 4 minutes, a
// new taskworker before its first pass beside the old one's last, the api's
// zeros, and another environment's stopped sweep stay quiet.
func TestLagDriftSweepStoppedEvaluate(t *testing.T) {
	rule := provisionedAlertRuleByUID(t, loadProvisionedAlertGroups(t, lagDriftAlertsFile)["lag-drift"], "lag-drift-sweep-stopped")
	everyMinute := "0+60x70"
	cases := []promtoolAlertCase{
		{name: "a pass each minute", series: map[string]string{
			lagDriftSweepTimestamp("main", "taskworker", "t1"): everyMinute,
			lagDriftSweepTimestamp("main", "api", "a1"):        "0x70",
		}, evalTime: "60m"},
		{name: "the last pass ended 10 minutes before", series: map[string]string{
			lagDriftSweepTimestamp("main", "taskworker", "t1"): "0+60x50 3000x20",
		}, evalTime: "60m", fires: true},
		{name: "one taskworker stopped, another sweeps", series: map[string]string{
			lagDriftSweepTimestamp("main", "taskworker", "t1"): "0+60x20 1200x50",
			lagDriftSweepTimestamp("main", "taskworker", "t2"): everyMinute,
		}, evalTime: "60m"},
		{name: "a pass that took 4 minutes", series: map[string]string{
			lagDriftSweepTimestamp("main", "taskworker", "t1"): "0+60x54 3240x4 3540x12",
		}, evalTime: "60m"},
		{name: "a new taskworker before its first pass, beside the old one's last", series: map[string]string{
			lagDriftSweepTimestamp("main", "taskworker", "t1"): "0+60x58 _x12",
			lagDriftSweepTimestamp("main", "taskworker", "t2"): "_x58 0x12",
		}, evalTime: "60m"},
		{name: "no pass for 20 minutes, across a restart", series: map[string]string{
			lagDriftSweepTimestamp("main", "taskworker", "t1"): "0+60x40 _x30",
			lagDriftSweepTimestamp("main", "taskworker", "t2"): "_x50 0x20",
		}, evalTime: "60m", fires: true},
		{name: "another environment's stopped sweep", series: map[string]string{
			lagDriftSweepTimestamp("beta", "taskworker", "t1"): "0+60x20 1200x50",
			lagDriftSweepTimestamp("main", "taskworker", "t1"): everyMinute,
		}, evalTime: "60m"},
	}
	evaluateAlertRuleWithPromtool(t, rule, "1m", map[string]string{}, cases)
}

// Verdicts by reason on 10-minute samples, read at 12 hours over the 6 hours
// before: 12 inconsistent of 100 fires, and so do 7 of 47 from two processes'
// first counts, which an increase would miss. 6 of 20, as one token's 6 runs
// can be, 12 of 1,000, inconsistent verdicts 8 hours before, and another
// environment's stay quiet.
func TestLagDriftInconsistentSpikeEvaluate(t *testing.T) {
	rule := provisionedAlertRuleByUID(t, loadProvisionedAlertGroups(t, lagDriftAlertsFile)["lag-drift"], "lag-drift-inconsistent-spike")
	verdicts := func(env string, instance string, verdict string, reason string) string {
		return fmt.Sprintf("urnetwork_lag_drift_verdict_reasons_total{%s,verdict=%q,reason=%q}", lagDriftProcess(env, "api", instance), verdict, reason)
	}
	// counts that start at 0 and reach their value at 410 minutes, within
	// the 6 hours before 12 hours
	inWindow := func(count int) string { return fmt.Sprintf("0x40 %dx40", count) }
	cases := []promtoolAlertCase{
		{name: "12 inconsistent of 100", series: map[string]string{
			verdicts("main", "a1", "inconclusive", "inconsistent"):  inWindow(12),
			verdicts("main", "a1", "agree", "inside_ip_country"):    inWindow(80),
			verdicts("main", "a1", "disagree", "region_outside"):    inWindow(8),
			verdicts("main", "a2", "inconclusive", "low_precision"): "0x81",
		}, evalTime: "12h", fires: true},
		{name: "7 inconsistent of 47 from two processes' first counts", series: map[string]string{
			verdicts("main", "a1", "inconclusive", "inconsistent"): "_x50 4x30",
			verdicts("main", "a2", "inconclusive", "inconsistent"): "_x55 3x25",
			verdicts("main", "a1", "agree", "inside_ip_country"):   "_x50 40x30",
		}, evalTime: "12h", fires: true},
		{name: "6 inconsistent of 20, one token's runs", series: map[string]string{
			verdicts("main", "a1", "inconclusive", "inconsistent"): inWindow(6),
			verdicts("main", "a1", "agree", "inside_ip_country"):   inWindow(14),
		}, evalTime: "12h"},
		{name: "12 inconsistent of 1000", series: map[string]string{
			verdicts("main", "a1", "inconclusive", "inconsistent"): inWindow(12),
			verdicts("main", "a1", "agree", "inside_ip_country"):   inWindow(988),
		}, evalTime: "12h"},
		{name: "12 inconsistent 8 hours before, none since", series: map[string]string{
			verdicts("main", "a1", "inconclusive", "inconsistent"): "0x10 12x70",
			verdicts("main", "a1", "agree", "inside_ip_country"):   "0x10 20x70",
		}, evalTime: "12h"},
		{name: "another environment's", series: map[string]string{
			verdicts("beta", "a1", "inconclusive", "inconsistent"): inWindow(12),
			verdicts("beta", "a1", "agree", "inside_ip_country"):   inWindow(88),
			verdicts("main", "a1", "agree", "inside_ip_country"):   inWindow(100),
		}, evalTime: "12h"},
	}
	evaluateAlertRuleWithPromtool(t, rule, "10m", map[string]string{}, cases)
}

// The calibration's age on the stats collector's 5-minute samples, read at 3
// hours: 16 days for 3 hours fires, from either taskworker. A week, one failed
// week's 14.5 days, past 15 days for only 25 minutes, a calibration that
// applied 75 minutes before, and no calibration at all stay quiet.
func TestLagDriftCalibrationStaleEvaluate(t *testing.T) {
	rule := provisionedAlertRuleByUID(t, loadProvisionedAlertGroups(t, lagDriftAlertsFile)["lag-drift"], "lag-drift-calibration-stale")
	age := func(env string, instance string) string {
		return "urnetwork_stats_lag_drift_calibration_age_seconds{" + lagDriftProcess(env, "taskworker", instance) + "}"
	}
	// an age from start seconds, refreshed every 5 minutes
	from := func(start int) string { return fmt.Sprintf("%d+300x40", start) }
	const day = 86400
	cases := []promtoolAlertCase{
		{name: "16 days for 3 hours", series: map[string]string{
			age("main", "t1"): from(16 * day),
			age("main", "t2"): from(16 * day),
		}, evalTime: "3h", fires: true},
		{name: "one taskworker publishing 16 days", series: map[string]string{
			age("main", "t1"): from(16 * day),
		}, evalTime: "3h", fires: true},
		{name: "a week", series: map[string]string{
			age("main", "t1"): from(7 * day),
		}, evalTime: "3h"},
		{name: "one failed week, 14.5 days", series: map[string]string{
			age("main", "t1"): from(29 * day / 2),
		}, evalTime: "3h"},
		{name: "past 15 days for 25 minutes", series: map[string]string{
			age("main", "t1"): from(15*day - 9000),
		}, evalTime: "3h"},
		{name: "a calibration applied 75 minutes before", series: map[string]string{
			age("main", "t1"): fmt.Sprintf("%d+300x20 0+300x20", 16*day),
		}, evalTime: "3h"},
		{name: "no calibration, the defaults", series: map[string]string{
			age("beta", "t1"): from(16 * day),
		}, evalTime: "3h"},
	}
	evaluateAlertRuleWithPromtool(t, rule, "5m", map[string]string{}, cases)
}
