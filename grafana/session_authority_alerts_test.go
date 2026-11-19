package main

import (
	"fmt"
	"strings"
	"testing"
)

// The session authority rules (server session/REVOKE-OPERATIONS.md): authority
// loss and clock refusals on any increase, clock disagreement before the
// refusal bound, journal work that keeps aging, failing revocation writes, and
// maintenance that stalls or fails. Each reads metrics every server process
// already pushes, so each must stay quiet on the week of history its level
// came from, and on absent series.
func TestSessionAuthorityRulesShape(t *testing.T) {
	groups := loadProvisionedAlertGroups(t, "alerting/session-authority.yml")
	group, ok := groups["session-authority"]
	if !ok || group.Folder != "urnetwork alerts" || group.Interval != "1m" || len(group.Rules) != 8 {
		t.Fatalf("session-authority group = %+v", group)
	}
	for _, want := range []struct {
		uid, title, severity, holdFor, operator string
		threshold                               float64
		reads                                   []string
	}{
		{"session-authority-loss", "SessionAuthorityLoss", "page", "0s", "gt", 0, []string{"increase(urnetwork_session_authority_loss_total[10m])", "sum by (env, service)"}},
		{"session-clock-refusals", "SessionClockRefusals", "page", "0s", "gt", 0, []string{"increase(urnetwork_session_clock_refusals_total[10m])", "sum by (env, service, host)"}},
		{"session-clock-disagreement", "SessionClockDisagreement", "warn", "2m", "gt", 10, []string{"max by (env, service, host) (urnetwork_session_clock_disagreement_seconds)"}},
		{"session-journal-stuck", "SessionJournalStuck", "warn", "2m", "gt", 60, []string{"(urnetwork_session_journal_oldest_seconds > 60)", "delta(urnetwork_session_journal_oldest_seconds[5m]) > 0", "max by (env, state)"}},
		{"session-journal-stuck-long", "SessionJournalStuckLong", "page", "5m", "gt", 900, []string{`urnetwork_session_journal_oldest_seconds{state=~"prepared|enforced"} > 900`, `delta(urnetwork_session_journal_oldest_seconds{state=~"prepared|enforced"}[5m]) > 0`}},
		{"session-revocation-writes-failing", "SessionRevocationWritesFailing", "warn", "5m", "gt", 0.01, []string{`{kind!="projection",outcome="failure"}[5m]`, `{kind!="projection"}[5m]`, "> 0.1)"}},
		{"session-maintenance-stalled", "SessionMaintenanceStalled", "warn", "10m", "lt", 32, []string{`task="work.MaintainNetworkSessions",outcome="succeeded"}[5m])) * 60`}},
		{"session-maintenance-failing", "SessionMaintenanceFailing", "warn", "10m", "gt", 1, []string{`task="work.MaintainNetworkSessions",outcome="failed"}[10m])) * 60`}},
	} {
		rule := provisionedAlertRuleByUID(t, group, want.uid)
		if rule.Title != want.title || rule.Labels["severity"] != want.severity || rule.For != want.holdFor {
			t.Errorf("%s title, severity and for = %s %s %s", want.uid, rule.Title, rule.Labels["severity"], rule.For)
		}
		if rule.NoDataState != "OK" || rule.ExecErrState != "Error" {
			t.Errorf("%s noDataState/execErrState = %s/%s", want.uid, rule.NoDataState, rule.ExecErrState)
		}
		if len(rule.Data) != 2 || rule.Data[0].DatasourceUID != "warp-mimir" || len(rule.Data[1].Model.Conditions) != 1 {
			t.Fatalf("%s wants a mimir query and one threshold", want.uid)
		}
		evaluator := rule.Data[1].Model.Conditions[0].Evaluator
		if evaluator.Type != want.operator || len(evaluator.Params) != 1 || evaluator.Params[0] != want.threshold {
			t.Errorf("%s threshold = %s %v, want %s %v", want.uid, evaluator.Type, evaluator.Params, want.operator, want.threshold)
		}
		for _, read := range want.reads {
			if !strings.Contains(rule.Data[0].Model.Expr, read) {
				t.Errorf("%s does not read %s: %s", want.uid, read, rule.Data[0].Model.Expr)
			}
		}
		if rule.Annotations["summary"] == "" {
			t.Errorf("%s has no summary", want.uid)
		}
	}
}

// A counter that every process exports from 0: quiet while it stays 0, after
// a restart, and 10 minutes after an increase; firing at once on an increase.
func TestSessionAuthorityIncidentRulesEvaluate(t *testing.T) {
	groups := loadProvisionedAlertGroups(t, "alerting/session-authority.yml")
	for _, c := range []struct {
		uid, metric string
		firing      map[string]string
	}{
		{"session-authority-loss", "urnetwork_session_authority_loss_total", map[string]string{"env": "main", "service": "api"}},
		{"session-clock-refusals", "urnetwork_session_clock_refusals_total", map[string]string{"env": "main", "service": "api", "host": "h1"}},
	} {
		process := func(instance string) string {
			return c.metric + `{env="main",service="api",block="g1",host="h1",instance="` + instance + `",job="api"}`
		}
		evaluateAlertRuleWithPromtool(t, provisionedAlertRuleByUID(t, groups["session-authority"], c.uid), "1m", c.firing, []promtoolAlertCase{
			{name: "a week at 0", series: map[string]string{process("i1"): "0x40"}, evalTime: "30m"},
			{name: "one event at minute 20", series: map[string]string{process("i1"): "0x19 1x20"}, evalTime: "25m", fires: true},
			{name: "10 minutes after the event", series: map[string]string{process("i1"): "0x19 1x20"}, evalTime: "35m"},
			{name: "a restart starts a new process at 0", series: map[string]string{process("i1"): "0x19", process("i2"): "_x20 0x20"}, evalTime: "30m"},
		})
	}
}

// The gauge each mint samples: 10 seconds held 2 minutes warns, before the
// 15-second refusal; a moment above it or the week's 0 does not.
func TestSessionClockDisagreementEvaluate(t *testing.T) {
	groups := loadProvisionedAlertGroups(t, "alerting/session-authority.yml")
	gauge := `urnetwork_session_clock_disagreement_seconds{env="main",service="api",block="g1",host="h1",instance="i1",job="api"}`
	evaluateAlertRuleWithPromtool(t, provisionedAlertRuleByUID(t, groups["session-authority"], "session-clock-disagreement"), "1m", map[string]string{"env": "main", "service": "api", "host": "h1"}, []promtoolAlertCase{
		{name: "nothing mints yet", series: map[string]string{gauge: "0x40"}, evalTime: "30m"},
		{name: "a host 66 ms off", series: map[string]string{gauge: "0.066x40"}, evalTime: "30m"},
		{name: "12 seconds since minute 20", series: map[string]string{gauge: "0x19 12x20"}, evalTime: "30m", fires: true},
		{name: "12 seconds for one minute", series: map[string]string{gauge: "0x19 12 0x19"}, evalTime: "30m"},
	})
}

// Only the taskworker running maintenance shard 0 refreshes the journal
// gauges; every other taskworker keeps what it last saw. A stuck operation
// ages at every observation, so a rising series fires; a stale copy that stays
// flat, or the week's index repair that drained within 32 seconds, does not.
func TestSessionJournalStuckEvaluate(t *testing.T) {
	groups := loadProvisionedAlertGroups(t, "alerting/session-authority.yml")
	gauge := func(state, instance string) string {
		return `urnetwork_session_journal_oldest_seconds{env="main",service="taskworker",block="g1",host="h1",instance="` + instance + `",job="taskworker",state="` + state + `"}`
	}
	// stuck since minute 5: the shard-0 taskworker observes the age every minute
	stuck := "0x5 60+60x34"
	warn := provisionedAlertRuleByUID(t, groups["session-authority"], "session-journal-stuck")
	evaluateAlertRuleWithPromtool(t, warn, "1m", map[string]string{"env": "main", "state": "prepared"}, []promtoolAlertCase{
		{name: "a revoke stuck in prepared", series: map[string]string{gauge("prepared", "t1"): stuck, gauge("prepared", "t2"): "0x40"}, evalTime: "30m", fires: true},
		{name: "a stale copy at 75 seconds on a taskworker that no longer runs shard 0", series: map[string]string{gauge("prepared", "t2"): "75x40", gauge("prepared", "t1"): "0x40"}, evalTime: "30m"},
		{name: "a stuck revoke whose observer moves between taskworkers", series: map[string]string{gauge("prepared", "t1"): "0x5 60+60x9 600x25", gauge("prepared", "t2"): "0x15 660+60x24"}, evalTime: "30m", fires: true},
		{name: "the stuck revoke finished at minute 20", series: map[string]string{gauge("prepared", "t1"): "0x5 60+60x14 0x20"}, evalTime: "30m"},
	})
	evaluateAlertRuleWithPromtool(t, warn, "1m", map[string]string{"env": "main", "state": "index"}, []promtoolAlertCase{
		{name: "index repair behind since minute 5", series: map[string]string{gauge("index", "t1"): stuck}, evalTime: "30m", fires: true},
		{name: "the week's peak: index repair drained within 32 seconds", series: map[string]string{gauge("index", "t1"): "0x10 16 32 0x28"}, evalTime: "13m"},
	})
	long := provisionedAlertRuleByUID(t, groups["session-authority"], "session-journal-stuck-long")
	evaluateAlertRuleWithPromtool(t, long, "1m", map[string]string{"env": "main", "state": "enforced"}, []promtoolAlertCase{
		{name: "an enforced revoke unfinished for 20 minutes", series: map[string]string{gauge("enforced", "t1"): "0+60x40"}, evalTime: "25m", fires: true},
		{name: "an enforced revoke 13 minutes old", series: map[string]string{gauge("enforced", "t1"): "0x12 60+60x28"}, evalTime: "25m"},
		{name: "index repair 20 minutes behind does not page", series: map[string]string{gauge("index", "t1"): "0+60x40"}, evalTime: "25m"},
	})
}

// Client revocations write about 400 times a second and failed at most 0.05%
// in 5 minutes on api and proxy in the week. Projection failures only cost a
// later SQL fallback and are left out.
func TestSessionRevocationWritesFailingEvaluate(t *testing.T) {
	groups := loadProvisionedAlertGroups(t, "alerting/session-authority.yml")
	const process = `env="main",service="api",block="g1",host="h1",instance="i1",job="api"`
	counter := func(kind, outcome string) string {
		return `urnetwork_session_revocation_record_writes_total{` + process + `,kind="` + kind + `",outcome="` + outcome + `"}`
	}
	perMinute := func(perSecond float64, fromMinute int) string {
		return fmt.Sprintf("0x%d 0+%gx%d", fromMinute, perSecond*60, 40-fromMinute)
	}
	evaluateAlertRuleWithPromtool(t, provisionedAlertRuleByUID(t, groups["session-authority"], "session-revocation-writes-failing"), "1m", map[string]string{"env": "main", "service": "api"}, []promtoolAlertCase{
		{name: "the week's worst share, 0.05%", series: map[string]string{counter("client", "success"): perMinute(400, 0), counter("client", "failure"): perMinute(0.2, 0)}, evalTime: "30m"},
		{name: "one master of 48 unreachable: 2% fail", series: map[string]string{counter("client", "success"): perMinute(392, 0), counter("client", "failure"): perMinute(8, 10)}, evalTime: "30m", fires: true},
		{name: "half of a service's few writes, below the floor", series: map[string]string{counter("client", "success"): perMinute(0.05, 0), counter("client", "failure"): perMinute(0.05, 0)}, evalTime: "30m"},
		{name: "projections failing", series: map[string]string{counter("client", "success"): perMinute(400, 0), counter("projection", "failure"): perMinute(100, 0), counter("projection", "success"): perMinute(100, 0)}, evalTime: "30m"},
		{name: "a 3-minute burst", series: map[string]string{counter("client", "success"): perMinute(392, 0), counter("client", "failure"): "0x24 0+480x2 960x13"}, evalTime: "30m"},
	})
}

// MaintainNetworkSessions succeeds about 62 times a minute; rolls dipped it for
// at most 5 minutes, and it failed 7 times in the week.
func TestSessionMaintenanceRulesEvaluate(t *testing.T) {
	groups := loadProvisionedAlertGroups(t, "alerting/session-authority.yml")
	counter := func(instance, outcome string) string {
		return `urnetwork_taskworker_executions_total{env="main",service="taskworker",block="g1",host="h1",instance="` + instance + `",job="taskworker",task="work.MaintainNetworkSessions",outcome="` + outcome + `"}`
	}
	firing := map[string]string{"env": "main"}
	evaluateAlertRuleWithPromtool(t, provisionedAlertRuleByUID(t, groups["session-authority"], "session-maintenance-stalled"), "1m", firing, []promtoolAlertCase{
		{name: "62 runs a minute", series: map[string]string{counter("t1", "succeeded"): "0+31x40", counter("t2", "succeeded"): "0+31x40"}, evalTime: "30m"},
		{name: "a 5-minute roll dip", series: map[string]string{counter("t1", "succeeded"): "0+62x14 868x5 868+62x20"}, evalTime: "30m"},
		{name: "every shard stopped at minute 10", series: map[string]string{counter("t1", "succeeded"): "0+62x10 620x30"}, evalTime: "30m", fires: true},
		{name: "half the shards lost", series: map[string]string{counter("t1", "succeeded"): "0+62x10 620+31x30"}, evalTime: "30m", fires: true},
	})
	evaluateAlertRuleWithPromtool(t, provisionedAlertRuleByUID(t, groups["session-authority"], "session-maintenance-failing"), "1m", firing, []promtoolAlertCase{
		{name: "a failure every 10 minutes, as in the week", series: map[string]string{counter("t1", "failed"): "0x10 1x10 2x10 3x10"}, evalTime: "30m"},
		{name: "a Redis blip's deadlines for 10 minutes", series: map[string]string{counter("t1", "failed"): "0x10 0+0.6x10 6x20"}, evalTime: "25m"},
		{name: "one shard failing every run since minute 5", series: map[string]string{counter("t1", "failed"): "0x5 0+2x35"}, evalTime: "30m", fires: true},
	})
}
