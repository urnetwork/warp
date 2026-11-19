package main

import (
	"fmt"
	"strings"
	"testing"
)

// Owner decision 3 of 2026-11-18 (server session/REVOKE-FINAL.md §15): a
// credential check that cannot reach Redis accepts the credential and counts
// it, and an alert fires on the rate; a mint that cannot reach Redis issues an
// untagged credential, counted and alerted the same way. The rules read the
// share of each service's checks (or mints), with a floor on the absolute
// rate, and stay quiet until the counters exist.
func TestSessionAuthRulesShape(t *testing.T) {
	groups := loadProvisionedAlertGroups(t, "alerting/session-auth.yml")
	group, ok := groups["session-auth"]
	if !ok || group.Folder != "urnetwork alerts" || group.Interval != "1m" || len(group.Rules) != 3 {
		t.Fatalf("session-auth group = %+v", group)
	}
	for _, want := range []struct {
		uid, title, severity, holdFor string
		threshold                     float64
		reads                         []string
		floor                         string
	}{
		{"session-checks-unchecked", "SessionChecksUnchecked", "warn", "10m", 0.05,
			[]string{"urnetwork_session_check_unavailable_total[5m]", "urnetwork_jwt_state_record_checks_total[5m]"}, "> 1)"},
		{"session-checks-unchecked-severe", "SessionChecksUncheckedSevere", "page", "5m", 0.25,
			[]string{"urnetwork_session_check_unavailable_total[5m]", "urnetwork_jwt_state_record_checks_total[5m]"}, "> 10)"},
		{"session-mints-untagged", "SessionMintsUntagged", "warn", "10m", 0.01,
			[]string{"urnetwork_session_mint_untagged_total[5m]", `urnetwork_session_storage_seconds_count{operation="mint"}[5m]`}, "> 0.1)"},
	} {
		rule := provisionedAlertRuleByUID(t, group, want.uid)
		if rule.Title != want.title || rule.Labels["severity"] != want.severity || rule.For != want.holdFor {
			t.Errorf("%s title, severity and for = %s %s %s", want.uid, rule.Title, rule.Labels["severity"], rule.For)
		}
		// absent counters (before the emitting code runs) are not an outage
		if rule.NoDataState != "OK" || rule.ExecErrState != "Error" {
			t.Errorf("%s noDataState/execErrState = %s/%s", want.uid, rule.NoDataState, rule.ExecErrState)
		}
		if len(rule.Data) != 2 || rule.Data[0].DatasourceUID != "warp-mimir" || len(rule.Data[1].Model.Conditions) != 1 {
			t.Fatalf("%s wants a mimir query and one threshold", want.uid)
		}
		evaluator := rule.Data[1].Model.Conditions[0].Evaluator
		if evaluator.Type != "gt" || len(evaluator.Params) != 1 || evaluator.Params[0] != want.threshold {
			t.Errorf("%s threshold = %s %v, want gt %v", want.uid, evaluator.Type, evaluator.Params, want.threshold)
		}
		expr := rule.Data[0].Model.Expr
		for _, read := range want.reads {
			if !strings.Contains(expr, read) {
				t.Errorf("%s does not read %s: %s", want.uid, read, expr)
			}
		}
		if !strings.Contains(expr, "and on (env, service)") || !strings.HasSuffix(strings.TrimSpace(expr), want.floor) {
			t.Errorf("%s does not floor the absolute rate with %s: %s", want.uid, want.floor, expr)
		}
		// grouping by env and service alone keeps one alert per service
		if strings.Count(expr, "sum by (env, service)") != 4 {
			t.Errorf("%s does not group every term by env and service: %s", want.uid, expr)
		}
		if !strings.Contains(rule.Annotations["summary"], "{{ $labels.service }}") {
			t.Errorf("%s summary does not name the service", want.uid)
		}
	}
}

// One service's checks at 1-minute samples, read at 30 minutes: the share of
// unchecked acceptances and its floor, held for the rule's for. Connect's
// standing 1.5-3.2% of record_unavailable (11-16..11-18) and a few seconds of
// dial-timeout burst stay quiet; a sustained partial outage fires.
func TestSessionChecksUncheckedEvaluate(t *testing.T) {
	groups := loadProvisionedAlertGroups(t, "alerting/session-auth.yml")
	const process = `env="main",service="connect",block="g1",host="h1",instance="i1"`
	// a counter at a constant rate per second, then another, switching at a
	// minute; 31 samples cover minutes 0 to 30
	counter := func(perSecond float64, fromMinute int, thenPerSecond float64) string {
		before := fmt.Sprintf("0+%gx%d", perSecond*60, fromMinute)
		after := fmt.Sprintf("%g+%gx%d", perSecond*60*float64(fromMinute)+thenPerSecond*60, thenPerSecond*60, 30-fromMinute-1)
		return before + " " + after
	}
	steady := func(perSecond float64) string { return counter(perSecond, 15, perSecond) }
	checks := `urnetwork_jwt_state_record_checks_total{` + process + `,caller="connect_h1",operation="validate",credential="client",outcome="record_valid"}`
	unchecked := `urnetwork_session_check_unavailable_total{` + process + `,path="lease",credential="client"}`
	// 30 seconds of every check unchecked at minute 20: 300,000 in one sample step
	burst := "0x19 300000x10"
	firing := map[string]string{"env": "main", "service": "connect"}

	evaluateAlertRuleWithPromtool(t, provisionedAlertRuleByUID(t, groups["session-auth"], "session-checks-unchecked"), "1m", firing, []promtoolAlertCase{
		{name: "connect's standing share of 2.6%", series: map[string]string{checks: steady(10000), unchecked: steady(260)}, evalTime: "30m"},
		{name: "a 30-second dial burst of every check", series: map[string]string{checks: steady(10000), unchecked: burst}, evalTime: "30m"},
		{name: "a partial outage at 10% since minute 5", series: map[string]string{checks: steady(10000), unchecked: counter(0, 5, 1000)}, evalTime: "30m", fires: true},
		{name: "the outage has held only 7 minutes", series: map[string]string{checks: steady(10000), unchecked: counter(0, 23, 1000)}, evalTime: "30m"},
		{name: "below the floor of 1 a second", series: map[string]string{checks: steady(5), unchecked: steady(0.5)}, evalTime: "30m"},
		{name: "unchecked acceptances with no record checks", series: map[string]string{unchecked: steady(5)}, evalTime: "30m", fires: true},
	})
	evaluateAlertRuleWithPromtool(t, provisionedAlertRuleByUID(t, groups["session-auth"], "session-checks-unchecked-severe"), "1m", firing, []promtoolAlertCase{
		{name: "a broad outage at 30% since minute 20", series: map[string]string{checks: steady(10000), unchecked: counter(0, 20, 3000)}, evalTime: "30m", fires: true},
		{name: "a partial outage at 10% pages no one", series: map[string]string{checks: steady(10000), unchecked: counter(0, 5, 1000)}, evalTime: "30m"},
		{name: "half of 10 checks a second is below the floor", series: map[string]string{checks: steady(10), unchecked: steady(5)}, evalTime: "30m"},
	})
}

// One service's mints at 1-minute samples, read at 30 minutes: more than 1%
// untagged for 10 minutes fires; a short fallback or one below the floor does
// not.
func TestSessionMintsUntaggedEvaluate(t *testing.T) {
	groups := loadProvisionedAlertGroups(t, "alerting/session-auth.yml")
	const process = `env="main",service="api",block="g1",host="h1",instance="i1"`
	counter := func(perSecond float64, fromMinute int, thenPerSecond float64) string {
		before := fmt.Sprintf("0+%gx%d", perSecond*60, fromMinute)
		after := fmt.Sprintf("%g+%gx%d", perSecond*60*float64(fromMinute)+thenPerSecond*60, thenPerSecond*60, 30-fromMinute-1)
		return before + " " + after
	}
	mints := `urnetwork_session_storage_seconds_count{` + process + `,operation="mint",outcome="success"}`
	// another operation is not a mint
	inventory := `urnetwork_session_storage_seconds_count{` + process + `,operation="inventory",outcome="success"}`
	untagged := `urnetwork_session_mint_untagged_total{` + process + `,kind="api_key_client"}`
	firing := map[string]string{"env": "main", "service": "api"}

	evaluateAlertRuleWithPromtool(t, provisionedAlertRuleByUID(t, groups["session-auth"], "session-mints-untagged"), "1m", firing, []promtoolAlertCase{
		{name: "2% of mints untagged since minute 5", series: map[string]string{mints: counter(380, 15, 380), untagged: counter(0, 5, 7.6)}, evalTime: "30m", fires: true},
		{name: "0.5% of mints untagged", series: map[string]string{mints: counter(380, 15, 380), untagged: counter(1.9, 15, 1.9)}, evalTime: "30m"},
		{name: "2% of mints, but measured against inventory reads too", series: map[string]string{mints: counter(380, 15, 380), inventory: counter(100000, 15, 100000), untagged: counter(0, 5, 7.6)}, evalTime: "30m", fires: true},
		{name: "every mint untagged below the floor of 0.1 a second", series: map[string]string{mints: counter(0.05, 15, 0.05), untagged: counter(0.05, 15, 0.05)}, evalTime: "30m"},
		{name: "a 3-minute fallback", series: map[string]string{mints: counter(380, 15, 380), untagged: "0x22 3420x7"}, evalTime: "30m"},
	})
}
