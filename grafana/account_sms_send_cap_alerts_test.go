package main

import (
	"strings"
	"testing"
)

// The account SMS send cap rule (owner, 2026-11-26) warns, by cap, on any text
// the server's send caps (server controller/aws_sms_send_cap.go) refused in the
// last 15 minutes, read from every process's per-process counter.
func TestAccountSmsSendCapRefusalsRuleShape(t *testing.T) {
	groups := loadProvisionedAlertGroups(t, "alerting/account-sms-send-cap.yml")
	group, ok := groups["account-sms-send-cap"]
	if !ok || group.Folder != "urnetwork alerts" || group.Interval != "1m" || len(group.Rules) != 1 {
		t.Fatalf("account-sms-send-cap group = %+v", group)
	}
	rule := provisionedAlertRuleByUID(t, group, "account-sms-send-cap-refusals")
	if rule.Title != "AccountSmsSendCapRefusals" || rule.Labels["service"] != "account-sms" || rule.Labels["severity"] != "warn" {
		t.Errorf("send cap rule title and labels = %s %v", rule.Title, rule.Labels)
	}
	// any refusal fires at once; missing data is a process that refused nothing
	if rule.NoDataState != "OK" || rule.ExecErrState != "Error" || rule.For != "0s" {
		t.Errorf("send cap rule noDataState/execErrState/for = %s/%s/%s", rule.NoDataState, rule.ExecErrState, rule.For)
	}
	if len(rule.Data) != 2 || rule.Data[0].DatasourceUID != "warp-mimir" || rule.Data[1].DatasourceUID != "__expr__" || len(rule.Data[1].Model.Conditions) != 1 {
		t.Fatalf("send cap rule wants a mimir query and one threshold")
	}
	if want := `sum by (env, cap) (increase(urnetwork_account_message_sms_cap_refusals_total{instance!=""}[15m]))`; rule.Data[0].Model.Expr != want {
		t.Errorf("send cap rule reads %q, want %q", rule.Data[0].Model.Expr, want)
	}
	evaluator := rule.Data[1].Model.Conditions[0].Evaluator
	if evaluator.Type != "gt" || len(evaluator.Params) != 1 || evaluator.Params[0] != 0 {
		t.Errorf("send cap rule threshold = %s %v, want gt 0", evaluator.Type, evaluator.Params)
	}
	summary := rule.Annotations["summary"]
	for _, want := range []string{"{{ $labels.cap }}", "{{ $labels.env }}", "15 minutes", "refused by the {{ $labels.cap }} send cap"} {
		if !strings.Contains(summary, want) {
			t.Errorf("send cap summary does not name %s: %q", want, summary)
		}
	}
}

// The rule on synthetic counters at 1-minute samples, for each cap the server
// labels, the daily caps included. Every process registers every cap at zero:
// quiet while every cap stays at zero, after a restart starts a new process at
// zero, and once the last refusal is more than 15 minutes old; firing at once
// for the cap that refused a text, from the api or the taskworker, and through
// a long burst. A series without a per-process instance is not read.
func TestAccountSmsSendCapRefusalsEvaluate(t *testing.T) {
	groups := loadProvisionedAlertGroups(t, "alerting/account-sms-send-cap.yml")
	rule := provisionedAlertRuleByUID(t, groups["account-sms-send-cap"], "account-sms-send-cap-refusals")
	caps := []string{"global", "country", "global_daily", "country_daily"}
	counter := func(service string, instance string, capKind string) string {
		return `urnetwork_account_message_sms_cap_refusals_total{env="main",service="` + service + `",block="g1",host="h1",instance="` + instance + `",job="` + service + `",cap="` + capKind + `"}`
	}
	for _, refusing := range caps {
		// every cap of the api and taskworker processes at zero for an hour,
		// except the given series
		series := func(values map[string]string) map[string]string {
			all := map[string]string{}
			for _, service := range []string{"api", "taskworker"} {
				for _, capKind := range caps {
					all[counter(service, "i-"+service, capKind)] = "0x60"
				}
			}
			for name, value := range values {
				all[name] = value
			}
			return all
		}
		cases := []promtoolAlertCase{
			{name: refusing + ": every cap at zero", series: series(nil), evalTime: "40m"},
			{name: refusing + ": one refusal at minute 20, 5 minutes later", series: series(map[string]string{counter("api", "i-api", refusing): "0x19 1x40"}), evalTime: "25m", fires: true},
			{name: refusing + ": one refusal at minute 20, 10 minutes later", series: series(map[string]string{counter("api", "i-api", refusing): "0x19 1x40"}), evalTime: "30m", fires: true},
			{name: refusing + ": one refusal at minute 20, 20 minutes later", series: series(map[string]string{counter("api", "i-api", refusing): "0x19 1x40"}), evalTime: "40m"},
			{name: refusing + ": the taskworker's outbox notice refused", series: series(map[string]string{counter("taskworker", "i-taskworker", refusing): "0x19 1x40"}), evalTime: "25m", fires: true},
			{name: refusing + ": a refusal every minute from minute 10", series: series(map[string]string{counter("api", "i-api", refusing): "0x9 1+1x50"}), evalTime: "55m", fires: true},
			{name: refusing + ": a restart starts a new process at zero", series: series(map[string]string{
				counter("api", "i-api", refusing):  "3x19",
				counter("api", "i-api2", refusing): "_x20 0x40",
			}), evalTime: "30m"},
			{name: refusing + ": a series without an instance", series: series(map[string]string{
				`urnetwork_account_message_sms_cap_refusals_total{env="main",service="api",cap="` + refusing + `"}`: "0x19 1x40",
			}), evalTime: "25m"},
		}
		evaluateAlertRuleWithPromtool(t, rule, "1m", map[string]string{"env": "main", "cap": refusing}, cases)
	}
}
