package main

import (
	"strings"
	"testing"
	"time"
)

// The dead man's switch (owner, 2026-11-16). The Watchdog fires at every
// evaluation with no series at all, so only a stopped Grafana, a failing
// Mimir query, or failed notifications silence it.
func TestWatchdogAlwaysFires(t *testing.T) {
	groups := loadProvisionedAlertGroups(t, "alerting/watchdog.yml")
	rule := provisionedAlertRuleByUID(t, groups["watchdog"], "urnetwork-watchdog")
	const unrelated = `urnetwork_backup_onsite_in_progress{archive="pg",env="main",host="by-us-fmt-5-edge-6",job="node"}`
	cases := []promtoolAlertCase{
		{name: "at the first evaluation", series: map[string]string{unrelated: "0x10"}, evalTime: "0m", fires: true},
		{name: "after a day", series: map[string]string{unrelated: "0x10"}, evalTime: "24h", fires: true},
		{name: "with every series gone", series: map[string]string{unrelated: "_x10"}, evalTime: "2h", fires: true},
	}
	evaluateAlertRuleWithPromtool(t, rule, "1m", map[string]string{}, cases)
}

// The rule as server grafana/alert_routing.go routes it: its title is the
// alertname and its service label is watchdog (WatchdogAlertName and
// WatchdogAlertService there), and a query error must not keep it firing, or
// a Mimir that stopped answering would keep the heartbeat alive. Its group
// evaluates within the route's 1-minute group interval and it fires at
// once, so a new Grafana pings within minutes of its start.
func TestWatchdogMatchesItsHeartbeatRoute(t *testing.T) {
	groups := loadProvisionedAlertGroups(t, "alerting/watchdog.yml")
	group := groups["watchdog"]
	if len(groups) != 1 || len(group.Rules) != 1 || group.Folder != "urnetwork alerts" {
		t.Fatalf("watchdog groups = %+v", groups)
	}
	interval, err := time.ParseDuration(group.Interval)
	if err != nil || time.Minute < interval {
		t.Errorf("watchdog group interval = %q, want at most 1m", group.Interval)
	}
	rule := provisionedAlertRuleByUID(t, group, "urnetwork-watchdog")
	if rule.Title != "Watchdog" || rule.Labels["service"] != "watchdog" || len(rule.Labels) != 2 {
		t.Errorf("watchdog title = %q, labels = %v, want Watchdog with service watchdog and a severity", rule.Title, rule.Labels)
	}
	if rule.ExecErrState != "Error" || rule.NoDataState != "OK" {
		t.Errorf("watchdog execErrState/noDataState = %s/%s, want Error/OK", rule.ExecErrState, rule.NoDataState)
	}
	if forDuration, err := time.ParseDuration(rule.For); err != nil || forDuration != 0 {
		t.Errorf("watchdog for = %q, want 0s", rule.For)
	}
	if rule.Data[0].DatasourceUID != "warp-mimir" || rule.Data[0].Model.Expr != "vector(1)" {
		t.Errorf("watchdog query = %s %q, want Mimir's vector(1)", rule.Data[0].DatasourceUID, rule.Data[0].Model.Expr)
	}
	summary := rule.Annotations["summary"]
	for _, words := range []string{"bringyourctl grafana reconcile-alerting", "alerts.watchdog_heartbeat_url", "external heartbeat"} {
		if !strings.Contains(summary, words) {
			t.Errorf("watchdog summary lacks %q: %s", words, summary)
		}
	}
}
