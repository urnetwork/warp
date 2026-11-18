package main

import (
	"fmt"
	"regexp"
	"strings"
	"testing"
)

const hostClockSelector = `{env="main",job="node"}`

// The hosts whose clocks xops host-clock.timer watches: every host that ships
// its metrics to Mimir but the offsite VPN server (2026-11-18).
var hostClockHosts = []string{
	"by-us-fmt-5-edge-0",
	"by-us-fmt-5-edge-1",
	"by-us-fmt-5-edge-2",
	"by-us-fmt-5-edge-3",
	"by-us-fmt-5-edge-4",
	"by-us-fmt-5-edge-5",
	"by-us-fmt-5-edge-6",
	"crisp",
	"fireside",
	"snow",
	"planetoid",
}

const hostClockHostsRegexp = `by-us-fmt-5-edge-[0-6]|crisp|fireside|snow|planetoid`

// A host clock series as it arrives in Mimir.
func hostClockSeries(metric string, host string) string {
	return fmt.Sprintf(`%s{env="main",host="%s",job="node"}`, metric, host)
}

// node_uname_info as the host's Fluent Bit ships it.
func hostUnameSeries(host string) string {
	return fmt.Sprintf(`node_uname_info{env="main",host="%s",job="node",machine="x86_64",nodename="%s",sysname="Linux"}`, host, host)
}

// The owner's clock watch (2026-11-18): page on a clock more than a second
// off NTP for 5 minutes, warn on a clock not synchronized for 15 minutes, and
// warn on a check that is stale or missing.
func TestHostClockAlertsWatchEveryHostsClock(t *testing.T) {
	want := map[string]struct {
		title     string
		expr      string
		evaluator string
		threshold float64
		severity  string
		forValue  string
	}{
		"host-clock-offset":     {"HostClockOffset", "max by (host) (abs(urnetwork_host_clock_offset_seconds" + hostClockSelector + "))", "gt", 1, "page", "5m"},
		"host-clock-not-synced": {"HostClockNotSynced", "min by (host) (urnetwork_host_clock_synced" + hostClockSelector + ")", "lt", 1, "warn", "15m"},
		"host-clock-check-stale": {
			"HostClockCheckStale",
			"time() - ( max by (host) (urnetwork_host_clock_check_timestamp_seconds" + hostClockSelector + ")" +
				` or (0 * max by (host) (node_uname_info{env="main",job="node",host=~"` + hostClockHostsRegexp + `"})) )`,
			"gt", 300, "warn", "5m",
		},
	}
	groups := loadProvisionedAlertGroups(t, "alerting/host-clock.yml")
	group, ok := groups["host-clock"]
	if !ok || group.Folder != "urnetwork alerts" || group.Interval != "1m" {
		t.Fatalf("host-clock group = %+v", group)
	}
	if len(group.Rules) != len(want) {
		t.Errorf("host-clock rule count = %d, want %d", len(group.Rules), len(want))
	}
	for uid, expected := range want {
		rule := provisionedAlertRuleByUID(t, group, uid)
		if rule.Title != expected.title {
			t.Errorf("%s title = %s, want %s", uid, rule.Title, expected.title)
		}
		if len(rule.Data) != 2 || len(rule.Data[1].Model.Conditions) != 1 {
			t.Errorf("%s wants a query and one threshold condition", uid)
			continue
		}
		if rule.Data[0].DatasourceUID != "warp-mimir" {
			t.Errorf("%s reads %s, want warp-mimir", uid, rule.Data[0].DatasourceUID)
		}
		if got := strings.TrimSpace(rule.Data[0].Model.Expr); got != expected.expr {
			t.Errorf("%s expr = %s, want %s", uid, got, expected.expr)
		}
		evaluator := rule.Data[1].Model.Conditions[0].Evaluator
		if evaluator.Type != expected.evaluator || len(evaluator.Params) != 1 || evaluator.Params[0] != expected.threshold {
			t.Errorf("%s threshold = %s %v, want %s %v", uid, evaluator.Type, evaluator.Params, expected.evaluator, expected.threshold)
		}
		if rule.Labels["service"] != "host-clock" || rule.Labels["severity"] != expected.severity {
			t.Errorf("%s labels = %v, want service host-clock, severity %s", uid, rule.Labels, expected.severity)
		}
		// a host whose series drop out is the stale rule's
		if rule.NoDataState != "OK" || rule.ExecErrState != "Error" || rule.For != expected.forValue {
			t.Errorf("%s noDataState/execErrState/for = %s/%s/%s, want OK/Error/%s", uid, rule.NoDataState, rule.ExecErrState, rule.For, expected.forValue)
		}
		if !strings.Contains(rule.Annotations["summary"], "{{ $labels.host }}") {
			t.Errorf("%s summary does not name the host: %q", uid, rule.Annotations["summary"])
		}
	}

	// the stale rule expects exactly the watched hosts, so the VPN server,
	// which runs no collector, is never read as missing
	hosts := regexp.MustCompile(`^(?:` + hostClockHostsRegexp + `)$`)
	for _, host := range hostClockHosts {
		if !hosts.MatchString(host) {
			t.Errorf("the stale rule does not expect %s", host)
		}
	}
	for _, host := range []string{"by-us-west-1-vpn-0", "by-us-fmt-5-edge-7", "sille"} {
		if hosts.MatchString(host) {
			t.Errorf("the stale rule expects %s, which runs no collector", host)
		}
	}
}

// The rules on synthetic histories at 1-minute samples, the collector's
// cadence, against the hosts' readings of 2026-11-18: offsets of 0.1-22 ms,
// all synchronized.
func TestHostClockAlertsEvaluate(t *testing.T) {
	groups := loadProvisionedAlertGroups(t, "alerting/host-clock.yml")
	group := groups["host-clock"]

	offset := func(host string) string { return hostClockSeries("urnetwork_host_clock_offset_seconds", host) }
	synced := func(host string) string { return hostClockSeries("urnetwork_host_clock_synced", host) }
	check := func(host string) string {
		return hostClockSeries("urnetwork_host_clock_check_timestamp_seconds", host)
	}
	edge0, edge6 := "by-us-fmt-5-edge-0", "by-us-fmt-5-edge-6"
	vpn := "by-us-west-1-vpn-0"

	cases := map[string][]promtoolAlertCase{
		"host-clock-offset": {
			{name: "milliseconds off", series: map[string]string{offset(edge0): "-0.000222x40", offset(edge6): "0.022499x40"}, evalTime: "40m"},
			{name: "1.5 s ahead for 10 minutes", series: map[string]string{offset(edge0): "-0.000222x30 -1.5x10", offset(edge6): "0.022499x40"}, evalTime: "40m", fires: true},
			{name: "2 s behind for 10 minutes", series: map[string]string{offset(edge0): "0.0007x30 2x10"}, evalTime: "40m", fires: true},
			// timesyncd stepped the clock and measured again a minute later
			{name: "off for 3 minutes, then kept", series: map[string]string{offset(edge0): "0.0007x30 1.5x3 0.001x7"}, evalTime: "40m"},
			{name: "1.5 s for the last 3 minutes", series: map[string]string{offset(edge0): "0.0007x36 1.5x4"}, evalTime: "40m"},
			{name: "exactly a second", series: map[string]string{offset(edge0): "1x40"}, evalTime: "40m"},
		},
		"host-clock-not-synced": {
			{name: "synchronized", series: map[string]string{synced(edge0): "1x40", synced(edge6): "1x40"}, evalTime: "40m"},
			{name: "not synchronized for 20 minutes", series: map[string]string{synced(edge0): "1x20 0x20", synced(edge6): "1x40"}, evalTime: "40m", fires: true},
			{name: "not synchronized for 10 minutes", series: map[string]string{synced(edge0): "1x30 0x10"}, evalTime: "40m"},
			// timesyncd restarted and synchronized again
			{name: "12 minutes without, then synchronized", series: map[string]string{synced(edge0): "1x20 0x12 1x8"}, evalTime: "40m"},
		},
		"host-clock-check-stale": {
			{name: "fresh every minute", series: map[string]string{check(edge0): "0+60x40", hostUnameSeries(edge0): "1x40"}, evalTime: "40m"},
			// Fluent Bit keeps shipping the file, whose timestamp stopped at 28m
			{name: "the file stopped updating 12 minutes ago", series: map[string]string{check(edge0): "0+60x28 1680x12", hostUnameSeries(edge0): "1x40"}, evalTime: "40m", fires: true},
			{name: "the file stopped updating 7 minutes ago", series: map[string]string{check(edge0): "0+60x33 1980x7", hostUnameSeries(edge0): "1x40"}, evalTime: "40m"},
			// the file is gone and the host still ships its other metrics
			{name: "no check while the host ships", series: map[string]string{check(edge6): "0+60x40", hostUnameSeries(edge0): "1x40", hostUnameSeries(edge6): "1x40"}, evalTime: "40m", fires: true},
			// the VPN server ships node metrics and runs no collector
			{name: "the vpn server", series: map[string]string{check(edge0): "0+60x40", hostUnameSeries(edge0): "1x40", hostUnameSeries(vpn): "1x40"}, evalTime: "40m"},
		},
	}
	labels := map[string]string{"host": edge0}
	for uid, ruleCases := range cases {
		t.Run(uid, func(t *testing.T) {
			evaluateAlertRuleWithPromtool(t, provisionedAlertRuleByUID(t, group, uid), "1m", labels, ruleCases)
		})
	}
}
