package main

import (
	"fmt"
	"strings"
	"testing"
)

const (
	dbDiskSelector = `node_filesystem_avail_bytes{env="main",host="by-us-fmt-5-edge-2",mountpoint="/"}`
	// the labels the series carries in Mimir
	dbDiskSeries = `node_filesystem_avail_bytes{device="/dev/mapper/ubuntu--vg-ubuntu--lv",env="main",fstype="ext4",host="by-us-fmt-5-edge-2",job="node",mountpoint="/"}`
)

// The owner's rules for Main's database disk (2026-11-15): the days until
// edge-2's root filesystem is full at the last 24 hours' net loss of free
// space warn under 21 and page under 10, and never while free space is flat
// or rising. A series that stops warns on its own.
func TestDbDiskAlertsWatchEdge2Runway(t *testing.T) {
	free := "max by (host) (" + dbDiskSelector + ")"
	dayAgo := "max by (host) (" + dbDiskSelector + " offset 1d)"
	runway := free + " / ((" + dayAgo + " - " + free + ") > 0)"
	want := map[string]struct {
		title     string
		expr      string
		evaluator string
		threshold float64
		severity  string
		forValue  string
	}{
		"db-disk-runway-low":        {"DbDiskRunwayLow", runway, "lt", 21, "warn", "3h"},
		"db-disk-runway-critical":   {"DbDiskRunwayCritical", runway, "lt", 10, "page", "1h"},
		"db-disk-telemetry-missing": {"DbDiskTelemetryMissing", "absent(" + dbDiskSelector + ")", "gt", 0, "warn", "15m"},
	}
	groups := loadProvisionedAlertGroups(t, "alerting/db-disk.yml")
	group, ok := groups["db-disk"]
	if !ok || group.Folder != "urnetwork alerts" || group.Interval != "5m" {
		t.Fatalf("db-disk group = %+v", group)
	}
	if len(group.Rules) != len(want) {
		t.Errorf("db-disk rule count = %d, want %d", len(group.Rules), len(want))
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
		if got := rule.Data[0].Model.Expr; got != expected.expr {
			t.Errorf("%s expr = %s, want %s", uid, got, expected.expr)
		}
		evaluator := rule.Data[1].Model.Conditions[0].Evaluator
		if evaluator.Type != expected.evaluator || len(evaluator.Params) != 1 || evaluator.Params[0] != expected.threshold {
			t.Errorf("%s threshold = %s %v, want %s %v", uid, evaluator.Type, evaluator.Params, expected.evaluator, expected.threshold)
		}
		if rule.Labels["service"] != "db-disk" || rule.Labels["severity"] != expected.severity {
			t.Errorf("%s labels = %v, want service db-disk, severity %s", uid, rule.Labels, expected.severity)
		}
		// quiet without data: flat or rising free space, or no sample a day ago
		if rule.NoDataState != "OK" || rule.ExecErrState != "Error" || rule.For != expected.forValue {
			t.Errorf("%s noDataState/execErrState/for = %s/%s/%s, want OK/Error/%s", uid, rule.NoDataState, rule.ExecErrState, rule.For, expected.forValue)
		}
		if !strings.Contains(rule.Annotations["summary"], "by-us-fmt-5-edge-2") {
			t.Errorf("%s summary does not name the host: %q", uid, rule.Annotations["summary"])
		}
	}
}

// The runway rules on synthetic histories, in GiB at 5-minute samples (288 a
// day): the ratio is the same in bytes. Today's disk, 4,627 GiB free and
// losing about 160 GiB a day, reads about 28 days.
func TestDbDiskRunwayEvaluate(t *testing.T) {
	groups := loadProvisionedAlertGroups(t, "alerting/db-disk.yml")
	group := groups["db-disk"]
	// a loss of perDay GiB a day from start, for 50 hours
	declining := func(start float64, perDay float64) string {
		return fmt.Sprintf("%g-%gx600", start, perDay/288)
	}
	cases := map[string][]promtoolAlertCase{
		"db-disk-runway-low": {
			{name: "about 28 days: 4,480 GiB free, losing 160 a day", series: map[string]string{dbDiskSeries: declining(4800, 160)}, evalTime: "48h"},
			{name: "14 days: 3,500 GiB free, losing 250 a day", series: map[string]string{dbDiskSeries: declining(4000, 250)}, evalTime: "48h", fires: true},
			{name: "flat", series: map[string]string{dbDiskSeries: "4000x600"}, evalTime: "48h"},
			{name: "rising 100 GiB a day", series: map[string]string{dbDiskSeries: "1000+0.3472x600"}, evalTime: "48h"},
			{name: "no sample a day ago", series: map[string]string{dbDiskSeries: declining(1000, 400)}, evalTime: "20h"},
			// 3,700 GiB over a 300 GiB loss reads 12.3 days for 2 hours
			{name: "a 2-hour dip of 300 GiB", series: map[string]string{dbDiskSeries: "4000x564 3700x24 4000x12"}, evalTime: "49h"},
			{name: "the same dip held 4 hours", series: map[string]string{dbDiskSeries: "4000x540 3700x60"}, evalTime: "49h55m", fires: true},
		},
		"db-disk-runway-critical": {
			{name: "14 days: 3,500 GiB free, losing 250 a day", series: map[string]string{dbDiskSeries: declining(4000, 250)}, evalTime: "48h"},
			{name: "5.5 days: 2,200 GiB free, losing 400 a day", series: map[string]string{dbDiskSeries: declining(3000, 400)}, evalTime: "48h", fires: true},
			{name: "flat", series: map[string]string{dbDiskSeries: "3000x600"}, evalTime: "48h"},
			// 2,600 GiB over a 400 GiB loss reads 6.5 days for 45 minutes
			{name: "a 45-minute dip of 400 GiB", series: map[string]string{dbDiskSeries: "3000x564 2600x9 3000x27"}, evalTime: "47h40m"},
			{name: "the same loss held 90 minutes", series: map[string]string{dbDiskSeries: "3000x564 2600x36"}, evalTime: "48h35m", fires: true},
		},
		"db-disk-telemetry-missing": {
			{name: "reporting", series: map[string]string{dbDiskSeries: "4000x600"}, evalTime: "2h"},
			{name: "stopped 30 minutes ago", series: map[string]string{dbDiskSeries: "4000x12"}, evalTime: "90m", fires: true},
			{name: "stopped 5 minutes ago", series: map[string]string{dbDiskSeries: "4000x12"}, evalTime: "65m"},
		},
	}
	labels := map[string]map[string]string{
		"db-disk-runway-low":        {"host": "by-us-fmt-5-edge-2"},
		"db-disk-runway-critical":   {"host": "by-us-fmt-5-edge-2"},
		"db-disk-telemetry-missing": {"env": "main", "host": "by-us-fmt-5-edge-2", "mountpoint": "/"},
	}
	for uid, ruleCases := range cases {
		t.Run(uid, func(t *testing.T) {
			evaluateAlertRuleWithPromtool(t, provisionedAlertRuleByUID(t, group, uid), "5m", labels[uid], ruleCases)
		})
	}
}
