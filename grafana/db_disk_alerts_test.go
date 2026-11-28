package main

import (
	"fmt"
	"strconv"
	"strings"
	"testing"
)

const (
	dbDiskSelector = `node_filesystem_avail_bytes{env="main",host="by-us-fmt-5-edge-2",mountpoint="/"}`
	// the labels the series carries in Mimir
	dbDiskSeries = `node_filesystem_avail_bytes{device="/dev/mapper/ubuntu--vg-ubuntu--lv",env="main",fstype="ext4",host="by-us-fmt-5-edge-2",job="node",mountpoint="/"}`
	// the page's hard floor, 1 TiB free, in bytes
	dbDiskFloorBytes = "1099511627776"
)

var (
	dbDiskFree   = "max by (host) (" + dbDiskSelector + ")"
	dbDiskDayAgo = "max by (host) (" + dbDiskSelector + " offset 1d)"
	dbDiskRunway = dbDiskFree + " / ((" + dbDiskDayAgo + " - " + dbDiskFree + ") > 0)"
	// the TiB free while under the floor, and otherwise the runway
	dbDiskFloorOrRunway = "(" + dbDiskFree + " / " + dbDiskFloorBytes + " < 1) or (" + dbDiskRunway + ")"
)

// The owner's rules for Main's database disk (2026-11-15): the days until
// edge-2's root filesystem is full at the last 24 hours' net loss of free
// space warn under 21 and page under 10, and never while free space is flat
// or rising. A series that stops warns on its own. The page also holds to a
// hard floor, 1 TiB free, whatever the trend (owner, 2026-11-28;
// TestDbDiskRunwayCriticalIsTheRunwayAndTheFloor).
func TestDbDiskAlertsWatchEdge2Runway(t *testing.T) {
	want := map[string]struct {
		title     string
		expr      string
		evaluator string
		threshold float64
		severity  string
		forValue  string
	}{
		"db-disk-runway-low":        {"DbDiskRunwayLow", dbDiskRunway, "lt", 21, "warn", "3h"},
		"db-disk-runway-critical":   {"DbDiskRunwayCritical", dbDiskFloorOrRunway, "lt", 10, "page", "1h"},
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

// The owner's decision of 2026-11-28 ("Parallel reaper + 12-07 fallback"):
// the page reads the runway now, the warn's own runway under 10 days, and
// keeps the hard floor of 1 TiB free, whatever the trend. The floor's branch
// comes first, so under the floor the page reads the TiB free even while the
// runway is long, and nothing in the query depends on the date any more: the
// floor that held in its place until 2026-12-14 is gone.
func TestDbDiskRunwayCriticalIsTheRunwayAndTheFloor(t *testing.T) {
	if strconv.FormatInt(1<<40, 10) != dbDiskFloorBytes {
		t.Fatalf("1 TiB is %d bytes, the floor is %s", int64(1)<<40, dbDiskFloorBytes)
	}
	group := loadProvisionedAlertGroups(t, "alerting/db-disk.yml")["db-disk"]
	low := provisionedAlertRuleByUID(t, group, "db-disk-runway-low")
	critical := provisionedAlertRuleByUID(t, group, "db-disk-runway-critical")
	if len(low.Data) == 0 || len(critical.Data) == 0 {
		t.Fatal("db-disk runway rules want a query")
	}
	lowExpr, expr := low.Data[0].Model.Expr, critical.Data[0].Model.Expr
	if lowExpr != dbDiskRunway || strings.Contains(lowExpr, "time()") {
		t.Errorf("db-disk-runway-low expr = %s, want the runway alone: %s", lowExpr, dbDiskRunway)
	}
	floor := "(" + dbDiskFree + " / " + dbDiskFloorBytes + " < 1)"
	if !strings.HasPrefix(expr, floor+" or ") {
		t.Errorf("db-disk-runway-critical does not start with the floor, %s: %s", floor, expr)
	}
	if !strings.HasSuffix(expr, " or ("+lowExpr+")") {
		t.Errorf("db-disk-runway-critical does not end with the warn's runway, %s: %s", lowExpr, expr)
	}
	if strings.Contains(expr, "time()") || strings.Contains(expr, "1797206400") {
		t.Errorf("db-disk-runway-critical still switches on the date: %s", expr)
	}
	summary := critical.Annotations["summary"]
	for _, says := range []string{"1 TiB hard floor", "whatever the trend", "under 10 days"} {
		if !strings.Contains(summary, says) {
			t.Errorf("db-disk-runway-critical summary does not say %q: %s", says, summary)
		}
	}
	if strings.Contains(summary, "2026-12-14") {
		t.Errorf("db-disk-runway-critical summary still names the floor's end: %s", summary)
	}
}

// The warn and the missing telemetry on synthetic histories, in GiB at
// 5-minute samples (288 a day): the ratio is the same in bytes. The disk of
// 11-15, 4,627 GiB free and losing about 160 GiB a day, read about 28 days.
// DbDiskRunwayCritical, whose floor reads bytes, is in
// TestDbDiskRunwayCriticalEvaluate.
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
		"db-disk-telemetry-missing": {
			{name: "reporting", series: map[string]string{dbDiskSeries: "4000x600"}, evalTime: "2h"},
			{name: "stopped 30 minutes ago", series: map[string]string{dbDiskSeries: "4000x12"}, evalTime: "90m", fires: true},
			{name: "stopped 5 minutes ago", series: map[string]string{dbDiskSeries: "4000x12"}, evalTime: "65m"},
		},
	}
	labels := map[string]map[string]string{
		"db-disk-runway-low":        {"host": "by-us-fmt-5-edge-2"},
		"db-disk-telemetry-missing": {"env": "main", "host": "by-us-fmt-5-edge-2", "mountpoint": "/"},
	}
	for uid, ruleCases := range cases {
		t.Run(uid, func(t *testing.T) {
			evaluateAlertRuleWithPromtool(t, provisionedAlertRuleByUID(t, group, uid), "5m", labels[uid], ruleCases)
		})
	}
}

// DbDiskRunwayCritical in bytes at 5-minute samples: the floor is 1,024 GiB.
// Above it the page reads the runway and pages under 10 days, held an hour:
// the disk of 11-28, 4,579 GiB free and losing 328 GiB a day, reads 14 days
// and is quiet, and 9.5 days pages. The partition cutover's drawdown, about
// 330 GiB a day, pages on its runway: from 2026-11-25 until this rule the
// page held to the floor alone and stayed quiet there until 2026-12-14. Under
// the floor it pages whatever the trend: flat, rising, or falling so slowly
// that the runway alone reads far past 10 days. On the calendar, at daily
// samples, it pages on a short runway on 12-01, 2026-12-01 being day 20788.
func TestDbDiskRunwayCriticalEvaluate(t *testing.T) {
	group := loadProvisionedAlertGroups(t, "alerting/db-disk.yml")["db-disk"]
	critical := provisionedAlertRuleByUID(t, group, "db-disk-runway-critical")
	host := map[string]string{"host": "by-us-fmt-5-edge-2"}
	gib := func(value float64) string {
		return strconv.FormatFloat(value*(1<<30), 'f', -1, 64)
	}
	// a loss of perDay GiB a day from start, for 50 hours
	declining := func(start float64, perDay float64) string {
		return gib(start) + "-" + gib(perDay/288) + "x600"
	}
	t.Run("the runway", func(t *testing.T) {
		evaluateAlertRuleWithPromtool(t, critical, "5m", host, []promtoolAlertCase{
			{name: "14 days: 3,500 GiB free, losing 250 a day", series: map[string]string{dbDiskSeries: declining(4000, 250)}, evalTime: "48h"},
			{name: "the disk of 11-28, 14 days: 4,579 GiB free, losing 328 a day", series: map[string]string{dbDiskSeries: declining(4579+2*328, 328)}, evalTime: "48h"},
			{name: "9.5 days: 3,116 GiB free, losing 328 a day", series: map[string]string{dbDiskSeries: declining(3116+2*328, 328)}, evalTime: "48h", fires: true},
			{name: "5.5 days: 2,200 GiB free, losing 400 a day", series: map[string]string{dbDiskSeries: declining(3000, 400)}, evalTime: "48h", fires: true},
			{name: "the drawdown, 5.3 days: 1,740 GiB free, losing 330 a day", series: map[string]string{dbDiskSeries: declining(2400, 330)}, evalTime: "48h", fires: true},
			{name: "flat", series: map[string]string{dbDiskSeries: gib(3000) + "x600"}, evalTime: "48h"},
			{name: "no sample a day ago", series: map[string]string{dbDiskSeries: declining(3000, 400)}, evalTime: "20h"},
			// 2,600 GiB over a 400 GiB loss reads 6.5 days for 45 minutes
			{name: "a 45-minute dip of 400 GiB", series: map[string]string{dbDiskSeries: gib(3000) + "x564 " + gib(2600) + "x9 " + gib(3000) + "x27"}, evalTime: "47h40m"},
			{name: "the same loss held 90 minutes", series: map[string]string{dbDiskSeries: gib(3000) + "x564 " + gib(2600) + "x36"}, evalTime: "48h35m", fires: true},
		})
	})
	t.Run("the floor", func(t *testing.T) {
		evaluateAlertRuleWithPromtool(t, critical, "5m", host, []promtoolAlertCase{
			{name: "under the floor and flat: 1,000 GiB", series: map[string]string{dbDiskSeries: gib(1000) + "x600"}, evalTime: "48h", fires: true},
			{name: "under the floor and rising 100 GiB a day: 900 GiB", series: map[string]string{dbDiskSeries: gib(700) + "+" + gib(100.0/288) + "x600"}, evalTime: "48h", fires: true},
			{name: "under the floor with a 50-day runway: 1,000 GiB, losing 20 a day", series: map[string]string{dbDiskSeries: declining(1040, 20)}, evalTime: "48h", fires: true},
			{name: "under the floor before a day of samples", series: map[string]string{dbDiskSeries: gib(1000) + "x600"}, evalTime: "2h", fires: true},
			{name: "at the floor and flat: 1,024 GiB", series: map[string]string{dbDiskSeries: gib(1024) + "x600"}, evalTime: "48h"},
			{name: "above the floor and flat: 1,100 GiB", series: map[string]string{dbDiskSeries: gib(1100) + "x600"}, evalTime: "48h"},
			{name: "45 minutes under the floor", series: map[string]string{dbDiskSeries: gib(1100) + "x564 " + gib(1000) + "x9 " + gib(1100) + "x27"}, evalTime: "47h50m"},
			{name: "the same held 90 minutes", series: map[string]string{dbDiskSeries: gib(1100) + "x564 " + gib(1000) + "x36"}, evalTime: "48h35m", fires: true},
		})
	})
	t.Run("on the calendar", func(t *testing.T) {
		// 3,600 GiB on 11-30 losing 400 a day: 8 days on 12-01, far above the floor
		shortRunway := "_x20786 " + gib(3600) + "-" + gib(400) + "x4"
		evaluateAlertRuleWithPromtool(t, critical, "1d", host, []promtoolAlertCase{
			{name: "an 8-day runway, paging on 12-01, before 12-14", series: map[string]string{dbDiskSeries: shortRunway}, evalTime: "20788d", fires: true},
			{name: "the series' first day, with no runway yet", series: map[string]string{dbDiskSeries: shortRunway}, evalTime: "20786d"},
		})
	})
}
