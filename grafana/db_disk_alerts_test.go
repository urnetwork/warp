package main

import (
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"
)

const (
	dbDiskSelector = `node_filesystem_avail_bytes{env="main",host="by-us-fmt-5-edge-2",mountpoint="/"}`
	// the labels the series carries in Mimir
	dbDiskSeries = `node_filesystem_avail_bytes{device="/dev/mapper/ubuntu--vg-ubuntu--lv",env="main",fstype="ext4",host="by-us-fmt-5-edge-2",job="node",mountpoint="/"}`
	// until 2026-12-14T00:00:00Z, in unix seconds, the page holds to a floor of
	// 1 TiB free, in bytes (owner, 2026-11-25)
	dbDiskFloorUntil = "1797206400"
	dbDiskFloorBytes = "1099511627776"
)

var (
	dbDiskFree   = "max by (host) (" + dbDiskSelector + ")"
	dbDiskDayAgo = "max by (host) (" + dbDiskSelector + " offset 1d)"
	dbDiskRunway = dbDiskFree + " / ((" + dbDiskDayAgo + " - " + dbDiskFree + ") > 0)"
	// the runway from the expiry, and before it the TiB free while under 1
	dbDiskRunwayOrFloor = "(" + dbDiskRunway + " and on() (vector(time()) >= " + dbDiskFloorUntil + "))" +
		" or (" + dbDiskFree + " / " + dbDiskFloorBytes + " < 1 and on() (vector(time()) < " + dbDiskFloorUntil + "))"
)

// The owner's rules for Main's database disk (2026-11-15): the days until
// edge-2's root filesystem is full at the last 24 hours' net loss of free
// space warn under 21 and page under 10, and never while free space is flat
// or rising. A series that stops warns on its own. Until 2026-12-14 the page
// holds to a 1 TiB floor instead (TestDbDiskRunwayCriticalFloorExpires).
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
		"db-disk-runway-critical":   {"DbDiskRunwayCritical", dbDiskRunwayOrFloor, "lt", 10, "page", "1h"},
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

// The owner's decision of 2026-11-25, for the partition cutover's drawdown:
// warn as is, and until 2026-12-14 00:00 UTC page only on free space under
// 1 TiB. The expiry is in the page's query, so the page turns back into the
// runway rule by itself: both branches stay, the epoch is that instant (not a
// year off), and the branch from it is the warn's runway, unchanged.
func TestDbDiskRunwayCriticalFloorExpires(t *testing.T) {
	if until := time.Date(2026, time.December, 14, 0, 0, 0, 0, time.UTC).Unix(); strconv.FormatInt(until, 10) != dbDiskFloorUntil {
		t.Fatalf("2026-12-14T00:00:00Z is %d, the expiry is %s", until, dbDiskFloorUntil)
	}
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
	runwayFrom := "(" + lowExpr + " and on() (vector(time()) >= " + dbDiskFloorUntil + "))"
	floorUntil := " or (" + dbDiskFree + " / " + dbDiskFloorBytes + " < 1 and on() (vector(time()) < " + dbDiskFloorUntil + "))"
	if !strings.HasPrefix(expr, runwayFrom) {
		t.Errorf("db-disk-runway-critical does not start with the warn's runway from the expiry, %s: %s", runwayFrom, expr)
	}
	if !strings.HasSuffix(expr, floorUntil) {
		t.Errorf("db-disk-runway-critical does not end with the floor until the expiry, %s: %s", floorUntil, expr)
	}
	if count := strings.Count(expr, dbDiskFloorUntil); count != 2 {
		t.Errorf("db-disk-runway-critical names its expiry %d times, want 2: %s", count, expr)
	}
	summary := critical.Annotations["summary"]
	for _, says := range []string{"2026-12-14 00:00 UTC", "under a 1 TiB floor", "under 10 days"} {
		if !strings.Contains(summary, says) {
			t.Errorf("db-disk-runway-critical summary does not say %q: %s", says, summary)
		}
	}
}

// DbDiskRunwayCritical with its expiry moved to seconds on promtool's clock,
// which starts at 0, so the switch evaluates at 5-minute samples
func dbDiskCriticalExpiringAt(t *testing.T, group provisionedAlertGroup, seconds int) provisionedAlertRule {
	t.Helper()
	rule := provisionedAlertRuleByUID(t, group, "db-disk-runway-critical")
	if len(rule.Data) == 0 {
		t.Fatal("db-disk-runway-critical wants a query")
	}
	if count := strings.Count(rule.Data[0].Model.Expr, dbDiskFloorUntil); count != 2 {
		t.Fatalf("db-disk-runway-critical names its expiry %d times, want 2", count)
	}
	// a copy, so the group's rule keeps its expiry
	rule.Data = append(rule.Data[:0:0], rule.Data...)
	rule.Data[0].Model.Expr = strings.ReplaceAll(rule.Data[0].Model.Expr, dbDiskFloorUntil, strconv.Itoa(seconds))
	return rule
}

// The runway rules on synthetic histories, in GiB at 5-minute samples (288 a
// day): the ratio is the same in bytes. Today's disk, 4,627 GiB free and
// losing about 160 GiB a day, reads about 28 days. DbDiskRunwayCritical is
// here as it reads from its expiry; TestDbDiskRunwayCriticalFloorEvaluate
// covers the floor before it.
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
			rule := provisionedAlertRuleByUID(t, group, uid)
			if uid == "db-disk-runway-critical" {
				rule = dbDiskCriticalExpiringAt(t, group, 0)
			}
			evaluateAlertRuleWithPromtool(t, rule, "5m", labels[uid], ruleCases)
		})
	}
}

// DbDiskRunwayCritical before its expiry and across it, in bytes: the floor
// is 1,024 GiB. The cutover's drawdown loses about 330 GiB a day. promtool's
// clock starts at 1970, before the expiry, so the rule as provisioned shows
// the floor; moved to 48 hours, the switch at 5-minute samples; and on the
// calendar, 2026-12-14 being day 20801, the rule as provisioned at daily
// samples, the first evaluation of each day.
func TestDbDiskRunwayCriticalFloorEvaluate(t *testing.T) {
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
	drawdown := declining(2400, 330)
	t.Run("before the expiry", func(t *testing.T) {
		evaluateAlertRuleWithPromtool(t, critical, "5m", host, []promtoolAlertCase{
			// the runway alone read 5.3 days and paged from 25 hours
			{name: "the drawdown above the floor: 1,740 GiB free, losing 330 a day", series: map[string]string{dbDiskSeries: drawdown}, evalTime: "48h"},
			{name: "under the floor and flat: 1,000 GiB", series: map[string]string{dbDiskSeries: gib(1000) + "x600"}, evalTime: "48h", fires: true},
			{name: "under the floor and rising 100 GiB a day: 900 GiB", series: map[string]string{dbDiskSeries: gib(700) + "+" + gib(100.0/288) + "x600"}, evalTime: "48h", fires: true},
			{name: "at the floor: 1,024 GiB", series: map[string]string{dbDiskSeries: gib(1024) + "x600"}, evalTime: "48h"},
			{name: "45 minutes under the floor", series: map[string]string{dbDiskSeries: gib(1100) + "x564 " + gib(1000) + "x9 " + gib(1100) + "x27"}, evalTime: "47h50m"},
			{name: "the same held 90 minutes", series: map[string]string{dbDiskSeries: gib(1100) + "x564 " + gib(1000) + "x36"}, evalTime: "48h35m", fires: true},
		})
	})
	t.Run("across an expiry at 48 hours", func(t *testing.T) {
		evaluateAlertRuleWithPromtool(t, dbDiskCriticalExpiringAt(t, group, 48*60*60), "5m", host, []promtoolAlertCase{
			{name: "the drawdown, quiet before the expiry", series: map[string]string{dbDiskSeries: drawdown}, evalTime: "47h55m"},
			{name: "the drawdown, pending 55 minutes after it", series: map[string]string{dbDiskSeries: drawdown}, evalTime: "48h55m"},
			{name: "the drawdown, paging an hour after it", series: map[string]string{dbDiskSeries: drawdown}, evalTime: "49h", fires: true},
			{name: "flat under the floor, paging before the expiry", series: map[string]string{dbDiskSeries: gib(1000) + "x600"}, evalTime: "47h55m", fires: true},
			{name: "flat under the floor, quiet from the expiry as the runway is", series: map[string]string{dbDiskSeries: gib(1000) + "x600"}, evalTime: "48h"},
		})
	})
	t.Run("on the calendar", func(t *testing.T) {
		// 2,390 GiB on 12-11 down to 1,070 on 12-15; 1,000 GiB from 12-10
		calendarDrawdown := "_x20798 " + gib(2390) + "-" + gib(330) + "x4"
		underTheFloor := "_x20797 " + gib(1000) + "x5"
		evaluateAlertRuleWithPromtool(t, critical, "1d", host, []promtoolAlertCase{
			{name: "the drawdown, quiet on 12-13", series: map[string]string{dbDiskSeries: calendarDrawdown}, evalTime: "20800d"},
			{name: "the drawdown, paging on 12-15 from 12-14", series: map[string]string{dbDiskSeries: calendarDrawdown}, evalTime: "20802d", fires: true},
			{name: "under the floor, paging on 12-13", series: map[string]string{dbDiskSeries: underTheFloor}, evalTime: "20800d", fires: true},
			{name: "under the floor and flat, quiet on 12-14", series: map[string]string{dbDiskSeries: underTheFloor}, evalTime: "20801d"},
		})
	})
}
