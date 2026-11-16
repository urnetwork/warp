package main

import (
	"fmt"
	"strings"
	"testing"
)

const driveHealthSelector = `{env="main",job="node",host="by-us-fmt-5-edge-2"}`

// A drive series as it arrives in Mimir, for one slot.
func driveSlotSeries(metric string, slot string) string {
	return fmt.Sprintf(`%s{env="main",host="by-us-fmt-5-edge-2",job="node",slot="%s"}`, metric, slot)
}

// The owner's watch on the drives behind Main's database volume (2026-11-16):
// pages when redundancy is lost or a drive says it is failing, warns when a
// drive's error counts grow, and warns when the collector goes blind.
func TestDriveHealthAlertsWatchEdge2Drives(t *testing.T) {
	grew := func(metric string) string {
		return "max by (host, slot) (" + metric + driveHealthSelector + ") - min by (host, slot) (min_over_time(" + metric + driveHealthSelector + "[24h]))"
	}
	want := map[string]struct {
		title     string
		expr      string
		evaluator string
		threshold float64
		severity  string
		forValue  string
	}{
		"drive-volume-not-optimal":      {"DriveVolumeNotOptimal", "min by (host, volume) (urnetwork_drive_perc_volume_optimal" + driveHealthSelector + ")", "lt", 1, "page", "15m"},
		"drive-not-online":              {"DriveNotOnline", "min by (host, slot) (urnetwork_drive_perc_online" + driveHealthSelector + ")", "lt", 1, "page", "15m"},
		"drive-smart-alert":             {"DriveSmartAlert", "max by (host, slot) (urnetwork_drive_perc_smart_alert" + driveHealthSelector + ")", "gt", 0, "page", "15m"},
		"drive-predictive-failure":      {"DrivePredictiveFailure", "max by (host, slot) (urnetwork_drive_perc_predictive_failures_total" + driveHealthSelector + ")", "gt", 0, "page", "15m"},
		"drive-smart-health-failed":     {"DriveSmartHealthFailed", "min by (host, slot) (urnetwork_drive_smart_health_passed" + driveHealthSelector + ")", "lt", 1, "page", "15m"},
		"drive-reallocated-blocks-grew": {"DriveReallocatedBlocksGrew", grew("urnetwork_drive_reallocated_blocks"), "gt", 0, "warn", "15m"},
		"drive-program-failures-grew":   {"DriveProgramFailuresGrew", grew("urnetwork_drive_program_failures_total"), "gt", 0, "warn", "15m"},
		"drive-erase-failures-grew":     {"DriveEraseFailuresGrew", grew("urnetwork_drive_erase_failures_total"), "gt", 0, "warn", "15m"},
		"drive-media-errors-grew":       {"DriveMediaErrorsGrew", grew("urnetwork_drive_perc_media_errors_total"), "gt", 0, "warn", "15m"},
		"drive-health-source-down":      {"DriveHealthSourceDown", "min by (host, source) (urnetwork_drive_health_source_up" + driveHealthSelector + ")", "lt", 1, "warn", "15m"},
		"drive-health-sample-stale":     {"DriveHealthSampleStale", "time() - (max(urnetwork_drive_health_sample_timestamp_seconds" + driveHealthSelector + ") or vector(0))", "gt", 1800, "warn", "5m"},
	}
	groups := loadProvisionedAlertGroups(t, "alerting/drive-health.yml")
	group, ok := groups["edge2-drive-health"]
	if !ok || group.Folder != "urnetwork alerts" || group.Interval != "5m" {
		t.Fatalf("edge2-drive-health group = %+v", group)
	}
	if len(group.Rules) != len(want) {
		t.Errorf("edge2-drive-health rule count = %d, want %d", len(group.Rules), len(want))
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
		if rule.Labels["service"] != "drive-health" || rule.Labels["severity"] != expected.severity {
			t.Errorf("%s labels = %v, want service drive-health, severity %s", uid, rule.Labels, expected.severity)
		}
		// a source that fails drops its series; the collector's own rules cover that
		if rule.NoDataState != "OK" || rule.ExecErrState != "Error" || rule.For != expected.forValue {
			t.Errorf("%s noDataState/execErrState/for = %s/%s/%s, want OK/Error/%s", uid, rule.NoDataState, rule.ExecErrState, rule.For, expected.forValue)
		}
		if !strings.Contains(rule.Annotations["summary"], "by-us-fmt-5-edge-2") {
			t.Errorf("%s summary does not name the host: %q", uid, rule.Annotations["summary"])
		}
	}
}

// The rules on synthetic histories at 5-minute samples, against the live
// baseline: eight drives, all online and healthy, slot 4 with one reallocated
// block, two program failures and one erase failure.
func TestDriveHealthAlertsEvaluate(t *testing.T) {
	groups := loadProvisionedAlertGroups(t, "alerting/drive-health.yml")
	group := groups["edge2-drive-health"]

	// slots 0-7 at value, slot 4 overridden by slot4
	slots := func(metric string, value string, slot4 string) map[string]string {
		series := map[string]string{}
		for slot := 0; slot < 8; slot += 1 {
			series[driveSlotSeries(metric, fmt.Sprint(slot))] = value
		}
		series[driveSlotSeries(metric, "4")] = slot4
		return series
	}
	volume := `urnetwork_drive_perc_volume_optimal{env="main",host="by-us-fmt-5-edge-2",job="node",volume="0"}`
	perccliUp := `urnetwork_drive_health_source_up{env="main",host="by-us-fmt-5-edge-2",job="node",source="perccli"}`
	smartctlUp := `urnetwork_drive_health_source_up{env="main",host="by-us-fmt-5-edge-2",job="node",source="smartctl"}`
	sampleTimestamp := `urnetwork_drive_health_sample_timestamp_seconds{env="main",host="by-us-fmt-5-edge-2",job="node"}`

	cases := map[string][]promtoolAlertCase{
		"drive-volume-not-optimal": {
			{name: "optimal", series: map[string]string{volume: "1x30"}, evalTime: "2h"},
			{name: "degraded for an hour", series: map[string]string{volume: "1x12 0x18"}, evalTime: "2h", fires: true},
			// one 10-minute run read it degraded, then optimal again
			{name: "one degraded run", series: map[string]string{volume: "1x20 0x1 1x9"}, evalTime: "2h"},
			{name: "two degraded runs", series: map[string]string{volume: "1x20 0x3 1x7"}, evalTime: "2h", fires: true},
		},
		"drive-not-online": {
			{name: "all online", series: slots("urnetwork_drive_perc_online", "1x30", "1x30"), evalTime: "2h"},
			{name: "slot 4 offline for 20 minutes", series: slots("urnetwork_drive_perc_online", "1x30", "1x12 0x18"), evalTime: "2h", fires: true},
		},
		"drive-smart-alert": {
			{name: "no alert", series: slots("urnetwork_drive_perc_smart_alert", "0x30", "0x30"), evalTime: "2h"},
			{name: "slot 4 alerting", series: slots("urnetwork_drive_perc_smart_alert", "0x30", "0x12 1x18"), evalTime: "2h", fires: true},
		},
		"drive-predictive-failure": {
			{name: "none", series: slots("urnetwork_drive_perc_predictive_failures_total", "0x30", "0x30"), evalTime: "2h"},
			{name: "slot 4 reported one", series: slots("urnetwork_drive_perc_predictive_failures_total", "0x30", "0x12 1x18"), evalTime: "2h", fires: true},
		},
		"drive-smart-health-failed": {
			{name: "all passing", series: slots("urnetwork_drive_smart_health_passed", "1x30", "1x30"), evalTime: "2h"},
			{name: "slot 4 failing", series: slots("urnetwork_drive_smart_health_passed", "1x30", "1x12 0x18"), evalTime: "2h", fires: true},
		},
		"drive-reallocated-blocks-grew": {
			{name: "slot 4 steady at its baseline", series: slots("urnetwork_drive_reallocated_blocks", "0x600", "1x600"), evalTime: "48h"},
			{name: "slot 4 reallocated another block", series: slots("urnetwork_drive_reallocated_blocks", "0x600", "1x500 2x100"), evalTime: "48h", fires: true},
			{name: "the growth is over a day old", series: slots("urnetwork_drive_reallocated_blocks", "0x600", "1x200 2x400"), evalTime: "48h"},
			{name: "slot 4 replaced by a clean drive", series: slots("urnetwork_drive_reallocated_blocks", "0x600", "1x500 0x100"), evalTime: "48h"},
		},
		"drive-program-failures-grew": {
			{name: "slot 4 steady at its baseline", series: slots("urnetwork_drive_program_failures_total", "0x600", "2x600"), evalTime: "48h"},
			{name: "slot 4 counted a third", series: slots("urnetwork_drive_program_failures_total", "0x600", "2x500 3x100"), evalTime: "48h", fires: true},
			{name: "slot 4 replaced by a clean drive", series: slots("urnetwork_drive_program_failures_total", "0x600", "2x500 0x100"), evalTime: "48h"},
		},
		"drive-erase-failures-grew": {
			{name: "slot 4 steady at its baseline", series: slots("urnetwork_drive_erase_failures_total", "0x600", "1x600"), evalTime: "48h"},
			{name: "slot 4 counted a second", series: slots("urnetwork_drive_erase_failures_total", "0x600", "1x500 2x100"), evalTime: "48h", fires: true},
		},
		"drive-media-errors-grew": {
			{name: "none", series: slots("urnetwork_drive_perc_media_errors_total", "0x600", "0x600"), evalTime: "48h"},
			{name: "slot 4 counted one", series: slots("urnetwork_drive_perc_media_errors_total", "0x600", "0x500 1x100"), evalTime: "48h", fires: true},
			// a misread run above the count, then the count again
			{name: "one run read one too many", series: slots("urnetwork_drive_perc_media_errors_total", "0x600", "0x500 1x1 0x98"), evalTime: "48h"},
		},
		"drive-health-source-down": {
			{name: "both up", series: map[string]string{perccliUp: "1x30", smartctlUp: "1x30"}, evalTime: "2h"},
			{name: "perccli down for one run", series: map[string]string{perccliUp: "1x20 0x1 1x9", smartctlUp: "1x30"}, evalTime: "2h"},
			{name: "perccli down for two runs", series: map[string]string{perccliUp: "1x20 0x3 1x7", smartctlUp: "1x30"}, evalTime: "2h", fires: true},
		},
		"drive-health-sample-stale": {
			{name: "fresh every 5 minutes", series: map[string]string{sampleTimestamp: "0+300x30"}, evalTime: "2h"},
			// Fluent Bit keeps shipping the file, whose timestamp stopped at 1h
			{name: "the file stopped updating 40 minutes ago", series: map[string]string{sampleTimestamp: "0+300x12 3600x18"}, evalTime: "1h40m", fires: true},
			{name: "the file stopped updating 25 minutes ago", series: map[string]string{sampleTimestamp: "0+300x12 3600x18"}, evalTime: "1h25m"},
			{name: "no series at all", series: map[string]string{perccliUp: "1x30"}, evalTime: "2h", fires: true},
		},
	}
	slot4 := map[string]string{"host": "by-us-fmt-5-edge-2", "slot": "4"}
	labels := map[string]map[string]string{
		"drive-volume-not-optimal":      {"host": "by-us-fmt-5-edge-2", "volume": "0"},
		"drive-not-online":              slot4,
		"drive-smart-alert":             slot4,
		"drive-predictive-failure":      slot4,
		"drive-smart-health-failed":     slot4,
		"drive-reallocated-blocks-grew": slot4,
		"drive-program-failures-grew":   slot4,
		"drive-erase-failures-grew":     slot4,
		"drive-media-errors-grew":       slot4,
		"drive-health-source-down":      {"host": "by-us-fmt-5-edge-2", "source": "perccli"},
		"drive-health-sample-stale":     {},
	}
	for uid, ruleCases := range cases {
		t.Run(uid, func(t *testing.T) {
			evaluateAlertRuleWithPromtool(t, provisionedAlertRuleByUID(t, group, uid), "5m", labels[uid], ruleCases)
		})
	}
}
