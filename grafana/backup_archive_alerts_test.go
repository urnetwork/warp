package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"
)

// Each planetoid archive pages, failing closed on missing data, once its
// newest copy is older than its objective: 7 days for pg (owner, 2026-11-15,
// for edge-6's Sun/Thu runs of 40 to 75 hours and the day-long pull), 5 days
// for the others. pg's is not judged while edge-6 makes the next generation
// (owner, 2026-11-16; TestBackupArchivePostgresStaleEvaluate), so its query
// is empty only when excused: it resolves on no data, and a missing series
// counts from 1970 instead.
func TestBackupArchiveAlertsFailClosedPastTheirObjective(t *testing.T) {
	data, err := os.ReadFile("alerting/backup-archives.yml")
	if err != nil {
		t.Fatal(err)
	}
	config := string(data)
	const day = 86400
	objectives := map[string]float64{
		"pg":                  7 * day,
		"redis":               5 * day,
		"github-urnetwork":    5 * day,
		"github-urfoundation": 5 * day,
		"router-config":       5 * day,
	}
	groups := loadProvisionedAlertGroups(t, "alerting/backup-archives.yml")
	group, ok := groups["planetoid-backup-archives"]
	if !ok {
		t.Fatal("planetoid-backup-archives group is missing")
	}
	if len(group.Rules) != len(objectives) {
		t.Fatalf("backup archive alert count = %d, want %d", len(group.Rules), len(objectives))
	}
	for archive, objective := range objectives {
		rule := provisionedAlertRuleByUID(t, group, "backup-archive-"+archive+"-stale")
		if len(rule.Data) != 2 || len(rule.Data[1].Model.Conditions) != 1 {
			t.Errorf("%s wants a query and one threshold condition", rule.UID)
			continue
		}
		expr := fmt.Sprintf(`time() - max(urnetwork_backup_archive_latest_timestamp_seconds{env="main",host="planetoid",archive=%q})`, archive)
		noData := "Alerting"
		if archive == "pg" {
			const (
				latest      = `urnetwork_backup_archive_latest_timestamp_seconds{env="main",host="planetoid",archive="pg"}`
				inProgress  = `urnetwork_backup_onsite_in_progress{env="main",host="by-us-fmt-5-edge-6",archive="pg"}`
				pool        = `node_filesystem_avail_bytes{env="main",host="by-us-fmt-5-edge-6",mountpoint="/mnt/archive"}`
				lastSuccess = `urnetwork_backup_onsite_last_success_timestamp_seconds{env="main",host="by-us-fmt-5-edge-6",archive="pg"}`
			)
			expr = `(time() - (max(` + latest + `) or vector(0)))` +
				` unless on() ((((max(` + inProgress + `) == 1)` +
				` and on() (max(max_over_time(` + pool + `[3h]) - min_over_time(` + pool + `[3h])) > 1000000000))` +
				` or on() ((time() - max(` + lastSuccess + `)) < 187200))` +
				` and on() (max(` + latest + `) >= max(max_over_time(` + lastSuccess + `[1h] offset 52h)) - 43200)` +
				` and on() ((time() - max(` + latest + `)) < 1058400))`
			noData = "OK"
		}
		if got := rule.Data[0].Model.Expr; got != expr {
			t.Errorf("%s expr = %s, want %s", rule.UID, got, expr)
		}
		evaluator := rule.Data[1].Model.Conditions[0].Evaluator
		if evaluator.Type != "gt" || len(evaluator.Params) != 1 || evaluator.Params[0] != objective {
			t.Errorf("%s threshold = %s %v, want gt %v", rule.UID, evaluator.Type, evaluator.Params, objective)
		}
		if rule.NoDataState != noData || rule.ExecErrState != "Error" {
			t.Errorf("%s noDataState/execErrState = %s/%s, want %s/Error", rule.UID, rule.NoDataState, rule.ExecErrState, noData)
		}
		if rule.Labels["service"] != "backup-archive" || rule.Labels["severity"] != "page" || rule.Labels["archive"] != archive {
			t.Errorf("%s labels = %v", rule.UID, rule.Labels)
		}
		days := map[float64]string{5 * day: "five days", 7 * day: "seven days"}[objective]
		if !strings.Contains(rule.Annotations["summary"], days) {
			t.Errorf("%s summary %q does not say %s", rule.UID, rule.Annotations["summary"], days)
		}
	}
	// the dashboard and the monitor keep the same boundaries
	for _, boundary := range []string{"604800 seconds for pg", "432000 for the others", "backup-archives.json", "§11.22"} {
		if !strings.Contains(config, boundary) {
			t.Errorf("backup archive alerts do not name %q", boundary)
		}
	}
}

// planetoid's newest pg generation's file time at 5-minute samples: each pull
// lands a generation at landedHour whose file time is fileHour.
type planetoidPgHistory struct {
	hours int
	// the generation planetoid holds at the test's zero
	fileHour float64
	pulls    []planetoidPgPull
	// no series at all: the textfile or its shipper is gone
	noSeries bool
}

type planetoidPgPull struct {
	landedHour float64
	fileHour   float64
}

func (self planetoidPgHistory) series() map[string]string {
	const perHour = 12
	if self.noSeries {
		return map[string]string{}
	}
	steps := self.hours*perHour + 1
	values := make([]string, steps)
	for k := 0; k < steps; k++ {
		hour := float64(k) / perHour
		file := self.fileHour
		for _, pull := range self.pulls {
			if pull.landedHour <= hour {
				file = pull.fileHour
			}
		}
		values[k] = strconv.FormatInt(int64(file*3600), 10)
	}
	return map[string]string{
		`urnetwork_backup_archive_latest_timestamp_seconds{archive="pg",env="main",generation="main-pg-synthetic",host="planetoid",job="node"}`: promtoolValues(values),
	}
}

// The planetoid pg rule on synthetic histories of planetoid's copy and
// edge-6's runs (owner, 2026-11-16). As on 11-15, edge-6 succeeds at hour 10
// with a generation packed at 8.7, which planetoid lands at hour 37 (27 hours
// after the next 12:00 pull starts). Thursday's full copy starts 96 hours
// after that success and runs 128, and its generation lands 40 hours after it
// succeeds: planetoid's age passes 7 days 71 hours into the run, and 11 days
// when the copy lands. That holds while edge-6 writes, and for 52 hours after
// its success. A generation planetoid did not land, one it missed before the
// run, a run that stalls or fails, and an age past 12.25 days page, as does a
// missing series.
func TestBackupArchivePostgresStaleEvaluate(t *testing.T) {
	groups := loadProvisionedAlertGroups(t, "alerting/backup-archives.yml")
	rule := provisionedAlertRuleByUID(t, groups["planetoid-backup-archives"], "backup-archive-pg-stale")
	// planetoid's copy and edge-6's archive as one history
	merge := func(planetoid planetoidPgHistory, edge pgArchiveHistory) map[string]string {
		series := edge.series()
		for name, values := range planetoid.series() {
			series[name] = values
		}
		return series
	}
	thursday := pgArchiveHistory{hours: 320, lastSuccessHour: 10, runs: []pgArchiveRun{{startHour: 106, endHour: 234, success: true}}}
	landed := planetoidPgHistory{hours: 320, fileHour: 8.7, pulls: []planetoidPgPull{{landedHour: 274, fileHour: 232.7}}}
	notLanded := planetoidPgHistory{hours: 320, fileHour: 8.7}
	// planetoid never landed the hour-10 generation; it holds one from 3 days before
	missedBefore := planetoidPgHistory{hours: 320, fileHour: -63.3}
	stalled := pgArchiveHistory{hours: 320, lastSuccessHour: 10, runs: []pgArchiveRun{{startHour: 106, endHour: 234, success: true}},
		stallHours: [][2]float64{{180, 234}}}
	failed := pgArchiveHistory{hours: 320, lastSuccessHour: 10, runs: []pgArchiveRun{{startHour: 106, endHour: 180}}}
	longRun := pgArchiveHistory{hours: 320, lastSuccessHour: 10, runs: []pgArchiveRun{{startHour: 106, endHour: 320}}}
	cases := []promtoolAlertCase{
		{name: "Thursday's full copy writing, planetoid at 7.5 days", series: merge(landed, thursday), evalTime: "190h"},
		{name: "edge-6 succeeded 30 hours ago, the pull not landed", series: merge(landed, thursday), evalTime: "264h"},
		{name: "the pull landed the new generation", series: merge(landed, thursday), evalTime: "280h"},
		{name: "the new generation not landed 51 hours after edge-6's success", series: merge(notLanded, thursday), evalTime: "285h"},
		{name: "the new generation not landed 53 hours after edge-6's success", series: merge(notLanded, thursday), evalTime: "287h", fires: true},
		{name: "planetoid missed the generation before the run", series: merge(missedBefore, thursday), evalTime: "120h", fires: true},
		{name: "edge-6's run has written nothing for 3 hours", series: merge(landed, stalled), evalTime: "183h", fires: true},
		{name: "edge-6's run failed", series: merge(landed, failed), evalTime: "180h10m", fires: true},
		{name: "a run writing at 12.2 days", series: merge(notLanded, longRun), evalTime: "301h40m"},
		{name: "a run writing past the 12.25-day ceiling", series: merge(notLanded, longRun), evalTime: "302h55m", fires: true},
		{name: "planetoid's series is missing", series: merge(planetoidPgHistory{noSeries: true}, thursday), evalTime: "190h", fires: true},
	}
	evaluateAlertRuleWithPromtool(t, rule, "5m", map[string]string{}, cases)
}
