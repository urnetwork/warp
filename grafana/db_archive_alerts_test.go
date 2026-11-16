package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

type dbArchiveRule struct {
	UID  string `yaml:"uid"`
	Data []struct {
		Model struct {
			Expr       string `yaml:"expr"`
			Conditions []struct {
				Evaluator struct {
					Params []float64 `yaml:"params"`
					Type   string    `yaml:"type"`
				} `yaml:"evaluator"`
			} `yaml:"conditions"`
		} `yaml:"model"`
	} `yaml:"data"`
	NoDataState  string            `yaml:"noDataState"`
	ExecErrState string            `yaml:"execErrState"`
	For          string            `yaml:"for"`
	Labels       map[string]string `yaml:"labels"`
}

func readDbArchiveRules(t *testing.T) map[string]dbArchiveRule {
	t.Helper()
	data, err := os.ReadFile("alerting/db-archive.yml")
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Groups []struct {
			Name     string          `yaml:"name"`
			Interval string          `yaml:"interval"`
			Rules    []dbArchiveRule `yaml:"rules"`
		} `yaml:"groups"`
	}
	if err := yaml.Unmarshal(data, &document); err != nil {
		t.Fatalf("parse db archive alerts: %v", err)
	}
	if len(document.Groups) != 1 || document.Groups[0].Name != "edge6-db-archive" {
		t.Fatalf("db archive alerts want one group edge6-db-archive, got %d", len(document.Groups))
	}
	rules := map[string]dbArchiveRule{}
	for _, rule := range document.Groups[0].Rules {
		rules[rule.UID] = rule
	}
	return rules
}

// The edge-6 archive's rules (owner, 2026-11-03): page on a PostgreSQL dump
// more than 6 days old (4.5 until 2026-11-15), warn on a Redis copy more than
// 2 days old that no PostgreSQL run explains (owner, 2026-11-16), the
// /mnt/archive runway to its 3 TB floor, a stale heartbeat, page on a run in
// progress more than 168 hours (owner, 2026-11-16; 120 from 2026-11-15, when
// runs of 40 to 75 hours began, 30 before), and page on a full copy refused
// for want of room beside the base (owner, 2026-11-16). The series are those
// Mimir holds from edge-6's textfiles and node_exporter.
func TestDbArchiveAlertsWatchTheEdge6Archive(t *testing.T) {
	const (
		selector     = `env="main",host="by-us-fmt-5-edge-6"`
		lastSuccess  = "urnetwork_backup_onsite_last_success_timestamp_seconds"
		lastRun      = "urnetwork_backup_onsite_last_run_timestamp_seconds"
		heartbeat    = "urnetwork_backup_onsite_heartbeat_timestamp_seconds"
		inProgress   = "urnetwork_backup_onsite_in_progress"
		roomShort    = "urnetwork_backup_onsite_full_copy_room_short_bytes"
		pool         = `node_filesystem_avail_bytes{` + selector + `,mountpoint="/mnt/archive"}`
		floorBytes   = 3e12
		hour         = 3600
		day          = 24 * hour
		firstDumpDue = "2026-11-04T06:00:00Z"
		firstCopyDue = "2026-11-03T22:00:00Z"
	)
	due := func(when string) int64 {
		parsed, err := time.Parse(time.RFC3339, when)
		if err != nil {
			t.Fatal(err)
		}
		return parsed.Unix()
	}
	want := map[string]struct {
		expr      string
		evaluator string
		threshold float64
		severity  string
		noData    string
	}{
		"db-archive-pg-stale": {
			expr:      fmt.Sprintf(`time() - (max(%s{%s,archive="pg"}) or vector(%d))`, lastSuccess, selector, due(firstDumpDue)),
			evaluator: "gt", threshold: 6 * day, severity: "page", noData: "Alerting",
		},
		"db-archive-redis-copy-stale": {
			expr: fmt.Sprintf(`(time() - (max(%s{%s,archive="redis"}) or vector(%d)))`+
				` unless on() (max(%s{%s,archive="redis",result="skipped"})`+
				` and on() (max_over_time(max(%s{%s,archive="pg"})[30h:5m]) > 0))`,
				lastSuccess, selector, due(firstCopyDue), lastRun, selector, inProgress, selector),
			evaluator: "gt", threshold: 2 * day, severity: "warn", noData: "OK",
		},
		"db-archive-pg-heartbeat-stale": {
			expr:      fmt.Sprintf(`time() - max(%s{%s,archive="pg"})`, heartbeat, selector),
			evaluator: "gt", threshold: 3 * hour, severity: "warn", noData: "Alerting",
		},
		"db-archive-redis-heartbeat-stale": {
			expr:      fmt.Sprintf(`time() - (max(%s{%s,archive="redis"}) or vector(%d))`, heartbeat, selector, due(firstCopyDue)),
			evaluator: "gt", threshold: 30 * hour, severity: "warn", noData: "Alerting",
		},
		// the uid keeps its 30h so the provisioned rule updates in place
		"db-archive-run-over-30h": {
			expr: fmt.Sprintf(`min_over_time(max by (archive) (%[1]s{%[2]s})[168h:5m]) and count_over_time(max by (archive) (%[1]s{%[2]s})[168h:5m]) > 1728`,
				inProgress, selector),
			evaluator: "gt", threshold: 0, severity: "page", noData: "OK",
		},
		"db-archive-full-copy-room-short": {
			expr:      fmt.Sprintf(`max(%s{%s,archive="pg"})`, roomShort, selector),
			evaluator: "gt", threshold: 0, severity: "page", noData: "OK",
		},
		"db-archive-below-floor": {
			expr:      "max(" + pool + ")",
			evaluator: "lt", threshold: floorBytes, severity: "page", noData: "OK",
		},
		"db-archive-runway-short": {
			expr:      "predict_linear(max_over_time(" + pool + "[1d])[7d:1h], 14 * 86400)",
			evaluator: "lt", threshold: floorBytes, severity: "warn", noData: "OK",
		},
		"db-archive-telemetry-missing": {
			expr:      "absent(" + pool + ")",
			evaluator: "gt", threshold: 0, severity: "warn", noData: "OK",
		},
	}

	rules := readDbArchiveRules(t)
	if len(rules) != len(want) {
		t.Errorf("db archive alert count = %d, want %d", len(rules), len(want))
	}
	for uid, expected := range want {
		rule, ok := rules[uid]
		if !ok {
			t.Errorf("missing db archive alert %s", uid)
			continue
		}
		if len(rule.Data) != 2 || len(rule.Data[1].Model.Conditions) != 1 {
			t.Errorf("%s wants a query and one threshold condition", uid)
			continue
		}
		if got := rule.Data[0].Model.Expr; got != expected.expr {
			t.Errorf("%s expr = %s, want %s", uid, got, expected.expr)
		}
		evaluator := rule.Data[1].Model.Conditions[0].Evaluator
		if evaluator.Type != expected.evaluator || len(evaluator.Params) != 1 || evaluator.Params[0] != expected.threshold {
			t.Errorf("%s threshold = %s %v, want %s %v", uid, evaluator.Type, evaluator.Params, expected.evaluator, expected.threshold)
		}
		if rule.Labels["severity"] != expected.severity || rule.Labels["service"] != "db-archive" {
			t.Errorf("%s labels = %v, want service db-archive, severity %s", uid, rule.Labels, expected.severity)
		}
		if rule.NoDataState != expected.noData || rule.ExecErrState != "Error" {
			t.Errorf("%s noDataState/execErrState = %s/%s, want %s/Error", uid, rule.NoDataState, rule.ExecErrState, expected.noData)
		}
		if _, err := time.ParseDuration(rule.For); err != nil {
			t.Errorf("%s for = %q: %v", uid, rule.For, err)
		}
	}
}

// Before the first dump and the first copy their last-success series do not
// exist (the owner: no page on no data before the first dump). A rule that
// alerts on missing data reads either a series that already reports, or a
// fallback to the time its first sample was due, after which missing data
// counts as stale.
func TestDbArchiveAlertsDoNotPageOnNoDataBeforeTheFirstRun(t *testing.T) {
	reportingSince1103 := map[string]bool{"db-archive-pg-heartbeat-stale": true}
	for uid, rule := range readDbArchiveRules(t) {
		if rule.NoDataState != "Alerting" || reportingSince1103[uid] {
			continue
		}
		expr := rule.Data[0].Model.Expr
		if !strings.Contains(expr, ") or vector(") {
			t.Errorf("%s alerts on missing data with no first-due fallback: %s", uid, expr)
		}
	}
	if rule := readDbArchiveRules(t)["db-archive-pg-heartbeat-stale"]; rule.Labels["severity"] != "warn" {
		t.Errorf("the heartbeat rule that alerts on missing data must not page")
	}
}

// The archive's textfiles reached Mimir with job db-archive from a second Fluent
// Bit input, then with job node from the host's one node_exporter_metrics
// input. A rule that selected a job would go silent across that move, so none
// does.
func TestDbArchiveAlertsSelectNoJob(t *testing.T) {
	for uid, rule := range readDbArchiveRules(t) {
		if expr := rule.Data[0].Model.Expr; strings.Contains(expr, "job=") {
			t.Errorf("%s selects a job label: %s", uid, expr)
		}
	}
}

// The run rule on synthetic in-progress series at 5-minute samples. It pages
// a run in progress for more than 168 hours, systemd's bound, and none of the
// normal ones: an incremental run of 75 hours, the 28-day full copy, in
// progress 104.5 hours from 2026-11-10 21:20Z to 11-15 05:50Z, or a full
// copy's run of 128 hours, which the 120-hour rule of 2026-11-15 paged (owner,
// 2026-11-16). A series that begins during a run with less than 144 of the 168
// hours is not judged. The title says 168h; the uid keeps the 30h it was
// provisioned with, so the rule updates in place.
func TestDbArchiveRunOver168hEvaluate(t *testing.T) {
	groups := loadProvisionedAlertGroups(t, "alerting/db-archive.yml")
	rule := provisionedAlertRuleByUID(t, groups["edge6-db-archive"], "db-archive-run-over-30h")
	if rule.Title != "DbArchiveRunOver168h" {
		t.Errorf("run rule title = %s, want DbArchiveRunOver168h", rule.Title)
	}
	const (
		pg    = `urnetwork_backup_onsite_in_progress{archive="pg",env="main",host="by-us-fmt-5-edge-6",job="node"}`
		redis = `urnetwork_backup_onsite_in_progress{archive="redis",env="main",host="by-us-fmt-5-edge-6",job="node"}`
	)
	// exactly hours of samples of value, 12 an hour
	samples := func(value int, hours float64) string {
		return fmt.Sprintf("%dx%d", value, int(hours*12)-1)
	}
	// 5 days idle, so the 168-hour window is full of samples, a run of hours
	// from 120h, a day idle
	run := func(hours float64) string {
		return samples(0, 120) + " " + samples(1, hours) + " " + samples(0, 24)
	}
	idle := samples(0, 330)
	cases := []promtoolAlertCase{
		{name: "an incremental run of 75 hours, at its end", series: map[string]string{pg: run(75), redis: idle}, evalTime: "194h55m"},
		{name: "the full copy of 104.5 hours, at its end", series: map[string]string{pg: run(104.5), redis: idle}, evalTime: "224h25m"},
		{name: "a full copy's run of 128 hours, at its end", series: map[string]string{pg: run(128), redis: idle}, evalTime: "247h55m"},
		{name: "a run 167 hours in progress", series: map[string]string{pg: run(200), redis: idle}, evalTime: "287h"},
		{name: "a run 169 hours in progress", series: map[string]string{pg: run(200), redis: idle}, evalTime: "289h", fires: true},
		{name: "a series that begins during a run, 140 hours of samples", series: map[string]string{pg: samples(1, 200), redis: idle}, evalTime: "139h55m"},
		{name: "a series that begins during a run, 150 hours of samples", series: map[string]string{pg: samples(1, 200), redis: idle}, evalTime: "149h55m", fires: true},
		{name: "a Redis copy of 6 hours", series: map[string]string{pg: idle, redis: run(6)}, evalTime: "125h55m"},
	}
	evaluateAlertRuleWithPromtool(t, rule, "5m", map[string]string{"archive": "pg"}, cases)
}

// edge-6's archive textfiles at 5-minute samples, as Mimir holds them: the
// PostgreSQL archive's in-progress gauge, the Redis copy's last success, and
// its newest run's time under that run's result, the one series of the three
// results the textfile carries. The copy runs at 22:00 each day: it skips
// while a PostgreSQL run is in progress (it holds the archive lock), and
// otherwise succeeds or, on a failed day, fails. The history starts at a
// successful copy at time 0.
type redisCopyHistory struct {
	hours int
	// PostgreSQL runs in progress over [start, end) hours
	pgRuns [][2]int
	// no PostgreSQL in-progress series at all
	noPgSeries bool
	// days whose copy fails
	failed map[int]bool
	// days whose copy skips with no PostgreSQL run: the lock held by another
	locked map[int]bool
	// from this day on no copy runs: the timer stopped (0: never)
	stoppedFrom int
}

func (self redisCopyHistory) series() map[string]string {
	const (
		labels   = `env="main",host="by-us-fmt-5-edge-6",job="node"`
		step     = 300
		perHour  = 3600 / step
		copyHour = 22
	)
	steps := self.hours * perHour
	progress := make([]string, steps)
	success := make([]string, steps)
	runs := map[string][]string{"success": make([]string, steps), "failed": make([]string, steps), "skipped": make([]string, steps)}
	lastSuccess, lastRun, lastResult := 0, 0, "success"
	for k := 0; k < steps; k++ {
		now := k * step
		inProgress := false
		for _, run := range self.pgRuns {
			if run[0]*3600 <= now && now < run[1]*3600 {
				inProgress = true
			}
		}
		if now%86400 == copyHour*3600 {
			day := now / 86400
			if self.stoppedFrom == 0 || day < self.stoppedFrom {
				lastRun = now
				switch {
				case inProgress || self.locked[day]:
					lastResult = "skipped"
				case self.failed[day]:
					lastResult = "failed"
				default:
					lastResult = "success"
					lastSuccess = now
				}
			}
		}
		progress[k] = "0"
		if inProgress {
			progress[k] = "1"
		}
		success[k] = strconv.Itoa(lastSuccess)
		for result, values := range runs {
			values[k] = "_"
			if result == lastResult {
				values[k] = strconv.Itoa(lastRun)
			}
		}
	}
	series := map[string]string{
		`urnetwork_backup_onsite_last_success_timestamp_seconds{archive="redis",` + labels + `}`: promtoolValues(success),
	}
	if !self.noPgSeries {
		series[`urnetwork_backup_onsite_in_progress{archive="pg",`+labels+`}`] = promtoolValues(progress)
	}
	for result, values := range runs {
		series[`urnetwork_backup_onsite_last_run_timestamp_seconds{archive="redis",`+labels+`,result="`+result+`"}`] = promtoolValues(values)
	}
	return series
}

// One sample per value in promtool's expanding notation: "vxn" is v n+1
// times, "_xn" n missing samples.
func promtoolValues(values []string) string {
	parts := []string{}
	for i := 0; i < len(values); {
		j := i
		for j < len(values) && values[j] == values[i] {
			j += 1
		}
		switch {
		case values[i] == "_":
			parts = append(parts, fmt.Sprintf("_x%d", j-i))
		case j-i == 1:
			parts = append(parts, values[i])
		default:
			parts = append(parts, fmt.Sprintf("%sx%d", values[i], j-i-1))
		}
		i = j
	}
	return strings.Join(parts, " ")
}

// The Redis copy rule on synthetic histories (owner, 2026-11-16). A copy
// skips by design while a PostgreSQL run holds the archive lock, so the six
// copies a 6-day run skips do not warn, which the 2-day rule did through the
// runs of 11-05 to 11-07 and of 11-10 to 11-15; nor does the wait for the
// next 22:00 after a run. A copy that fails warns once the last success is 2
// days old, at once when the copies before it skipped, and so does a copy
// that skips with no PostgreSQL run, or a timer stopped after a skip once the
// run has been over for 30 hours.
func TestDbArchiveRedisCopyStaleEvaluate(t *testing.T) {
	groups := loadProvisionedAlertGroups(t, "alerting/db-archive.yml")
	rule := provisionedAlertRuleByUID(t, groups["edge6-db-archive"], "db-archive-redis-copy-stale")
	if rule.Title != "DbArchiveRedisCopyStale" {
		t.Errorf("redis copy rule title = %s, want DbArchiveRedisCopyStale", rule.Title)
	}
	// day 1 06:00 to day 7 06:00, as the 11-10 full copy's run plus a day
	sixDayRun := redisCopyHistory{hours: 200, pgRuns: [][2]int{{30, 174}}}
	// day 1 06:00 to day 4 09:00, 75 hours; the day 4 copy fails
	failsAfterRun := redisCopyHistory{hours: 130, pgRuns: [][2]int{{30, 105}}, failed: map[int]bool{4: true}}
	failsTwice := redisCopyHistory{hours: 80, failed: map[int]bool{1: true, 2: true}}
	lockedNoRun := redisCopyHistory{hours: 80, locked: map[int]bool{1: true, 2: true, 3: true}}
	lockedNoSeries := redisCopyHistory{hours: 80, locked: map[int]bool{1: true, 2: true, 3: true}, noPgSeries: true}
	// day 1 06:00 to day 2 09:00; the day 1 copy skips, and none runs after
	stoppedAfterSkip := redisCopyHistory{hours: 100, pgRuns: [][2]int{{30, 57}}, stoppedFrom: 2}
	cases := []promtoolAlertCase{
		{name: "a 6-day PostgreSQL run, mid-run", series: sixDayRun.series(), evalTime: "120h"},
		{name: "a 6-day PostgreSQL run, waiting for the next copy", series: sixDayRun.series(), evalTime: "189h"},
		{name: "a 6-day PostgreSQL run, the next copy succeeded", series: sixDayRun.series(), evalTime: "191h"},
		{name: "a 75-hour PostgreSQL run, before the next copy", series: failsAfterRun.series(), evalTime: "117h"},
		{name: "a 75-hour PostgreSQL run, the next copy failed", series: failsAfterRun.series(), evalTime: "118h30m", fires: true},
		{name: "two failed copies, the second 47 hours on", series: failsTwice.series(), evalTime: "69h"},
		{name: "two failed copies, the second 49 hours on", series: failsTwice.series(), evalTime: "71h", fires: true},
		{name: "copies skip with no PostgreSQL run", series: lockedNoRun.series(), evalTime: "71h", fires: true},
		{name: "copies skip with no PostgreSQL series", series: lockedNoSeries.series(), evalTime: "71h", fires: true},
		{name: "the timer stopped after a skip, 29 hours after the run", series: stoppedAfterSkip.series(), evalTime: "86h"},
		{name: "the timer stopped after a skip, 31 hours after the run", series: stoppedAfterSkip.series(), evalTime: "88h", fires: true},
	}
	evaluateAlertRuleWithPromtool(t, rule, "5m", map[string]string{}, cases)
}

// The run rule's words (owner, 2026-11-16). A run that copies the primary in
// full takes about 95 to 130 hours (the 11-10 one 104.5), so a healthy one
// paged at the 120 hours of 2026-11-15. Until then the rule's words said to
// stop a run past its bound, which would throw away a healthy full copy's
// replay and dump: they say to read the journal and let a moving run finish.
func TestDbArchiveRunOver168hDoesNotSayToStopAHealthyFullCopy(t *testing.T) {
	groups := loadProvisionedAlertGroups(t, "alerting/db-archive.yml")
	rule := provisionedAlertRuleByUID(t, groups["edge6-db-archive"], "db-archive-run-over-30h")
	summary := rule.Annotations["summary"]
	for _, words := range []string{"in full", "every 28 days", "the first after a PostgreSQL minor release",
		"about 95 to 130", "Read its journal first", "stopping it throws that work away"} {
		if !strings.Contains(summary, words) {
			t.Errorf("run rule summary lacks %q: %s", words, summary)
		}
	}
	lower := strings.ToLower(summary)
	for _, words := range []string{"stop it", "systemctl stop", "past the dump's"} {
		if strings.Contains(lower, words) {
			t.Errorf("run rule summary says %q: %s", words, summary)
		}
	}
	data, err := os.ReadFile("alerting/db-archive.yml")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "systemctl stop bringyour-pg-backup.service") {
		t.Errorf("alerting/db-archive.yml still tells the reader to stop the pg run")
	}
}

// The room rule on synthetic series of the gauge, which edge-6's textfile
// carries from a run refused its full copy for want of room until the next run
// starts, and which is absent otherwise. It pages after 5 minutes of a refusal
// and stays quiet without one, for a refusal that lasted less than its for,
// and once the next run has started and cleared it.
func TestDbArchiveFullCopyRoomShortEvaluate(t *testing.T) {
	groups := loadProvisionedAlertGroups(t, "alerting/db-archive.yml")
	rule := provisionedAlertRuleByUID(t, groups["edge6-db-archive"], "db-archive-full-copy-room-short")
	if rule.Title != "DbArchiveFullCopyRoomShort" {
		t.Errorf("room rule title = %s, want DbArchiveFullCopyRoomShort", rule.Title)
	}
	if rule.Labels["archive"] != "pg" {
		t.Errorf("room rule labels = %v, want archive pg", rule.Labels)
	}
	const (
		short    = `urnetwork_backup_onsite_full_copy_room_short_bytes{archive="pg",env="main",host="by-us-fmt-5-edge-6",job="node"}`
		progress = `urnetwork_backup_onsite_in_progress{archive="pg",env="main",host="by-us-fmt-5-edge-6",job="node"}`
		// a run refused its full copy at minute 60, 1.5 TB short; the textfile
		// keeps the gauge from then on
		refused = "_x60 1500000000000x120"
		// and the next run started at minute 90, which cleared it
		cleared = "_x60 1500000000000x30"
	)
	cases := []promtoolAlertCase{
		{name: "no refusal: the gauge is absent", series: map[string]string{progress: "0x240"}, evalTime: "4h"},
		{name: "a refused full copy, 10 minutes on", series: map[string]string{short: refused, progress: "0x240"},
			evalTime: "70m", fires: true},
		{name: "a refused full copy, two hours on", series: map[string]string{short: refused, progress: "0x240"},
			evalTime: "3h", fires: true},
		{name: "a refused full copy, 3 minutes on", series: map[string]string{short: refused, progress: "0x240"},
			evalTime: "63m"},
		{name: "the next run started and cleared it", series: map[string]string{short: cleared, progress: "0x90 1x150"},
			evalTime: "3h"},
	}
	evaluateAlertRuleWithPromtool(t, rule, "1m", map[string]string{}, cases)
}
