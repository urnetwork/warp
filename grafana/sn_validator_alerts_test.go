package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

// The gauges xops main/ansible/files/sn-validator-health/health.py publishes.
// A rule on any other urnetwork_sn_validator_ name would never have data.
var snValidatorGauges = map[string]bool{
	"sample_timestamp_seconds":                true,
	"progress_ok":                             true,
	"progress_heartbeat_timestamp_seconds":    true,
	"process_start_timestamp_seconds":         true,
	"unit_ok":                                 true,
	"unit_active":                             true,
	"unit_restarts":                           true,
	"unit_start_timestamp_seconds":            true,
	"native_current":                          true,
	"native_epoch":                            true,
	"native_block":                            true,
	"native_blocks_since_epoch":               true,
	"intent_current":                          true,
	"intent_present":                          true,
	"intent_native_epoch":                     true,
	"intent_status":                           true,
	"intent_finalized_block":                  true,
	"intent_epoch_lag":                        true,
	"intent_missing_blocks":                   true,
	"intent_finalized_age_blocks":             true,
	"steering_outcome":                        true,
	"steering_observed_timestamp_seconds":     true,
	"steering_last_success_timestamp_seconds": true,
	"steering_cycle_max_seconds":              true,
	"journal_ok":                              true,
	"journal_window_seconds":                  true,
	"steering_hard_errors_recent":             true,
	"steering_read_waits_recent":              true,
	"trails_completed_recent":                 true,
	"trails_failed_recent":                    true,
	"native_gap_edges_recorded_recent":        true,
	"weights_age_blocks":                      true,
	"weights_age_observed_timestamp_seconds":  true,
	"intents_file_bytes":                      true,
	"intents_file_limit_bytes":                true,
	"replay_dir_bytes":                        true,
	"state_filesystem_available_bytes":        true,
	"state_filesystem_size_bytes":             true,
}

type snValidatorRule struct {
	UID       string `yaml:"uid"`
	Title     string `yaml:"title"`
	Condition string `yaml:"condition"`
	Data      []struct {
		RefID         string `yaml:"refId"`
		DatasourceUID string `yaml:"datasourceUid"`
		Model         struct {
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
	Annotations  map[string]string `yaml:"annotations"`
}

func loadSnValidatorRules(t *testing.T) []snValidatorRule {
	t.Helper()
	data, err := os.ReadFile("alerting/sn-validator.yml")
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Groups []struct {
			Name     string            `yaml:"name"`
			Folder   string            `yaml:"folder"`
			Interval string            `yaml:"interval"`
			Rules    []snValidatorRule `yaml:"rules"`
		} `yaml:"groups"`
	}
	if err := yaml.Unmarshal(data, &document); err != nil {
		t.Fatalf("parse validator alerts: %v", err)
	}
	if len(document.Groups) != 1 {
		t.Fatalf("validator alert groups = %d, want 1", len(document.Groups))
	}
	group := document.Groups[0]
	if group.Name != "sn-validator" || group.Folder != "urnetwork alerts" || group.Interval != "1m" {
		t.Fatalf("validator alert group = %q in %q every %q", group.Name, group.Folder, group.Interval)
	}
	return group.Rules
}

func TestSnValidatorAlertsReadOnlySnowsPublishedGauges(t *testing.T) {
	metric := regexp.MustCompile(`urnetwork_sn_validator_([a-z_]+)(\{[^}]*\})?`)
	seen := map[string]bool{}
	for _, rule := range loadSnValidatorRules(t) {
		if !strings.HasPrefix(rule.UID, "sn-validator-") || seen[rule.UID] {
			t.Errorf("rule uid %q is not a unique sn-validator- uid", rule.UID)
		}
		seen[rule.UID] = true
		if rule.Condition != "B" || len(rule.Data) != 2 || rule.Data[0].RefID != "A" || rule.Data[1].RefID != "B" {
			t.Errorf("%s does not threshold query A in expression B", rule.UID)
			continue
		}
		if rule.Data[0].DatasourceUID != "warp-mimir" || rule.Data[1].DatasourceUID != "__expr__" {
			t.Errorf("%s does not query warp-mimir", rule.UID)
		}
		if rule.ExecErrState != "Error" || rule.Labels["service"] != "sn-validator" {
			t.Errorf("%s must keep execErrState Error and service sn-validator", rule.UID)
		}
		if severity := rule.Labels["severity"]; severity != "page" && severity != "warn" {
			t.Errorf("%s severity = %q", rule.UID, severity)
		}
		if rule.Annotations["summary"] == "" {
			t.Errorf("%s has no summary", rule.UID)
		}
		matches := metric.FindAllStringSubmatch(rule.Data[0].Model.Expr, -1)
		if len(matches) == 0 {
			t.Errorf("%s reads no validator gauge", rule.UID)
		}
		for _, match := range matches {
			if !snValidatorGauges[match[1]] {
				t.Errorf("%s reads urnetwork_sn_validator_%s, which the collector does not publish", rule.UID, match[1])
			}
			// Each selector names snow's series by env and host alone (see
			// TestSnAlertsSelectNoJob).
			if match[2] != `{env="main",host="snow"}` {
				t.Errorf("%s selects urnetwork_sn_validator_%s with %q", rule.UID, match[1], match[2])
			}
		}
	}
}

func TestSnValidatorAlertsCoverEachFailureMode(t *testing.T) {
	type want struct {
		gauge, evaluator string
		threshold        float64
		severity, noData string
	}
	required := map[string]want{
		"sn-validator-health-stale":          {"sample_timestamp_seconds", "gt", 180, "warn", "Alerting"},
		"sn-validator-progress-down":         {"progress_ok", "lt", 1, "page", "Alerting"},
		"sn-validator-unit-inactive":         {"unit_active", "lt", 1, "page", "Alerting"},
		"sn-validator-restarted":             {"unit_restarts", "gt", 0, "warn", "OK"},
		"sn-validator-intent-late":           {"intent_missing_blocks", "gt", 100, "warn", "OK"},
		"sn-validator-intent-missing":        {"intent_missing_blocks", "gt", 150, "page", "OK"},
		"sn-validator-epoch-missed":          {"intent_epoch_lag", "gt", 1, "page", "OK"},
		"sn-validator-steering-slow":         {"steering_cycle_max_seconds", "gt", 45, "warn", "OK"},
		"sn-validator-steering-failing":      {"steering_hard_errors_recent", "gt", 3, "warn", "OK"},
		"sn-validator-steering-stuck":        {"steering_last_success_timestamp_seconds", "gt", 1800, "page", "OK"},
		"sn-validator-native-gap-edge":       {"native_gap_edges_recorded_recent", "gt", 0, "warn", "OK"},
		"sn-validator-weights-stale":         {"weights_age_blocks", "gt", 860, "page", "Alerting"},
		"sn-validator-disk-low":              {"state_filesystem_available_bytes", "lt", 0.2, "warn", "OK"},
		"sn-validator-disk-critical":         {"state_filesystem_available_bytes", "lt", 0.1, "page", "OK"},
		"sn-validator-intents-file-large":    {"intents_file_bytes", "gt", 0.5, "warn", "OK"},
		"sn-validator-intents-file-critical": {"intents_file_bytes", "gt", 0.8, "page", "OK"},
		"sn-validator-trails-not-completing": {"trails_completed_recent", "lt", 1, "warn", "OK"},
	}
	rules := loadSnValidatorRules(t)
	if len(rules) != len(required) {
		t.Fatalf("validator alert count = %d, want %d", len(rules), len(required))
	}
	for _, rule := range rules {
		expected, ok := required[rule.UID]
		if !ok {
			t.Errorf("unexpected validator alert %s", rule.UID)
			continue
		}
		if !strings.Contains(rule.Data[0].Model.Expr, "urnetwork_sn_validator_"+expected.gauge+"{") {
			t.Errorf("%s does not read %s", rule.UID, expected.gauge)
		}
		conditions := rule.Data[1].Model.Conditions
		if len(conditions) != 1 || conditions[0].Evaluator.Type != expected.evaluator ||
			len(conditions[0].Evaluator.Params) != 1 || conditions[0].Evaluator.Params[0] != expected.threshold {
			t.Errorf("%s threshold = %+v, want %s %v", rule.UID, conditions, expected.evaluator, expected.threshold)
		}
		if rule.Labels["severity"] != expected.severity {
			t.Errorf("%s severity = %q, want %q", rule.UID, rule.Labels["severity"], expected.severity)
		}
		// Missing telemetry, progress, unit state or weight readings is itself
		// an outage; gauges that are absent by design resolve instead.
		if rule.NoDataState != expected.noData {
			t.Errorf("%s noDataState = %q, want %q", rule.UID, rule.NoDataState, expected.noData)
		}
	}
	// A missed epoch strands the validator, so its page holds for one minute at most.
	for _, uid := range []string{"sn-validator-epoch-missed", "sn-validator-intent-missing"} {
		for _, rule := range rules {
			if rule.UID == uid && rule.For != "1m" {
				t.Errorf("%s holds for %s, want 1m", uid, rule.For)
			}
		}
	}
	// The fallback's reading exists only while its timer runs, so the weights
	// rule also reads the validator's own commits (TestSnValidatorWeightsStaleEvaluate).
	for _, rule := range rules {
		if rule.UID == "sn-validator-weights-stale" &&
			!strings.Contains(rule.Data[0].Model.Expr, "urnetwork_sn_validator_intent_finalized_block{") {
			t.Errorf("%s reads only the fallback's reading: %s", rule.UID, rule.Data[0].Model.Expr)
		}
	}
}

// A healthy validator's finalized commit block as health.py publishes it, a
// sample a minute: each 72-minute native epoch opens with one pending minute
// (0), then holds that epoch's commit, 361 blocks after the one before.
func snValidatorCommits(epochs int) string {
	values := []string{}
	for epoch := 0; epoch < epochs; epoch++ {
		values = append(values, fmt.Sprintf("0 %dx70", 1000000+361*epoch))
	}
	return strings.Join(values, " ")
}

// The weight fallback's readings, a check every 10 minutes, each held until
// the next because health.py republishes the newest one every minute.
func snValidatorFallbackReadings(ages ...int) string {
	values := []string{}
	for _, age := range ages {
		values = append(values, fmt.Sprintf("%dx9", age))
	}
	return strings.Join(values, " ")
}

// The fallback's readings while the validator is down: each check reads the
// age 50 blocks older, and the one that reads 760 or more commits, so the
// next reads 49 again. That highest reading, 799, holds for the 10 minutes
// after its commit lands.
func snValidatorFallbackCycles(cycles int) []int {
	ages := []int{}
	for cycle := 0; cycle < cycles; cycle++ {
		for age := 49; age < 800; age += 50 {
			ages = append(ages, age)
		}
	}
	return ages
}

// What the weights rule does on synthetic series, through the official
// evaluator: it pages only when neither the validator nor the weight fallback
// has committed. It read the fallback's reading alone until 2026-11-14, and
// that reading exists only while the fallback's timer runs, so the stopped
// timer paged from 11-11 06:03Z for three days while the validator committed
// every epoch. The fallback's commit at 760 paged too, under the old 500.
// Run it with URNETWORK_PROMTOOL naming promtool 3.5.0 (server
// grafana/promtool.sh prints one); the structure tests run without it.
func TestSnValidatorWeightsStaleEvaluate(t *testing.T) {
	promtool := os.Getenv("URNETWORK_PROMTOOL")
	if promtool == "" {
		var err error
		promtool, err = exec.LookPath("promtool")
		if err != nil {
			t.Skip("no promtool; set URNETWORK_PROMTOOL")
		}
	}
	var stale *snValidatorRule
	rules := loadSnValidatorRules(t)
	for index := range rules {
		if rules[index].UID == "sn-validator-weights-stale" {
			stale = &rules[index]
		}
	}
	if stale == nil {
		t.Fatal("sn-validator-weights-stale is missing")
	}
	evaluator := stale.Data[1].Model.Conditions[0].Evaluator
	if evaluator.Type != "gt" || len(evaluator.Params) != 1 || stale.NoDataState != "Alerting" {
		t.Fatalf("the weights rule compares %q %v with noDataState %q", evaluator.Type, evaluator.Params, stale.NoDataState)
	}
	query := stale.Data[0].Model.Expr
	// Grafana alerts on an empty query when noDataState is Alerting; a
	// Prometheus rule does not, so absent() stands in for that.
	rulesYaml, err := yaml.Marshal(map[string]any{"groups": []map[string]any{{
		"name": "sn-validator",
		"rules": []map[string]string{{
			"alert": stale.Title,
			"expr":  fmt.Sprintf("((%s) > %f) or absent(%s)", query, evaluator.Params[0], query),
			"for":   stale.For,
		}},
	}}})
	if err != nil {
		t.Fatal(err)
	}

	// The second epoch's commit, first published at minute 73, is the last.
	lastCommitHeld := snValidatorCommits(2) + " 1000361x240"
	cases := []struct {
		name     string
		series   map[string]string
		evalTime string
		fires    bool
	}{
		{
			// The timer stops after its sixth check, whose line stays in
			// health.py's 30-minute window, then the reading is gone.
			name: "the fallback timer stopped while the validator commits every epoch",
			series: map[string]string{
				"weights_age_blocks":     snValidatorFallbackReadings(49, 99, 149, 199, 249) + " 299x39",
				"intent_finalized_block": snValidatorCommits(5),
			},
			evalTime: "5h",
		},
		{
			// A new intent's commit is 0 until it finalizes; 91 minutes after the last commit is 455 blocks.
			name:     "a commit pending for 20 minutes while the fallback timer is stopped",
			series:   map[string]string{"intent_finalized_block": "0 1000000x70 0x20 1000361x60"},
			evalTime: "92m",
		},
		{
			// health.py publishes no intent while a restarted validator's
			// progress is not current; 47 minutes after the last commit is 235 blocks.
			name:     "a validator restart while the fallback timer is stopped",
			series:   map[string]string{"intent_finalized_block": "0 1000000x70 0 1000361x30 _x25 1000361x15 0 1000722x70"},
			evalTime: "120m",
		},
		{
			// 150 minutes is 750 blocks: one missed epoch, which the epoch rules page.
			name:     "the fallback timer stopped and the validator stopped committing, 150 minutes on",
			series:   map[string]string{"intent_finalized_block": lastCommitHeld},
			evalTime: "223m",
		},
		{
			// 187 minutes is 935 blocks, though the same commit is still published.
			name:     "the fallback timer stopped and the validator stopped committing, 187 minutes on",
			series:   map[string]string{"intent_finalized_block": lastCommitHeld},
			evalTime: "260m",
			fires:    true,
		},
		{
			name:     "the fallback timer stopped and the validator stopped publishing",
			series:   map[string]string{"intent_finalized_block": snValidatorCommits(2)},
			evalTime: "260m",
			fires:    true,
		},
		{
			// No commit in four hours and no fallback reading is no data.
			name:     "the fallback timer stopped and the validator stopped publishing, past the window",
			series:   map[string]string{"intent_finalized_block": snValidatorCommits(2)},
			evalTime: "10h",
			fires:    true,
		},
		{
			// The reading of 799 holds from minute 150, 10 minutes past the fallback's commit.
			name:     "the validator is down and the fallback commits",
			series:   map[string]string{"weights_age_blocks": snValidatorFallbackReadings(snValidatorFallbackCycles(2)...)},
			evalTime: "158m",
		},
		{
			name:     "the validator is down and the fallback's commit failed",
			series:   map[string]string{"weights_age_blocks": snValidatorFallbackReadings(append(snValidatorFallbackCycles(1), 849, 899, 949)...)},
			evalTime: "180m",
			fires:    true,
		},
		{
			name:     "no reading at all",
			series:   map[string]string{},
			evalTime: "30m",
			fires:    true,
		},
		{
			name: "the fallback and the validator both healthy",
			series: map[string]string{
				"weights_age_blocks":     snValidatorFallbackReadings(49, 99, 149, 199, 249, 299, 349, 9, 59, 109, 159, 209, 259, 309, 359, 9, 59, 109),
				"intent_finalized_block": snValidatorCommits(3),
			},
			evalTime: "170m",
		},
	}

	tests := []map[string]any{}
	for _, testCase := range cases {
		inputSeries := []map[string]string{}
		for name, values := range testCase.series {
			inputSeries = append(inputSeries, map[string]string{
				"series": "urnetwork_sn_validator_" + name + `{env="main",host="snow",job="node"}`,
				"values": values,
			})
		}
		expected := []map[string]any{}
		if testCase.fires {
			expected = append(expected, map[string]any{"exp_labels": map[string]string{}})
		}
		tests = append(tests, map[string]any{
			"name":         testCase.name,
			"interval":     "1m",
			"input_series": inputSeries,
			"alert_rule_test": []map[string]any{{
				"eval_time":  testCase.evalTime,
				"alertname":  stale.Title,
				"exp_alerts": expected,
			}},
		})
	}
	encoded, err := yaml.Marshal(map[string]any{
		"rule_files":          []string{"rules.yml"},
		"evaluation_interval": "1m",
		"tests":               tests,
	})
	if err != nil {
		t.Fatal(err)
	}

	directory := t.TempDir()
	if err := os.WriteFile(filepath.Join(directory, "rules.yml"), rulesYaml, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "tests.yml"), encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Minute)
	defer cancel()
	command := exec.CommandContext(ctx, promtool, "test", "rules", "tests.yml")
	command.Dir = directory
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("promtool: %v\n%s", err, output)
	}
}

// A stuck read logs one read wait every 5 minutes, under the failing rule's
// threshold of more than three in 15 minutes. The stuck rule measures time
// since the later of the last steering success and 15 minutes after the
// process started. These are the cases it was written for, run on the rule's
// own constants.
func TestSnValidatorSteeringStuckSeparatesStuckFromSlow(t *testing.T) {
	var stuck *snValidatorRule
	rules := loadSnValidatorRules(t)
	for index := range rules {
		if rules[index].UID == "sn-validator-steering-stuck" {
			stuck = &rules[index]
		}
	}
	if stuck == nil {
		t.Fatal("sn-validator-steering-stuck is missing")
	}
	expr := stuck.Data[0].Model.Expr
	success := `urnetwork_sn_validator_steering_last_success_timestamp_seconds{env="main",host="snow"}`
	start := `urnetwork_sn_validator_process_start_timestamp_seconds{env="main",host="snow"}`
	allowance := regexp.MustCompile(regexp.QuoteMeta(start)+` \+ (\d+)\)`).FindAllStringSubmatch(expr, -1)
	if !strings.HasPrefix(expr, "time() - max((") || !strings.Contains(expr, success+" > ("+start+" + ") ||
		!strings.Contains(expr, ") or ("+start+" + ") || len(allowance) != 2 || allowance[0][1] != allowance[1][1] {
		t.Fatalf("the stuck rule does not count from the later of the last success and its start allowance: %s", expr)
	}
	startup, err := strconv.ParseFloat(allowance[0][1], 64)
	if err != nil {
		t.Fatal(err)
	}
	threshold := stuck.Data[1].Model.Conditions[0].Evaluator.Params[0]
	if stuck.For != "2m" {
		t.Fatalf("the stuck rule holds for %s, want 2m", stuck.For)
	}
	// age mirrors the expression: a success before the start allowance ends,
	// or none at all, counts from the allowance's end.
	age := func(now, lastSuccess, processStart float64) float64 {
		if lastSuccess > processStart+startup {
			return now - lastSuccess
		}
		return now - (processStart + startup)
	}
	const minute = 60.0
	for _, test := range []struct {
		name                           string
		now, lastSuccess, processStart float64
		fires                          bool
	}{
		{name: "a 25 minute operation after a success", now: 200 * minute, lastSuccess: 175 * minute, processStart: 0},
		{name: "15 minute startup, then a 25 minute operation", now: 40 * minute, lastSuccess: 0, processStart: 0},
		{name: "an intent waiting to apply, a success every 3 s", now: 300 * minute, lastSuccess: 300*minute - 3, processStart: 0},
		{name: "a success carried over from the previous process", now: 140 * minute, lastSuccess: 100 * minute, processStart: 120 * minute},
		{name: "a stuck read, a read wait every 5 minutes", now: 236 * minute, lastSuccess: 204 * minute, processStart: 0, fires: true},
		{name: "a native gap hold looking once a minute", now: 400 * minute, lastSuccess: 365 * minute, processStart: 0, fires: true},
		{name: "a new process that never succeeds", now: 46 * minute, lastSuccess: 0, processStart: 0, fires: true},
	} {
		if fires := age(test.now, test.lastSuccess, test.processStart) > threshold; fires != test.fires {
			t.Errorf("%s: fires=%t, want %t", test.name, fires, test.fires)
		}
	}
}

// Snow's validator health gauges reached Mimir with job sn-validator, and the
// commitment oracle's with job sn-commitment-oracle, each from a
// node_exporter_metrics input of its own in snow's Fluent Bit. A second
// instance of that plugin corrupts the first one's collectors, so snow's one
// input now reads both textfile directories and ships them with job node
// (xops files/fluent-bit/fluent-bit.conf). A rule that selected a job would go
// silent across that move, or stay silent if Grafana deployed after it, so
// none does: each selects snow's env and host alone.
func TestSnAlertsSelectNoJob(t *testing.T) {
	for _, rules := range [][]snValidatorRule{loadSnValidatorRules(t), loadSnCommitmentOracleRules(t)} {
		if len(rules) == 0 {
			t.Fatal("no rules read")
		}
		for _, rule := range rules {
			for _, query := range rule.Data {
				if strings.Contains(query.Model.Expr, "job") {
					t.Errorf("%s selects a job label: %s", rule.UID, query.Model.Expr)
				}
			}
		}
	}
}
