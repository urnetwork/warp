package main

import (
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"

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
			// Each selector names exactly the series Fluent Bit ships from snow.
			if match[2] != `{env="main",host="snow",job="sn-validator"}` {
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
		"sn-validator-weights-stale":         {"weights_age_blocks", "gt", 500, "page", "Alerting"},
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
	success := `urnetwork_sn_validator_steering_last_success_timestamp_seconds{env="main",host="snow",job="sn-validator"}`
	start := `urnetwork_sn_validator_process_start_timestamp_seconds{env="main",host="snow",job="sn-validator"}`
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
