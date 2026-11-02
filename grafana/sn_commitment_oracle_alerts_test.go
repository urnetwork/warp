package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

// The gauges sn commitmentoracle/metrics.go publishes. A rule on any other
// urnetwork_sn_commitment_oracle_ name would never have data.
var snCommitmentOracleGauges = map[string]bool{
	"sample_timestamp_seconds":        true,
	"process_start_timestamp_seconds": true,
	"dry_run":                         true,
	"oracle_active":                   true,
	"coordinator_paused":              true,
	"last_cycle_ok":                   true,
	"cycle_failures":                  true,
	"evm_finalized_block":             true,
	"native_finalized_block":          true,
	"native_lag_blocks":               true,
	"commitments":                     true,
	"fleet_commitments":               true,
	"fleet_commitments_mirrored":      true,
	"fleet_commitments_expired":       true,
	"fleet_commitments_conflicting":   true,
	"fleet_commitments_inconsistent":  true,
	"legacy_sha256_commitments":       true,
	"pending_unmirrored":              true,
	"pending_min_blocks_to_expiry":    true,
	"in_flight":                       true,
	"in_flight_age_seconds":           true,
	"oracle_balance_wei":              true,
	"oracle_balance_low":              true,
	"low_balance_threshold_wei":       true,
	"mirrors_sent":                    true,
	"last_success_timestamp_seconds":  true,
	"last_mirror_timestamp_seconds":   true,
	"last_error_timestamp_seconds":    true,
}

const snCommitmentOracleSelector = `{env="main",host="snow",job="sn-commitment-oracle"}`

func loadSnCommitmentOracleRules(t *testing.T) []snValidatorRule {
	t.Helper()
	// The embedded provisioning input, not a fixture.
	data, err := alertingFs.ReadFile("alerting/sn-commitment-oracle.yml")
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		APIVersion int `yaml:"apiVersion"`
		Groups     []struct {
			OrgID    int               `yaml:"orgId"`
			Name     string            `yaml:"name"`
			Folder   string            `yaml:"folder"`
			Interval string            `yaml:"interval"`
			Rules    []snValidatorRule `yaml:"rules"`
		} `yaml:"groups"`
	}
	if err := yaml.Unmarshal(data, &document); err != nil {
		t.Fatalf("parse oracle alerts: %v", err)
	}
	if document.APIVersion != 1 || len(document.Groups) != 1 {
		t.Fatalf("oracle provisioning version/groups = %d/%d, want 1/1", document.APIVersion, len(document.Groups))
	}
	group := document.Groups[0]
	if group.OrgID != 1 || group.Name != "sn-commitment-oracle" || group.Folder != "urnetwork alerts" || group.Interval != "1m" {
		t.Fatalf("oracle alert group = %q in %q every %q", group.Name, group.Folder, group.Interval)
	}
	return group.Rules
}

func TestSnCommitmentOracleAlertsReadOnlyPublishedGauges(t *testing.T) {
	metric := regexp.MustCompile(`urnetwork_sn_commitment_oracle_([a-z0-9_]+)(\{[^}]*\})?`)
	seen := map[string]bool{}
	for _, rule := range loadSnCommitmentOracleRules(t) {
		if !strings.HasPrefix(rule.UID, "sn-commitment-oracle-") || seen[rule.UID] {
			t.Errorf("rule uid %q is not a unique sn-commitment-oracle- uid", rule.UID)
		}
		seen[rule.UID] = true
		if rule.Condition != "B" || len(rule.Data) != 2 || rule.Data[0].RefID != "A" || rule.Data[1].RefID != "B" {
			t.Errorf("%s does not threshold query A in expression B", rule.UID)
			continue
		}
		if rule.Data[0].DatasourceUID != "warp-mimir" || rule.Data[1].DatasourceUID != "__expr__" {
			t.Errorf("%s does not query warp-mimir", rule.UID)
		}
		if rule.ExecErrState != "Error" || rule.Labels["service"] != "sn-commitment-oracle" {
			t.Errorf("%s must keep execErrState Error and service sn-commitment-oracle", rule.UID)
		}
		if rule.Annotations["summary"] == "" {
			t.Errorf("%s has no summary", rule.UID)
		}
		matches := metric.FindAllStringSubmatch(rule.Data[0].Model.Expr, -1)
		if len(matches) == 0 {
			t.Errorf("%s reads no oracle gauge", rule.UID)
		}
		for _, match := range matches {
			if !snCommitmentOracleGauges[match[1]] {
				t.Errorf("%s reads urnetwork_sn_commitment_oracle_%s, which the oracle does not publish", rule.UID, match[1])
			}
			// Each selector names exactly the series Fluent Bit ships from snow.
			if match[2] != snCommitmentOracleSelector {
				t.Errorf("%s selects urnetwork_sn_commitment_oracle_%s with %q", rule.UID, match[1], match[2])
			}
		}
	}
}

func TestSnCommitmentOracleAlertsCoverEachFailureMode(t *testing.T) {
	type want struct {
		gauge, evaluator string
		threshold        float64
		severity, hold   string
	}
	required := map[string]want{
		"sn-commitment-oracle-stale":            {"sample_timestamp_seconds", "gt", 300, "page", "10m"},
		"sn-commitment-oracle-not-active":       {"oracle_active", "lt", 1, "page", "5m"},
		"sn-commitment-oracle-no-success":       {"last_success_timestamp_seconds", "gt", 900, "warn", "0s"},
		"sn-commitment-oracle-no-success-long":  {"last_success_timestamp_seconds", "gt", 3600, "page", "0s"},
		"sn-commitment-oracle-pending-stuck":    {"pending_unmirrored", "gt", 0, "warn", "30m"},
		"sn-commitment-oracle-expiry-near":      {"pending_min_blocks_to_expiry", "lt", 7200, "page", "5m"},
		"sn-commitment-oracle-in-flight-old":    {"in_flight_age_seconds", "gt", 900, "warn", "0s"},
		"sn-commitment-oracle-balance-low":      {"oracle_balance_low", "gt", 0, "warn", "5m"},
		"sn-commitment-oracle-balance-critical": {"oracle_balance_wei", "lt", 2e15, "page", "1m"},
		"sn-commitment-oracle-paused":           {"coordinator_paused", "gt", 0, "warn", "1m"},
		"sn-commitment-oracle-records-disagree": {"fleet_commitments_inconsistent", "gt", 0, "warn", "1h"},
		"sn-commitment-oracle-native-lag":       {"native_lag_blocks", "gt", 50, "warn", "5m"},
		"sn-commitment-oracle-restarting":       {"process_start_timestamp_seconds", "gt", 2, "warn", "0s"},
	}
	rules := loadSnCommitmentOracleRules(t)
	if len(rules) != len(required) {
		t.Fatalf("oracle alert count = %d, want %d", len(rules), len(required))
	}
	for _, rule := range rules {
		expected, ok := required[rule.UID]
		if !ok {
			t.Errorf("unexpected oracle alert %s", rule.UID)
			continue
		}
		if !strings.Contains(rule.Data[0].Model.Expr, "urnetwork_sn_commitment_oracle_"+expected.gauge+"{") {
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
		if rule.For != expected.hold {
			t.Errorf("%s holds for %s, want %s", rule.UID, rule.For, expected.hold)
		}
	}
}

// The rules provision whether or not the oracle has ever run, so no series at
// all has to read as quiet. The stale rule alone keeps watching an oracle that
// stops: without its lookback, a series that stops would read as quiet too.
func TestSnCommitmentOracleAlertsResolveOnMissingData(t *testing.T) {
	for _, rule := range loadSnCommitmentOracleRules(t) {
		if rule.NoDataState != "OK" {
			t.Errorf("%s noDataState = %q, want OK", rule.UID, rule.NoDataState)
		}
		lookback := strings.Contains(rule.Data[0].Model.Expr, "max_over_time(")
		if lookback != (rule.UID == "sn-commitment-oracle-stale") {
			t.Errorf("%s lookback = %t: %s", rule.UID, lookback, rule.Data[0].Model.Expr)
		}
	}
}

// One Prometheus alerting rule per Grafana rule, comparing query A with
// expression B's threshold as Grafana does, without labels or annotations.
func snCommitmentOraclePrometheusRules(t *testing.T, rules []snValidatorRule) []byte {
	t.Helper()
	comparison := map[string]string{"gt": ">", "lt": "<"}
	translated := []map[string]string{}
	for _, rule := range rules {
		evaluator := rule.Data[1].Model.Conditions[0].Evaluator
		operator, ok := comparison[evaluator.Type]
		if !ok {
			t.Fatalf("%s evaluator %q", rule.UID, evaluator.Type)
		}
		translated = append(translated, map[string]string{
			"alert": rule.Title,
			"expr":  fmt.Sprintf("(%s) %s %f", rule.Data[0].Model.Expr, operator, evaluator.Params[0]),
			"for":   rule.For,
		})
	}
	encoded, err := yaml.Marshal(map[string]any{"groups": []map[string]any{{"name": "oracle", "rules": translated}}})
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

// The series notation of promtool: a sample a minute from time 0, so a value of
// 0+60xN reads as a timestamp written that minute. stops is the same up to a
// minute, then holds it, as a file nothing rewrites does.
func snOracleFresh(minutes int) string {
	return fmt.Sprintf("0+60x%d", minutes)
}

func snOracleStops(atMinute int, minutes int) string {
	return fmt.Sprintf("0+60x%d %dx%d", atMinute, atMinute*60, minutes-atMinute)
}

// A gauge rewritten every 10 minutes, as with the oracle's longest backoff.
func snOracleEveryTenMinutes(minutes int) string {
	values := []string{}
	for start := 0; start < minutes; start += 10 {
		values = append(values, fmt.Sprintf("%dx9", start*60))
	}
	return strings.Join(values, " ")
}

// A healthy live oracle for the first 3 hours, with some gauges replaced.
func snOracleSeries(replacements map[string]string) map[string]string {
	series := map[string]string{
		"sample_timestamp_seconds":        snOracleFresh(180),
		"process_start_timestamp_seconds": "0x180",
		"last_success_timestamp_seconds":  snOracleFresh(180),
		"dry_run":                         "0x180",
		"oracle_active":                   "1x180",
		"coordinator_paused":              "0x180",
		"pending_unmirrored":              "0x180",
		"fleet_commitments_inconsistent":  "0x180",
		"fleet_commitments_conflicting":   "0x180",
		"native_lag_blocks":               "0x180",
		"oracle_balance_low":              "0x180",
		"oracle_balance_wei":              "47917500000000000x180",
	}
	for name, values := range replacements {
		if values == "" {
			delete(series, name)
		} else {
			series[name] = values
		}
	}
	return series
}

// What each rule actually does on synthetic series, through the official
// evaluator. Run it with URNETWORK_PROMTOOL naming promtool 3.5.0 (server
// grafana/promtool.sh prints one); the structure tests above run without it.
func TestSnCommitmentOracleAlertsEvaluate(t *testing.T) {
	promtool := os.Getenv("URNETWORK_PROMTOOL")
	if promtool == "" {
		var err error
		promtool, err = exec.LookPath("promtool")
		if err != nil {
			t.Skip("no promtool; set URNETWORK_PROMTOOL")
		}
	}
	rules := loadSnCommitmentOracleRules(t)

	cases := []struct {
		name     string
		series   map[string]string
		evalTime string
		firing   []string
	}{
		{
			// The state the rules land in: no series at all, however long.
			name:     "the oracle has never run",
			series:   map[string]string{},
			evalTime: "3h",
		},
		{
			name:     "a healthy live oracle",
			series:   snOracleSeries(nil),
			evalTime: "2h",
		},
		{
			// A dry run signs nothing, so what it would send stays pending until it
			// ages out, and it does not spend the balance it has.
			name: "a dry run with pending commitments near expiry and little balance",
			series: snOracleSeries(map[string]string{
				"dry_run":                      "1x180",
				"pending_unmirrored":           "3x180",
				"pending_min_blocks_to_expiry": "5000x180",
				"oracle_balance_wei":           "1000000000000000x180",
				"oracle_balance_low":           "1x180",
			}),
			evalTime: "2h",
			firing:   []string{"SnCommitmentOracleBalanceLow"},
		},
		{
			name: "a live oracle with a commitment it has not mirrored",
			series: snOracleSeries(map[string]string{
				"pending_unmirrored":           "1x180",
				"pending_min_blocks_to_expiry": "5000x180",
			}),
			evalTime: "2h",
			firing:   []string{"SnCommitmentOraclePendingStuck", "SnCommitmentOracleExpiryNear"},
		},
		{
			name: "a pending commitment a first cycle is still mirroring",
			series: snOracleSeries(map[string]string{
				"pending_unmirrored":           "1x3",
				"pending_min_blocks_to_expiry": "5000x3",
			}),
			evalTime: "3m",
		},
		{
			name: "a live oracle running out of balance",
			series: snOracleSeries(map[string]string{
				"oracle_balance_wei": "1000000000000000x180",
				"oracle_balance_low": "1x180",
			}),
			evalTime: "2h",
			firing:   []string{"SnCommitmentOracleBalanceLow", "SnCommitmentOracleBalanceCritical"},
		},
		{
			// The file stays and is shipped with its old sample time.
			name: "the process stopped and its file is still shipped",
			series: snOracleSeries(map[string]string{
				"sample_timestamp_seconds":       snOracleStops(60, 180),
				"last_success_timestamp_seconds": snOracleStops(60, 180),
			}),
			evalTime: "2h10m",
			firing:   []string{"SnCommitmentOracleStale", "SnCommitmentOracleNoSuccess", "SnCommitmentOracleNoSuccessLong"},
		},
		{
			// Every series ends at minute 60: the shipper or the fragment is gone.
			name: "the series stopped, 20 minutes later",
			series: map[string]string{
				"sample_timestamp_seconds":        snOracleFresh(60),
				"process_start_timestamp_seconds": "0x60",
				"last_success_timestamp_seconds":  snOracleFresh(60),
				"dry_run":                         "0x60",
				"oracle_active":                   "1x60",
			},
			evalTime: "1h20m",
			firing:   []string{"SnCommitmentOracleStale"},
		},
		{
			name: "the series stopped, past the lookback",
			series: map[string]string{
				"sample_timestamp_seconds": snOracleFresh(60),
			},
			evalTime: "7d2h",
		},
		{
			// A sample every 10 minutes is not a stopped oracle, even 8 minutes after
			// one. No success is its alert.
			name: "cycles failing at the longest backoff",
			series: snOracleSeries(map[string]string{
				"sample_timestamp_seconds":       snOracleEveryTenMinutes(180),
				"last_success_timestamp_seconds": "0x180",
			}),
			evalTime: "1h58m",
			firing:   []string{"SnCommitmentOracleNoSuccess", "SnCommitmentOracleNoSuccessLong"},
		},
		{
			// The success gauge is absent until a process's first success.
			name: "a process that has never succeeded, after 20 minutes",
			series: snOracleSeries(map[string]string{
				"last_success_timestamp_seconds": "",
			}),
			evalTime: "20m",
			firing:   []string{"SnCommitmentOracleNoSuccess"},
		},
		{
			name: "a process that has never succeeded, after 70 minutes",
			series: snOracleSeries(map[string]string{
				"last_success_timestamp_seconds": "",
			}),
			evalTime: "70m",
			firing:   []string{"SnCommitmentOracleNoSuccess", "SnCommitmentOracleNoSuccessLong"},
		},
		{
			// Each start exits on its check, so the success gauge stays absent.
			name: "a start that keeps failing its active oracle check",
			series: snOracleSeries(map[string]string{
				"oracle_active":                   "0x180",
				"process_start_timestamp_seconds": "0+120x180",
				"last_success_timestamp_seconds":  "",
			}),
			evalTime: "1h",
			firing:   []string{"SnCommitmentOracleNotActive", "SnCommitmentOracleRestarting"},
		},
		{
			name: "one failed start",
			series: snOracleSeries(map[string]string{
				"oracle_active": "0 0 1x178",
			}),
			evalTime: "1m",
		},
		{
			name: "dry run, then the deploy that goes live",
			series: snOracleSeries(map[string]string{
				"process_start_timestamp_seconds": "0x60 3600x10 4200x110",
				"dry_run":                         "1x70 0x110",
			}),
			evalTime: "1h15m",
		},
		{
			name: "the coordinator paused",
			series: snOracleSeries(map[string]string{
				"coordinator_paused": "1x180",
			}),
			evalTime: "10m",
			firing:   []string{"SnCommitmentOraclePaused"},
		},
		{
			name: "a conflicting record, under the hold",
			series: snOracleSeries(map[string]string{
				"fleet_commitments_conflicting": "1x180",
			}),
			evalTime: "30m",
		},
		{
			name: "a conflicting record, past the hold",
			series: snOracleSeries(map[string]string{
				"fleet_commitments_conflicting": "1x180",
			}),
			evalTime: "70m",
			firing:   []string{"SnCommitmentOracleRecordsDisagree"},
		},
		{
			name: "an inconsistent record, past the hold",
			series: snOracleSeries(map[string]string{
				"fleet_commitments_inconsistent": "1x180",
			}),
			evalTime: "70m",
			firing:   []string{"SnCommitmentOracleRecordsDisagree"},
		},
		{
			name: "a transaction not final and the cycle behind",
			series: snOracleSeries(map[string]string{
				"in_flight_age_seconds": "1000x180",
				"native_lag_blocks":     "60x180",
			}),
			evalTime: "10m",
			firing:   []string{"SnCommitmentOracleInFlightOld", "SnCommitmentOracleNativeLag"},
		},
	}

	tests := []map[string]any{}
	for _, testCase := range cases {
		inputSeries := []map[string]string{}
		for name, values := range testCase.series {
			inputSeries = append(inputSeries, map[string]string{
				"series": "urnetwork_sn_commitment_oracle_" + name + snCommitmentOracleSelector,
				"values": values,
			})
		}
		alertTests := []map[string]any{}
		for _, rule := range rules {
			expected := []map[string]any{}
			if slices.Contains(testCase.firing, rule.Title) {
				expected = append(expected, map[string]any{"exp_labels": map[string]string{}})
			}
			alertTests = append(alertTests, map[string]any{
				"eval_time":  testCase.evalTime,
				"alertname":  rule.Title,
				"exp_alerts": expected,
			})
		}
		for _, title := range testCase.firing {
			if !slices.ContainsFunc(rules, func(rule snValidatorRule) bool { return rule.Title == title }) {
				t.Errorf("%s expects %s, which no rule is", testCase.name, title)
			}
		}
		tests = append(tests, map[string]any{
			"name":            testCase.name,
			"interval":        "1m",
			"input_series":    inputSeries,
			"alert_rule_test": alertTests,
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
	if err := os.WriteFile(filepath.Join(directory, "rules.yml"), snCommitmentOraclePrometheusRules(t, rules), 0o600); err != nil {
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
