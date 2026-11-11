package main

import (
	"os"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

type tcpListenRule struct {
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
	Annotations  map[string]string `yaml:"annotations"`
}

func readTcpListenRules(t *testing.T) map[string]tcpListenRule {
	t.Helper()
	data, err := os.ReadFile("alerting/tcp-listen.yml")
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Groups []struct {
			Name  string          `yaml:"name"`
			Rules []tcpListenRule `yaml:"rules"`
		} `yaml:"groups"`
	}
	if err := yaml.Unmarshal(data, &document); err != nil {
		t.Fatalf("parse tcp listen alerts: %v", err)
	}
	if len(document.Groups) != 1 || document.Groups[0].Name != "tcp-listen" {
		t.Fatalf("tcp listen alerts want one group tcp-listen, got %d", len(document.Groups))
	}
	rules := map[string]tcpListenRule{}
	for _, rule := range document.Groups[0].Rules {
		if len(rule.Data) != 2 || len(rule.Data[1].Model.Conditions) != 1 {
			t.Fatalf("rule %s wants a query and one threshold", rule.UID)
		}
		rules[rule.UID] = rule
	}
	return rules
}

// On 2026-10-25 the kernel's listen overflows rose on a Redis host while its
// nodes refused about 2.3 million connections, and they were found by hand
// nearly two hours in. tcp-counters.timer ships the counter from every Main
// host since 2026-11-03 (xops tasks/tcp-counters.yml). Any overflow on any
// host that ships it warns, each host by itself, so edge-5's and edge-6's
// Redis listeners are covered with the rest and a new host needs no edit.
func TestTcpListenOverflowsWarnOnAnyOverflowOfAnyHost(t *testing.T) {
	rule, ok := readTcpListenRules(t)["tcp-listen-overflows"]
	if !ok {
		t.Fatal("missing tcp-listen-overflows")
	}
	expr := rule.Data[0].Model.Expr
	if expr != "max by (env, host) (rate(node_netstat_TcpExt_ListenOverflows[5m]))" {
		t.Errorf("overflow expr = %q, want the per host five-minute rate of every host's counter", expr)
	}
	// no host or env selector: every host that ships the counter is watched
	if strings.Contains(expr, "{") {
		t.Errorf("overflow expr selects series: %s", expr)
	}
	evaluator := rule.Data[1].Model.Conditions[0].Evaluator
	if evaluator.Type != "gt" || len(evaluator.Params) != 1 || evaluator.Params[0] != 0 {
		t.Errorf("overflow threshold = %s %v, want gt 0", evaluator.Type, evaluator.Params)
	}
	// a burst keeps the five-minute rate above zero for five minutes, so the
	// pending period must be shorter for a single burst to fire
	if rule.For != "1m" {
		t.Errorf("overflow for = %q, want 1m", rule.For)
	}
	if rule.Labels["severity"] != "warn" || rule.Labels["service"] != "tcp-listen" {
		t.Errorf("overflow labels = %v, want service tcp-listen and severity warn", rule.Labels)
	}
	// a host without the series is the telemetry rule's to report
	if rule.NoDataState != "OK" || rule.ExecErrState != "Error" {
		t.Errorf("overflow noDataState/execErrState = %s/%s, want OK/Error", rule.NoDataState, rule.ExecErrState)
	}
	if summary := rule.Annotations["summary"]; !strings.Contains(summary, "{{ $labels.host }}") || !strings.Contains(summary, "ss -ltn") {
		t.Errorf("overflow summary must name the host and how to find the full listener: %q", summary)
	}
}

// Counters that stop updating read as a host without overflows. A stopped
// timer leaves its last file, which fluent-bit keeps shipping with fresh
// timestamps, so the sample's own timestamp is aged, over a day's lookback
// that outlives a vanished series, and edge-5's and edge-6's samples must
// exist at all.
func TestTcpListenTelemetryFailsClosed(t *testing.T) {
	rule, ok := readTcpListenRules(t)["tcp-listen-telemetry-stale"]
	if !ok {
		t.Fatal("missing tcp-listen-telemetry-stale")
	}
	// the folded expr joins its lines with spaces
	terms := strings.Split(rule.Data[0].Model.Expr, " or ")
	want := []string{
		`(time() - max by (env, host) (max_over_time(urnetwork_tcp_counters_sample_timestamp_seconds{env="main"}[1d])) > 300)`,
		`absent(urnetwork_tcp_counters_sample_timestamp_seconds{env="main",host="by-us-fmt-5-edge-5"})`,
		`absent(urnetwork_tcp_counters_sample_timestamp_seconds{env="main",host="by-us-fmt-5-edge-6"})`,
	}
	if len(terms) != len(want) {
		t.Fatalf("telemetry expr has %d terms, want %d: %q", len(terms), len(want), rule.Data[0].Model.Expr)
	}
	for i := range want {
		if strings.TrimSpace(terms[i]) != want[i] {
			t.Errorf("telemetry term %d = %q, want %q", i, terms[i], want[i])
		}
	}
	evaluator := rule.Data[1].Model.Conditions[0].Evaluator
	if evaluator.Type != "gt" || len(evaluator.Params) != 1 || evaluator.Params[0] != 0 {
		t.Errorf("telemetry threshold = %s %v, want gt 0", evaluator.Type, evaluator.Params)
	}
	if rule.For != "10m" || rule.Labels["severity"] != "warn" || rule.Labels["service"] != "tcp-listen" {
		t.Errorf("telemetry for/labels = %s/%v, want 10m, service tcp-listen and severity warn", rule.For, rule.Labels)
	}
	if rule.NoDataState != "OK" || rule.ExecErrState != "Error" {
		t.Errorf("telemetry noDataState/execErrState = %s/%s, want OK/Error", rule.NoDataState, rule.ExecErrState)
	}
	if len(readTcpListenRules(t)) != 2 {
		t.Errorf("tcp listen rule count = %d, want 2", len(readTcpListenRules(t)))
	}
}
