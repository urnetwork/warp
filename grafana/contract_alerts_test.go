package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"
)

func TestContractFailureAlertsUseLosslessBoundedCounter(t *testing.T) {
	data, err := os.ReadFile("alerting/contract-failures.yml")
	if err != nil {
		t.Fatal(err)
	}

	config := string(data)
	for _, want := range []string{
		`urnetwork_connect_contract_failures_total{cause="insufficient_balance"}`,
		`urnetwork_connect_contract_failures_total{cause="missing_companion_origin",companion="false"}`,
		`urnetwork_connect_contract_failures_total{cause="missing_companion_origin",companion="true"}`,
		"uid: contract-insufficient-balance-spike",
		"uid: contract-missing-companion-origin-spike",
		"uid: contract-missing-origin-requested-spike",
	} {
		if !strings.Contains(config, want) {
			t.Errorf("contract alert configuration is missing %q", want)
		}
	}
}

// The two partitions of missing companion-origin failures have their own
// baselines (2026-11-05..11-19, the rule's 5-minute rate): companion=false
// levels off at 12,000-25,400/min since 11-16, companion=true peaks at
// 2,550/min. Each partition has its rule and threshold, and each summary
// names the threshold its rule compares.
func TestContractMissingCompanionOriginRulesShape(t *testing.T) {
	group, ok := loadProvisionedAlertGroups(t, "alerting/contract-failures.yml")["contract-failures"]
	if !ok || group.Folder != "urnetwork alerts" || group.Interval != "1m" {
		t.Fatalf("contract-failures group = %+v", group)
	}
	for uid, want := range map[string]struct {
		title     string
		companion string
		threshold float64
	}{
		"contract-missing-companion-origin-spike": {"ContractMissingCompanionOriginSpike", "false", 40000},
		"contract-missing-origin-requested-spike": {"ContractMissingCompanionOriginRequestedSpike", "true", 4000},
	} {
		rule := provisionedAlertRuleByUID(t, group, uid)
		if rule.Title != want.title || rule.Labels["severity"] != "warn" {
			t.Errorf("%s title and labels = %s %v", uid, rule.Title, rule.Labels)
		}
		if rule.NoDataState != "OK" || rule.ExecErrState != "Error" || rule.For != "5m" {
			t.Errorf("%s noDataState/execErrState/for = %s/%s/%s", uid, rule.NoDataState, rule.ExecErrState, rule.For)
		}
		if len(rule.Data) != 2 || rule.Data[0].DatasourceUID != "warp-mimir" || len(rule.Data[1].Model.Conditions) != 1 {
			t.Fatalf("%s wants a warp-mimir query and one threshold", uid)
		}
		wantExpr := `sum by (env, companion) (rate(urnetwork_connect_contract_failures_total{cause="missing_companion_origin",companion="` + want.companion + `"}[5m])) * 60`
		if rule.Data[0].Model.Expr != wantExpr {
			t.Errorf("%s expr = %s, want %s", uid, rule.Data[0].Model.Expr, wantExpr)
		}
		evaluator := rule.Data[1].Model.Conditions[0].Evaluator
		if evaluator.Type != "gt" || len(evaluator.Params) != 1 || evaluator.Params[0] != want.threshold {
			t.Errorf("%s threshold = %s %v, want gt %v", uid, evaluator.Type, evaluator.Params, want.threshold)
		}
		exceeds := "exceed " + strconv.FormatFloat(want.threshold, 'f', -1, 64) + "/min"
		if !strings.Contains(rule.Annotations["summary"], exceeds) {
			t.Errorf("%s summary does not say %q: %s", uid, exceeds, rule.Annotations["summary"])
		}
	}
}

// One api process's missing companion-origin counter for a request partition.
func missingOriginCounter(companion string, instance string) string {
	return `urnetwork_connect_contract_failures_total{env="main",service="api",block="g1",host="h1",instance="` + instance +
		`",job="api",cause="missing_companion_origin",companion="` + companion + `"}`
}

// A counter's growth for some minutes.
type counterSegment struct {
	perMinute float64
	minutes   int
}

// A counter's 1-minute samples from 0 that grow by each segment's rate a
// minute for its minutes, in order.
func counterSamples(segments ...counterSegment) string {
	format := func(value float64) string { return strconv.FormatFloat(value, 'f', -1, 64) }
	value := 0.0
	parts := []string{"0"}
	for _, segment := range segments {
		parts = append(parts, fmt.Sprintf("%s+%sx%d", format(value+segment.perMinute), format(segment.perMinute), segment.minutes-1))
		value += segment.perMinute * float64(segment.minutes)
	}
	return strings.Join(parts, " ")
}

// The rules on synthetic histories at 1-minute samples, each partition's rate
// split over two api processes, read at 60 minutes. The measured levels of
// 2026-11-05..11-19 stay quiet: companion=false at its 25,400/min peak since
// 11-16 and through the regrowth after the 11-19 connect roll (2,000 to
// 5,200/min), companion=true at its 2,550/min peak. Both fired at the old
// 500/min. Growth like the companion=false climb before 11-16, and a
// sustained spike over either threshold, fire; a spike shorter than the 5
// minutes the rules hold, or the other partition's rate, does not.
func TestContractMissingCompanionOriginAlertsEvaluate(t *testing.T) {
	group := loadProvisionedAlertGroups(t, "alerting/contract-failures.yml")["contract-failures"]
	split := func(companion string, segments ...counterSegment) map[string]string {
		halves := make([]counterSegment, len(segments))
		for i, segment := range segments {
			halves[i] = counterSegment{segment.perMinute / 2, segment.minutes}
		}
		return map[string]string{
			missingOriginCounter(companion, "a1"): counterSamples(halves...),
			missingOriginCounter(companion, "a2"): counterSamples(halves...),
		}
	}
	both := func(a map[string]string, b map[string]string) map[string]string {
		series := map[string]string{}
		for name, values := range a {
			series[name] = values
		}
		for name, values := range b {
			series[name] = values
		}
		return series
	}
	fallbackPlateau := split("false", counterSegment{25400, 60})
	requestedPeak := split("true", counterSegment{2550, 60})

	cases := map[string][]promtoolAlertCase{
		"contract-missing-companion-origin-spike": {
			{name: "the plateau's peak since 11-16", series: both(fallbackPlateau, requestedPeak), evalTime: "60m"},
			{name: "the regrowth after the 11-19 connect roll", series: split("false",
				counterSegment{2000, 20}, counterSegment{3200, 20}, counterSegment{5200, 20}), evalTime: "60m"},
			{name: "a climb like the one before 11-16", series: split("false",
				counterSegment{30000, 20}, counterSegment{45000, 20}, counterSegment{60000, 20}), evalTime: "60m", fires: true},
			{name: "50,000 a minute for 10 minutes", series: split("false",
				counterSegment{25400, 50}, counterSegment{50000, 10}), evalTime: "60m", fires: true},
			{name: "50,000 a minute for 4 minutes", series: split("false",
				counterSegment{25400, 50}, counterSegment{50000, 4}, counterSegment{25400, 6}), evalTime: "60m"},
			{name: "an api process restarts", series: map[string]string{
				missingOriginCounter("false", "a1"): counterSamples(counterSegment{12700, 30}) + " " + counterSamples(counterSegment{12700, 29}),
				missingOriginCounter("false", "a2"): counterSamples(counterSegment{12700, 60}),
			}, evalTime: "60m"},
			{name: "requested companions at 50,000 a minute", series: both(fallbackPlateau, split("true", counterSegment{50000, 60})), evalTime: "60m"},
		},
		"contract-missing-origin-requested-spike": {
			{name: "the 14-day peak", series: both(fallbackPlateau, requestedPeak), evalTime: "60m"},
			{name: "6,000 a minute for 10 minutes", series: split("true",
				counterSegment{550, 50}, counterSegment{6000, 10}), evalTime: "60m", fires: true},
			{name: "6,000 a minute for 4 minutes", series: split("true",
				counterSegment{550, 50}, counterSegment{6000, 4}, counterSegment{550, 6}), evalTime: "60m"},
			{name: "the fallback partition at 50,000 a minute", series: both(split("false", counterSegment{50000, 60}), requestedPeak), evalTime: "60m"},
		},
	}
	labels := map[string]map[string]string{
		"contract-missing-companion-origin-spike": {"env": "main", "companion": "false"},
		"contract-missing-origin-requested-spike": {"env": "main", "companion": "true"},
	}
	for uid, ruleCases := range cases {
		t.Run(uid, func(t *testing.T) {
			evaluateAlertRuleWithPromtool(t, provisionedAlertRuleByUID(t, group, uid), "1m", labels[uid], ruleCases)
		})
	}
}
