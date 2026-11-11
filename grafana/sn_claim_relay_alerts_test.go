package main

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func snClaimRelayRules(t *testing.T) []settlementV2WatcherRule {
	t.Helper()
	// the actual embedded provisioning input, not a separate fixture
	data, err := alertingFs.ReadFile("alerting/sn-claim-relay.yml")
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		APIVersion int `yaml:"apiVersion"`
		Groups     []struct {
			OrgID    int                       `yaml:"orgId"`
			Name     string                    `yaml:"name"`
			Folder   string                    `yaml:"folder"`
			Interval string                    `yaml:"interval"`
			Rules    []settlementV2WatcherRule `yaml:"rules"`
		} `yaml:"groups"`
	}
	if err := yaml.Unmarshal(data, &document); err != nil {
		t.Fatal(err)
	}
	if document.APIVersion != 1 || len(document.Groups) != 1 {
		t.Fatalf("provisioning version/groups = %d/%d, want 1/1", document.APIVersion, len(document.Groups))
	}
	group := document.Groups[0]
	if group.OrgID != 1 || group.Name != "sn-claim-relay" || group.Folder != "urnetwork alerts" || group.Interval != "1m" {
		t.Fatalf("alert group = %+v", group)
	}
	return group.Rules
}

// Each thing the relay can go wrong with has its rule: griefing, overspending,
// passes stopping, a low balance, the cap, refused claims, stalling, gas.
func TestSnClaimRelayAlertsCoverEachStop(t *testing.T) {
	required := map[string]struct {
		metric    string
		kind      string
		threshold float64
		severity  string
	}{
		"sn-claim-relay-griefing-stop":  {`urnetwork_sn_claim_relay_state{env="main",service="taskworker",instance!="",state="griefing_stop"}`, "gt", 0, "page"},
		"sn-claim-relay-overspend":      {`urnetwork_sn_claim_relay_spent_today_tao{`, "gt", 0.01, "page"},
		"sn-claim-relay-no-pass":        {`time() - max(urnetwork_sn_claim_relay_last_pass_timestamp_seconds{`, "gt", 3600, "warn"},
		"sn-claim-relay-low-balance":    {`urnetwork_sn_claim_relay_relayer_balance_tao{`, "lt", 0.03, "warn"},
		"sn-claim-relay-cap-reached":    {`state="cap_reached"`, "gt", 0.5, "warn"},
		"sn-claim-relay-refused":        {`urnetwork_sn_claim_relay_claims_total{env="main",service="taskworker",instance!="",result="refused"}`, "gt", 5, "warn"},
		"sn-claim-relay-stalled":        {`in_flight|send_failed|chain_unavailable|ledger_unavailable|bad_key|low_balance`, "gt", 0, "warn"},
		"sn-claim-relay-gas-price-high": {`state="gas_price_high"`, "gt", 0, "warn"},
	}
	for _, rule := range snClaimRelayRules(t) {
		want, ok := required[rule.UID]
		if !ok {
			t.Errorf("unexpected or duplicate rule %q", rule.UID)
			continue
		}
		delete(required, rule.UID)
		if rule.Condition != "B" || len(rule.Data) != 2 || rule.Data[0].RefID != "A" || rule.Data[1].RefID != "B" {
			t.Errorf("%s must threshold query A in expression B", rule.UID)
			continue
		}
		query, condition := rule.Data[0], rule.Data[1]
		if query.DatasourceUID != "warp-mimir" || condition.DatasourceUID != "__expr__" {
			t.Errorf("%s must query the normal warp-mimir datasource", rule.UID)
		}
		if !strings.Contains(query.Model.Expr, want.metric) {
			t.Errorf("%s query = %q, want it to read %q", rule.UID, query.Model.Expr, want.metric)
		}
		conditions := condition.Model.Conditions
		if len(conditions) != 1 || conditions[0].Evaluator.Type != want.kind || len(conditions[0].Evaluator.Params) != 1 || conditions[0].Evaluator.Params[0] != want.threshold {
			t.Errorf("%s threshold = %+v, want %s %v", rule.UID, conditions, want.kind, want.threshold)
		}
		if rule.Labels["service"] != "sn-claim-relay" || rule.Labels["severity"] != want.severity {
			t.Errorf("%s routing labels = %v", rule.UID, rule.Labels)
		}
		if rule.Title == "" || rule.Annotations["summary"] == "" || rule.IsPaused == nil || *rule.IsPaused {
			t.Errorf("%s is missing its title or operator summary, or is paused", rule.UID)
		}
		// The rules ship with grafana, which can deploy before the taskworker
		// that exports these series.
		if rule.NoDataState != "OK" || rule.ExecErrState != "Error" {
			t.Errorf("%s must not fire on series that do not exist yet, and must keep query errors", rule.UID)
		}
	}
	if len(required) != 0 {
		t.Errorf("missing rules: %v", required)
	}
}

// With no relayer key the balance reads zero, which is not an alert: a relay that
// has not been given a key yet stays quiet, and the dashboard says so.
func TestSnClaimRelayLowBalanceIsQuietWithoutAKey(t *testing.T) {
	for _, rule := range snClaimRelayRules(t) {
		if rule.UID != "sn-claim-relay-low-balance" {
			continue
		}
		if expr := rule.Data[0].Model.Expr; !strings.Contains(expr, `state=~"no_key|bad_key|not_configured"`) || !strings.Contains(expr, "== 0") {
			t.Errorf("the rule fires without a key: %q", expr)
		}
		return
	}
	t.Fatal("no low balance rule")
}

// A gauge reads the worker with the newest pass: every worker keeps the values of
// its own last one, so another reading would hold a stale stop for good.
func TestSnClaimRelayGaugeRulesReadTheNewestPass(t *testing.T) {
	for _, rule := range snClaimRelayRules(t) {
		expr := rule.Data[0].Model.Expr
		switch rule.UID {
		case "sn-claim-relay-no-pass", "sn-claim-relay-cap-reached", "sn-claim-relay-refused":
			continue
		}
		if !strings.Contains(expr, "scalar(max(urnetwork_sn_claim_relay_last_pass_timestamp_seconds{") {
			t.Errorf("%s reads every worker's gauge: %q", rule.UID, expr)
		}
	}
}
