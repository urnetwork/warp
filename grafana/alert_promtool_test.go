package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

// One file-provisioned rule, as the alert rule tests read it.
type provisionedAlertRule struct {
	UID   string `yaml:"uid"`
	Title string `yaml:"title"`
	Data  []struct {
		RelativeTimeRange struct {
			From int `yaml:"from"`
			To   int `yaml:"to"`
		} `yaml:"relativeTimeRange"`
		DatasourceUID string `yaml:"datasourceUid"`
		Model         struct {
			Expr       string `yaml:"expr"`
			Expression string `yaml:"expression"`
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

type provisionedAlertGroup struct {
	Name     string                 `yaml:"name"`
	Folder   string                 `yaml:"folder"`
	Interval string                 `yaml:"interval"`
	Rules    []provisionedAlertRule `yaml:"rules"`
}

func loadProvisionedAlertGroups(t *testing.T, path string) map[string]provisionedAlertGroup {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Groups []provisionedAlertGroup `yaml:"groups"`
	}
	if err := yaml.Unmarshal(data, &document); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	groups := map[string]provisionedAlertGroup{}
	for _, group := range document.Groups {
		groups[group.Name] = group
	}
	return groups
}

func provisionedAlertRuleByUID(t *testing.T, group provisionedAlertGroup, uid string) provisionedAlertRule {
	t.Helper()
	for _, rule := range group.Rules {
		if rule.UID == uid {
			return rule
		}
	}
	t.Fatalf("group %s has no rule %s", group.Name, uid)
	return provisionedAlertRule{}
}

// One synthetic history and whether the rule fires at evalTime.
type promtoolAlertCase struct {
	name     string
	series   map[string]string
	evalTime string
	fires    bool
}

// Evaluates a rule whose noDataState is OK through promtool, the official
// evaluator: the query, then its threshold, held for the rule's for. Grafana's
// empty result and promtool's are both quiet, so the rule translates as is.
// A case that fires expects one alert with firingLabels, the query's labels.
// Run it with URNETWORK_PROMTOOL naming promtool 3.5.0 (server
// grafana/promtool.sh prints one); the structure tests run without it.
func evaluateAlertRuleWithPromtool(t *testing.T, rule provisionedAlertRule, interval string, firingLabels map[string]string, cases []promtoolAlertCase) {
	t.Helper()
	promtool := os.Getenv("URNETWORK_PROMTOOL")
	if promtool == "" {
		var err error
		promtool, err = exec.LookPath("promtool")
		if err != nil {
			t.Skip("no promtool; set URNETWORK_PROMTOOL")
		}
	}
	if rule.NoDataState != "OK" {
		t.Fatalf("%s alerts on no data; this evaluation does not model that", rule.UID)
	}
	if len(rule.Data) != 2 || len(rule.Data[1].Model.Conditions) != 1 {
		t.Fatalf("%s wants a query and one threshold condition", rule.UID)
	}
	evaluator := rule.Data[1].Model.Conditions[0].Evaluator
	operators := map[string]string{"gt": ">", "lt": "<"}
	operator, ok := operators[evaluator.Type]
	if !ok || len(evaluator.Params) != 1 {
		t.Fatalf("%s compares %q %v", rule.UID, evaluator.Type, evaluator.Params)
	}
	rulesYaml, err := yaml.Marshal(map[string]any{"groups": []map[string]any{{
		"name": "rules",
		"rules": []map[string]string{{
			"alert": rule.Title,
			"expr":  fmt.Sprintf("(%s) %s %v", rule.Data[0].Model.Expr, operator, evaluator.Params[0]),
			"for":   rule.For,
		}},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	tests := []map[string]any{}
	for _, testCase := range cases {
		inputSeries := []map[string]string{}
		for series, values := range testCase.series {
			inputSeries = append(inputSeries, map[string]string{"series": series, "values": values})
		}
		expected := []map[string]any{}
		if testCase.fires {
			expected = append(expected, map[string]any{"exp_labels": firingLabels})
		}
		tests = append(tests, map[string]any{
			"name":         testCase.name,
			"interval":     interval,
			"input_series": inputSeries,
			"alert_rule_test": []map[string]any{{
				"eval_time":  testCase.evalTime,
				"alertname":  rule.Title,
				"exp_alerts": expected,
			}},
		})
	}
	encoded, err := yaml.Marshal(map[string]any{
		"rule_files":          []string{"rules.yml"},
		"evaluation_interval": interval,
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
