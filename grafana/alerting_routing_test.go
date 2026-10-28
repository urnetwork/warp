package main

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// Every file-provisioned rule carries a severity label of page or warn. The
// notification tree sends each alert no child route matches to the slack root
// receiver (server grafana/alert_routing.go), and severity is what an operator
// reads and routes on there.
func TestEveryProvisionedRuleHasPageOrWarnSeverity(t *testing.T) {
	entries, err := alertingFs.ReadDir("alerting")
	if err != nil {
		t.Fatal(err)
	}
	ruleCount := 0
	for _, entry := range entries {
		content, err := alertingFs.ReadFile("alerting/" + entry.Name())
		if err != nil {
			t.Fatal(err)
		}
		var provisioning struct {
			Groups []struct {
				Rules []struct {
					Uid    string            `yaml:"uid"`
					Labels map[string]string `yaml:"labels"`
				} `yaml:"rules"`
			} `yaml:"groups"`
		}
		if err := yaml.Unmarshal(content, &provisioning); err != nil {
			t.Fatalf("%s: %s", entry.Name(), err)
		}
		for _, group := range provisioning.Groups {
			for _, rule := range group.Rules {
				ruleCount += 1
				if severity := rule.Labels["severity"]; severity != "page" && severity != "warn" {
					t.Errorf("%s rule %s has severity %q, want page or warn", entry.Name(), rule.Uid, severity)
				}
			}
		}
	}
	if ruleCount == 0 {
		t.Fatal("no provisioned rules read")
	}
}

// Grafana refuses a rule whose uid is longer than 40 characters or already
// used, and one refused rule fails the whole provisioning module, so the
// server exits at startup. On 2026-10-28 the 41-character
// competition-automation-reward-receipt-lag kept every grafana block's new
// release in a restart loop that never answered /api/health.
func TestEveryProvisionedRuleUidIsShortAndUnique(t *testing.T) {
	entries, err := alertingFs.ReadDir("alerting")
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]string{}
	for _, entry := range entries {
		content, err := alertingFs.ReadFile("alerting/" + entry.Name())
		if err != nil {
			t.Fatal(err)
		}
		var provisioning struct {
			Groups []struct {
				Rules []struct {
					Uid string `yaml:"uid"`
				} `yaml:"rules"`
			} `yaml:"groups"`
		}
		if err := yaml.Unmarshal(content, &provisioning); err != nil {
			t.Fatalf("%s: %s", entry.Name(), err)
		}
		for _, group := range provisioning.Groups {
			for _, rule := range group.Rules {
				if rule.Uid == "" || 40 < len(rule.Uid) {
					t.Errorf("%s rule uid %q has %d characters, want 1 to 40", entry.Name(), rule.Uid, len(rule.Uid))
				}
				if file, ok := seen[rule.Uid]; ok {
					t.Errorf("%s rule uid %q is also used in %s", entry.Name(), rule.Uid, file)
				}
				seen[rule.Uid] = entry.Name()
			}
		}
	}
	if len(seen) == 0 {
		t.Fatal("no provisioned rules read")
	}
}

// An alerting file that describes routing names the code that reconciles it.
// Before, three files said contact points and notification policies were
// managed in the grafana ui, which hid where the 2026-10-19 pgbouncer pages
// were routed.
func TestAlertingFilesNameTheReconciledRouting(t *testing.T) {
	entries, err := alertingFs.ReadDir("alerting")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		content, err := alertingFs.ReadFile("alerting/" + entry.Name())
		if err != nil {
			t.Fatal(err)
		}
		text := strings.ToLower(string(content))
		if strings.Contains(text, "managed in the grafana ui") {
			t.Errorf("%s says routing is managed in the grafana ui", entry.Name())
		}
		if strings.Contains(text, "contact points") && !strings.Contains(text, "bringyourctl grafana reconcile-alerting") {
			t.Errorf("%s describes contact points without naming bringyourctl grafana reconcile-alerting", entry.Name())
		}
	}
}
