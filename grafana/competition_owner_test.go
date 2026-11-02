// Rule-owner metadata must remain attached to every competition signal independently of the configured native notification transport.
package main

import (
	"testing"

	"gopkg.in/yaml.v3"
)

// The public incident contact, as warp's own copy of server's grafana.CompetitionIncidentContact:
// neither module depends on the other. server's grafana/competition_incident_owner_test.go holds
// that constant to this value, and to the rules themselves when warp is checked out beside server.
const competitionIncidentContact = "support@ur.xyz"

// Expected ownership comes from the public incident contract rather than a copied private identity or transport credential.
func TestCompetitionAlertRulesRetainIncidentOwner(t *testing.T) {
	body, err := alertingFs.ReadFile("alerting/competition.yml")
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Groups []struct {
			Rules []struct {
				Uid    string            `yaml:"uid"`
				Labels map[string]string `yaml:"labels"`
			} `yaml:"rules"`
		} `yaml:"groups"`
	}
	if err := yaml.Unmarshal(body, &document); err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, group := range document.Groups {
		for _, rule := range group.Rules {
			count++
			if rule.Labels["owner"] != competitionIncidentContact || rule.Labels["service"] != "sim-latency" || (rule.Labels["severity"] != "warn" && rule.Labels["severity"] != "page") {
				t.Errorf("rule %s lost incident ownership or routing severity", rule.Uid)
			}
		}
	}
	if count != 7 {
		t.Fatalf("competition rule census=%d", count)
	}
}
