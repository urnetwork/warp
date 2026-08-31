package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

const grafanaAlertSchedulerInterval = 10 * time.Second

// Grafana 13 rejects a provisioned rule group unless its interval divides
// exactly by the scheduler interval. Keep this validation beside the embedded
// provisioning files so an invalid rule cannot make every new Grafana
// container fail readiness during a rollout.
func TestProvisionedAlertIntervalsMatchGrafanaScheduler(t *testing.T) {
	entries, err := os.ReadDir("alerting")
	if err != nil {
		t.Fatal(err)
	}

	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".yml" {
			continue
		}
		path := filepath.Join("alerting", entry.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var document struct {
			Groups []struct {
				Name     string `yaml:"name"`
				Interval string `yaml:"interval"`
			} `yaml:"groups"`
		}
		if err := yaml.Unmarshal(data, &document); err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		for _, group := range document.Groups {
			interval, err := time.ParseDuration(group.Interval)
			if err != nil {
				t.Errorf("%s group %q has invalid interval %q: %v", path, group.Name, group.Interval, err)
				continue
			}
			if interval <= 0 || interval%grafanaAlertSchedulerInterval != 0 {
				t.Errorf(
					"%s group %q interval %s must be a positive multiple of Grafana scheduler interval %s",
					path,
					group.Name,
					interval,
					grafanaAlertSchedulerInterval,
				)
			}
		}
	}
}
