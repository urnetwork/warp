package main

import (
	"testing"

	"gopkg.in/yaml.v3"
)

// Exercise the operator-facing YAML through the same limits renderer used by
// the child config. Omission must retain Mimir's default; zero explicitly
// disables the limit and must not be confused with an omitted setting.
func TestMimirLimitsConfig(t *testing.T) {
	for _, test := range []struct {
		name          string
		configYAML    string
		wantRetention string
		wantLimit     int
		hasLimit      bool
	}{
		{
			name:          "no mimir settings",
			configYAML:    "{}",
			wantRetention: defaultMimirRetention,
		},
		{
			name:          "empty mimir settings",
			configYAML:    "mimir: {}",
			wantRetention: defaultMimirRetention,
		},
		{
			name:          "retention only preserves series default",
			configYAML:    "mimir:\n  retention: 720h\n",
			wantRetention: "720h",
		},
		{
			name:          "one million cluster series",
			configYAML:    "mimir:\n  max_global_series_per_user: 1000000\n",
			wantRetention: defaultMimirRetention,
			wantLimit:     1000000,
			hasLimit:      true,
		},
		{
			name:          "custom limit and retention",
			configYAML:    "mimir:\n  retention: 720h\n  max_global_series_per_user: 2000000\n",
			wantRetention: "720h",
			wantLimit:     2000000,
			hasLimit:      true,
		},
		{
			name:          "explicit zero disables limit",
			configYAML:    "mimir:\n  max_global_series_per_user: 0\n",
			wantRetention: defaultMimirRetention,
			wantLimit:     0,
			hasLimit:      true,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			var config GrafanaConfig
			if err := yaml.Unmarshal([]byte(test.configYAML), &config); err != nil {
				t.Fatal(err)
			}
			rendered, err := yaml.Marshal(map[string]any{"limits": mimirLimitsConfig(config.Mimir)})
			if err != nil {
				t.Fatal(err)
			}
			var parsed struct {
				Limits map[string]any `yaml:"limits"`
			}
			if err := yaml.Unmarshal(rendered, &parsed); err != nil {
				t.Fatal(err)
			}
			if got := parsed.Limits["compactor_blocks_retention_period"]; got != test.wantRetention {
				t.Fatalf("retention = %v, want %s", got, test.wantRetention)
			}
			limit, present := parsed.Limits["max_global_series_per_user"]
			if present != test.hasLimit {
				t.Fatalf("series limit present = %t, want %t:\n%s", present, test.hasLimit, rendered)
			}
			if test.hasLimit && limit != test.wantLimit {
				t.Fatalf("series limit = %#v, want integer %d", limit, test.wantLimit)
			}
		})
	}
}

func TestMimirLimitsConfigRejectsNegativeSeriesLimit(t *testing.T) {
	var config GrafanaConfig
	if err := yaml.Unmarshal([]byte("mimir:\n  max_global_series_per_user: -1\n"), &config); err != nil {
		t.Fatal(err)
	}
	defer func() {
		got := recover()
		err, ok := got.(error)
		if !ok || err.Error() != "mimir.max_global_series_per_user must be non-negative" {
			t.Fatalf("panic = %v, want negative series limit validation error", got)
		}
	}()
	mimirLimitsConfig(config.Mimir)
}
