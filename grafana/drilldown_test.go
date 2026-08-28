package main

import (
	"os"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestLogsDrilldownLokiFeaturesAreExplicitlyEnabled(t *testing.T) {
	limits := map[string]any{"retention_period": "240h"}
	config := map[string]any{"limits_config": limits}

	enableLogsDrilldownLokiFeatures(config)

	for _, key := range []string{
		"allow_structured_metadata",
		"volume_enabled",
		"discover_log_levels",
	} {
		if enabled, ok := limits[key].(bool); !ok || !enabled {
			t.Errorf("limits_config.%s = %#v, want true", key, limits[key])
		}
	}
	serviceLabels, ok := limits["discover_service_name"].([]string)
	if !ok || len(serviceLabels) != 1 || serviceLabels[0] != "service" {
		t.Fatalf("limits_config.discover_service_name = %#v, want [service]", limits["discover_service_name"])
	}
	if limits["retention_period"] != "240h" {
		t.Fatalf("existing Loki limits were replaced: %#v", limits)
	}
	patternIngester, ok := config["pattern_ingester"].(map[string]any)
	if !ok || patternIngester["enabled"] != true {
		t.Fatalf("pattern_ingester = %#v", config["pattern_ingester"])
	}
}

func TestLogsDrilldownLokiFeaturesRequireLimitsConfig(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("missing limits_config must fail before writing a partial Loki config")
		}
	}()
	enableLogsDrilldownLokiFeatures(map[string]any{})
}

func TestLogsDrilldownPluginProvisioningUsesWarpLoki(t *testing.T) {
	pluginYaml := renderLogsDrilldownPluginYaml(&GrafanaConfig{
		Loki: &LokiConfig{Retention: "240h"},
	})
	var parsed struct {
		ApiVersion int `yaml:"apiVersion"`
		Apps       []struct {
			Type     string `yaml:"type"`
			OrgId    int    `yaml:"org_id"`
			Disabled *bool  `yaml:"disabled"`
			JsonData struct {
				DataSource       string `yaml:"dataSource"`
				Interval         string `yaml:"interval"`
				PatternsDisabled *bool  `yaml:"patternsDisabled"`
				DefaultTimeRange struct {
					From string `yaml:"from"`
					To   string `yaml:"to"`
				} `yaml:"defaultTimeRange"`
			} `yaml:"jsonData"`
		} `yaml:"apps"`
	}
	if err := yaml.Unmarshal([]byte(pluginYaml), &parsed); err != nil {
		t.Fatal(err)
	}
	if parsed.ApiVersion != 1 || len(parsed.Apps) != 1 {
		t.Fatalf("plugin provisioning header = %#v", parsed)
	}
	app := parsed.Apps[0]
	if app.Type != logsDrilldownPluginID || app.OrgId != 1 {
		t.Fatalf("provisioned app = %#v", app)
	}
	if app.Disabled == nil || *app.Disabled {
		t.Fatal("Logs Drilldown app is not explicitly enabled")
	}
	if app.JsonData.DataSource != lokiDatasourceUid {
		t.Fatalf("default datasource = %q", app.JsonData.DataSource)
	}
	if app.JsonData.Interval != "240h" {
		t.Fatalf("maximum interval = %q", app.JsonData.Interval)
	}
	if app.JsonData.DefaultTimeRange.From != "now-1h" || app.JsonData.DefaultTimeRange.To != "now" {
		t.Fatalf("default time range = %#v", app.JsonData.DefaultTimeRange)
	}
	if app.JsonData.PatternsDisabled == nil || *app.JsonData.PatternsDisabled {
		t.Fatal("patterns must remain enabled when Loki's pattern ingester is enabled")
	}
}

func TestGrafanaImageBakesChecksumPinnedLogsDrilldown(t *testing.T) {
	dockerfileBytes, err := os.ReadFile("Dockerfile")
	if err != nil {
		t.Fatal(err)
	}
	dockerfile := string(dockerfileBytes)
	for _, required := range []string{
		"ARG grafana_version=13.2.0",
		`apt-get install -y "grafana=${grafana_version}"`,
		"ARG logs_drilldown_version=2.5.2",
		"ARG logs_drilldown_sha256=315aae6ddec2a548547856a1bd884651507da2e182f358191988379f6522d05d",
		"grafana-lokiexplore-app/versions/${logs_drilldown_version}/download",
		"sha256sum --check -",
		"unzip -q /tmp/grafana-lokiexplore-app.zip -d /var/lib/grafana/plugins",
	} {
		if !strings.Contains(dockerfile, required) {
			t.Errorf("Dockerfile is missing %q", required)
		}
	}
}
