package main

// The lb process's environment (TLS-M6-07): a block's defaults with nothing set, a test's directories and lbmap's
// windows when set, and a duration that does not parse, or a bound LbMapSettings refuses, stopping the process.

import (
	"testing"
	"time"

	"github.com/urnetwork/warp"
)

func TestLbEnvironmentKeepsABlocksDefaults(t *testing.T) {
	environment, err := readLbEnvironment(func(string) string { return "" })
	if err != nil {
		t.Fatal(err)
	}
	defaults := warp.DefaultLbMapSettings()
	if environment.configDir != "/srv/warp/nginx.conf" || environment.runDir != warp.LbRunDir ||
		environment.lbMapConfig.LoadDelay != defaults.LoadDelay || environment.lbMapConfig.ReloadMinInterval != defaults.ReloadMinInterval {
		t.Fatalf("the defaults: %+v, %+v", environment, environment.lbMapConfig)
	}
	if path := environment.runPath(warp.LbTlsCustomHostsMapPath); path != warp.LbTlsCustomHostsMapPath {
		t.Fatalf("the map's path %s", path)
	}
}

func TestLbEnvironmentTakesATestsDirectoriesAndWindows(t *testing.T) {
	values := map[string]string{
		"WARP_LB_CONFIG_DIR":             "/tmp/lb-config",
		"WARP_LB_RUN_DIR":                "/tmp/lb-run",
		"WARP_LBMAP_LOAD_DELAY":          "50ms",
		"WARP_LBMAP_RELOAD_MIN_INTERVAL": "200ms",
		"WARP_LBMAP_START_TIMEOUT":       "2s",
		"WARP_LBMAP_POLL_TIMEOUT":        "1s",
		"WARP_LBMAP_POLL_MIN_INTERVAL":   "0s",
	}
	environment, err := readLbEnvironment(func(key string) string { return values[key] })
	if err != nil {
		t.Fatal(err)
	}
	settings := environment.lbMapConfig
	if environment.configDir != "/tmp/lb-config" || environment.runDir != "/tmp/lb-run" || settings.LoadDelay != 50*time.Millisecond ||
		settings.ReloadMinInterval != 200*time.Millisecond || settings.StartTimeout != 2*time.Second || settings.PollTimeout != time.Second ||
		settings.PollMinInterval != 0 {
		t.Fatalf("the environment: %+v, %+v", environment, settings)
	}
	if path := environment.runPath(warp.LbTlsCustomHosts80Path); path != "/tmp/lb-run/tls-custom-hosts-80.conf" {
		t.Fatalf("the 80 include's path %s", path)
	}
}

func TestLbEnvironmentRefusesWhatDoesNotParse(t *testing.T) {
	for key, value := range map[string]string{
		"WARP_LBMAP_LOAD_DELAY":    "five seconds",
		"WARP_LBMAP_POLL_TIMEOUT":  "0s",
		"WARP_LBMAP_START_TIMEOUT": "-1s",
	} {
		if _, err := readLbEnvironment(func(name string) string {
			if name == key {
				return value
			}
			return ""
		}); err == nil {
			t.Errorf("%s=%s was taken", key, value)
		}
	}
}
