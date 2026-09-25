package main

import (
	"strings"
	"testing"

	"github.com/docopt/docopt-go"
)

func TestBuildConfigRestartOption(t *testing.T) {
	cases := []struct {
		name    string
		opts    docopt.Opts
		service string
		want    string
		wantErr string
	}{
		{"absent is restart", docopt.Opts{"--config_restart": nil}, "config-updater", "yes", ""},
		{"yes is restart", docopt.Opts{"--config_restart": "yes"}, "config-updater", "yes", ""},
		{"no holds", docopt.Opts{"--config_restart": "no"}, "config-updater", "no", ""},
		{"only yes or no", docopt.Opts{"--config_restart": "later"}, "config-updater", "", "must be yes or no"},
		{"no applies to config-updater only", docopt.Opts{"--config_restart": "no"}, "api", "", "config-updater only"},
		{"yes is harmless elsewhere", docopt.Opts{"--config_restart": "yes"}, "api", "yes", ""},
	}
	for _, c := range cases {
		got, err := buildConfigRestart(c.opts, c.service)
		if c.wantErr != "" {
			if err == nil || !strings.Contains(err.Error(), c.wantErr) {
				t.Errorf("%s: err=%v, want %q", c.name, err, c.wantErr)
			}
			continue
		}
		if err != nil || got != c.want {
			t.Errorf("%s: got %q err=%v, want %q", c.name, got, err, c.want)
		}
	}
}
