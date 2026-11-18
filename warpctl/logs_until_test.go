package main

import (
	"testing"
	"time"

	"github.com/docopt/docopt-go"
)

// The CLI's explicit endpoint must reach the backend without losing its offset
// or precision. Unsupported backends and follow mode fail before client setup.
func TestLogSearchWindowFixedUntil(t *testing.T) {
	now := time.Date(2026, 11, 18, 18, 0, 0, 0, time.UTC)
	end := now.Add(-time.Hour + 123*time.Nanosecond)
	args := []string{"logs", "fixture", "proxy", "--since=2m", "--until=" + end.In(time.FixedZone("fixture", -8*3600)).Format(time.RFC3339Nano), "--limit=20000"}
	opts, err := docopt.ParseArgs(usage, args, Version)
	if err != nil {
		t.Fatal(err)
	}
	start, gotEnd, err := logSearchWindow(opts, time.UTC, now, LOG_SOURCE_GRAFANA, false)
	if err != nil || !gotEnd.Equal(end) || !start.Equal(end.Add(-2*time.Minute)) {
		t.Fatal("CLI lost the fixed end or resolved the relative start against the wall clock")
	}
	for _, test := range []struct {
		end, start, source string
		follow             bool
	}{
		{"2m", "2m", LOG_SOURCE_GRAFANA, false},
		{"2026-11-18T17:00:00", "2m", LOG_SOURCE_GRAFANA, false},
		{now.Add(time.Nanosecond).Format(time.RFC3339Nano), "2m", LOG_SOURCE_GRAFANA, false},
		{end.Format(time.RFC3339Nano), end.Format(time.RFC3339Nano), LOG_SOURCE_GRAFANA, false},
		{end.Format(time.RFC3339Nano), "1m", LOG_SOURCE_CLOUDWATCH, false},
		{end.Format(time.RFC3339Nano), "1m", LOG_SOURCE_GRAFANA, true},
	} {
		opts := docopt.Opts{"--since": test.start, "--until": test.end}
		if _, _, err := logSearchWindow(opts, time.UTC, now, test.source, test.follow); err == nil {
			t.Fatal("invalid bounded search accepted")
		}
	}
	start, gotEnd, err = logSearchWindow(docopt.Opts{}, time.UTC, now, LOG_SOURCE_CLOUDWATCH, true)
	if err != nil || !gotEnd.IsZero() || !start.Equal(now.Add(-5*time.Minute)) {
		t.Fatal("ordinary unfenced search or follow changed")
	}
}
