package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/coreos/go-semver/semver"
)

func TestConfigVersionRestartOnlyWithholdsOnExplicitFalse(t *testing.T) {
	configHome := t.TempDir()
	version := semver.New("2026.9.25+1055000000")
	versionHome := filepath.Join(configHome, version.String())
	if err := os.Mkdir(versionHome, 0o700); err != nil {
		t.Fatal(err)
	}

	// no file: every config version restarted services before the file existed
	restart, err := configVersionRestart(configHome, version)
	if err != nil || !restart {
		t.Fatalf("no file: restart=%v err=%v, want restart", restart, err)
	}

	write := func(content string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(versionHome, configUpdaterFile), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	write("# written by warpctl build --config_restart=no\nrestart: false\n")
	restart, err = configVersionRestart(configHome, version)
	if err != nil || restart {
		t.Fatalf("restart: false: restart=%v err=%v, want hold", restart, err)
	}

	write("restart: true\n")
	restart, err = configVersionRestart(configHome, version)
	if err != nil || !restart {
		t.Fatalf("restart: true: restart=%v err=%v, want restart", restart, err)
	}

	// a file without the field is the default
	write("built: 2026-09-25\n")
	restart, err = configVersionRestart(configHome, version)
	if err != nil || !restart {
		t.Fatalf("no field: restart=%v err=%v, want restart", restart, err)
	}

	// unreadable settings fail open to the old behavior, and say so
	write("restart: [\n")
	restart, err = configVersionRestart(configHome, version)
	if err == nil || !restart {
		t.Fatalf("malformed: restart=%v err=%v, want restart with an error", restart, err)
	}
}

func TestHoldConfigVersionOnlyWhileServiceIsOlder(t *testing.T) {
	older := semver.New("2026.9.24+1054000000")
	config := semver.New("2026.9.25+1055000000")
	sameBaseNewer := semver.New("2026.9.25+1055000001")
	newer := semver.New("2026.9.26+1056000000")

	cases := []struct {
		name     string
		deployed *semver.Version
		restart  bool
		hold     bool
	}{
		{"older service waits for its deploy", older, false, true},
		{"service already on the config's version restarts for it", config, false, false},
		{"newer build of the same day restarts for it", sameBaseNewer, false, false},
		{"newer release restarts for it", newer, false, false},
		{"restart: true never holds", older, true, false},
		{"nothing running, nothing to hold", nil, false, false},
	}
	for _, c := range cases {
		if hold := holdConfigVersion(c.deployed, config, c.restart); hold != c.hold {
			t.Errorf("%s: hold=%v, want %v", c.name, hold, c.hold)
		}
	}
	if holdConfigVersion(older, nil, false) {
		t.Error("no config version: held")
	}
}

// The run worker reads the decision from the config home it mounts, and logs
// the hold once per config version rather than on every poll.
func TestRunWorkerHoldsConfigVersionAndLogsOnce(t *testing.T) {
	configHome := t.TempDir()
	config := semver.New("2026.9.25+1055000000")
	versionHome := filepath.Join(configHome, config.String())
	if err := os.Mkdir(versionHome, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(versionHome, configUpdaterFile), []byte("restart: false\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	worker := &RunWorker{
		warpState: &WarpState{
			warpSettings: &WarpSettings{ConfigHome: &configHome},
		},
		deployedVersion:       semver.New("2026.9.24+1054000000"),
		deployedConfigVersion: semver.New("2026.9.24+1054000000"),
	}
	output := captureErrOutput(t)

	for i := 0; i < 3; i += 1 {
		if !worker.holdsConfigVersion(config) {
			t.Fatalf("poll %d: not held", i)
		}
	}
	if logged := countOccurrences(output.String(), "restart: false"); logged != 1 {
		t.Fatalf("hold logged %d times, want once:\n%s", logged, output.String())
	}

	// the block's own deploy arrives: nothing holds a service on the config's version
	worker.deployedVersion = config
	if worker.holdsConfigVersion(config) {
		t.Fatal("service on the config's version was held")
	}
	if worker.heldConfigVersion != nil {
		t.Fatal("hold not cleared")
	}
}

func countOccurrences(s string, sub string) int {
	count := 0
	for i := 0; ; {
		j := indexFrom(s, sub, i)
		if j < 0 {
			return count
		}
		count += 1
		i = j + len(sub)
	}
}

func indexFrom(s string, sub string, from int) int {
	if from >= len(s) {
		return -1
	}
	for i := from; i+len(sub) <= len(s); i += 1 {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
