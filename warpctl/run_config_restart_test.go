package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

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

// A restart: false config holds every running block whatever its build stamp,
// newer stamps included. Only a block on exactly the config's version, whose
// own release deploy landed before the config reached its host, restarts once.
func TestHoldConfigVersionHoldsRunningBlocksWhateverTheirStamp(t *testing.T) {
	config := semver.New("2026.9.25+1055000000")

	cases := []struct {
		name     string
		deployed *semver.Version
		restart  bool
		hold     bool
	}{
		{"older release waits for its deploy", semver.New("2026.9.24+1054000000"), false, true},
		{"older hand-deployed build waits for its deploy", semver.New("2026.9.24-devhost+1054500000"), false, true},
		{"newer hand-deployed build of the same day waits for its deploy", semver.New("2026.9.25-devhost+1055000500"), false, true},
		{"newer build of the same day waits for its deploy", semver.New("2026.9.25+1055000001"), false, true},
		{"newer release waits for its deploy", semver.New("2026.9.26+1056000000"), false, true},
		{"a hand-deployed build with the release's code is not the release", semver.New("2026.9.25-devhost+1055000000"), false, true},
		{"the config's own release restarts once to take it", semver.New("2026.9.25+1055000000"), false, false},
		{"restart: true never holds an older block", semver.New("2026.9.24+1054000000"), true, false},
		{"restart: true never holds a newer block", semver.New("2026.9.25-devhost+1055000500"), true, false},
		{"nothing running, nothing to hold", nil, false, false},
	}
	for _, c := range cases {
		if hold := holdConfigVersion(c.deployed, config, c.restart); hold != c.hold {
			t.Errorf("%s: hold=%v, want %v", c.name, hold, c.hold)
		}
	}
	if holdConfigVersion(semver.New("2026.9.24+1054000000"), nil, false) {
		t.Error("no config version: held")
	}
}

// The 2026-10-10 defect at the run worker: a nightly config built with
// --config_restart=no reached blocks running hand-deployed builds. Their
// stamps compare newer than the nightly's, so the old order rule let every one
// of them restart for the config. Such a block keeps its config until its next
// deploy.
func TestRunWorkerHoldsNewerHandDeployedBlockForRestartFalseConfig(t *testing.T) {
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
		// built by hand after the nightly minted its version code
		deployedVersion:       semver.New("2026.9.25-devhost+1055000500"),
		deployedConfigVersion: semver.New("2026.9.24+1054000000"),
	}
	captureErrOutput(t)

	if !worker.holdsConfigVersion(config) {
		t.Fatalf("version=%s restarts for restart: false configVersion=%s", worker.deployedVersion, config)
	}
	if worker.heldConfigVersion == nil || *worker.heldConfigVersion != *config {
		t.Fatalf("held config version = %v, want %s", worker.heldConfigVersion, config)
	}
}

// configPushPoll is one Run poll after a config-only push: the selector still
// names the block's running service version, and the host has a newer
// completed config than the one the block runs.
type configPushPoll struct {
	deployed *semver.Version
	// the content of the new config's config-updater.yml; "" builds the config
	// without --config_restart=no, so the file is absent
	configUpdater string
	// whether Docker reports the block's container as running
	running bool
}

// configPushDecision is what Run decided for the new config.
type configPushDecision struct {
	// the "Deploy version=..." line, "" when Run started no deploy
	deployLine string
	held       bool
	log        string
}

const configPushOldConfig = "2026.9.24+1054000000"
const configPushNewConfig = "2026.9.25+1055000000"

// configPushLogWriter quits Run at its first deploy or hold decision, from
// inside the Run goroutine that logged it, so the decision is observed at its
// own boundary rather than after a sleep.
type configPushLogWriter struct {
	worker *RunWorker

	stateLock  sync.Mutex
	log        strings.Builder
	deployLine string
	held       bool
}

func (self *configPushLogWriter) Write(p []byte) (int, error) {
	line := string(p)
	decided := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.log.WriteString(line)
		if self.deployLine == "" && strings.Contains(line, "Deploy version=") {
			self.deployLine = strings.TrimSpace(line)
			return true
		}
		if strings.Contains(line, "has restart: false; keeping version=") {
			self.held = true
			return true
		}
		return false
	}()
	if decided {
		self.worker.quitEvent.Set()
	}
	return len(p), nil
}

// runConfigPushPoll drives the actual Run loop, its version poll, config read
// and running-container check, through one decision. Docker is a fixture
// script on PATH that answers only `docker ps`; command hooks refuse every
// other command, and a deploy quits before allocating ports or pulling. No
// real Docker, sudo, firewall, credentials or selector is contacted.
func runConfigPushPoll(t *testing.T, poll configPushPoll) configPushDecision {
	t.Helper()
	home := t.TempDir()
	bin := filepath.Join(home, "bin")
	if err := os.Mkdir(bin, 0o700); err != nil {
		t.Fatal(err)
	}
	psOutput := ""
	if poll.running {
		psOutput = "echo fixture0container1"
	}
	// docker() runs `docker` directly off Linux and `sudo docker` on Linux
	dockerScript := "#!/bin/sh\ncase \"$1\" in\n  ps) " + psOutput + " ;;\n  *) exit 97 ;;\nesac\n"
	sudoScript := "#!/bin/sh\nif [ \"$1\" = docker ]; then\n  shift\n  exec \"${0%/*}/docker\" \"$@\"\nfi\nexit 97\n"
	for name, script := range map[string]string{"docker": dockerScript, "sudo": sudoScript} {
		if err := os.WriteFile(filepath.Join(bin, name), []byte(script), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", bin)
	t.Setenv("WARP_HOME", home)

	configHome := filepath.Join(home, "config")
	for _, version := range []string{configPushOldConfig, configPushNewConfig} {
		if err := os.MkdirAll(filepath.Join(configHome, version), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if poll.configUpdater != "" {
		path := filepath.Join(configHome, configPushNewConfig, configUpdaterFile)
		if err := os.WriteFile(path, []byte(poll.configUpdater), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	namespace := "fixture"
	worker := &RunWorker{
		warpState: &WarpState{warpSettings: &WarpSettings{
			ConfigHome:      &configHome,
			DockerNamespace: &namespace,
		}},
		dynamoClient:          fixedDeploymentVersionClient{version: poll.deployed.String()},
		env:                   "test",
		service:               "taskworker",
		block:                 "g1",
		portBlocks:            parsePortBlocks("80:41080:42080"),
		statusMode:            STATUS_MODE_NO,
		vaultMountMode:        MOUNT_MODE_NO,
		configMountMode:       MOUNT_MODE_YES,
		siteMountMode:         MOUNT_MODE_NO,
		dataMountMode:         MOUNT_MODE_NO,
		dockerMountMode:       MOUNT_MODE_NO,
		deployedVersion:       poll.deployed,
		deployedConfigVersion: semver.New(configPushOldConfig),
	}

	oldRun, oldOut, oldQuiet, oldSudo := runAndLogFunc, outAndLogFunc, runQuietFunc, sudo2Func
	runAndLogFunc = func(cmd *exec.Cmd) error {
		if strings.Contains(strings.Join(cmd.Args, " "), "docker container prune ") {
			return nil
		}
		return fmt.Errorf("fixture refused command %v", cmd.Args)
	}
	outAndLogFunc = func(cmd *exec.Cmd) ([]byte, error) {
		return nil, fmt.Errorf("fixture refused output command %v", cmd.Args)
	}
	runQuietFunc = func(cmd *exec.Cmd) (commandOutput, error) {
		return commandOutput{}, fmt.Errorf("fixture refused quiet command %v", cmd.Args)
	}
	sudo2Func = nil
	oldWriter := Err.Writer()
	logWriter := &configPushLogWriter{worker: worker}
	Err.SetOutput(logWriter)

	done := make(chan struct{})
	go func() {
		defer close(done)
		worker.Run()
	}()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		// Run still owns the hooks; restoring them under it would race
		panic("fixture Run reached no deploy or hold decision")
	}
	Err.SetOutput(oldWriter)
	runAndLogFunc, outAndLogFunc, runQuietFunc, sudo2Func = oldRun, oldOut, oldQuiet, oldSudo

	logWriter.stateLock.Lock()
	defer logWriter.stateLock.Unlock()
	return configPushDecision{
		deployLine: logWriter.deployLine,
		held:       logWriter.held,
		log:        logWriter.log.String(),
	}
}

// The 2026-10-10 defect where it was observable: Run restarted a running
// block on a newer hand-deployed build for a nightly restart: false config.
func TestRunWorkerRunKeepsNewerHandDeployedBlockForRestartFalseConfig(t *testing.T) {
	decision := runConfigPushPoll(t, configPushPoll{
		deployed:      semver.New("2026.9.25-devhost+1055000500"),
		configUpdater: "# written by warpctl build --config_restart=no\nrestart: false\n",
		running:       true,
	})
	if decision.deployLine != "" {
		t.Fatalf("restart: false config restarted the running block: %q\n%s", decision.deployLine, decision.log)
	}
	if !decision.held {
		t.Fatalf("hold not logged:\n%s", decision.log)
	}
}

// A newer release that the config's rollout did not redeploy is held the same
// way.
func TestRunWorkerRunKeepsNewerReleaseBlockForRestartFalseConfig(t *testing.T) {
	decision := runConfigPushPoll(t, configPushPoll{
		deployed:      semver.New("2026.9.26+1056000000"),
		configUpdater: "restart: false\n",
		running:       true,
	})
	if decision.deployLine != "" {
		t.Fatalf("restart: false config restarted the running block: %q\n%s", decision.deployLine, decision.log)
	}
	if !decision.held {
		t.Fatalf("hold not logged:\n%s", decision.log)
	}
}

// Config built without --config_restart=no restarts running blocks, whatever
// their stamp, as every config version has.
func TestRunWorkerRunRestartsNewerBlockForConfigBuiltWithoutTheFlag(t *testing.T) {
	decision := runConfigPushPoll(t, configPushPoll{
		deployed: semver.New("2026.9.25-devhost+1055000500"),
		running:  true,
	})
	want := "Deploy version=2026.9.25-devhost+1055000500, configVersion=" + configPushNewConfig
	if !strings.HasSuffix(decision.deployLine, want) {
		t.Fatalf("deploy line %q, want suffix %q\n%s", decision.deployLine, want, decision.log)
	}
	if decision.held {
		t.Fatalf("config without the flag was held:\n%s", decision.log)
	}
}

// The release that published the config deployed this block before the config
// reached its host: the block restarts once to take its release's config.
func TestRunWorkerRunFinishesReleaseDeployForItsOwnConfig(t *testing.T) {
	decision := runConfigPushPoll(t, configPushPoll{
		deployed:      semver.New(configPushNewConfig),
		configUpdater: "restart: false\n",
		running:       true,
	})
	want := "Deploy version=" + configPushNewConfig + ", configVersion=" + configPushNewConfig
	if !strings.HasSuffix(decision.deployLine, want) {
		t.Fatalf("deploy line %q, want suffix %q\n%s", decision.deployLine, want, decision.log)
	}
}

// A hold never leaves a block down: with no running container the block
// deploys, and takes the newest config.
func TestRunWorkerRunDeploysMissingHeldBlockWithNewConfig(t *testing.T) {
	decision := runConfigPushPoll(t, configPushPoll{
		deployed:      semver.New("2026.9.25-devhost+1055000500"),
		configUpdater: "restart: false\n",
		running:       false,
	})
	want := "Deploy version=2026.9.25-devhost+1055000500, configVersion=" + configPushNewConfig
	if !strings.HasSuffix(decision.deployLine, want) {
		t.Fatalf("deploy line %q, want suffix %q\n%s", decision.deployLine, want, decision.log)
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
