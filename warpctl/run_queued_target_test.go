package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/urnetwork/warp/warpctl/dynamo"
)

type queuedTargetLogWriter struct {
	once     sync.Once
	selected chan struct{}
}

type fixedDeploymentVersionClient struct{ version string }

func (c fixedDeploymentVersionClient) GetLatestVersion(ctx context.Context, _, _, _ string) (string, error) {
	return c.version, ctx.Err()
}

func (c fixedDeploymentVersionClient) GetLatestVersionConsistent(ctx context.Context, _, _, _ string) (string, error) {
	return c.version, ctx.Err()
}

type queuedTargetControl struct {
	changeService bool
	configChange  string
	cancelAtLease bool
	cancelAtRead  bool
}

func (w *queuedTargetLogWriter) Write(p []byte) (int, error) {
	if strings.Contains(string(p), "Deploy version=1.0.0") {
		w.once.Do(func() { close(w.selected) })
	}
	return len(p), nil
}

// This exercises the actual Run/getLatestVersion/deploy/startContainer path,
// the real DynamoDB HTTP decoder against a loopback-only selector, and a native
// service flock. The only intercepted deployment operation is the first image
// pull: observing that target is enough to establish stale activation intent,
// and the fixture then quits before starting a container or changing routing.
func TestRunWorkerQueuedTargetRechecksServiceVersion(t *testing.T) {
	testRunWorkerQueuedTarget(t, queuedTargetControl{changeService: true})
}

func TestRunWorkerQueuedTargetUnchangedStartsOnce(t *testing.T) {
	testRunWorkerQueuedTarget(t, queuedTargetControl{})
}

func TestRunWorkerQueuedTargetRechecksCompletedConfig(t *testing.T) {
	testRunWorkerQueuedTarget(t, queuedTargetControl{configChange: "completed"})
}

func TestRunWorkerQueuedTargetIgnoresStagingConfig(t *testing.T) {
	testRunWorkerQueuedTarget(t, queuedTargetControl{configChange: "staging"})
}

func TestRunWorkerQueuedTargetCancellationBeforeLeaseRelease(t *testing.T) {
	testRunWorkerQueuedTarget(t, queuedTargetControl{cancelAtLease: true})
}

func TestRunWorkerQueuedTargetCancellationDuringSelectorRead(t *testing.T) {
	testRunWorkerQueuedTarget(t, queuedTargetControl{cancelAtRead: true})
}

func testRunWorkerQueuedTarget(t *testing.T, control queuedTargetControl) {
	home := t.TempDir()
	bin := filepath.Join(home, "bin")
	if err := os.Mkdir(bin, 0o700); err != nil {
		t.Fatal(err)
	}
	// Direct command.Output callers also stay inside the fixture. No real
	// Docker, sudo, firewall, credentials, selector or service is contacted.
	script := "#!/bin/sh\ncase \"$*\" in\n  \"docker ps \"*) exit 0 ;;\n  \"iptables \"*\" -L \"*) exit 0 ;;\n  *) exit 97 ;;\nesac\n"
	if err := os.WriteFile(filepath.Join(bin, "sudo"), []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin)
	t.Setenv("WARP_HOME", home)
	var selected atomic.Value
	selected.Store("1.0.0")
	var reads atomic.Int32
	var strongReads atomic.Int32
	recheckEntered := make(chan struct{})
	var recheckOnce sync.Once
	selector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Amz-Target") != "DynamoDB_20120810.GetItem" {
			t.Errorf("unexpected local selector operation %q", r.Header.Get("X-Amz-Target"))
			http.Error(w, "unexpected fixture operation", 400)
			return
		}
		var request struct{ ConsistentRead bool }
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Error(err)
			return
		}
		if request.ConsistentRead {
			strongReads.Add(1)
			if control.cancelAtRead {
				recheckOnce.Do(func() { close(recheckEntered) })
				<-r.Context().Done()
				return
			}
		}
		reads.Add(1)
		w.Header().Set("Content-Type", "application/x-amz-json-1.0")
		json.NewEncoder(w).Encode(map[string]any{"Item": map[string]any{"version": map[string]string{"S": selected.Load().(string)}}})
	}))
	defer selector.Close()
	awsEmpty := filepath.Join(home, "aws-empty")
	if err := os.WriteFile(awsEmpty, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	for key, value := range map[string]string{
		"AWS_ACCESS_KEY_ID": "fixture", "AWS_SECRET_ACCESS_KEY": "fixture", "AWS_SESSION_TOKEN": "",
		"AWS_PROFILE": "", "AWS_SHARED_CREDENTIALS_FILE": awsEmpty, "AWS_CONFIG_FILE": awsEmpty,
		"AWS_EC2_METADATA_DISABLED": "true", "AWS_ENDPOINT_URL_DYNAMODB": selector.URL,
	} {
		t.Setenv(key, value)
	}
	dc, err := dynamo.NewClient()
	if err != nil {
		t.Fatal(err)
	}
	namespace := "fixture"
	worker := &RunWorker{
		warpState:    &WarpState{warpSettings: &WarpSettings{DockerNamespace: &namespace}},
		dynamoClient: dc, env: "test", service: "connect", block: "g2",
		hostNetworking: true, staggerHostDrain: true, statusMode: STATUS_MODE_NO,
		portBlocks:            parsePortBlocks("80:41080:42080"),
		servicesDockerNetwork: &DockerNetwork{networkName: "fixture", ipv4: &NetworkInterface{interfaceIp: "127.0.0.1"}},
		vaultMountMode:        MOUNT_MODE_NO, configMountMode: MOUNT_MODE_NO, siteMountMode: MOUNT_MODE_NO,
		dataMountMode: MOUNT_MODE_NO, dockerMountMode: MOUNT_MODE_NO,
	}
	configHome := filepath.Join(home, "config")
	if control.configChange != "" {
		if err := os.MkdirAll(filepath.Join(configHome, "1.0.0"), 0o700); err != nil {
			t.Fatal(err)
		}
		worker.warpState.warpSettings.ConfigHome = &configHome
		worker.configMountMode = MOUNT_MODE_YES
	}
	oldRun, oldOut, oldQuiet, oldSudo := runAndLogFunc, outAndLogFunc, runQuietFunc, sudo2Func
	type attemptedTarget struct {
		image  string
		config string
	}
	pulled := make(chan attemptedTarget, 1)
	runAndLogFunc = func(cmd *exec.Cmd) error {
		args := strings.Join(cmd.Args, " ")
		if strings.Contains(args, "docker pull ") {
			config := ""
			if worker.deployedConfigVersion != nil {
				config = worker.deployedConfigVersion.String()
			}
			pulled <- attemptedTarget{cmd.Args[len(cmd.Args)-1], config}
			worker.quitEvent.Set()
			return errors.New("fixture stopped before Docker pull")
		}
		if strings.Contains(args, "iptables ") && strings.Contains(args, " -C ") {
			return errors.New("fixture rule absent")
		}
		if strings.Contains(args, "iptables ") || strings.Contains(args, "docker container prune ") {
			return nil
		}
		return fmt.Errorf("unexpected fixture command %v", cmd.Args)
	}
	outAndLogFunc = func(cmd *exec.Cmd) ([]byte, error) {
		return nil, fmt.Errorf("unexpected fixture output command %v", cmd.Args)
	}
	runQuietFunc = func(cmd *exec.Cmd) (commandOutput, error) {
		if filepath.Base(cmd.Args[0]) == "netstat" {
			return commandOutput{}, nil
		}
		return commandOutput{}, fmt.Errorf("unexpected fixture quiet command %v", cmd.Args)
	}
	sudo2Func = nil
	oldWriter := Err.Writer()
	logWriter := &queuedTargetLogWriter{selected: make(chan struct{})}
	Err.SetOutput(logWriter)
	holder := newHostDrainLock(home, "test", "connect")
	if !holder.lock(time.Second) {
		t.Fatal("fixture holder did not acquire native service lease")
	}
	done := make(chan struct{})
	go func() { defer close(done); worker.Run() }()
	defer func() {
		holder.unlock()
		select {
		case <-logWriter.selected:
			worker.quitEvent.Set()
		default:
		}
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			panic("fixture Run owner did not join before hook restoration")
		}
		Err.SetOutput(oldWriter)
		runAndLogFunc, outAndLogFunc, runQuietFunc, sudo2Func = oldRun, oldOut, oldQuiet, oldSudo
	}()
	select {
	case <-logWriter.selected:
	case <-time.After(5 * time.Second):
		t.Fatal("actual Run did not capture selector A")
	}
	// Observe the second open lease descriptor, not an arbitrary sleep. Run
	// has captured A and entered the actual native flock acquisition loop.
	deadline := time.Now().Add(3 * time.Second)
	for {
		fds, err := os.ReadDir("/proc/self/fd")
		if err != nil {
			t.Fatal(err)
		}
		count := 0
		for _, fd := range fds {
			target, err := os.Readlink(filepath.Join("/proc/self/fd", fd.Name()))
			if err == nil && target == holder.path {
				count++
			}
		}
		if count >= 2 {
			break
		}
		if !time.Now().Before(deadline) {
			t.Fatal("actual Run did not wait on the occupied native lease")
		}
		time.Sleep(time.Millisecond)
	}
	select {
	case image := <-pulled:
		t.Fatalf("candidate bypassed held lease: %+v", image)
	default:
	}
	wantVersion, wantConfig := "1.0.0", ""
	if control.changeService {
		selected.Store("2.0.0")
		wantVersion = "2.0.0"
	}
	if control.configChange != "" {
		wantConfig = "1.0.0"
		next := "2.0.0"
		if control.configChange == "staging" {
			next += ".tmp"
		} else {
			wantConfig = "2.0.0"
		}
		if err := os.Mkdir(filepath.Join(configHome, next), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if control.cancelAtLease {
		worker.quitEvent.Set()
	}
	holder.unlock()
	if control.cancelAtRead {
		select {
		case <-recheckEntered:
		case <-time.After(3 * time.Second):
			t.Fatal("no strong post-lease selector read")
		}
		worker.quitEvent.Set()
	}
	if control.cancelAtLease || control.cancelAtRead {
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Fatal("canceled Run did not join")
		}
		select {
		case target := <-pulled:
			t.Fatalf("canceled deployment reached pull: %+v", target)
		default:
		}
		return
	}
	select {
	case target := <-pulled:
		t.Logf("native lease released; first pull=%s config=%s; selector reads=%d strong=%d", target.image, target.config, reads.Load(), strongReads.Load())
		if target.image != "fixture/test-connect:"+wantVersion || target.config != wantConfig {
			t.Fatalf("queued obsolete target reached Docker pull: got %+v, want service%s config%s", target, wantVersion, wantConfig)
		}
		if strongReads.Load() == 0 {
			t.Fatal("candidate start lacked strongly consistent selector revalidation")
		}
	case <-time.After(8 * time.Second):
		t.Fatal("current selector target did not reach the owning pull boundary")
	}
}
