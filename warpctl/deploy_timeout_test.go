package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

type deployTimeoutFixture struct {
	mu     sync.Mutex
	events []string
	output bytes.Buffer
}

// Exercise the real CLI parser and deploy command. Docker is intercepted,
// DynamoDB writes use a loopback server with fixture credentials, and both
// convergence boundaries record calls without contacting a load balancer.
func newDeployTimeoutFixture(t *testing.T, failAt string) *deployTimeoutFixture {
	t.Helper()
	servicesYaml, err := testServicesFS.ReadFile("testdata/services.yml")
	if err != nil {
		t.Fatal(err)
	}
	return newDeployFixture(t, servicesYaml, failAt)
}

// newDeployTimeoutFixture for a services config of the test's own.
func newDeployFixture(t *testing.T, servicesYaml []byte, failAt string) *deployTimeoutFixture {
	t.Helper()
	f := &deployTimeoutFixture{}
	setupTestVault(t, servicesYaml)
	home := os.Getenv("WARP_HOME")
	settings, err := json.Marshal(map[string]string{
		"dockerNamespace": "fixture",
		"vaultHome":       filepath.Join(home, "vault"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, "warp.json"), settings, 0o600); err != nil {
		t.Fatal(err)
	}
	// Even an unexpected direct command cannot reach the host's Docker.
	t.Setenv("PATH", t.TempDir())

	record := func(event string) error {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.events = append(f.events, event)
		if event == failAt {
			return errors.New("fixture deployment failed")
		}
		return nil
	}
	selector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Amz-Target") == "DynamoDB_20120810.GetItem" {
			var read struct{ ConsistentRead bool }
			if err := json.NewDecoder(r.Body).Decode(&read); err != nil || !read.ConsistentRead {
				t.Errorf("selector read must be strongly consistent: %+v, %v", read, err)
			}
			w.Header().Set("Content-Type", "application/x-amz-json-1.0")
			io.WriteString(w, `{"Item":{"version":{"S":"1.0.0"}}}`)
			return
		}
		if r.Header.Get("X-Amz-Target") != "DynamoDB_20120810.PutItem" {
			t.Errorf("unexpected selector operation %q", r.Header.Get("X-Amz-Target"))
			http.Error(w, "unexpected operation", http.StatusBadRequest)
			return
		}
		var request struct {
			TableName string
			Item      map[string]struct{ S string }
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Error(err)
			return
		}
		if request.TableName != "deployment-blocks" {
			t.Errorf("unexpected table %q", request.TableName)
		}
		w.Header().Set("Content-Type", "application/x-amz-json-1.0")
		event := fmt.Sprintf("version:%s=%s", request.Item["env-service-block"].S, request.Item["version"].S)
		if err := record(event); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			io.WriteString(w, `{"__type":"ValidationException","message":"fixture deployment failed"}`)
			return
		}
		io.WriteString(w, "{}")
	}))
	t.Cleanup(selector.Close)
	useLoopbackDynamo(t, home, selector.URL)

	oldRun := runAndLogFunc
	oldBlocks, oldService := deployPollBlockStatusUntil, deployPollServiceStatusUntil
	oldOut, oldErr := Out.Writer(), Err.Writer()
	t.Cleanup(func() {
		runAndLogFunc = oldRun
		deployPollBlockStatusUntil, deployPollServiceStatusUntil = oldBlocks, oldService
		Out.SetOutput(oldOut)
		Err.SetOutput(oldErr)
	})
	Out.SetOutput(&f.output)
	Err.SetOutput(io.Discard)
	runAndLogFunc = func(cmd *exec.Cmd) error {
		args := cmd.Args
		if filepath.Base(args[0]) == "sudo" {
			args = args[1:]
		}
		if len(args) == 5 && filepath.Base(args[0]) == "docker" && slices.Equal(args[1:4], []string{"buildx", "imagetools", "inspect"}) && cmd.Dir == home {
			return nil // read-only image verification, not a promotion event
		}
		if len(args) != 7 || filepath.Base(args[0]) != "docker" ||
			!slices.Equal(args[1:5], []string{"buildx", "imagetools", "create", "-t"}) || cmd.Dir != home {
			return fmt.Errorf("unexpected fixture command %v", args)
		}
		return record(fmt.Sprintf("tag:%s<-%s", args[5], args[6]))
	}
	deployPollBlockStatusUntil = func(env, service string, blocks []string, version string, timeout time.Duration) {
		if err := record(fmt.Sprintf("blocks:%s/%s/%s=%s timeout=%s", env, service, strings.Join(blocks, ","), version, timeout)); err != nil {
			panic(err)
		}
	}
	deployPollServiceStatusUntil = func(env, service, version string, timeout time.Duration) {
		if err := record(fmt.Sprintf("service:%s/%s=%s timeout=%s", env, service, version, timeout)); err != nil {
			panic(err)
		}
	}
	return f
}

func (f *deployTimeoutFixture) deploy(service string, options ...string) (failure any) {
	oldArgs := os.Args
	defer func() {
		os.Args = oldArgs
		failure = recover()
	}()
	os.Args = append([]string{"warpctl", "deploy", "test", service, "2.0.0"}, options...)
	main()
	return nil
}

func (f *deployTimeoutFixture) assertEvents(t *testing.T, want []string) {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if !slices.Equal(f.events, want) {
		t.Fatalf("deployment events = %v, want %v", f.events, want)
	}
}

// Sends the AWS SDK's DynamoDB calls to a loopback server with fixture
// credentials, so no test reaches AWS or reads the caller's AWS config.
func useLoopbackDynamo(t *testing.T, home string, url string) {
	t.Helper()
	awsEmpty := filepath.Join(home, "aws-empty")
	if err := os.WriteFile(awsEmpty, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	for key, value := range map[string]string{
		"AWS_ACCESS_KEY_ID": "fixture", "AWS_SECRET_ACCESS_KEY": "fixture", "AWS_SESSION_TOKEN": "",
		"AWS_PROFILE": "", "AWS_SHARED_CREDENTIALS_FILE": awsEmpty, "AWS_CONFIG_FILE": awsEmpty,
		"AWS_EC2_METADATA_DISABLED": "true", "AWS_ENDPOINT_URL_DYNAMODB": url,
		"AWS_IGNORE_CONFIGURED_ENDPOINT_URLS": "", "AWS_MAX_ATTEMPTS": "1",
	} {
		t.Setenv(key, value)
	}
}

func deployPromotionEvents(blocks []string) []string {
	var events []string
	for _, block := range blocks {
		events = append(events,
			fmt.Sprintf("tag:fixture/test-svc-a:%s-latest<-fixture/test-svc-a:2.0.0", block),
			fmt.Sprintf("version:test-svc-a-%s=2.0.0", block),
		)
	}
	return append(events, "tag:fixture/test-svc-a:latest<-fixture/test-svc-a:2.0.0")
}

func TestDeployTimeoutControlsOnlyConvergencePolling(t *testing.T) {
	for _, test := range []struct {
		name, timeout string
		percent       int
		wantTimeout   time.Duration
	}{
		{"default", "", 100, 120 * time.Second},
		{"positive", "150ms", 100, 150 * time.Millisecond},
		{"negative_unlimited", "-1s", 100, -time.Second},
		{"zero", "0", 100, 0},
		{"zero_duration", "0s", 100, 0},
		{"positive_partial", "1s", 50, time.Second},
		{"zero_partial", "0", 50, 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newDeployTimeoutFixture(t, "")
			options := []string{fmt.Sprintf("--percent=%d", test.percent), "--set-latest"}
			if test.timeout != "" {
				options = append(options, "--timeout", test.timeout)
			}
			if failure := f.deploy("svc-a", options...); failure != nil {
				t.Fatalf("deployment failed: %v", failure)
			}
			blocks := []string{"beta", "g1"}
			if test.percent == 50 {
				blocks = blocks[:1]
			}
			want := deployPromotionEvents(blocks)
			if test.wantTimeout != 0 {
				want = append(want, fmt.Sprintf("blocks:test/svc-a/%s=2.0.0 timeout=%s", strings.Join(blocks, ","), test.wantTimeout))
				if test.percent == 100 {
					want = append(want, fmt.Sprintf("service:test/svc-a=2.0.0 timeout=%s", test.wantTimeout))
				}
			}
			f.assertEvents(t, want)
			if skipped := strings.Contains(f.output.String(), "skipping convergence polling"); skipped != (test.wantTimeout == 0) {
				t.Fatalf("skip diagnostic = %t, timeout = %s; output=%q", skipped, test.wantTimeout, f.output.String())
			}
		})
	}
}

func TestDeployZeroTimeoutPreservesEveryPromotionFailure(t *testing.T) {
	promotions := deployPromotionEvents([]string{"beta", "g1"})
	for i, failedPromotion := range promotions {
		t.Run(fmt.Sprintf("step_%d", i), func(t *testing.T) {
			f := newDeployTimeoutFixture(t, failedPromotion)
			failure := f.deploy("svc-a", "--percent=100", "--set-latest", "--timeout=0")
			if failure == nil || !strings.Contains(fmt.Sprint(failure), "fixture deployment failed") {
				t.Fatalf("deployment failure = %v, want fixture failure", failure)
			}
			f.assertEvents(t, promotions[:i+1])
			if strings.Contains(f.output.String(), "Version promoted") {
				t.Fatal("failed promotion reported success")
			}
		})
	}
}

func TestDeployZeroTimeoutStillChecksOnlyOlder(t *testing.T) {
	f := newDeployTimeoutFixture(t, "")
	failure := f.deploy("lb", "--percent=100", "--only-older", "--timeout=0")
	if failure == nil || !strings.Contains(fmt.Sprint(failure), "--only-older cannot verify running versions") {
		t.Fatalf("unobservable only-older failure = %v", failure)
	}
	f.assertEvents(t, nil)
}

func TestDeployInvalidTimeoutFailsBeforePromotion(t *testing.T) {
	for _, timeout := range []string{"bad", "120"} {
		t.Run(timeout, func(t *testing.T) {
			f := newDeployTimeoutFixture(t, "")
			if failure := f.deploy("svc-a", "--percent=100", "--timeout", timeout); failure != "Bad timeout." {
				t.Fatalf("invalid timeout failure = %v", failure)
			}
			f.assertEvents(t, nil)
		})
	}
}

func TestDeployNonzeroTimeoutPreservesPollingFailure(t *testing.T) {
	want := append(deployPromotionEvents([]string{"beta", "g1"}),
		"blocks:test/svc-a/beta,g1=2.0.0 timeout=1s",
		"service:test/svc-a=2.0.0 timeout=1s",
	)
	for i := len(want) - 2; i < len(want); i++ {
		t.Run(fmt.Sprintf("step_%d", i), func(t *testing.T) {
			f := newDeployTimeoutFixture(t, want[i])
			failure := f.deploy("svc-a", "--percent=100", "--set-latest", "--timeout=1s")
			if failure == nil || !strings.Contains(fmt.Sprint(failure), "fixture deployment failed") {
				t.Fatalf("poll failure = %v, want fixture failure", failure)
			}
			f.assertEvents(t, want[:i+1])
		})
	}
}
