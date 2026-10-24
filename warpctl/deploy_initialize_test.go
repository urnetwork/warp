package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/coreos/go-semver/semver"
	"github.com/urnetwork/warp/warpctl/dynamo"
)

type deploymentWireItem map[string]map[string]string

func initializationItem(version, initialized string) deploymentWireItem {
	item := deploymentWireItem{"version": {"S": version}}
	if initialized != "" {
		item["initialized-version"] = map[string]string{"S": initialized}
	}
	return item
}

type initializationFixture struct {
	*deployTimeoutFixture
	service       string
	mu            sync.Mutex
	items         map[string]deploymentWireItem
	failAt        string
	beforeInspect func()
	observed      string
}

// The real CLI and DynamoDB SDK run against a stateful loopback selector that
// enforces create-if-absent. Only immutable image inspection, Docker tagging,
// and status sampling are replaced; no production endpoint is contacted.
func newInitializationFixture(t *testing.T) *initializationFixture {
	t.Helper()
	f := &initializationFixture{
		deployTimeoutFixture: newDeployTimeoutFixture(t, ""),
		service:              "svc-a",
		items:                map[string]deploymentWireItem{},
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request struct {
			TableName                string
			Key, Item                deploymentWireItem
			ConsistentRead           bool
			ConditionExpression      string
			ExpressionAttributeNames map[string]string
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Error(err)
			return
		}
		if request.TableName != "deployment-blocks" {
			t.Errorf("unexpected table %q", request.TableName)
		}
		w.Header().Set("Content-Type", "application/x-amz-json-1.0")
		fail := func(kind string) {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"__type": kind, "message": "fixture selector failure"})
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		switch r.Header.Get("X-Amz-Target") {
		case "DynamoDB_20120810.GetItem":
			if !request.ConsistentRead {
				t.Error("initialization used an eventually consistent read")
			}
			block := strings.TrimPrefix(request.Key["env-service-block"]["S"], "test-"+f.service+"-")
			event := "read:" + block
			f.record(event)
			if f.failAt == event {
				fail("AccessDeniedException")
				return
			}
			if item, exists := f.items[block]; exists {
				json.NewEncoder(w).Encode(map[string]any{"Item": item})
			} else {
				io.WriteString(w, "{}")
			}
		case "DynamoDB_20120810.PutItem":
			block := strings.TrimPrefix(request.Item["env-service-block"]["S"], "test-"+f.service+"-")
			if request.ConditionExpression != "" {
				if request.ConditionExpression != "attribute_not_exists(#key)" || request.ExpressionAttributeNames["#key"] != "env-service-block" {
					t.Error("initialization does not condition on the whole record being absent")
				}
				if request.Item["version"]["S"] == "" || request.Item["initialized-version"]["S"] != request.Item["version"]["S"] {
					t.Error("initialization did not mark its exact target version")
				}
				event := "initialize:" + block
				f.record(event)
				if _, exists := f.items[block]; exists {
					fail("ConditionalCheckFailedException")
					return
				}
				if f.failAt == event {
					fail("AccessDeniedException")
					return
				}
				f.items[block] = request.Item
				if f.failAt == "lost-response:"+block {
					w.WriteHeader(http.StatusInternalServerError)
					io.WriteString(w, `{"__type":"InternalServerError","message":"fixture lost committed response"}`)
					return
				}
			} else {
				f.record("version:" + block)
				f.items[block] = request.Item
			}
			io.WriteString(w, "{}")
		default:
			t.Error("unexpected selector operation")
			fail("ValidationException")
		}
	}))
	t.Cleanup(server.Close)
	t.Setenv("AWS_ENDPOINT_URL_DYNAMODB", server.URL)

	previousRun := runAndLogFunc
	runAndLogFunc = func(cmd *exec.Cmd) error {
		args := cmd.Args
		if args[0] == "sudo" {
			args = args[1:]
		}
		if len(args) == 5 && slices.Equal(args[1:4], []string{"buildx", "imagetools", "inspect"}) && args[4] == "fixture/test-"+f.service+":2.0.0" {
			f.record("inspect")
			if f.beforeInspect != nil {
				f.beforeInspect()
			}
			if f.failAt == "inspect" {
				return errors.New("fixture image unavailable")
			}
			return nil
		}
		return previousRun(cmd)
	}
	previousSample := deploySampleBlockCurrentVersions
	t.Cleanup(func() { deploySampleBlockCurrentVersions = previousSample })
	deploySampleBlockCurrentVersions = func(_, _ string, blocks ...string) (map[string]map[semver.Version]float32, error) {
		f.record("sample:" + strings.Join(blocks, ","))
		if f.observed == "" {
			return nil, errors.New("fixture HTTP 404 status route")
		}
		result := map[string]map[semver.Version]float32{}
		for _, block := range blocks {
			result[block] = map[semver.Version]float32{*semver.New(f.observed): 100}
		}
		return result, nil
	}
	return f
}

func (f *initializationFixture) record(event string) {
	f.deployTimeoutFixture.mu.Lock()
	defer f.deployTimeoutFixture.mu.Unlock()
	f.events = append(f.events, event)
}

func (f *initializationFixture) run(percent int) any {
	return f.deploy("svc-a", fmt.Sprintf("--percent=%d", percent), "--only-older", "--initialize-unset", "--timeout=0")
}

func (f *initializationFixture) assertItem(t *testing.T, block, version, marker string) {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	item := f.items[block]
	if item["version"]["S"] != version || item["initialized-version"]["S"] != marker {
		t.Fatalf("block %s has unexpected selector or initialization marker: %v", block, item)
	}
}

func TestInitializeUnsetCumulativeWaves(t *testing.T) {
	f := newInitializationFixture(t)
	for _, percent := range []int{25, 50, 75, 100} {
		if failure := f.run(percent); failure != nil {
			t.Fatalf("wave %d failed: %v", percent, failure)
		}
	}
	f.assertEvents(t, []string{
		"read:beta", "inspect", "initialize:beta",
		"read:beta",
		"read:beta", "read:g1", "inspect", "initialize:g1",
		"read:beta", "read:g1",
	})
	f.assertItem(t, "beta", "2.0.0", "2.0.0")
	f.assertItem(t, "g1", "2.0.0", "2.0.0")
}

func TestInitializeUnsetRequiresExplicitCompatibleOptions(t *testing.T) {
	for _, options := range [][]string{
		{"--percent=25", "--initialize-unset"},
		{"--percent=25", "--initialize-unset", "--only-older", "--set-latest"},
	} {
		f := newInitializationFixture(t)
		if failure := f.deploy("svc-a", options...); failure == nil || !strings.Contains(fmt.Sprint(failure), "requires --only-older") {
			t.Fatalf("incompatible option failure = %v", failure)
		}
		f.assertEvents(t, nil)
	}
	t.Run("ordinary_only_older_still_rejects_missing_status", func(t *testing.T) {
		f := newInitializationFixture(t)
		f.items["beta"] = initializationItem("1.0.0", "")
		if failure := f.deploy("svc-a", "--percent=25", "--only-older", "--timeout=0"); failure == nil {
			t.Fatal("ordinary only-older initialized a block")
		}
		f.assertEvents(t, []string{"read:beta", "sample:beta"})
	})
}

func TestInitializeUnsetFailuresDoNotBecomeAbsence(t *testing.T) {
	for _, test := range []struct {
		fail string
		want []string
	}{
		{"read:beta", []string{"read:beta"}},
		{"read:g1", []string{"read:beta", "read:g1"}},
		{"inspect", []string{"read:beta", "read:g1", "inspect"}},
		{"initialize:beta", []string{"read:beta", "read:g1", "inspect", "initialize:beta"}},
	} {
		t.Run(test.fail, func(t *testing.T) {
			f := newInitializationFixture(t)
			f.failAt = test.fail
			if failure := f.run(100); failure == nil {
				t.Fatal("failed boundary was accepted")
			}
			f.assertEvents(t, test.want)
			f.assertItem(t, "beta", "", "")
			f.assertItem(t, "g1", "", "")
		})
	}
}

func TestInitializeUnsetRejectsMalformedExistingRecords(t *testing.T) {
	for name, item := range map[string]deploymentWireItem{
		"empty_record":    {},
		"missing_version": {"env-service-block": {"S": "test-svc-a-beta"}},
		"empty_version":   initializationItem("", ""),
		"number_version":  {"version": {"N": "2"}},
		"bad_semver":      initializationItem("invalid", ""),
		"marker_mismatch": initializationItem("3.0.0", "2.0.0"),
		"empty_marker":    {"version": {"S": "2.0.0"}, "initialized-version": {"S": ""}},
		"number_marker":   {"version": {"S": "2.0.0"}, "initialized-version": {"N": "2"}},
	} {
		t.Run(name, func(t *testing.T) {
			f := newInitializationFixture(t)
			f.items["beta"] = item
			if failure := f.run(100); failure == nil {
				t.Fatal("invalid existing record was accepted as absent")
			}
			f.assertEvents(t, []string{"read:beta"})
		})
	}
}

func TestInitializeUnsetDoesNotReplaceConcurrentSelector(t *testing.T) {
	for _, version := range []string{"1.0.0", "2.0.0", "3.0.0"} {
		t.Run(version, func(t *testing.T) {
			f := newInitializationFixture(t)
			f.beforeInspect = func() {
				f.mu.Lock()
				defer f.mu.Unlock()
				f.items["beta"] = initializationItem(version, "")
			}
			if failure := f.run(25); failure == nil || !strings.Contains(fmt.Sprint(failure), "ConditionalCheckFailedException") {
				t.Fatalf("competing selector was not protected: %v", failure)
			}
			f.assertEvents(t, []string{"read:beta", "inspect", "initialize:beta"})
			f.assertItem(t, "beta", version, "")
		})
	}
}

func TestInitializeUnsetPartialFailureDoesNotRollbackOtherWriters(t *testing.T) {
	f := newInitializationFixture(t)
	f.beforeInspect = func() {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.items["g1"] = initializationItem("3.0.0", "")
	}
	if failure := f.run(100); failure == nil {
		t.Fatal("partial initialization conflict was reported successful")
	}
	f.assertEvents(t, []string{"read:beta", "read:g1", "inspect", "initialize:beta", "initialize:g1"})
	f.assertItem(t, "beta", "2.0.0", "2.0.0")
	f.assertItem(t, "g1", "3.0.0", "")
}

func TestInitializeUnsetLostResponseResumesExactVersion(t *testing.T) {
	f := newInitializationFixture(t)
	f.failAt = "lost-response:beta"
	if failure := f.run(25); failure == nil {
		t.Fatal("uncertain write was reported successful")
	}
	f.assertItem(t, "beta", "2.0.0", "2.0.0")
	if failure := f.run(25); failure != nil {
		t.Fatalf("same-version retry failed: %v", failure)
	}
	f.assertEvents(t, []string{"read:beta", "inspect", "initialize:beta", "read:beta"})
}

func TestInitializeUnsetKeepsExistingLiveVersionGuard(t *testing.T) {
	for _, test := range []struct{ version, marker string }{
		{"1.0.0", ""}, {"2.0.0", ""}, {"3.0.0", ""},
		{"1.0.0", "1.0.0"}, {"3.0.0", "3.0.0"},
	} {
		t.Run(test.version+"_"+test.marker, func(t *testing.T) {
			f := newInitializationFixture(t)
			f.items["g1"] = initializationItem(test.version, test.marker)
			if failure := f.run(100); failure == nil || !strings.Contains(fmt.Sprint(failure), "HTTP 404") {
				t.Fatalf("existing record bypassed live verification: %v", failure)
			}
			f.assertEvents(t, []string{"read:beta", "read:g1", "sample:g1"})
			f.assertItem(t, "beta", "", "")
			f.assertItem(t, "g1", test.version, test.marker)
		})
	}
}

func TestInitializeUnsetOrdinaryPromotionRemovesMarker(t *testing.T) {
	f := newInitializationFixture(t)
	f.items["beta"] = initializationItem("1.0.0", "1.0.0")
	f.observed = "1.0.0"
	if failure := f.run(25); failure != nil {
		t.Fatalf("ordinary promotion failed: %v", failure)
	}
	f.assertEvents(t, []string{"read:beta", "sample:beta", "inspect", "tag:fixture/test-svc-a:beta-latest<-fixture/test-svc-a:2.0.0", "version:beta"})
	f.assertItem(t, "beta", "2.0.0", "")
}

func TestInitializationRequestsHonorCancellation(t *testing.T) {
	f := newInitializationFixture(t)
	client, err := dynamo.NewClient()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := client.GetDeploymentRecordConsistent(ctx, "test", "svc-a", "beta"); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled selector read = %v", err)
	}
	if err := client.InitializeVersion(ctx, "test", "svc-a", "beta", "2.0.0"); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled selector initialization = %v", err)
	}
	f.assertEvents(t, nil)
}

func TestInitializeVersionConcurrentCreatorsHaveOneWinner(t *testing.T) {
	f := newInitializationFixture(t)
	client, err := dynamo.NewClient()
	if err != nil {
		t.Fatal(err)
	}
	type result struct {
		version string
		err     error
	}
	start := make(chan struct{})
	results := make(chan result, 2)
	for _, version := range []string{"2.0.0", "3.0.0"} {
		go func() {
			<-start
			results <- result{version, client.InitializeVersion(context.Background(), "test", "svc-a", "beta", version)}
		}()
	}
	close(start)
	winner := ""
	failures := 0
	for range 2 {
		result := <-results
		if result.err == nil {
			if winner != "" {
				t.Fatal("two initializers replaced the same selector")
			}
			winner = result.version
		} else if strings.Contains(result.err.Error(), "ConditionalCheckFailedException") {
			failures++
		} else {
			t.Fatalf("unexpected concurrent creation failure: %v", result.err)
		}
	}
	if winner == "" || failures != 1 {
		t.Fatalf("winner=%q conditional failures=%d, want one of each", winner, failures)
	}
	f.assertItem(t, "beta", winner, winner)
	f.assertEvents(t, []string{"initialize:beta", "initialize:beta"})
}

// A renamed load-balancer interface is a new block with no selector. The
// load balancer's status cannot be sampled, but a block without a selector
// runs nothing to sample, so initialization proceeds for it.
func TestInitializeUnsetBootstrapsLoadBalancerBlocksWithoutSelectors(t *testing.T) {
	f := newInitializationFixture(t)
	f.service = "lb"
	blocks := []string{"edge-0.example.com-eth0", "edge-0.example.com-eth1"}
	if failure := f.deploy("lb", append(blocks, "--only-older", "--initialize-unset", "--timeout=0")...); failure != nil {
		t.Fatalf("load-balancer bootstrap failed: %v", failure)
	}
	for _, block := range blocks {
		f.assertItem(t, block, "2.0.0", "2.0.0")
	}
}

// A load-balancer block that already has a selector still needs its running
// version verified, which the load balancer cannot provide: the deployment is
// refused before any selector is written.
func TestInitializeUnsetRefusesLoadBalancerBlockWithSelector(t *testing.T) {
	f := newInitializationFixture(t)
	f.service = "lb"
	f.items["edge-0.example.com-eth0"] = initializationItem("1.0.0", "")
	failure := f.deploy("lb", "edge-0.example.com-eth0", "edge-0.example.com-eth1", "--only-older", "--initialize-unset", "--timeout=0")
	if failure == nil || !strings.Contains(fmt.Sprint(failure), "load-balancer block status sampling is not supported") {
		t.Fatalf("existing load-balancer selector bypassed live verification: %v", failure)
	}
	f.assertItem(t, "edge-0.example.com-eth0", "1.0.0", "")
	f.assertItem(t, "edge-0.example.com-eth1", "", "")
}
