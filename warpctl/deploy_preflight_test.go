package main

import (
	"errors"
	"fmt"
	"os/exec"
	"slices"
	"strings"
	"testing"
)

// These use the real docopt/main/deploy path and real AWS SDK against the
// existing strongly-consistent loopback fixture, never an AWS endpoint.
func TestDeployPreflightSharesGuardsAndPerformsNoMutations(t *testing.T) {
	for _, future := range []bool{false, true} {
		t.Run(fmt.Sprintf("future=%t", future), func(t *testing.T) {
			f := newInitializationFixture(t)
			f.items["beta"] = initializationItem("1.0.0", "")
			f.items["g1"] = initializationItem("1.0.0", "")
			f.observed = "1.0.0"
			previous := runAndLogFunc
			runAndLogFunc = func(cmd *exec.Cmd) error {
				// docker() runs "sudo docker ..." on Linux and "docker ..." elsewhere.
				args := cmd.Args
				if args[0] == "sudo" {
					args = args[1:]
				}
				if len(args) == 5 && slices.Equal(args[1:4], []string{"buildx", "imagetools", "inspect"}) {
					f.record("image:" + args[4])
					return nil
				}
				return previous(cmd)
			}
			options := []string{"--preflight", "--only-older", "--percent=100"}
			if future {
				options = append(options, "--allow-missing-image")
			}
			if failure := f.deploy("svc-a", options...); failure != nil {
				t.Fatal(failure)
			}
			for _, event := range f.events {
				if !strings.HasPrefix(event, "read:") && !strings.HasPrefix(event, "sample:") && !strings.HasPrefix(event, "image:") {
					t.Fatalf("preflight mutated or polled rollout: %s", event)
				}
			}
			image := "image:fixture/test-svc-a:2.0.0"
			if future {
				image = "image:fixture/test-svc-a:1.0.0"
			}
			if !slices.Contains(f.events, image) {
				t.Fatalf("missing correct registry authorization/existence read: %v", f.events)
			}
			f.assertItem(t, "beta", "1.0.0", "")
			f.assertItem(t, "g1", "1.0.0", "")
			if !strings.Contains(f.output.String(), "No mutations performed") {
				t.Fatal("missing read-only completion diagnostic")
			}
		})
	}
}

func TestDeployPreflightFailsClosedForSelectorRoutingAndImageErrors(t *testing.T) {
	for _, failure := range []string{"selector missing", "selector malformed", "selector denied", "status unavailable", "current image denied", "future image missing", "unknown service"} {
		t.Run(failure, func(t *testing.T) {
			f := newInitializationFixture(t)
			f.items["beta"] = initializationItem("1.0.0", "")
			f.observed = "1.0.0"
			options := []string{"--preflight", "--only-older", "--percent=25"}
			service := "svc-a"
			switch failure {
			case "selector missing":
				delete(f.items, "beta")
			case "selector malformed":
				f.items["beta"] = initializationItem("invalid", "")
			case "selector denied":
				f.failAt = "read:beta"
			case "status unavailable":
				f.observed = ""
			case "current image denied":
				options = append(options, "--allow-missing-image")
				runAndLogFunc = func(*exec.Cmd) error { return errors.New("synthetic registry authorization denied") }
			case "future image missing":
				f.failAt = "inspect"
			case "unknown service":
				service = "absent"
			}
			if result := f.deploy(service, options...); result == nil {
				t.Fatal("preflight accepted known deployment blocker")
			}
			for _, event := range f.events {
				if strings.HasPrefix(event, "initialize:") || strings.HasPrefix(event, "version:") || strings.HasPrefix(event, "tag:") || strings.HasPrefix(event, "blocks:") || strings.HasPrefix(event, "service:") {
					t.Fatalf("failed preflight mutated: %s", event)
				}
			}
		})
	}
}

func TestDeployFutureImageEscapeRequiresPreflightAndBootstrapIsReadOnly(t *testing.T) {
	f := newInitializationFixture(t)
	if result := f.deploy("svc-a", "--allow-missing-image", "--percent=25"); result == nil || !strings.Contains(fmt.Sprint(result), "requires --preflight") {
		t.Fatalf("normal deploy accepted missing-image escape: %v", result)
	}
	f.assertEvents(t, nil)
	if result := f.deploy("svc-a", "--preflight", "--allow-missing-image", "--only-older", "--initialize-unset", "--percent=25"); result != nil {
		t.Fatal(result)
	}
	if len(f.items) != 0 {
		t.Fatal("bootstrap preflight initialized a selector")
	}
	for _, event := range f.events {
		if event != "read:beta" {
			t.Fatalf("bootstrap preflight performed non-read: %s", event)
		}
	}
}
