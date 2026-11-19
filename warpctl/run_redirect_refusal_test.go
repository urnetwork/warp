package main

// Tests of a deploy whose redirect is refused after the cutover's commit:
// another chain claims one of the candidate's ports between the deploy's
// ownership check and the redirect's own (deployContainerOverlap).

import (
	"errors"
	"os/exec"
	"slices"
	"strings"
	"testing"
)

// Makes the redirect's own ownership check, the deploy's second full nat
// listing, list another block's chain holding the candidate's external port
// 7000, as a chain written between the deploy's check and the redirect's
// would. Every other command goes to the PATH fixture, as sudo2 sends it.
func refuseLbAltFixtureRedirect(t *testing.T) {
	t.Helper()
	previousSudo2 := sudo2Func
	t.Cleanup(func() {
		sudo2Func = previousSudo2
	})
	ownershipListings := 0
	sudo2Func = func(name []string, args ...string) *exec.Cmd {
		if strings.Join(args, " ") == "-t nat -L -n" {
			ownershipListings += 1
			if ownershipListings == 2 {
				listing := strings.Join([]string{
					"Chain WARP-TEST-API-G1 (1 references)",
					"target     prot opt source               destination",
					"DNAT       tcp  --  0.0.0.0/0            0.0.0.0/0            tcp dpt:7000 to:127.0.0.1:7000",
				}, "\n")
				return exec.Command("/bin/sh", "-c", `printf '%s\n' "$1"`, "sh", listing)
			}
		}
		return exec.Command("sudo", append(slices.Clone(name), args...)...)
	}
}

// A block that binds no lb interface writes no lb_alt chain, and a refused
// redirect changes no rule, so after a refusal that follows the commit no rule
// points at the candidate: the deploy stops it, as a candidate that never
// took traffic, and leaves nothing pending, so Run's next poll deploys
// afresh. The candidate used to keep running with no owner, holding its pool
// ports, while Run started another.
func TestDeployStopsACandidateWhoseRedirectIsRefusedAfterTheCommit(t *testing.T) {
	f := newLbAltWorkerFixture(t)
	f.worker.lbAltInterfaces = nil
	refuseLbAltFixtureRedirect(t)
	stoppedIds := []string{}
	run := runAndLogFunc
	runAndLogFunc = func(cmd *exec.Cmd) error {
		if strings.Contains(strings.Join(cmd.Args, " "), "docker container stop ") {
			stoppedIds = append(stoppedIds, cmd.Args[len(cmd.Args)-1])
		}
		return run(cmd)
	}

	err := f.worker.deployContainerOverlap(true, nil)
	var retirementErr *deploymentRetirementError
	if err == nil || errors.As(err, &retirementErr) || !strings.Contains(err.Error(), "refusing redirect: port 7000 is still owned by WARP-TEST-API-G1") {
		t.Fatalf("deploy error = %v, want the redirect's refusal", err)
	}
	if want := []string{"start", "stop"}; !slices.Equal(f.events, want) {
		t.Fatalf("deploy events %v, want %v: the candidate stopped, and no cutover", f.events, want)
	}
	if !slices.Equal(stoppedIds, []string{lbAltFixtureContainerId}) {
		t.Fatalf("stopped %v, want the candidate alone", stoppedIds)
	}
	if f.worker.pendingDeployment != nil || f.worker.pendingCandidateCleanup != "" {
		t.Fatal("the refused candidate left a pending promotion or cleanup")
	}
}

// A block that binds lb interfaces has pointed its lb_alt chains at the
// candidate before the redirect, so the same refusal keeps the candidate as
// the deployed generation with its promotion pending, and stops nothing.
func TestDeployKeepsAnLbAltCandidateWhoseRedirectIsRefusedAfterTheCommit(t *testing.T) {
	f := newLbAltWorkerFixture(t)
	refuseLbAltFixtureRedirect(t)

	err := f.worker.deployContainerOverlap(true, nil)
	var retirementErr *deploymentRetirementError
	if !errors.As(err, &retirementErr) || !strings.Contains(err.Error(), "refusing redirect: port 7000 is still owned by WARP-TEST-API-G1") {
		t.Fatalf("deploy error = %v, want a promoted deploy with the redirect's refusal", err)
	}
	if want := []string{"render", "start", "readiness", "chains"}; !slices.Equal(f.events, want) {
		t.Fatalf("deploy events %v, want %v", f.events, want)
	}
	if f.worker.pendingDeployment == nil {
		t.Fatal("the committed candidate's promotion is not pending")
	}
}
