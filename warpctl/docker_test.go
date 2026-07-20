package main

import (
	"testing"
)

// the deploy poll (`pollBasicContainerStatus`) fails a status IsError deems an
// error, which times the deploy out and reverts it. The server repo's status
// latch (router/warp_handlers.go) emits "error not ready: ..." on a failed
// readiness check and "draining"/"ok" otherwise; both sides are pinned here.
func TestWarpStatusResponseIsError(t *testing.T) {
	isError := func(status string) bool {
		response := &WarpStatusResponse{
			Status: status,
		}
		return response.IsError()
	}

	// healthy and informational statuses pass the poll
	for _, status := range []string{
		"ok",
		"draining",
		"",
		// no word boundary: not the word "error"
		"erroneous",
	} {
		if isError(status) {
			t.Fatalf("status %q must pass the deploy poll", status)
		}
	}

	// error statuses fail the poll, in both separator forms and any case
	for _, status := range []string{
		"error not ready: pg: connection refused",
		"error: draining",
		"error: pg down",
		"error timeout",
		"Error not ready: redis: connection refused",
		"ERROR: nope",
	} {
		if !isError(status) {
			t.Fatalf("status %q must fail the deploy poll", status)
		}
	}
}
