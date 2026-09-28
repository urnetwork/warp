// The existing deployment status reader must accept the miner's optional
// delivery extension while preserving its process-liveness interpretation.
package main

import (
	"encoding/json"
	"math"
	"net/http"
	"net/http/httptest"
	"testing"
)

// Exercise the actual current HTTP sampler and decoder, not a copied decoder.
// This does not teach the old reader to treat delivery as protocol readiness.
func TestMinerOptionalDiagnosticsPreservesStatusReader(t *testing.T) {
	for _, withDiagnostics := range []bool{false, true} {
		body := map[string]any{"version": "1.2.3", "status": "ok", "host": "synthetic-provider.example"}
		if withDiagnostics {
			delivery := map[string]any{"outcome": "unavailable", "delivered": uint64(0), "dropped": uint64(math.MaxUint64), "dropped_bytes": uint64(math.MaxUint64), "unavailable": uint64(math.MaxUint64)}
			body["diagnostics"] = map[string]any{"schema": "urnetwork-provider-diagnostics-v1", "authentication": delivery, "keys": delivery, "extender": delivery, "runtime": delivery}
		}
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(w).Encode(body); err != nil {
				t.Error(err)
			}
		}))
		status := sampleStatusVersions(1, []string{server.URL})
		server.Close()
		if len(status.errors) != 0 || len(status.versions) != 1 || len(status.configVersions) != 0 {
			t.Fatal("current status reader rejected the optional miner extension")
		}
		for version, count := range status.versions {
			if version.String() != "1.2.3" || count != 1 {
				t.Fatal("optional delivery changed the existing process-status sample")
			}
		}
	}
}
