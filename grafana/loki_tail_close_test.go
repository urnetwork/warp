package main

import (
	"os"
	"strings"
	"testing"
)

// Loki 3.7.3's internal tail timeout closes a Tailer before TailHandler runs
// its deferred close. The image must compile the pinned source with an
// idempotent close and run the regression against that exact source; resetting
// or clamping the exposed gauge would leave the lifecycle defect intact.
func TestGrafanaImageBuildsPatchedLokiTailClose(t *testing.T) {
	dockerfileBytes, err := os.ReadFile("Dockerfile")
	if err != nil {
		t.Fatal(err)
	}
	dockerfile := string(dockerfileBytes)
	for _, required := range []string{
		"ARG loki_go_version=1.26.4",
		"ARG loki_version=3.7.3",
		"loki_source_sha256=1f74768fc476978796b49455fd962587a6b0e3b75212215ed8449f792aa5c776",
		"COPY loki-tailer-close.patch /tmp/loki-tailer-close.patch",
		"patch --batch --forward -p1",
		"go test ./pkg/querier/tail -run '^TestTailerCloseIsIdempotent$' -count=1",
		"github.com/grafana/loki/v3/pkg/util/build.Version=${loki_version}-urnetwork.1",
		"COPY --from=loki-build /out/loki /usr/local/sbin/loki",
	} {
		if !strings.Contains(dockerfile, required) {
			t.Errorf("Dockerfile omits patched Loki invariant %q", required)
		}
	}
	if strings.Contains(dockerfile, "loki-linux-${TARGETARCH}.zip") {
		t.Fatal("Grafana image still installs the unpatched Loki release binary")
	}

	patchBytes, err := os.ReadFile("loki-tailer-close.patch")
	if err != nil {
		t.Fatal(err)
	}
	patch := string(patchBytes)
	for _, required := range []string{
		"closeOnce         sync.Once",
		"t.closeOnce.Do(func()",
		"t.closeErr = t.openStreamIterator.Close()",
		"func TestTailerCloseIsIdempotent",
		"prometheus_testutil.ToFloat64(metrics.tailsActive)",
		"prometheus_testutil.ToFloat64(metrics.tailedStreamsActive)",
	} {
		if !strings.Contains(patch, required) {
			t.Errorf("Loki patch omits close invariant %q", required)
		}
	}
}
