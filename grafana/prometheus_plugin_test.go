package main

import (
	"os"
	"strings"
	"testing"
)

// Grafana 13.2 moved Prometheus from the core binary to a standalone plugin.
// The generated grafana.ini deliberately disables runtime preinstallation, so
// the image must carry a checksum-pinned native plugin for every architecture
// the multi-platform build supports. A datasource row alone is insufficient:
// without these files /api/ds/query returns plugin.notRegistered.
func TestPrometheusPluginIsBakedForGrafana13(t *testing.T) {
	dockerfileBytes, err := os.ReadFile("Dockerfile")
	if err != nil {
		t.Fatal(err)
	}
	dockerfile := string(dockerfileBytes)
	for _, required := range []string{
		"ARG grafana_version=13.2.0",
		"ARG prometheus_plugin_version=13.1.7",
		"prometheus_plugin_sha256_amd64=31b0e919ae51db0fdb91ffb2ba0991f358bbd5e02fac676b6ffad56cc223d57c",
		"prometheus_plugin_sha256_arm64=c2a29c56683d31d4dfaf71907a60ed47f4f378990ff381be99549fa3c2639010",
		"download?os=linux&arch=${TARGETARCH}",
		"unzip -q /tmp/prometheus.zip -d /var/lib/grafana/plugins",
	} {
		if !strings.Contains(dockerfile, required) {
			t.Errorf("Dockerfile does not pin the Grafana 13 Prometheus plugin component %q", required)
		}
	}

	mainBytes, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(mainBytes), "preinstall_disabled = true") {
		t.Fatal("runtime plugin downloads are enabled; the checksum-pinned image invariant is not enforced")
	}
}
