package main

import (
	"os"
	"strings"
	"testing"
)

// Grafana 13 registers Loki through a standalone native datasource plugin.
// Logs Drilldown does not provide datasource type "loki", and provisioning a
// warp-loki database row cannot compensate for a missing executable plugin.
// Runtime downloads are disabled, so both supported image architectures must
// carry the checksum-pinned catalog artifact.
func TestLokiDatasourcePluginIsBakedForGrafana13(t *testing.T) {
	dockerfileBytes, err := os.ReadFile("Dockerfile")
	if err != nil {
		t.Fatal(err)
	}
	dockerfile := string(dockerfileBytes)
	for _, required := range []string{
		"ARG grafana_version=13.2.0",
		"ARG loki_datasource_plugin_version=13.1.0",
		"loki_datasource_plugin_sha256_amd64=e09d6c6fbadb9e486c4e01f4adb8477a7064d02fa44ca80c639efa47334d731d",
		"loki_datasource_plugin_sha256_arm64=e2e8a300915cc08c8aca3e35090fd4e08d87e8ed524dbf7b93bd94c10b3cbaf8",
		`amd64) loki_datasource_plugin_sha256="$loki_datasource_plugin_sha256_amd64"`,
		`arm64) loki_datasource_plugin_sha256="$loki_datasource_plugin_sha256_arm64"`,
		"api/plugins/loki/versions/${loki_datasource_plugin_version}/download?os=linux&arch=${TARGETARCH}",
		`echo "${loki_datasource_plugin_sha256}  /tmp/loki-datasource.zip" | sha256sum --check -`,
		"unzip -q /tmp/loki-datasource.zip -d /var/lib/grafana/plugins",
	} {
		if !strings.Contains(dockerfile, required) {
			t.Errorf("Dockerfile does not pin the Grafana 13 Loki datasource plugin component %q", required)
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
