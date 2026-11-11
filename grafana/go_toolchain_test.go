package main

import (
	"go/version"
	"os"
	"regexp"
	"testing"
)

// The nested Loki build has its own compiler. Updating Warp's module alone
// must not leave that executable on an older Go release.
func lokiCompilerSupportsModule(module, dockerfile []byte) bool {
	moduleGo := regexp.MustCompile(`(?m)^go ([0-9]+\.[0-9]+\.[0-9]+)$`).FindSubmatch(module)
	compilerGo := regexp.MustCompile(`(?m)^ARG loki_go_version=([0-9]+\.[0-9]+\.[0-9]+)$`).FindSubmatch(dockerfile)
	if len(moduleGo) != 2 || len(compilerGo) != 2 {
		return false
	}
	required, actual := "go"+string(moduleGo[1]), "go"+string(compilerGo[1])
	toolchain := regexp.MustCompile(`(?m)^toolchain (go[0-9]+\.[0-9]+\.[0-9]+)$`).FindSubmatch(module)
	if len(toolchain) == 2 && version.Compare(string(toolchain[1]), required) > 0 {
		required = string(toolchain[1])
	}
	return version.IsValid(actual) && version.IsValid(required) && version.Compare(actual, required) >= 0
}

func TestLokiCompilerSupportsCurrentModule(t *testing.T) {
	module := []byte("module example.test/warp\n\ngo 1.27.4\n")
	for _, fixture := range []struct {
		name, compiler string
		want           bool
	}{
		{"previous_minor", "1.26.4", false},
		{"previous_patch", "1.27.3", false},
		{"current_patch", "1.27.4", true},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			if got := lokiCompilerSupportsModule(module, []byte("ARG loki_go_version="+fixture.compiler+"\n")); got != fixture.want {
				t.Fatalf("compiler compatibility = %t, want %t", got, fixture.want)
			}
		})
	}
	if lokiCompilerSupportsModule(append(module, []byte("toolchain go1.27.5\n")...), []byte("ARG loki_go_version=1.27.4\n")) {
		t.Fatal("explicit newer toolchain was ignored")
	}
	workingModule, err := os.ReadFile("../go.mod")
	if err != nil {
		t.Fatal(err)
	}
	dockerfile, err := os.ReadFile("Dockerfile")
	if err != nil || !lokiCompilerSupportsModule(workingModule, dockerfile) {
		t.Fatalf("Loki compiler is older than Warp's module requirement: %v", err)
	}
}
