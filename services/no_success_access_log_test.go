package services

import (
	"fmt"
	"slices"
	"strings"
	"testing"
)

// a services document whose api lists the given no_success_access_log entries
func noSuccessAccessLogServicesYaml(entries string) string {
	return fmt.Sprintf(`
versions:
-   services:
        api:
            no_success_access_log:
%s            ports:
                - 80
            blocks:
                - g1: 1
`, entries)
}

// The api's busiest routes are parsed as listed, as exact paths.
func TestLoadServicesConfigParsesNoSuccessAccessLog(t *testing.T) {
	servicesConfig, err := loadInlineServicesConfig(t, noSuccessAccessLogServicesYaml(`
                - /connect/control
                - /hello
`))
	if err != nil {
		t.Fatal(err)
	}
	paths := servicesConfig.Latest().Services["api"].NoSuccessAccessLog
	if !slices.Equal(paths, []string{"/connect/control", "/hello"}) {
		t.Fatalf("no_success_access_log = %v, want [/connect/control /hello]", paths)
	}
}

// A path that can never equal a request's normalized uri would leave the route
// it was meant to quiet in the log, so it is refused when the document loads,
// before any lb config is generated.
func TestLoadServicesConfigRejectsInvalidNoSuccessAccessLog(t *testing.T) {
	for _, test := range []struct {
		name    string
		entries string
		message string
	}{
		{name: "relative path", entries: "                - connect/control\n", message: "not an exact path"},
		{name: "regex path", entries: "                - /connect/.*\n", message: "not an exact path"},
		{name: "space", entries: "                - \"/connect/control x\"\n", message: "not an exact path"},
		{name: "nginx variable", entries: "                - /connect/$host\n", message: "not an exact path"},
		{name: "empty segment", entries: "                - /connect//control\n", message: "not an exact path"},
		{name: "root", entries: "                - /\n", message: "not an exact path"},
		{name: "dot segment", entries: "                - /connect/../control\n", message: "dot segment"},
		{name: "repeated path", entries: "                - /hello\n                - /hello\n", message: "more than once"},
	} {
		err := loadInlineServices(t, noSuccessAccessLogServicesYaml(test.entries))
		if err == nil || !strings.Contains(err.Error(), test.message) {
			t.Errorf("%s: err = %v, want %q", test.name, err, test.message)
		}
	}
}
