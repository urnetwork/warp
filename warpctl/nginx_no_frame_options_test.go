package main

// services.yml no_frame_options (QD-678): the lb adds no X-Frame-Options to a listed host's responses,
// which keep the lb's other security headers, while every other host keeps SAMEORIGIN. The one host
// mmm.yml lists is the sidecar's key origin, which ur.io frames under the key origin's own CSP
// frame-ancestors (sidecar DESIGN §18.8), which SAMEORIGIN would contradict.

import (
	"fmt"
	"net/http"
	"slices"
	"strings"
	"testing"
)

// The lb's X-Frame-Options, as addSecurityHeaders writes it.
const nginxFrameOptionsDirective = "add_header X-Frame-Options 'SAMEORIGIN' always;"

// The security headers addSecurityHeaders writes beside it, each once wherever it writes them.
var nginxOtherSecurityDirectives = []string{
	"add_header Strict-Transport-Security 'max-age=63072000; includeSubDomains; preload' always;",
	"add_header X-Content-Type-Options 'nosniff' always;",
	"add_header X-XSS-Protection '1; mode=block' always;",
}

// The test services with svc-a serving framed.example.com and other.example.com beside its own names,
// and hosts as the services.yml no_frame_options list. aliases replaces svc-a's two names when set.
func noFrameOptionsServicesYaml(t *testing.T, aliases []string, hosts ...string) []byte {
	t.Helper()
	if aliases == nil {
		aliases = []string{"framed.example.com", "other.example.com"}
	}
	aliasLines := "            expose_aliases:\n"
	for _, alias := range aliases {
		aliasLines += fmt.Sprintf("                - %s\n", alias)
	}
	servicesYaml := testServicesYamlWith(t, testServicesYaml(t), "svc-a", aliasLines)
	if len(hosts) == 0 {
		return servicesYaml
	}
	list := "no_frame_options:\n"
	for _, host := range hosts {
		list += fmt.Sprintf("    - %s\n", host)
	}
	domains := "domains:\n    example.com: route53\n"
	if !strings.Contains(string(servicesYaml), domains) {
		t.Fatal("test services fixture lacks the domains insertion boundary")
	}
	return []byte(strings.Replace(string(servicesYaml), domains, domains+list, 1))
}

// Every lb block's config for a services document.
func noFrameOptionsNginxConfigs(t *testing.T, servicesYaml []byte) map[string]string {
	t.Helper()
	env, _ := setupTestVaultWithTLS(t, servicesYaml)
	nginxConfig, err := NewNginxConfig(env, nil)
	if err != nil {
		t.Fatal(err)
	}
	blockConfigs := nginxConfig.Generate()
	if len(blockConfigs) == 0 {
		t.Fatal("no lb block config generated")
	}
	return blockConfigs
}

// The https server blocks of a generated config by each name they serve, lowercase. An https server block
// is one with a certificate; the port 80 redirect and the stream servers have none.
func nginxHttpsServerBlocks(config string) map[string][]string {
	serverBlocks := map[string][]string{}
	for _, server := range nginxServerBlocks(config) {
		if len(nginxDirectives(server, "ssl_certificate")) == 0 {
			continue
		}
		for _, serverName := range nginxDirectives(server, "server_name") {
			for _, name := range strings.Fields(strings.TrimSuffix(serverName, ";"))[1:] {
				name = strings.ToLower(name)
				serverBlocks[name] = append(serverBlocks[name], server)
			}
		}
	}
	return serverBlocks
}

// How often a server block writes each security header, the trimmed directive's lines counted.
func nginxSecurityDirectiveCounts(server string) map[string]int {
	counts := map[string]int{}
	for _, line := range strings.Split(server, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == nginxFrameOptionsDirective || slices.Contains(nginxOtherSecurityDirectives, trimmed) {
			counts[trimmed] += 1
		}
	}
	return counts
}

// Holds every https server block of a config to the rule: a host in framedHosts writes the other security
// headers and no X-Frame-Options at all, and every other host that writes security headers writes
// SAMEORIGIN with each of them. Returns how many server blocks wrote SAMEORIGIN.
func checkNginxFrameOptions(t *testing.T, block string, config string, framedHosts []string) int {
	t.Helper()
	sameOriginServers := 0
	for name, servers := range nginxHttpsServerBlocks(config) {
		for _, server := range servers {
			counts := nginxSecurityDirectiveCounts(server)
			headerCount := counts[nginxOtherSecurityDirectives[0]]
			for _, directive := range nginxOtherSecurityDirectives[1:] {
				if counts[directive] != headerCount {
					t.Errorf("block %s: %s writes %q %d times and %q %d times", block, name, nginxOtherSecurityDirectives[0], headerCount, directive, counts[directive])
				}
			}
			if slices.Contains(framedHosts, name) {
				if headerCount == 0 {
					t.Errorf("block %s: %s writes no security headers", block, name)
				}
				if strings.Contains(server, "X-Frame-Options") {
					t.Errorf("block %s: %s, which no_frame_options lists, sends X-Frame-Options:\n%s", block, name, server)
				}
				continue
			}
			if counts[nginxFrameOptionsDirective] != headerCount {
				t.Errorf("block %s: %s writes X-Frame-Options %d times beside %d of its other security headers", block, name, counts[nginxFrameOptionsDirective], headerCount)
			}
			if 0 < counts[nginxFrameOptionsDirective] {
				sameOriginServers += 1
			}
		}
	}
	return sameOriginServers
}

// no_frame_options takes the header out of the listed host's server block and nothing else out of the
// render: the listed host keeps its other security headers, every other host keeps SAMEORIGIN, and with
// the X-Frame-Options lines of that one block put back the render is byte for byte the one without the
// list, which sends SAMEORIGIN to every host.
func TestNginxConfigNoFrameOptionsTakesOutOnlyTheListedHostsHeader(t *testing.T) {
	without := noFrameOptionsNginxConfigs(t, noFrameOptionsServicesYaml(t, nil))
	with := noFrameOptionsNginxConfigs(t, noFrameOptionsServicesYaml(t, nil, "framed.example.com"))
	if len(with) != len(without) {
		t.Fatalf("rendered %d blocks with the list and %d without", len(with), len(without))
	}
	for block, config := range without {
		if checkNginxFrameOptions(t, block, config, nil) == 0 {
			t.Errorf("block %s without the list sends X-Frame-Options to no host", block)
		}
		if checkNginxFrameOptions(t, block, with[block], []string{"framed.example.com"}) == 0 {
			t.Errorf("block %s with the list sends X-Frame-Options to no host", block)
		}

		httpConfig := nginxHttpConfig(config)
		framedServers := nginxHttpsServerBlocks(httpConfig)["framed.example.com"]
		if len(framedServers) != 1 {
			t.Fatalf("block %s has %d server blocks for framed.example.com, want 1", block, len(framedServers))
		}
		lines := []string{}
		for _, line := range strings.Split(framedServers[0], "\n") {
			if strings.TrimSpace(line) != nginxFrameOptionsDirective {
				lines = append(lines, line)
			}
		}
		if len(lines) == len(strings.Split(framedServers[0], "\n")) {
			t.Fatalf("block %s: framed.example.com has no X-Frame-Options to take out", block)
		}
		want := strings.Replace(httpConfig, framedServers[0], strings.Join(lines, "\n"), 1)
		if nginxHttpConfig(with[block]) != want {
			t.Errorf("block %s changed beyond framed.example.com's X-Frame-Options", block)
		}
	}
}

// The list is compared as nginx spells a host, as no_access_log is: an entry in another case or with a
// trailing dot names the host, and so does an entry for an alias written in another case. The alias keeps
// its domain lowercase, which is how the vault names the certificate it falls back to.
func TestNginxConfigMatchesANoFrameOptionsHostAsNginxSpellsIt(t *testing.T) {
	for _, c := range []struct {
		aliases []string
		host    string
	}{
		{aliases: []string{"framed.example.com", "other.example.com"}, host: "Framed.Example.Com."},
		{aliases: []string{"Framed.example.com", "other.example.com"}, host: "framed.example.com"},
	} {
		for block, config := range noFrameOptionsNginxConfigs(t, noFrameOptionsServicesYaml(t, c.aliases, c.host)) {
			if len(nginxHttpsServerBlocks(config)["framed.example.com"]) != 1 {
				t.Fatalf("aliases %q, host %q: block %s does not serve framed.example.com", c.aliases, c.host, block)
			}
			checkNginxFrameOptions(t, block, config, []string{"framed.example.com"})
		}
	}
}

// A misspelled no_frame_options host would leave the host that was meant with SAMEORIGIN, which
// contradicts its own frame-ancestors, so the lb config is not generated at all.
func TestNginxConfigRejectsNoFrameOptionsHostTheLbDoesNotServe(t *testing.T) {
	env, _ := setupTestVaultWithTLS(t, noFrameOptionsServicesYaml(t, nil, "framed.example.com", "framd.example.com"))
	_, err := NewNginxConfig(env, nil)
	if err == nil || !strings.Contains(err.Error(), "no_frame_options names framd.example.com, which the lb does not serve") {
		t.Fatalf("err = %v, want framd.example.com rejected", err)
	}
}

// Runs the generated lb config in nginx: a listed host answers a request and a CORS preflight with the
// other security headers and no X-Frame-Options, and another alias of the same service and the service's
// own name answer both with X-Frame-Options: SAMEORIGIN.
func TestNginxSendsNoFrameOptionsOnlyToAListedHost(t *testing.T) {
	lb := startNginxTestLb(t, &nginxTestLbSettings{
		servicesYaml: noFrameOptionsServicesYaml(t, nil, "framed.example.com"),
		service: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintln(w, "ok")
		}),
	})

	type lbRequest struct {
		method string
		url    string
		status int
		// the X-Frame-Options values the answer must carry
		frameOptions []string
	}
	for _, request := range []lbRequest{
		{method: "GET", url: "https://framed.example.com/r/", status: http.StatusOK},
		{method: "OPTIONS", url: "https://framed.example.com/r/", status: http.StatusNoContent},
		{method: "GET", url: "https://other.example.com/r/", status: http.StatusOK, frameOptions: []string{"SAMEORIGIN"}},
		{method: "OPTIONS", url: "https://other.example.com/r/", status: http.StatusNoContent, frameOptions: []string{"SAMEORIGIN"}},
		{method: "GET", url: "https://test-svc-a.example.com/r/", status: http.StatusOK, frameOptions: []string{"SAMEORIGIN"}},
		{method: "OPTIONS", url: "https://test-svc-a.example.com/r/", status: http.StatusNoContent, frameOptions: []string{"SAMEORIGIN"}},
	} {
		httpRequest, err := http.NewRequest(request.method, request.url, nil)
		if err != nil {
			t.Fatal(err)
		}
		// svc-a allows https://example.com, so an OPTIONS from it is a preflight
		httpRequest.Header.Set("Origin", "https://example.com")
		if request.method == "OPTIONS" {
			httpRequest.Header.Set("Access-Control-Request-Method", "PUT")
		}
		response, err := lb.client.Do(httpRequest)
		if err != nil {
			t.Fatalf("%s %s: %s\n%s", request.method, request.url, err, lb.errors())
		}
		response.Body.Close()
		if response.StatusCode != request.status {
			t.Fatalf("%s %s: status %d, want %d\n%s", request.method, request.url, response.StatusCode, request.status, lb.errors())
		}
		if frameOptions := response.Header.Values("X-Frame-Options"); !slices.Equal(frameOptions, request.frameOptions) {
			t.Errorf("%s %s: X-Frame-Options %q, want %q", request.method, request.url, frameOptions, request.frameOptions)
		}
		for header, want := range map[string]string{
			"Strict-Transport-Security":   "max-age=63072000; includeSubDomains; preload",
			"X-Content-Type-Options":      "nosniff",
			"X-Xss-Protection":            "1; mode=block",
			"Access-Control-Allow-Origin": "https://example.com",
		} {
			if got := response.Header.Values(header); !slices.Equal(got, []string{want}) {
				t.Errorf("%s %s: %s %q, want %q", request.method, request.url, header, got, want)
			}
		}
	}
}
