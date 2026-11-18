package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"maps"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"
)

// lag.dev's Content-Security-Policy as mmm's nginx sends it
// (mmm/nginx/nginx.conf.j2), with the given frame-ancestors: https: for the
// drift test's widget, the home page with a token, and 'none' for every other
// response
func lagDevContentSecurityPolicy(frameAncestors string) string {
	return "default-src 'self'; connect-src 'self' https://api.bringyour.com https://*.extender.bringyour.com wss://*.extender.bringyour.com; img-src 'self' data:; style-src 'self' 'unsafe-inline'; font-src 'self'; frame-ancestors " + frameAncestors + "; base-uri 'none'; form-action 'self'"
}

// An upstream response's Content-Security-Policy headers, in order, and the
// X-Frame-Options the lb sends with it, "" for none.
type frameOptionsCase struct {
	name                    string
	contentSecurityPolicies []string
	frameOptions            string
}

var frameOptionsCases = []frameOptionsCase{
	{
		name:                    "lag.dev's widget, frame-ancestors https:",
		contentSecurityPolicies: []string{lagDevContentSecurityPolicy("https:")},
		frameOptions:            "",
	},
	{
		name:                    "lag.dev's other responses, frame-ancestors 'none'",
		contentSecurityPolicies: []string{lagDevContentSecurityPolicy("'none'")},
		frameOptions:            "SAMEORIGIN",
	},
	{
		name:         "no CSP",
		frameOptions: "SAMEORIGIN",
	},
	{
		name:                    "frame-ancestors 'self'",
		contentSecurityPolicies: []string{lagDevContentSecurityPolicy("'self'")},
		frameOptions:            "SAMEORIGIN",
	},
	{
		name:                    "a CSP without frame-ancestors",
		contentSecurityPolicies: []string{"default-src 'self'; img-src https:"},
		frameOptions:            "SAMEORIGIN",
	},
	{
		name:                    "frame-ancestors 'self' and another host",
		contentSecurityPolicies: []string{"default-src 'self'; frame-ancestors 'self' https://partner.example"},
		frameOptions:            "",
	},
	{
		name:                    "frame-ancestors in capitals",
		contentSecurityPolicies: []string{"FRAME-ANCESTORS HTTPS:"},
		frameOptions:            "",
	},
	{
		// equivalent to 'none'
		name:                    "frame-ancestors with no source",
		contentSecurityPolicies: []string{"default-src 'self'; frame-ancestors; base-uri 'none'"},
		frameOptions:            "SAMEORIGIN",
	},
	{
		// a keyword frame-ancestors does not accept grants nothing
		name:                    "frame-ancestors 'unsafe-inline'",
		contentSecurityPolicies: []string{"frame-ancestors 'unsafe-inline'"},
		frameOptions:            "SAMEORIGIN",
	},
	{
		// a browser enforces both policies, so nothing but the site may frame it
		name:                    "a second policy with frame-ancestors 'none'",
		contentSecurityPolicies: []string{"frame-ancestors https:", "frame-ancestors 'none'"},
		frameOptions:            "SAMEORIGIN",
	},
	{
		name:                    "a second policy without frame-ancestors",
		contentSecurityPolicies: []string{"frame-ancestors https:", "default-src 'self'"},
		frameOptions:            "",
	},
}

// The X-Frame-Options map of the lb's http block, in order. nginx tries the
// regexes in order, so a frame-ancestors of only keywords anywhere in the CSP
// wins over one with a source.
var frameOptionsMapEntries = []string{
	"default SAMEORIGIN;",
	`"~*(?:^|[;,])\s*frame-ancestors(?:\s+'[^'\s;,]*')*\s*(?:[;,]|$)" SAMEORIGIN;`,
	`"~*(?:^|[;,])\s*frame-ancestors(?:\s+[^\s;,]+)*?\s+[^'\s;,]" "";`,
}

// A service response's security headers, as the lb set them before
// X-Frame-Options followed the upstream's CSP, but for X-Frame-Options.
var serviceSecurityHeaders = []string{
	"add_header Strict-Transport-Security 'max-age=63072000; includeSubDomains; preload' always;",
	"add_header X-Frame-Options $warp_x_frame_options always;",
	"add_header X-Content-Type-Options 'nosniff' always;",
	"add_header X-XSS-Protection '1; mode=block' always;",
}

// The value an nginx map of a default and quoted regexes (`"~regex"`, or
// `"~*regex"` to ignore case) gives source: the value of the first regex that
// matches, in order, else the default. nginx tries no regex on an empty
// source. Go's regexp agrees with nginx's PCRE on whether these patterns
// match.
func nginxRegexMapValue(t *testing.T, entries []string, source string) string {
	t.Helper()
	unquote := func(s string) string {
		if 2 <= len(s) && s[0] == '"' && s[len(s)-1] == '"' {
			return s[1 : len(s)-1]
		}
		return s
	}
	type regexEntry struct {
		regex *regexp.Regexp
		value string
	}
	defaultValue := ""
	hasDefault := false
	regexEntries := []regexEntry{}
	for _, entry := range entries {
		statement, ok := strings.CutSuffix(entry, ";")
		if !ok {
			t.Fatalf("map entry %q does not end with ;", entry)
		}
		if value, ok := strings.CutPrefix(statement, "default "); ok {
			defaultValue = unquote(value)
			hasDefault = true
			continue
		}
		// the regexes here hold no space or quote
		key, value, ok := strings.Cut(statement, " ")
		pattern, isRegex := strings.CutPrefix(unquote(key), "~")
		if !ok || !strings.HasPrefix(key, `"`) || !isRegex {
			t.Fatalf("map entry %q is neither the default nor a quoted regex", entry)
		}
		if caseless, ok := strings.CutPrefix(pattern, "*"); ok {
			pattern = "(?i)" + caseless
		}
		regexEntries = append(regexEntries, regexEntry{
			regex: regexp.MustCompile(pattern),
			value: unquote(value),
		})
	}
	if !hasDefault {
		t.Fatal("map has no default")
	}
	if source == "" {
		return defaultValue
	}
	for _, regexEntry := range regexEntries {
		if regexEntry.regex.MatchString(source) {
			return regexEntry.value
		}
	}
	return defaultValue
}

// Every lb block defines $warp_x_frame_options from the upstream's CSP, and
// every service response's X-Frame-Options, lag.dev's included, is that
// variable, with the other security headers as they were. The map leaves
// X-Frame-Options out only when the CSP's frame-ancestors lets another origin
// frame the response, as lag.dev's widget's https: does, and keeps SAMEORIGIN
// for lag.dev's other responses ('none'), for 'self' and without a CSP.
func TestNginxConfigTakesFrameOptionsFromTheUpstreamFrameAncestors(t *testing.T) {
	env, _ := setupLagDevTestVault(t, lagDevServicesYaml(t))
	nginxConfig, err := NewNginxConfig(env, nil)
	if err != nil {
		t.Fatal(err)
	}

	blockConfigs := nginxConfig.Generate()
	blocks := slices.Sorted(maps.Keys(blockConfigs))
	if len(blocks) == 0 {
		t.Fatal("no lb block config generated")
	}
	for _, block := range blocks {
		config := blockConfigs[block]

		mapEntries := nginxBlockLines(t, config, "map $upstream_http_content_security_policy $warp_x_frame_options")
		if !slices.Equal(mapEntries, frameOptionsMapEntries) {
			t.Errorf("block %s $warp_x_frame_options = %q, want %q", block, mapEntries, frameOptionsMapEntries)
		}

		frameOptions := nginxDirectives(config, "add_header X-Frame-Options")
		if len(frameOptions) == 0 {
			t.Errorf("block %s sends no X-Frame-Options", block)
		}
		for _, directive := range frameOptions {
			if directive != serviceSecurityHeaders[1] {
				t.Errorf("block %s: %q, want %q", block, directive, serviceSecurityHeaders[1])
			}
		}

		// each X-Frame-Options among the other security headers, unchanged
		lines := []string{}
		for _, line := range strings.Split(config, "\n") {
			lines = append(lines, strings.TrimSpace(line))
		}
		securityHeaders := 0
		for i, line := range lines {
			if line != serviceSecurityHeaders[0] {
				continue
			}
			securityHeaders += 1
			end := min(i+len(serviceSecurityHeaders), len(lines))
			if !slices.Equal(lines[i:end], serviceSecurityHeaders) {
				t.Errorf("block %s security headers = %q, want %q", block, lines[i:end], serviceSecurityHeaders)
			}
		}
		if securityHeaders != len(frameOptions) {
			t.Errorf("block %s has %d X-Frame-Options for %d security header sets", block, len(frameOptions), securityHeaders)
		}

		lagDevServed := false
		for _, server := range nginxServerBlocks(config) {
			if slices.Contains(nginxDirectives(server, "server_name"), "server_name lag.dev;") && slices.Contains(nginxDirectives(server, "listen"), "listen 443 ssl;") {
				lagDevServed = true
				if !strings.Contains(server, serviceSecurityHeaders[1]) {
					t.Errorf("block %s: lag.dev's server sends no X-Frame-Options from the map", block)
				}
			}
		}
		if !lagDevServed {
			t.Errorf("block %s does not serve lag.dev over https", block)
		}
	}

	mapEntries := nginxBlockLines(t, blockConfigs[blocks[0]], "map $upstream_http_content_security_policy $warp_x_frame_options")
	for _, c := range frameOptionsCases {
		// nginx joins repeated headers with ", "
		contentSecurityPolicy := strings.Join(c.contentSecurityPolicies, ", ")
		if frameOptions := nginxRegexMapValue(t, mapEntries, contentSecurityPolicy); frameOptions != c.frameOptions {
			t.Errorf("%s: X-Frame-Options %q, want %q", c.name, frameOptions, c.frameOptions)
		}
	}
}

// Runs the generated lb config in nginx in front of a service, in mmm's place,
// that answers with the Content-Security-Policy headers each request names,
// and checks the X-Frame-Options the lb adds: none with lag.dev's widget
// (frame-ancestors https:), SAMEORIGIN with lag.dev's other responses
// ('none'), with 'self' and with no CSP. The other security headers stay as
// they were on every answer, and the lb's own answer to a preflight, with no
// upstream response, keeps SAMEORIGIN. Before, every answer had SAMEORIGIN.
func TestNginxSendsNoFrameOptionsWhenTheUpstreamLetsOtherOriginsFrameIt(t *testing.T) {
	servicesYaml, err := testServicesFS.ReadFile("testdata/services.yml")
	if err != nil {
		t.Fatal(err)
	}
	service := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for _, contentSecurityPolicy := range r.URL.Query()["csp"] {
			w.Header().Add("Content-Security-Policy", contentSecurityPolicy)
		}
		fmt.Fprintln(w, "ok")
	})
	// a general harness: the lb's first block, with every upstream at service
	httpsPort, nginxErrors := runRouteRequestBodyNginx(t, servicesYaml, nil, service)

	client := &http.Client{
		Transport: &http.Transport{
			// every name is the local lb
			DialContext: func(ctx context.Context, network string, addr string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, network, fmt.Sprintf("127.0.0.1:%d", httpsPort))
			},
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		Timeout: 10 * time.Second,
	}

	send := func(name string, method string, contentSecurityPolicies []string, header http.Header, status int) http.Header {
		t.Helper()
		requestUrl := "https://test-svc-a.example.com/"
		if 0 < len(contentSecurityPolicies) {
			requestUrl += "?" + url.Values{"csp": contentSecurityPolicies}.Encode()
		}
		request, err := http.NewRequest(method, requestUrl, nil)
		if err != nil {
			t.Fatal(err)
		}
		for key, values := range header {
			request.Header[key] = values
		}
		response, err := client.Do(request)
		if err != nil {
			t.Fatalf("%s: %s\n%s", name, err, nginxErrors())
		}
		response.Body.Close()
		if response.StatusCode != status {
			t.Fatalf("%s: status %d, want %d\n%s", name, response.StatusCode, status, nginxErrors())
		}
		return response.Header
	}

	checkSecurityHeaders := func(name string, header http.Header, frameOptions string) {
		t.Helper()
		want := map[string][]string{
			"Strict-Transport-Security": {"max-age=63072000; includeSubDomains; preload"},
			"X-Content-Type-Options":    {"nosniff"},
			"X-XSS-Protection":          {"1; mode=block"},
			"X-Frame-Options":           nil,
		}
		if frameOptions != "" {
			want["X-Frame-Options"] = []string{frameOptions}
		}
		for _, key := range slices.Sorted(maps.Keys(want)) {
			if values := header.Values(key); !slices.Equal(values, want[key]) {
				t.Errorf("%s: %s %q, want %q", name, key, values, want[key])
			}
		}
	}

	for _, c := range frameOptionsCases {
		header := send(c.name, "GET", c.contentSecurityPolicies, nil, http.StatusOK)
		// the service's CSP reaches the browser as the service sent it
		if values := header.Values("Content-Security-Policy"); !slices.Equal(values, c.contentSecurityPolicies) {
			t.Errorf("%s: Content-Security-Policy %q, want %q", c.name, values, c.contentSecurityPolicies)
		}
		checkSecurityHeaders(c.name, header, c.frameOptions)
	}

	// the lb answers a preflight itself, so whatever the request names, there
	// is no upstream CSP
	preflight := send(
		"a preflight",
		"OPTIONS",
		[]string{lagDevContentSecurityPolicy("https:")},
		http.Header{
			"Origin":                        {"https://example.com"},
			"Access-Control-Request-Method": {"GET"},
		},
		http.StatusNoContent,
	)
	checkSecurityHeaders("a preflight", preflight, "SAMEORIGIN")
}
