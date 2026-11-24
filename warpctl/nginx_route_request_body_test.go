// Tests of services.yml route_request_bodies in the generated lb config and in
// a running nginx: the route's exact locations, the server-wide body values
// every other location keeps, and the stall timeout and http/2 upload window
// nginx applies per route.
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"maps"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"syscall"
	"testing"
	"time"
)

// The validator uploads attempt artifacts of up to about 4.2 MB to the api's
// /sn/attempt-artifact. On 2026-11-16 a lossy path stalled uploads for more
// than the lb's server-wide 15 s client_body_timeout, and the lb ended them
// with a 408 before the validator's own 30 s stall window decided anything.
// services.yml now gives such a route a body buffer and stall timeout of its
// own (route_request_bodies), which the lb renders as an exact location in
// every server and behind every prefix that proxies the service, while every
// other location keeps the server-wide 64k and 15s. The tests below put
// svc-b, an api-like service with cors origins, in the place of the api, and
// svc-d, whose streamable_paths stream /upload/.*, for a streamed route.

// the test services with `serviceSettings` inserted at the top of the latest
// version's entry of each named service, and `extra` inserted before the
// services, e.g. hidden_prefixes
func routeRequestBodyServicesYaml(t *testing.T, serviceSettings map[string]string, extra string) []byte {
	t.Helper()
	baseYaml, err := testServicesFS.ReadFile("testdata/services.yml")
	if err != nil {
		t.Fatal(err)
	}
	servicesYaml := string(baseYaml)
	services := slices.Sorted(maps.Keys(serviceSettings))
	for _, service := range services {
		// the first entry is the latest version's, which the lb is generated from
		serviceLine := fmt.Sprintf("        %s:\n", service)
		if !strings.Contains(servicesYaml, serviceLine) {
			t.Fatalf("test services fixture lacks %s", service)
		}
		servicesYaml = strings.Replace(servicesYaml, serviceLine, serviceLine+serviceSettings[service], 1)
	}
	if extra != "" {
		domains := "domains:\n    example.com: route53\n"
		if !strings.Contains(servicesYaml, domains) {
			t.Fatal("test services fixture lacks the domains insertion boundary")
		}
		servicesYaml = strings.Replace(servicesYaml, domains, domains+extra, 1)
	}
	return []byte(servicesYaml)
}

const attemptArtifactRouteRequestBodies = "" +
	"            route_request_bodies:\n" +
	"                -   path: /sn/attempt-artifact\n" +
	"                    client_body_buffer_size: 1mib\n" +
	"                    client_body_timeout: 60s\n"

// the production shape: the stall timeout alone, the buffer left at the
// server-wide size
const attemptArtifactTimeoutRouteRequestBodies = "" +
	"            route_request_bodies:\n" +
	"                -   path: /sn/attempt-artifact\n" +
	"                    client_body_timeout: 60s\n"

// svc-d streams /upload/.*, so its upload route streams too
const uploadArtifactRouteRequestBodies = "" +
	"            route_request_bodies:\n" +
	"                -   path: /upload/artifact\n" +
	"                    client_body_buffer_size: 1mib\n"

// The generated lines equal to `line` after trimming, with the indent of each.
func nginxLineIndents(config string, line string) []int {
	indents := []int{}
	for _, configLine := range strings.Split(config, "\n") {
		if strings.TrimSpace(configLine) == line {
			indents = append(indents, len(configLine)-len(strings.TrimLeft(configLine, " ")))
		}
	}
	return indents
}

// Checks that the http block keeps the server-wide body buffer and stall
// timeout, once each among the http block's own settings (which
// client_max_body_size is one of), and that no location but the route's
// exact locations, `routeLocations` of them, sets either.
func checkServerWideRequestBody(t *testing.T, blockName string, config string, routeBufferLine string, routeTimeoutLine string, routeLocations int) {
	t.Helper()
	httpIndents := nginxLineIndents(config, "client_max_body_size 16m;")
	if len(httpIndents) != 1 {
		t.Fatalf("block %s has client_max_body_size at indents %v, want once in the http block", blockName, httpIndents)
	}
	for _, serverWide := range []string{"client_body_buffer_size 64k;", "client_body_timeout 15s;"} {
		if indents := nginxLineIndents(config, serverWide); !slices.Equal(indents, httpIndents) {
			t.Errorf("block %s has %q at indents %v, want once among the http block's settings (indent %d)", blockName, serverWide, indents, httpIndents[0])
		}
	}
	for directive, routeLine := range map[string]string{
		"client_body_buffer_size": routeBufferLine,
		"client_body_timeout":     routeTimeoutLine,
	} {
		count := 0
		for _, line := range strings.Split(config, "\n") {
			if strings.HasPrefix(strings.TrimSpace(line), directive+" ") {
				count += 1
			}
		}
		want := 1
		if routeLine != "" {
			want += routeLocations
			if routeCount := len(nginxLineIndents(config, routeLine)); routeCount != routeLocations {
				t.Errorf("block %s has %q %d times, want once per route location (%d)", blockName, routeLine, routeCount, routeLocations)
			}
			for _, location := range enclosingLocations(config, routeLine) {
				if !strings.HasPrefix(location, "location = ") || !strings.HasSuffix(location, " {") {
					t.Errorf("block %s sets %q in %q, which is not a route's exact location", blockName, routeLine, location)
				}
			}
		}
		if count != want {
			t.Errorf("block %s has %d %s lines, want %d (the http block's and the route locations')", blockName, count, directive, want)
		}
	}
}

// /sn/attempt-artifact gets an exact location in each of svc-b's https
// server blocks and beside each of its lb host proxy locations, which sets
// the route's body buffer and stall timeout and proxies as the prefix
// location does, while the http block keeps the server-wide 64k and 15s for
// every other location. Before route_request_bodies the key was ignored and
// the route read its body with the server-wide values: an upload that
// stalled 15 s was dropped.
func TestNginxConfigScopesARouteRequestBodyToItsRoute(t *testing.T) {
	servicesYaml := routeRequestBodyServicesYaml(t, map[string]string{"svc-b": attemptArtifactRouteRequestBodies}, "")
	env, _ := setupTestVaultWithTLS(t, servicesYaml)
	nginxConfig, err := NewNginxConfig(env, nil)
	if err != nil {
		t.Fatal(err)
	}

	blockConfigs := nginxConfig.Generate()
	if len(blockConfigs) == 0 {
		t.Fatal("no lb block config generated")
	}
	for blockName, config := range blockConfigs {
		svcBHttpsServerCount := 0
		serviceRouteLocationCount := 0
		for _, server := range nginxServerBlocks(config) {
			routeLocations := nginxBlocks(server, "location = /sn/attempt-artifact")
			svcBHttps := strings.Contains(server, "server_name test-svc-b.example.com;") &&
				strings.Contains(server, "listen 443 ssl;")
			if !svcBHttps {
				if 0 < len(routeLocations) {
					t.Errorf("block %s has a /sn/attempt-artifact location outside svc-b's https server:\n%s", blockName, server)
				}
				continue
			}
			svcBHttpsServerCount += 1
			serviceRouteLocationCount += len(routeLocations)
			if len(routeLocations) != 1 {
				t.Errorf("block %s svc-b https server has %d /sn/attempt-artifact locations, want 1", blockName, len(routeLocations))
			}
			for _, routeLocation := range routeLocations {
				for _, required := range []string{
					"client_body_buffer_size 1m;",
					"client_body_timeout 60s;",
					// the exact location replaces the whole uri with the path
					"proxy_pass http://service-block-svc-b/sn/attempt-artifact;",
					// the lb-to-service contract headers of the prefix location
					"proxy_set_header X-UR-Forwarded-For $warp_client_addr:$remote_port;",
					`proxy_set_header X-Forwarded-For "";`,
					// a buffered route, as svc-b's other routes
					`proxy_set_header X-UR-Request-Buffering "";`,
					// the service's cors policy and security headers
					"set $cors_origin '';",
					"if ($http_origin = 'https://example.com') {",
					"if ($request_method = 'OPTIONS') {",
					"add_header 'Access-Control-Allow-Origin' $cors_origin always;",
					"add_header Strict-Transport-Security 'max-age=63072000; includeSubDomains; preload' always;",
				} {
					if !strings.Contains(routeLocation, required) {
						t.Errorf("block %s /sn/attempt-artifact location lacks %q:\n%s", blockName, required, routeLocation)
					}
				}
				for _, forbidden := range []string{"limit_req ", "proxy_request_buffering"} {
					if strings.Contains(routeLocation, forbidden) {
						t.Errorf("block %s /sn/attempt-artifact location has %q, which only the http block sets for it:\n%s", blockName, forbidden, routeLocation)
					}
				}
			}
			// the prefix location, which every other route of svc-b takes,
			// inherits the server-wide values
			for _, prefixLocation := range nginxBlocks(server, "location /") {
				if strings.Contains(prefixLocation, "client_body_") {
					t.Errorf("block %s svc-b prefix location sets a body value of its own:\n%s", blockName, prefixLocation)
				}
			}
		}
		if svcBHttpsServerCount == 0 {
			t.Errorf("block %s serves no svc-b https server", blockName)
		}

		// the lb host proxies the service at by/service and each block at by/b
		lbRouteLocationCount := 0
		for location, upstream := range map[string]string{
			"location = /by/service/svc-b/sn/attempt-artifact": "service-block-svc-b",
			"location = /by/b/svc-b/beta/sn/attempt-artifact":  "service-block-svc-b-beta",
			"location = /by/b/svc-b/g1/sn/attempt-artifact":    "service-block-svc-b-g1",
			"location = /by/b/svc-b/g4/sn/attempt-artifact":    "service-block-svc-b-g4",
		} {
			lbRouteLocations := nginxBlocks(config, location)
			if len(lbRouteLocations) == 0 {
				t.Errorf("block %s lacks %s", blockName, location)
			}
			for _, lbRouteLocation := range lbRouteLocations {
				for _, required := range []string{
					"client_body_buffer_size 1m;",
					"client_body_timeout 60s;",
					"proxy_pass http://" + upstream + "/sn/attempt-artifact;",
					`proxy_set_header X-UR-Request-Buffering "";`,
				} {
					if !strings.Contains(lbRouteLocation, required) {
						t.Errorf("block %s %s lacks %q:\n%s", blockName, location, required, lbRouteLocation)
					}
				}
			}
		}
		for _, line := range strings.Split(config, "\n") {
			if strings.HasPrefix(strings.TrimSpace(line), "location = /by/") && strings.HasSuffix(line, "/sn/attempt-artifact {") {
				lbRouteLocationCount += 1
			}
		}
		// by/service and the 5 by/b blocks of svc-b, in each lb host server
		lbHostServerCount := len(nginxBlocks(config, "location /by/service/svc-b/"))
		if lbHostServerCount == 0 || lbRouteLocationCount != 6*lbHostServerCount {
			t.Errorf("block %s has %d lb host route locations for %d lb host servers, want 6 each", blockName, lbRouteLocationCount, lbHostServerCount)
		}

		checkServerWideRequestBody(t, blockName, config, "client_body_buffer_size 1m;", "client_body_timeout 60s;", serviceRouteLocationCount+lbRouteLocationCount)
	}
}

// The production shape sets the stall timeout alone: the route's location
// sets client_body_timeout and inherits the server-wide 64k buffer, since a
// buffered upload's speed does not depend on the buffer (see
// TestNginxHttp2UploadWindowFollowsTheRouteBufferOnlyWhenStreamed).
func TestNginxConfigRouteRequestBodyTimeoutKeepsTheServerWideBuffer(t *testing.T) {
	servicesYaml := routeRequestBodyServicesYaml(t, map[string]string{"svc-b": attemptArtifactTimeoutRouteRequestBodies}, "")
	env, _ := setupTestVaultWithTLS(t, servicesYaml)
	nginxConfig, err := NewNginxConfig(env, nil)
	if err != nil {
		t.Fatal(err)
	}
	for blockName, config := range nginxConfig.Generate() {
		routeLocations := nginxBlocks(config, "location = /sn/attempt-artifact")
		if len(routeLocations) == 0 {
			t.Errorf("block %s has no /sn/attempt-artifact location", blockName)
		}
		for _, routeLocation := range routeLocations {
			if !strings.Contains(routeLocation, "client_body_timeout 60s;") || strings.Contains(routeLocation, "client_body_buffer_size") {
				t.Errorf("block %s /sn/attempt-artifact location does not set the timeout alone:\n%s", blockName, routeLocation)
			}
		}
		routeLocationCount := len(nginxLineIndents(config, "client_body_timeout 60s;"))
		checkServerWideRequestBody(t, blockName, config, "", "client_body_timeout 60s;", routeLocationCount)
	}
}

// Behind hidden route prefixes the exact location matches the prefixed uri
// and proxies the service-relative path, as the prefix location strips the
// prefix, and the lb host locations sit behind the lb's own prefix. No
// location serves the route without its prefix.
func TestNginxConfigRouteRequestBodyBehindHiddenPrefixes(t *testing.T) {
	servicesYaml := routeRequestBodyServicesYaml(
		t,
		map[string]string{"svc-b": attemptArtifactRouteRequestBodies},
		"hidden_prefixes:\n    - hidden-one\n    - hidden-two\nlb_hidden_prefixes:\n    - control-one\n",
	)
	env, _ := setupTestVaultWithTLS(t, servicesYaml)
	nginxConfig, err := NewNginxConfig(env, nil)
	if err != nil {
		t.Fatal(err)
	}

	for blockName, config := range nginxConfig.Generate() {
		for location, upstream := range map[string]string{
			"location = /hidden-one/sn/attempt-artifact":                   "service-block-svc-b",
			"location = /hidden-two/sn/attempt-artifact":                   "service-block-svc-b",
			"location = /control-one/by/service/svc-b/sn/attempt-artifact": "service-block-svc-b",
			"location = /control-one/by/b/svc-b/g2/sn/attempt-artifact":    "service-block-svc-b-g2",
		} {
			routeLocations := nginxBlocks(config, location)
			if len(routeLocations) == 0 {
				t.Errorf("block %s lacks %s", blockName, location)
			}
			for _, routeLocation := range routeLocations {
				for _, required := range []string{
					"proxy_pass http://" + upstream + "/sn/attempt-artifact;",
					"client_body_buffer_size 1m;",
					"client_body_timeout 60s;",
				} {
					if !strings.Contains(routeLocation, required) {
						t.Errorf("block %s %s lacks %q:\n%s", blockName, location, required, routeLocation)
					}
				}
			}
		}
		for _, unprefixed := range []string{
			"location = /sn/attempt-artifact",
			"location = /by/service/svc-b/sn/attempt-artifact",
			"location = /hidden-one/by/service/svc-b/sn/attempt-artifact",
		} {
			if 0 < len(nginxBlocks(config, unprefixed)) {
				t.Errorf("block %s serves %s", blockName, unprefixed)
			}
		}
	}
}

// A path with both a route_rate_limits and a route_request_bodies entry gets
// one exact location carrying both, as nginx refuses a second exact location
// of the same uri.
func TestNginxConfigRouteRequestBodySharesARouteRateLimitLocation(t *testing.T) {
	servicesYaml := routeRequestBodyServicesYaml(t, map[string]string{
		"svc-b": "" +
			"            route_rate_limits:\n" +
			"                -   path: /sn/attempt-artifact\n" +
			"                    requests_per_minute: 600\n" +
			"                    burst: 60\n" +
			attemptArtifactRouteRequestBodies,
	}, "")
	env, _ := setupTestVaultWithTLS(t, servicesYaml)
	nginxConfig, err := NewNginxConfig(env, nil)
	if err != nil {
		t.Fatal(err)
	}

	for blockName, config := range nginxConfig.Generate() {
		for _, server := range nginxServerBlocks(config) {
			if !strings.Contains(server, "server_name test-svc-b.example.com;") || !strings.Contains(server, "listen 443 ssl;") {
				continue
			}
			routeLocations := nginxBlocks(server, "location = /sn/attempt-artifact")
			if len(routeLocations) != 1 {
				t.Fatalf("block %s svc-b https server has %d /sn/attempt-artifact locations, want 1", blockName, len(routeLocations))
			}
			for _, required := range []string{
				"limit_req zone=route_svc-b_sn_attempt_artifact burst=60 nodelay;",
				"proxy_pass http://service-block-svc-b/sn/attempt-artifact;",
				"client_body_buffer_size 1m;",
				"client_body_timeout 60s;",
			} {
				if strings.Count(routeLocations[0], required) != 1 {
					t.Errorf("block %s /sn/attempt-artifact location does not have %q once:\n%s", blockName, required, routeLocations[0])
				}
			}
		}
	}
}

// A route request body on a streamed path streams its body like the nested
// streamable location it takes the request from, and its buffer, which for a
// streamed body is the http/2 upload window, is the route's. Every proxy
// location still carries exactly one buffering mark, off exactly where the
// body streams.
func TestNginxConfigRouteRequestBodyStreamsAStreamablePath(t *testing.T) {
	servicesYaml := routeRequestBodyServicesYaml(t, map[string]string{"svc-d": uploadArtifactRouteRequestBodies}, "")
	env, _ := setupTestVaultWithTLS(t, servicesYaml)
	nginxConfig, err := NewNginxConfig(env, nil)
	if err != nil {
		t.Fatal(err)
	}

	checkedBlockCount := 0
	for blockName, config := range nginxConfig.Generate() {
		if !strings.Contains(config, "service-block-svc-d") {
			continue
		}
		checkedBlockCount += 1
		for location, upstream := range map[string]string{
			"location = /upload/artifact":                  "service-block-svc-d",
			"location = /by/service/svc-d/upload/artifact": "service-block-svc-d",
			"location = /by/b/svc-d/beta/upload/artifact":  "service-block-svc-d-beta",
		} {
			routeLocations := nginxBlocks(config, location)
			if len(routeLocations) == 0 {
				t.Errorf("block %s lacks %s", blockName, location)
			}
			for _, routeLocation := range routeLocations {
				for _, required := range []string{
					"proxy_pass http://" + upstream + "/upload/artifact;",
					"client_body_buffer_size 1m;",
					"proxy_set_header X-UR-Request-Buffering off;",
					"proxy_request_buffering off;",
				} {
					if strings.Count(routeLocation, required) != 1 {
						t.Errorf("block %s %s does not have %q once:\n%s", blockName, location, required, routeLocation)
					}
				}
			}
		}
		// the other streamed paths keep the nested streamable location
		if len(enclosingLocations(config, `location ~ "^`+streamedPathsRegexTail)) == 0 {
			t.Errorf("block %s lost svc-d's nested streamable location", blockName)
		}

		offCount := strings.Count(config, "proxy_set_header X-UR-Request-Buffering off;")
		clearCount := strings.Count(config, `proxy_set_header X-UR-Request-Buffering "";`)
		streamingCount := strings.Count(config, "proxy_request_buffering off;")
		proxyPassCount := strings.Count(config, "proxy_pass http://")
		if offCount == 0 || offCount != streamingCount {
			t.Errorf("block %s marks %d locations streamed but %d stream", blockName, offCount, streamingCount)
		}
		if offCount+clearCount != proxyPassCount {
			t.Errorf("block %s has %d proxy locations but %d marks", blockName, proxyPassCount, offCount+clearCount)
		}
	}
	if checkedBlockCount == 0 {
		t.Fatal("generated config has no svc-d locations")
	}
}

// A services.yml without route_request_bodies gets no route location, and
// its http block keeps the server-wide body values, so an lb generated from
// it is what it was before the setting existed.
func TestNginxConfigWithoutRouteRequestBodiesHasNoRouteLocation(t *testing.T) {
	servicesYaml, err := testServicesFS.ReadFile("testdata/services.yml")
	if err != nil {
		t.Fatal(err)
	}
	env, _ := setupTestVaultWithTLS(t, servicesYaml)
	nginxConfig, err := NewNginxConfig(env, nil)
	if err != nil {
		t.Fatal(err)
	}
	for blockName, config := range nginxConfig.Generate() {
		if strings.Contains(config, "location = /") {
			t.Errorf("block %s has an exact route location without route_request_bodies", blockName)
		}
		checkServerWideRequestBody(t, blockName, config, "", "", 0)
	}
}

// nginx accepts the generated config with route request bodies: on a
// buffered and a streamed route, merged with a route rate limit, and behind
// hidden route prefixes and the lb's own prefix.
func TestNginxConfigValidationWithRouteRequestBodies(t *testing.T) {
	nginxBinary := nginxConfigValidationBinary(t)

	for _, variant := range []struct {
		serviceSettings map[string]string
		extra           string
	}{
		{
			serviceSettings: map[string]string{
				"svc-b": attemptArtifactRouteRequestBodies,
				"svc-d": uploadArtifactRouteRequestBodies,
			},
		},
		{
			serviceSettings: map[string]string{
				"svc-b": connectControlRouteRateLimits + "" +
					"                -   path: /sn/attempt-artifact\n" +
					"                    requests_per_minute: 600\n" +
					attemptArtifactTimeoutRouteRequestBodies,
			},
			extra: "hidden_prefixes:\n    - hidden-one\n    - hidden-two\n",
		},
	} {
		servicesYaml := nginxServicesWithLongStatusMapKey(t, routeRequestBodyServicesYaml(t, variant.serviceSettings, variant.extra))
		env, vaultDir := setupTestVaultWithTLS(t, servicesYaml)
		nginxConfig, err := NewNginxConfig(env, nil)
		if err != nil {
			t.Fatal(err)
		}
		blockConfigs := nginxConfig.Generate()
		if len(blockConfigs) == 0 {
			t.Fatal("no lb block config generated")
		}
		for block, config := range blockConfigs {
			if !strings.Contains(config, "client_body_timeout 60s;") && !strings.Contains(config, "client_body_buffer_size 1m;") {
				t.Fatalf("block %s has no route request body to validate", block)
			}
			config = localNginxConfig(config, vaultDir)
			tmpDir := t.TempDir()
			confPath := filepath.Join(tmpDir, "nginx.conf")
			if err := os.WriteFile(confPath, []byte(config), 0644); err != nil {
				t.Fatal(err)
			}
			for _, dir := range []string{"logs", "run"} {
				os.MkdirAll(filepath.Join(tmpDir, dir), 0755)
			}
			cmd := exec.Command(nginxBinary, "-t", "-c", confPath, "-p", tmpDir, "-e", filepath.Join(tmpDir, "error.log"))
			if output, err := cmd.CombinedOutput(); err != nil {
				t.Errorf("nginx config validation failed for block %s (extra %q):\n%s\n\nConfig written to: %s", block, variant.extra, string(output), confPath)
			}
		}
	}
}

// Runs the first lb block's generated config in nginx, in front of
// `service`, which every upstream is pointed at, with the lb's ports 80 and
// 443 on loopback ports, and returns the https port. `edit`, when given,
// changes the config text first. nginx runs one worker and stops when the
// test ends.
func runRouteRequestBodyNginx(
	t *testing.T,
	servicesYaml []byte,
	edit func(config string) string,
	service http.Handler,
) (httpsPort int, nginxErrors func() string) {
	t.Helper()
	nginxBinary := nginxConfigValidationBinary(t)

	// without capacity sizing nginx runs one worker
	servicesYamlText := strings.ReplaceAll(string(servicesYaml), "                    concurrent_clients: 786432\n", "")
	servicesYamlText = strings.ReplaceAll(servicesYamlText, "                    cores: 24\n", "")
	env, vaultDir := setupTestVaultWithTLS(t, []byte(servicesYamlText))
	nginxConfig, err := NewNginxConfig(env, nil)
	if err != nil {
		t.Fatal(err)
	}
	blockConfigs := nginxConfig.Generate()
	blocks := slices.Collect(maps.Keys(blockConfigs))
	if len(blocks) == 0 {
		t.Fatal("no lb block config generated")
	}
	sort.Strings(blocks)
	config := localNginxConfig(blockConfigs[blocks[0]], vaultDir)
	// the stream block, last in the config, proxies other ports and is not
	// under test
	if i := strings.Index(config, "\nstream {"); 0 <= i {
		config = config[:i+1]
	}
	if edit != nil {
		config = edit(config)
	}

	dir := t.TempDir()
	// a body larger than its buffer spills to a temp file, which the lb image
	// keeps under /var/cache/nginx and a local nginx in its build prefix
	if !strings.Contains(config, "\nhttp {\n") {
		t.Fatal("generated config has no http block")
	}
	config = strings.Replace(config, "\nhttp {\n", fmt.Sprintf(
		"\nhttp {\n    client_body_temp_path %s;\n    proxy_temp_path %s;\n",
		filepath.Join(dir, "client_body_temp"),
		filepath.Join(dir, "proxy_temp"),
	), 1)

	upstream := httptest.NewServer(service)
	t.Cleanup(upstream.Close)
	config = regexp.MustCompile(`server 127\.0\.0\.1:\d+`).ReplaceAllString(
		config,
		fmt.Sprintf("server 127.0.0.1:%d", upstream.Listener.Addr().(*net.TCPAddr).Port),
	)

	httpPort := freeLoopbackPort(t)
	httpsPort = freeLoopbackPort(t)
	config = loopbackNginxListens(t, config, map[int]int{80: httpPort, 443: httpsPort})

	if err := os.MkdirAll(filepath.Join(dir, "logs"), 0755); err != nil {
		t.Fatal(err)
	}
	confPath := filepath.Join(dir, "nginx.conf")
	if err := os.WriteFile(confPath, []byte(config), 0644); err != nil {
		t.Fatal(err)
	}
	stderrPath := filepath.Join(dir, "stderr")
	stderr, err := os.Create(stderrPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		stderr.Close()
	})
	nginxErrors = func() string {
		data, _ := os.ReadFile(stderrPath)
		errorLog, _ := os.ReadFile(filepath.Join(dir, "error.log"))
		return string(data) + string(errorLog)
	}

	cmd := exec.Command(nginxBinary, "-g", "daemon off;", "-c", confPath, "-p", dir, "-e", filepath.Join(dir, "error.log"))
	cmd.Stdout = stderr
	cmd.Stderr = stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cmd.Process.Signal(syscall.SIGTERM)
		cmd.Wait()
	})

	// a connection shows nginx is up without a request, which would spend a
	// rate limit budget
	for deadline := time.Now().Add(10 * time.Second); ; {
		if conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", httpsPort), time.Second); err == nil {
			conn.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("nginx did not start:\n%s", nginxErrors())
		}
		time.Sleep(50 * time.Millisecond)
	}
	return httpsPort, nginxErrors
}

// A service that reads the whole body and answers its length and sha256.
func bodyDigestService() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hash := sha256.New()
		n, err := io.Copy(hash, r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		fmt.Fprintf(w, "%d %s", n, hex.EncodeToString(hash.Sum(nil)))
	})
}

// The incident, at a compressed time scale: the http block's stall timeout
// is cut to 1 s, and two uploads to svc-b stall 3 s halfway through their
// bodies. The lb drops the one to another route, as it dropped the
// validator's uploads at 15 s, and carries the one to /sn/attempt-artifact,
// whose own 60 s timeout nginx applies because it selects the route's exact
// location. Before route_request_bodies both were dropped.
func TestNginxRouteRequestBodyRidesOutAStallTheServerWideTimeoutCuts(t *testing.T) {
	servicesYaml := routeRequestBodyServicesYaml(t, map[string]string{"svc-b": attemptArtifactTimeoutRouteRequestBodies}, "")
	httpsPort, nginxErrors := runRouteRequestBodyNginx(t, servicesYaml, func(config string) string {
		serverWide := regexp.MustCompile(`(?m)^( *)client_body_timeout 15s;$`)
		if matches := serverWide.FindAllString(config, -1); len(matches) != 1 {
			t.Fatalf("config has %d server-wide client_body_timeout 15s lines, want 1", len(matches))
		}
		return serverWide.ReplaceAllString(config, "${1}client_body_timeout 1s;")
	}, bodyDigestService())

	body := bytes.Repeat([]byte("synthetic attempt artifact "), 100)
	// a POST over http/1.1 that sends half its body, stalls, then sends the
	// rest; the lb's status, or an error when it closed the request without
	// one
	stalledPost := func(path string, stall time.Duration) (int, error) {
		conn, err := tls.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", httpsPort), &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         "test-svc-b.example.com",
			NextProtos:         []string{"http/1.1"},
		})
		if err != nil {
			return 0, err
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(30 * time.Second))
		header := fmt.Sprintf(
			"POST %s HTTP/1.1\r\nHost: test-svc-b.example.com\r\nContent-Type: application/octet-stream\r\nContent-Length: %d\r\nConnection: close\r\n\r\n",
			path,
			len(body),
		)
		half := len(body) / 2
		if _, err := conn.Write(append([]byte(header), body[:half]...)); err != nil {
			return 0, err
		}
		time.Sleep(stall)
		if _, err := conn.Write(body[half:]); err != nil {
			return 0, err
		}
		response, err := http.ReadResponse(bufio.NewReader(conn), nil)
		if err != nil {
			return 0, err
		}
		defer response.Body.Close()
		if _, err := io.Copy(io.Discard, response.Body); err != nil {
			return 0, err
		}
		return response.StatusCode, nil
	}

	type stalledResult struct {
		status int
		err    error
	}
	// both stall at once, so the test waits out one stall
	routeResult := make(chan stalledResult, 1)
	otherResult := make(chan stalledResult, 1)
	go func() {
		status, err := stalledPost("/sn/attempt-artifact", 3*time.Second)
		routeResult <- stalledResult{status: status, err: err}
	}()
	go func() {
		status, err := stalledPost("/other", 3*time.Second)
		otherResult <- stalledResult{status: status, err: err}
	}()

	route := <-routeResult
	if route.err != nil || route.status != http.StatusOK {
		t.Errorf("/sn/attempt-artifact after a 3 s stall: status %d, err %v; want 200 (the route's 60 s timeout)\n%s", route.status, route.err, nginxErrors())
	}
	other := <-otherResult
	if other.err == nil && other.status == http.StatusOK {
		t.Errorf("another route after a 3 s stall: status 200, want the lb to drop it at the server-wide 1 s timeout")
	}
}

// The validator's upload, as the post-deploy check sends it: 4.2 MB over
// http/2 to /sn/attempt-artifact, which reaches the service whole.
func TestNginxRouteRequestBodyTakesALargeHttp2Upload(t *testing.T) {
	servicesYaml := routeRequestBodyServicesYaml(t, map[string]string{"svc-b": attemptArtifactTimeoutRouteRequestBodies}, "")
	httpsPort, nginxErrors := runRouteRequestBodyNginx(t, servicesYaml, nil, bodyDigestService())

	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network string, addr string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, network, fmt.Sprintf("127.0.0.1:%d", httpsPort))
			},
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
			ForceAttemptHTTP2: true,
		},
		Timeout: 60 * time.Second,
	}

	body := bytes.Repeat([]byte("synthetic attempt artifact "), 4200000/len("synthetic attempt artifact "))
	hash := sha256.Sum256(body)
	request, err := http.NewRequest("POST", "https://test-svc-b.example.com/sn/attempt-artifact", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/octet-stream")
	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("upload: %s\n%s", err, nginxErrors())
	}
	defer response.Body.Close()
	answer, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if response.ProtoMajor != 2 {
		t.Fatalf("upload went over %s, want http/2", response.Proto)
	}
	if response.StatusCode != http.StatusOK {
		t.Fatalf("upload: status %d %s\n%s", response.StatusCode, answer, nginxErrors())
	}
	if want := fmt.Sprintf("%d %s", len(body), hex.EncodeToString(hash[:])); string(answer) != want {
		t.Fatalf("the service got %q, want %q", answer, want)
	}
}

// http/2 frame types, flags and the initial window setting (rfc 9113)
const (
	http2FrameHeaders      = 0x1
	http2FrameRstStream    = 0x3
	http2FrameSettings     = 0x4
	http2FramePing         = 0x6
	http2FrameGoaway       = 0x7
	http2FrameWindowUpdate = 0x8

	http2FlagAck        = 0x1
	http2FlagEndHeaders = 0x4

	http2SettingInitialWindowSize = 0x4
)

// The http/2 receive window nginx grants an upload stream: the initial window
// of its settings plus every window update it sends the stream while it
// handles the request's headers, which declare a 4.2 MB body and send none
// of it. A ping sent after the headers is the barrier: nginx runs the request
// as its headers complete and queues its control frames in order, so once its
// ping ack arrives every window update the request caused has arrived first.
func http2UploadWindow(t *testing.T, httpsPort int, host string, path string) int64 {
	t.Helper()
	conn, err := tls.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", httpsPort), &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         host,
		NextProtos:         []string{"h2"},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if conn.ConnectionState().NegotiatedProtocol != "h2" {
		t.Fatalf("negotiated %q, want h2", conn.ConnectionState().NegotiatedProtocol)
	}
	conn.SetDeadline(time.Now().Add(10 * time.Second))

	writeFrame := func(frameType byte, flags byte, streamId uint32, payload []byte) {
		// a 24 bit length, then the type, flags and stream id
		lengthBytes := binary.BigEndian.AppendUint32(nil, uint32(len(payload)))
		frame := append([]byte{}, lengthBytes[1:4]...)
		frame = append(frame, frameType, flags)
		frame = binary.BigEndian.AppendUint32(frame, streamId)
		frame = append(frame, payload...)
		if _, err := conn.Write(frame); err != nil {
			t.Fatal(err)
		}
	}

	// each field a literal without indexing, with a literal name (rfc 7541
	// 6.2.2), every length under the 7 bit prefix
	headerBlock := []byte{}
	for _, field := range [][2]string{
		{":method", "POST"},
		{":scheme", "https"},
		{":authority", host},
		{":path", path},
		{"content-type", "application/octet-stream"},
		{"content-length", "4200000"},
	} {
		for _, s := range field {
			if 127 <= len(s) {
				t.Fatalf("header %q needs a multi-byte length", s)
			}
		}
		headerBlock = append(headerBlock, 0x00, byte(len(field[0])))
		headerBlock = append(headerBlock, field[0]...)
		headerBlock = append(headerBlock, byte(len(field[1])))
		headerBlock = append(headerBlock, field[1]...)
	}

	barrier := []byte("barrier!")
	if _, err := conn.Write([]byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	writeFrame(http2FrameSettings, 0, 0, nil)
	writeFrame(http2FrameHeaders, http2FlagEndHeaders, 1, headerBlock)
	writeFrame(http2FramePing, 0, 0, barrier)

	reader := bufio.NewReader(conn)
	window := int64(65535)
	for {
		header := make([]byte, 9)
		if _, err := io.ReadFull(reader, header); err != nil {
			t.Fatalf("%s %s: no ping ack: %s", host, path, err)
		}
		length := binary.BigEndian.Uint32(append([]byte{0}, header[0:3]...))
		frameType := header[3]
		flags := header[4]
		streamId := binary.BigEndian.Uint32(header[5:9]) & 0x7fffffff
		payload := make([]byte, length)
		if _, err := io.ReadFull(reader, payload); err != nil {
			t.Fatal(err)
		}
		switch frameType {
		case http2FrameSettings:
			if flags&http2FlagAck != 0 {
				continue
			}
			for i := 0; i+6 <= len(payload); i += 6 {
				if binary.BigEndian.Uint16(payload[i:i+2]) == http2SettingInitialWindowSize {
					window = int64(binary.BigEndian.Uint32(payload[i+2 : i+6]))
				}
			}
			writeFrame(http2FrameSettings, http2FlagAck, 0, nil)
		case http2FrameWindowUpdate:
			if streamId == 1 {
				window += int64(binary.BigEndian.Uint32(payload) & 0x7fffffff)
			}
		case http2FrameRstStream, http2FrameGoaway:
			t.Fatalf("%s %s: nginx ended the stream (frame type %d)", host, path, frameType)
		case http2FramePing:
			if flags&http2FlagAck != 0 && bytes.Equal(payload, barrier) {
				return window
			}
		}
	}
}

// The http/2 window nginx grants an upload is the route's buffer only where
// the body streams: svc-d's streamed upload route gets its 1 MiB, its other
// streamed paths the server-wide 64k. For a buffered body nginx lifts the
// stream's flow control (2^31-1) whatever the buffer, so svc-b's buffered
// route uploads at the same window with or without a buffer of its own, and
// /sn/attempt-artifact, which the lb buffers, sets only its stall timeout.
// Before route_request_bodies the streamed upload route had 64k.
func TestNginxHttp2UploadWindowFollowsTheRouteBufferOnlyWhenStreamed(t *testing.T) {
	servicesYaml := routeRequestBodyServicesYaml(t, map[string]string{
		"svc-b": attemptArtifactRouteRequestBodies,
		"svc-d": uploadArtifactRouteRequestBodies,
	}, "")
	httpsPort, nginxErrors := runRouteRequestBodyNginx(t, servicesYaml, nil, bodyDigestService())

	for _, test := range []struct {
		host   string
		path   string
		window int64
	}{
		{host: "test-svc-d.example.com", path: "/upload/artifact", window: 1024 * 1024},
		{host: "test-svc-d.example.com", path: "/upload/other", window: 64 * 1024},
		{host: "test-svc-b.example.com", path: "/sn/attempt-artifact", window: 2147483647},
		{host: "test-svc-b.example.com", path: "/other", window: 2147483647},
	} {
		if window := http2UploadWindow(t, httpsPort, test.host, test.path); window != test.window {
			t.Errorf("%s %s: http/2 upload window %d, want %d\n%s", test.host, test.path, window, test.window, nginxErrors())
		}
	}
}
