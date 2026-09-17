package main

import (
	"strings"
	"testing"
)

// enclosingLocations reports, for every line of config equal to nestedLine,
// the location line that encloses it: the nearest preceding line with less
// indentation that opens a location. Generated blocks indent by four per
// level, so the enclosing block is the one the nested location was emitted
// inside of.
func enclosingLocations(config string, nestedLine string) []string {
	lines := strings.Split(config, "\n")
	indentOf := func(line string) int {
		return len(line) - len(strings.TrimLeft(line, " "))
	}
	enclosing := []string{}
	for i, line := range lines {
		if strings.TrimSpace(line) != nestedLine {
			continue
		}
		indent := indentOf(line)
		outer := ""
		for j := i - 1; 0 <= j; j-- {
			if indentOf(lines[j]) < indent && strings.HasPrefix(strings.TrimSpace(lines[j]), "location ") {
				outer = strings.TrimSpace(lines[j])
				break
			}
		}
		enclosing = append(enclosing, outer)
	}
	return enclosing
}

const streamedPathsRegexTail = `(?:(?:/upload/.*)|(?:/blob/[^/]+))$" {`

// streamable_paths streams the request body of the matching paths only. Each
// proxy location of the service nests one regex location that composes the
// service-relative patterns behind that location's prefix, strips the prefix
// itself (a regex location cannot use the prefix form of proxy_pass), and
// marks the request for the service; every other proxy location clears the
// mark. With a hidden prefix the composed regex and the rewrite carry it.
func TestNginxStreamablePathsNestRegexLocations(t *testing.T) {
	servicesYaml, err := testServicesFS.ReadFile("testdata/services.yml")
	if err != nil {
		t.Fatal(err)
	}
	servicesYaml = []byte(strings.Replace(
		string(servicesYaml),
		"domains:\n    example.com: route53\n",
		"domains:\n    example.com: route53\nhidden_prefixes:\n    - svc-one\nlb_hidden_prefixes:\n    - control-one\n",
		1,
	))

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
		checkedBlockCount++

		for nested, outer := range map[string]string{
			`location ~ "^/control-one/by/service/svc-d` + streamedPathsRegexTail: "location /control-one/by/service/svc-d/ {",
			`location ~ "^/control-one/by/b/svc-d/beta` + streamedPathsRegexTail:  "location /control-one/by/b/svc-d/beta/ {",
			`location ~ "^/svc-one` + streamedPathsRegexTail:                      "location /svc-one/ {",
		} {
			enclosing := enclosingLocations(config, nested)
			if len(enclosing) == 0 {
				t.Errorf("block %s lacks the nested location %s", blockName, nested)
			}
			for _, location := range enclosing {
				if location != outer {
					t.Errorf("block %s nests %s inside %q, want %q", blockName, nested, location, outer)
				}
			}
		}

		for _, required := range []string{
			`rewrite "^/control-one/by/service/svc-d(/.*)$" $1 break;`,
			`rewrite "^/control-one/by/b/svc-d/beta(/.*)$" $1 break;`,
			`rewrite "^/svc-one(/.*)$" $1 break;`,
			"proxy_pass http://service-block-svc-d;",
			"proxy_pass http://service-block-svc-d-beta;",
		} {
			if !strings.Contains(config, required) {
				t.Errorf("block %s is missing %q", blockName, required)
			}
		}

		// the buffered location keeps its prefix-form proxy_pass; the nested
		// location is what streams
		if !strings.Contains(config, "proxy_pass http://service-block-svc-d/;") {
			t.Errorf("block %s lost the buffered svc-d location", blockName)
		}

		// every proxy location carries exactly one mark, and the mark is off
		// exactly where the body streams
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

// Without a hidden prefix the service host location is the root, so the
// nested location has no prefix to compose or strip: the regex is the bare
// alternation and there is no rewrite. The lb locations still have their
// by/service and by/b prefixes.
func TestNginxStreamablePathsAtRootRewriteNothing(t *testing.T) {
	servicesYaml, err := testServicesFS.ReadFile("testdata/services.yml")
	if err != nil {
		t.Fatal(err)
	}

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
		checkedBlockCount++

		root := `location ~ "^` + streamedPathsRegexTail
		enclosing := enclosingLocations(config, root)
		if len(enclosing) == 0 {
			t.Errorf("block %s lacks the root nested location", blockName)
		}
		for _, location := range enclosing {
			if location != "location / {" {
				t.Errorf("block %s nests the root streamed location inside %q", blockName, location)
			}
		}
		if strings.Contains(config, `rewrite "^(/.*)$"`) {
			t.Errorf("block %s rewrites the root location", blockName)
		}

		lb := `location ~ "^/by/service/svc-d` + streamedPathsRegexTail
		for _, location := range enclosingLocations(config, lb) {
			if location != "location /by/service/svc-d/ {" {
				t.Errorf("block %s nests the lb streamed location inside %q", blockName, location)
			}
		}
		if !strings.Contains(config, `rewrite "^/by/service/svc-d(/.*)$" $1 break;`) {
			t.Errorf("block %s does not strip the lb prefix", blockName)
		}
	}
	if checkedBlockCount == 0 {
		t.Fatal("generated config has no svc-d locations")
	}
}

// The composed regex is one nginx token: the location prefix is quoted as a
// literal, each pattern is its own alternative, and the quoting escapes what
// nginx's tokenizer would otherwise collapse.
func TestNginxStreamablePathsRegexAndQuoting(t *testing.T) {
	if got := streamablePathsRegex("/p-1", []string{"/a", "/b/[^/]+"}); got != `^/p-1(?:(?:/a)|(?:/b/[^/]+))$` {
		t.Fatalf("regex = %s", got)
	}
	if got := streamablePathsRegex("", []string{"/a"}); got != `^(?:(?:/a))$` {
		t.Fatalf("root regex = %s", got)
	}
	if got := nginxQuotedString(`/a\d+/"x"`); got != `"/a\\d+/\"x\""` {
		t.Fatalf("quoted = %s", got)
	}
}
