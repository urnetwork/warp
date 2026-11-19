package main

import (
	"net/url"
	"strings"
	"testing"
)

// parseIni reads grafana.ini's sections and keys, the last value of a key
// winning as in Grafana's own reader.
func parseIni(t *testing.T, ini string) map[string]map[string]string {
	t.Helper()
	sections := map[string]map[string]string{"": {}}
	section := ""
	for _, line := range strings.Split(ini, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case line == "" || strings.HasPrefix(line, ";") || strings.HasPrefix(line, "#"):
		case strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]"):
			section = strings.TrimSuffix(strings.TrimPrefix(line, "["), "]")
			if _, ok := sections[section]; !ok {
				sections[section] = map[string]string{}
			}
		default:
			key, value, ok := strings.Cut(line, "=")
			if !ok {
				t.Fatalf("grafana.ini line %q is not key = value", line)
			}
			sections[section][strings.TrimSpace(key)] = strings.TrimSpace(value)
		}
	}
	return sections
}

// The login session cookie is host-only, HTTPS-only and same-site strict
// (Grafana's security hardening guide): no other primary.example host, an
// extender's among them, can set, overwrite or receive it.
func TestGrafanaSessionCookieIsHardened(t *testing.T) {
	ini := parseIni(t, renderGrafanaIni(3000, "main-grafana.primary.example", "[database]\ntype = sqlite3", "", "", "password", ""))
	for _, setting := range []struct{ section, key, want string }{
		{"auth", "login_cookie_name", "__Host-grafana_session"},
		{"security", "cookie_secure", "true"},
		{"security", "cookie_samesite", "strict"},
	} {
		if got := ini[setting.section][setting.key]; got != setting.want {
			t.Errorf("[%s] %s = %q, want %q", setting.section, setting.key, got, setting.want)
		}
	}
	// a __Host- cookie must have Path=/ and no Domain, or browsers refuse it
	for _, setting := range []struct{ section, key string }{
		{"security", "cookie_domain"},
		{"server", "cookie_domain"},
		{"server", "serve_from_sub_path"},
	} {
		if value, ok := ini[setting.section][setting.key]; ok {
			t.Errorf("[%s] %s = %q: a __Host- cookie needs the host's root and no domain", setting.section, setting.key, value)
		}
	}
	rootUrl, err := url.Parse(ini["server"]["root_url"])
	if err != nil || rootUrl.Scheme != "https" || rootUrl.Path != "/" {
		t.Errorf("root_url %q must be https at the host's root for a __Host- cookie", ini["server"]["root_url"])
	}
	// OAuth and SAML logins need SameSite=lax; this Grafana has its own form only
	for section := range ini {
		if strings.HasPrefix(section, "auth.") {
			t.Errorf("[%s] configures an external login, which cookie_samesite = strict breaks", section)
		}
	}
}
