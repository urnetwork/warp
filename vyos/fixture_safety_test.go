// Fixture privacy controls retain parser grammar without retaining live data.
package vyos

import (
	"net/netip"
	"regexp"
	"strings"
	"testing"
)

func TestSyntheticParserFixturesContainOnlyDocumentationIdentities(t *testing.T) {
	documentation := []netip.Prefix{
		netip.MustParsePrefix("192.0.2.0/24"),
		netip.MustParsePrefix("198.51.100.0/24"),
		netip.MustParsePrefix("203.0.113.0/24"),
		netip.MustParsePrefix("2001:db8::/32"),
	}
	protocolConstants := map[string]bool{
		"0.0.0.0": true, "127.0.0.1": true, "255.255.255.255": true, "::": true, "::1": true,
	}
	domainPattern := regexp.MustCompile(`[a-zA-Z0-9_-]+(?:\.[a-zA-Z0-9_-]+)*\.(?:com|net|org|io|tech|network|example)`)
	for _, name := range []string{"synthetic-router-a-config.boot", "synthetic-router-b-config.boot"} {
		root := mustParse(t, readFixture(t, name))
		for _, path := range root.Paths() {
			for _, element := range path {
				candidate := strings.SplitN(element, "/", 2)[0]
				if address, err := netip.ParseAddr(candidate); err == nil && !protocolConstants[candidate] {
					allowed := false
					for _, prefix := range documentation {
						allowed = allowed || prefix.Contains(address)
					}
					if !allowed {
						t.Fatalf("%s: non-documentation address in fixture (value withheld)", name)
					}
				}
				for _, domain := range domainPattern.FindAllString(element, -1) {
					if !strings.HasSuffix(domain, ".example") {
						t.Fatalf("%s: non-synthetic domain in fixture (value withheld)", name)
					}
				}
			}
			if len(path) < 2 {
				continue
			}
			field, value := path[len(path)-2], path[len(path)-1]
			switch field {
			case "host-name":
				if !strings.HasPrefix(value, "synthetic-") {
					t.Fatalf("%s: non-synthetic hostname (value withheld)", name)
				}
			case "encrypted-password":
				if value != "$5$synthetic$not-a-password" && value != "$5$synthetic$not*a*password" {
					t.Fatalf("%s: credential is not the test-only sentinel (value withheld)", name)
				}
			case "connection":
				if value != "wss://controller.synthetic.example:443+synthetic-key+allowUntrustedCert" && value != "wss://controller.synthetic.example:443+synthetic-*+allowUntrustedCert" {
					t.Fatalf("%s: connection is not the test-only sentinel (value withheld)", name)
				}
			}
		}
	}
}
