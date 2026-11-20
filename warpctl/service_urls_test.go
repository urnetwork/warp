package main

// The sidecar blocks' service urls (sidecar DESIGN §19.4): each block's fragment gives it api's url, and the edges
// the sockets service's, as env_vars on the deployment's own domain, https://<service>.${WARP_DOMAIN}, which warpctl
// writes out when it renders the block's unit, since systemd would read ${...} as its own and make it empty.

import (
	"strings"
	"testing"

	"github.com/urnetwork/warp/services"
)

// Every ${WARP_DOMAIN} in a value is written out as the domain; any other ${...} reaches the unit as written, and a
// value with none is unchanged.
func TestExpandEnvVarDomainWritesOutTheDomain(t *testing.T) {
	for _, c := range []struct {
		value string
		want  string
	}{
		{value: "https://api.${WARP_DOMAIN}", want: "https://api.example.com"},
		{value: "${WARP_DOMAIN},${WARP_DOMAIN}", want: "example.com,example.com"},
		{value: "/srv/warp/secrets", want: "/srv/warp/secrets"},
		{value: "${WARP_HOME}/x", want: "${WARP_HOME}/x"},
		{value: "$WARP_DOMAIN", want: "$WARP_DOMAIN"},
		{value: "", want: ""},
	} {
		if got := expandEnvVarDomain(c.value, "example.com"); got != c.want {
			t.Errorf("%q: %q, want %q", c.value, got, c.want)
		}
	}
}

// One lb host with api on it, which the fragments below add their blocks beside.
const serviceUrlsBaseYaml = `
domain: example.com
domains:
    example.com: route53
versions:
-   external_ports: 7000-7200
    internal_ports: 7201-10000
    routing_tables: 100-120
    parallel_block_count: 30
    services_docker_network: testservices
    lb:
        ports:
            - 80
            - 443
        interfaces:
            edge-0.example.com:
                eth0:
                    docker_network: warpeth0
                    ipv4: 10.0.0.1
                    ipv6: "fd00::1"
    services:
        api:
            ports:
                - 80
            blocks:
                - g1: 1
`

// The real evs.yml and tlsedge.yml, applied as the owner applies them: each block's unit hands run its service
// urls with the deployment's domain written out, evs api's and tlsedge api's and the sockets service's, beside the
// domain run hands every block as WARP_DOMAIN, and nothing of ${...} is left for systemd to read.
func TestSidecarBlockUnitsCarryTheirServiceUrls(t *testing.T) {
	fragments := []*services.ServicesFragment{}
	for _, name := range []string{"evs.yml", "tlsedge.yml"} {
		fragments = append(fragments, sidecarBlockFragmentFilled(t, name))
	}
	result, err := services.ApplyServicesFragments([]byte(serviceUrlsBaseYaml), "services.yml", fragments...)
	if err != nil {
		t.Fatal(err)
	}
	env, _ := setupTestVaultWithTLS(t, result.Text)
	hostUnits := NewSystemdUnits(env, "/srv/warp/test", "/usr/local/sbin/warpctl", true).Generate()["edge-0.example.com"]
	for service, wantUrls := range map[string][]string{
		"evs":     {"--envvar=UR_API_URL:https://api.example.com"},
		"tlsedge": {"--envvar=UR_API_URL:https://api.example.com", "--envvar=UR_SOCKETS_URL:https://sockets.example.com"},
	} {
		for _, block := range []string{"beta", "g1"} {
			unit := hostUnits[service][block]
			if unit == nil {
				t.Fatalf("no %s %s unit: %v", service, block, hostUnits)
			}
			fields := strings.Fields(unit.serviceUnit)
			envVars := []string{}
			for _, field := range fields {
				if strings.HasPrefix(field, "--envvar=UR_") {
					envVars = append(envVars, field)
				}
			}
			if strings.Join(envVars, " ") != strings.Join(wantUrls, " ") {
				t.Errorf("the %s %s unit hands run %q, want %q", service, block, envVars, wantUrls)
			}
			for _, want := range []string{"--domain=example.com", "--envvar=WARP_VAULT_HOME:/srv/warp/secrets"} {
				if !strings.Contains(unit.serviceUnit, want) {
					t.Errorf("the %s %s unit lacks %s", service, block, want)
				}
			}
			if strings.Contains(unit.serviceUnit, "${") {
				t.Errorf("the %s %s unit leaves ${...} for systemd:\n%s", service, block, unit.serviceUnit)
			}
		}
	}
}
