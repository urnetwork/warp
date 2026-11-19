package main

// The opt-in generator of the lb_alt parity harness's fixture (server
// nginx/parity_test.go; LBALT.md §8 step 2). From one synthetic services.yml,
// testdata/lbalt_parity_services.yml, it renders the nginx config of
// edge-a.example's eth1 lb block with NewNginxConfig, and the route file of a
// connect generation on the same host with renderLbAltRouteTable, so the
// pinned lb image and the front are compared on what one services config makes
// of them.
//
// Without LBALT_PARITY_FIXTURE_OUT it only checks that the fixture renders and
// that the two agree (checkLbAltRouteNginxParity). With it naming a directory,
// it also writes nginx.conf and route.json there. The server's copy is
// regenerated from the warp checkout with:
//
//	LBALT_PARITY_FIXTURE_OUT=<server>/nginx/testdata/parity go test -count=1 -run '^TestLbAltParityFixture$' ./warpctl
//
// The vault the generator renders from holds a certificate directory of its
// own for every hostname, and a star directory for every wildcard name, so
// each served name's ssl_certificate path names that name. The harness
// generates certificates at those paths when it runs.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The host, interface and generation the parity fixture is rendered for, and
// the generation's listen ports and addresses. The harness binds the same
// addresses inside its container.
const (
	lbAltParityHost       = "edge-a.example"
	lbAltParityInterface  = "eth1"
	lbAltParityBlock      = "edge-a.example-eth1"
	lbAltParityGeneration = "test-connect-g1-parity"
)

// Renders the parity fixture, checks the two renders agree, and writes them
// when LBALT_PARITY_FIXTURE_OUT names a directory.
func TestLbAltParityFixture(t *testing.T) {
	servicesYaml, err := os.ReadFile(filepath.Join("testdata", "lbalt_parity_services.yml"))
	if err != nil {
		t.Fatal(err)
	}
	env := setupTestVault(t, servicesYaml)
	servicesConfig := getServicesConfig(env)

	// a directory per hostname, so findLatestTls picks each name's own and
	// the config names every served name's certificate by its name
	tlsDir := filepath.Join(os.Getenv("WARP_HOME"), "vault", env, "tls", "1.0.0")
	for _, hostname := range servicesConfig.Hostnames(env, nil) {
		if base, ok := strings.CutPrefix(hostname, "*."); ok {
			generateTestTLSFiles(t, tlsDir, base, true)
		} else {
			generateTestTLSFiles(t, tlsDir, hostname, false)
		}
	}

	nginxConfig, err := NewNginxConfig(env, nil)
	if err != nil {
		t.Fatal(err)
	}
	blockConfig, ok := nginxConfig.Generate()[lbAltParityBlock]
	if !ok {
		t.Fatalf("the nginx generator wrote no config for %s", lbAltParityBlock)
	}

	table, err := renderLbAltRouteTable(&lbAltRouteInputs{
		servicesConfig: servicesConfig,
		env:            env,
		host:           lbAltParityHost,
		generation:     lbAltParityGeneration,
		interfaces: []lbAltRouteInterfaceInput{
			{name: lbAltParityInterface, lbAlt: true, ipv4: "198.51.100.1", ipv6: "2001:db8:1::1"},
		},
		servicePorts: map[int]int{
			lbAltHttpServicePort:   7080,
			lbAltHttpsServicePort:  7443,
			lbAltWhodisServicePort: 7453,
		},
		upstreamIpv4: "192.0.2.1",
		whodisTlds:   []string{"whodis.example."},
	})
	if err != nil {
		t.Fatal(err)
	}
	routeFile, err := encodeLbAltRouteTable(table)
	if err != nil {
		t.Fatal(err)
	}
	checkLbAltRouteNginxParity(t, table, env)

	// the default server, the first lb name's, names its own certificate, at
	// the path in the vault mount the harness writes it to
	if !strings.Contains(blockConfig, " /srv/warp/vault/tls/1.0.0/test-lb.service.example/test-lb.service.example.pem;") {
		t.Errorf("the default server's certificate is not test-lb.service.example's own")
	}

	outDir := os.Getenv("LBALT_PARITY_FIXTURE_OUT")
	if outDir == "" {
		return
	}
	if err := os.MkdirAll(outDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(outDir, "nginx.conf"), []byte(blockConfig), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(outDir, "route.json"), routeFile, 0644); err != nil {
		t.Fatal(err)
	}
	t.Logf("wrote nginx.conf and route.json to %s", outDir)
}
