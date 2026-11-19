package main

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func readLbAltRouteExample(t *testing.T) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "lbalt_route_v1_example.json"))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// Decodes a route file strictly, as connect does: no unknown field, and
// nothing after the table.
func decodeLbAltRouteTable(t *testing.T, data []byte) *LbAltRouteTable {
	t.Helper()
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var table LbAltRouteTable
	if err := decoder.Decode(&table); err != nil {
		t.Fatal(err)
	}
	if _, err := decoder.Token(); err != io.EOF {
		t.Fatalf("the route file goes on after its table: %v", err)
	}
	return &table
}

// The shared example decodes into the route types with no unknown field and
// encodes back to the same bytes, so the types declare every field of schema
// version 1, in contract order, with the contract's names.
func TestLbAltRouteTableRoundTripsTheSharedExample(t *testing.T) {
	data := readLbAltRouteExample(t)
	encoded, err := encodeLbAltRouteTable(decodeLbAltRouteTable(t, data))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(encoded, data) {
		return
	}
	exampleLines := strings.Split(string(data), "\n")
	encodedLines := strings.Split(string(encoded), "\n")
	for i := range max(len(exampleLines), len(encodedLines)) {
		exampleLine := ""
		if i < len(exampleLines) {
			exampleLine = exampleLines[i]
		}
		encodedLine := ""
		if i < len(encodedLines) {
			encodedLine = encodedLines[i]
		}
		if encodedLine != exampleLine {
			t.Fatalf("line %d is %q, the example's is %q", i+1, encodedLine, exampleLine)
		}
	}
	t.Fatal("the encoding differs from the example")
}

// requests_per_minute may be fractional (a converted per-second rate), and
// round-trips as the same json number.
func TestLbAltRouteTableCarriesAFractionalRate(t *testing.T) {
	table := decodeLbAltRouteTable(t, readLbAltRouteExample(t))
	table.Interfaces[0].RateLimit.RequestsPerMinute = 7.5
	table.Services[0].RouteRateLimits[0].RequestsPerMinute = 12000.25
	encoded, err := encodeLbAltRouteTable(table)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"requests_per_minute": 7.5,`, `"requests_per_minute": 12000.25,`} {
		if !bytes.Contains(encoded, []byte(want)) {
			t.Fatalf("the encoding has no %s", want)
		}
	}
	decoded := decodeLbAltRouteTable(t, encoded)
	if got := decoded.Interfaces[0].RateLimit.RequestsPerMinute; got != 7.5 {
		t.Fatalf("interface requests_per_minute = %v, want 7.5", got)
	}
	if got := decoded.Services[0].RouteRateLimits[0].RequestsPerMinute; got != 12000.25 {
		t.Fatalf("route requests_per_minute = %v, want 12000.25", got)
	}
}

// A nil slice encodes as null, which connect's parser refuses, so the
// encoder refuses it and names where it is.
func TestEncodeLbAltRouteTableRefusesNull(t *testing.T) {
	cases := []struct {
		name  string
		clear func(table *LbAltRouteTable)
		want  string
	}{
		{
			name:  "domains",
			clear: func(table *LbAltRouteTable) { table.Domains = nil },
			want:  "lbalt route table domains is null",
		},
		{
			name:  "the lb route prefixes",
			clear: func(table *LbAltRouteTable) { table.Lb.RoutePrefixes = nil },
			want:  "lbalt route table lb.route_prefixes is null",
		},
		{
			name:  "an interface's excluded subnets",
			clear: func(table *LbAltRouteTable) { table.Interfaces[1].RateLimit.ExcludeSubnets = nil },
			want:  "lbalt route table interfaces[1].rate_limit.exclude_subnets is null",
		},
		{
			name:  "a service's redirect aliases",
			clear: func(table *LbAltRouteTable) { table.Services[1].RedirectAliases = nil },
			want:  "lbalt route table services[1].redirect_aliases is null",
		},
		{
			name:  "the services",
			clear: func(table *LbAltRouteTable) { table.Services = nil },
			want:  "lbalt route table services is null",
		},
	}
	for _, c := range cases {
		table := decodeLbAltRouteTable(t, readLbAltRouteExample(t))
		c.clear(table)
		encoded, err := encodeLbAltRouteTable(table)
		if err == nil {
			t.Errorf("%s: a null encoded: %s", c.name, encoded)
			continue
		}
		if !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err = %v, want %q", c.name, err, c.want)
		}
	}
}

// connect parses only schema version 1, so the encoder writes no other.
func TestEncodeLbAltRouteTableRefusesAnotherSchemaVersion(t *testing.T) {
	for _, schemaVersion := range []int{0, 2} {
		table := decodeLbAltRouteTable(t, readLbAltRouteExample(t))
		table.SchemaVersion = schemaVersion
		if _, err := encodeLbAltRouteTable(table); err == nil || !strings.Contains(err.Error(), "schema version") {
			t.Errorf("schema version %d: err = %v, want a refusal", schemaVersion, err)
		}
	}
	if _, err := encodeLbAltRouteTable(nil); err == nil {
		t.Error("a missing table encoded")
	}
}

// The values connect and the lb unit share with warpctl, as the contract
// spells them (server/LBALT-IMPL.md §2.2, §2.4 and §2.5).
func TestLbAltContractValues(t *testing.T) {
	cases := []struct {
		name string
		got  any
		want any
	}{
		{name: "schema version", got: LbAltRouteSchemaVersion, want: 1},
		{name: "route file env", got: lbAltRouteFileEnvName, want: "WARP_LBALT_ROUTE_FILE"},
		{name: "generation env", got: lbAltGenerationEnvName, want: "WARP_GENERATION"},
		{name: "container path", got: lbAltRouteContainerPath, want: "/srv/warp/lbalt/route.json"},
		{name: "host route path", got: filepath.Join("/srv/warp/test", lbAltRouteHostDirName, "test-connect-g1-0123456789abcdef", lbAltRouteFileName), want: "/srv/warp/test/lbalt/test-connect-g1-0123456789abcdef/route.json"},
		{name: "route file mode", got: os.FileMode(lbAltRouteFileMode), want: os.FileMode(0444)},
		{name: "generation header", got: lbAltFrontGenerationHeader, want: "X-UR-Front-Generation"},
		{name: "route revision header", got: lbAltFrontRouteRevisionHeader, want: "X-UR-Front-Route-Revision"},
		{name: "ready header", got: lbAltFrontReadyHeader, want: "X-UR-Front-Ready"},
		{name: "sockets header", got: lbAltFrontSocketsHeader, want: "X-UR-Front-Sockets"},
		{name: "certificate expiry header", got: lbAltFrontCertExpiryHeader, want: "X-UR-Front-Cert-Expiry"},
		{name: "hmark mod", got: lbAltHmarkMod, want: 100},
		{name: "hmark offset", got: lbAltHmarkOffset, want: 0x10000},
		{name: "hmark seed", got: lbAltHmarkRnd, want: 0x4c42414c},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("%s = %v, want %v", c.name, c.got, c.want)
		}
	}
}
