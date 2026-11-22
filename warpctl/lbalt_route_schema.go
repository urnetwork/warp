package main

// The route file of an lb_alt connect generation (server/LBALT-IMPL.md §2.1,
// D5): the resolved table connect's front serves the lb interfaces from. The
// worker renders it when it starts the generation's container and never
// rewrites it, and connect parses it strictly at start (server/nginx's
// RouteTable). So the types here are the wire contract of schema version 1:
//   - fields are declared in contract order, with the contract's json names;
//   - every value is resolved, with no services.yml default left to the server;
//   - an empty array is [], never null.
//
// testdata/lbalt_route_v1_example.json, byte for byte the server's
// nginx/testdata/route_v1_example.json, pins the encoding.
//
// The other values the lb_alt deploy shares with connect live here too: how
// the file reaches the container (§2.2), the readiness headers of connect's
// private status (§2.4), and the HMARK parameters of the split (§2.5).

import (
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"

	"github.com/urnetwork/warp/services"
)

// The route file's schema version. connect refuses a file with any other.
const LbAltRouteSchemaVersion = 1

// The env vars a connect generation on an lb_alt host gets (§2.2): the route
// file's path in the container, and the generation, which is the container
// name.
const (
	lbAltRouteFileEnvName  = "WARP_LBALT_ROUTE_FILE"
	lbAltGenerationEnvName = "WARP_GENERATION"
)

// Where the route file is bind-mounted read-only in the container, the value
// of WARP_LBALT_ROUTE_FILE.
const lbAltRouteContainerPath = "/srv/warp/lbalt/route.json"

// Where the worker renders the route file on the host: one directory per
// generation under the worker's warp home (WARP_HOME, /srv/warp/<env> on a
// host), <warp home>/lbalt/<container name>/route.json, written once with
// mode 0444. The directory is removed with the container.
const (
	lbAltRouteHostDirName = "lbalt"
	lbAltRouteFileName    = "route.json"
	lbAltRouteFileMode    = 0444
)

// The headers connect's private status adds when its front is configured
// (§2.4). warpctl reads them from a candidate generation before it switches
// a block's split chain to it.
const (
	// the generation, WARP_GENERATION
	lbAltFrontGenerationHeader = "X-UR-Front-Generation"
	// the lowercase hex sha-256 of the route file's bytes
	lbAltFrontRouteRevisionHeader = "X-UR-Front-Route-Revision"
	// 1 only when the status is ok (not draining), the route file and every
	// certificate are loaded, and every expected socket is up; else 0
	lbAltFrontReadyHeader = "X-UR-Front-Ready"
	// <protocol>/<address>/<port>=<up>/<expected>, comma-separated and sorted
	lbAltFrontSocketsHeader = "X-UR-Front-Sockets"
	// the earliest certificate expiry, rfc 3339 utc
	lbAltFrontCertExpiryHeader = "X-UR-Front-Cert-Expiry"
)

// The HMARK parameters of the lb_alt split (§2.5): a new flow's source
// address hashes into lbAltHmarkMod buckets, marked lbAltHmarkOffset + the
// bucket, clear of the full-value routing fwmarks. The seed is fixed, so a
// restart keeps every address in its bucket. A new tcp flow from a port-hash
// source (services.LbAltPortHashSources; server LBALTOPT2 R16) hashes its
// source port too, the whole port under lbAltHmarkSourcePortMask, into the
// same buckets; its udp flows do not (lbAltPortHashProtocols).
const (
	lbAltHmarkMod            = services.LbAltBucketCount
	lbAltHmarkOffset         = 0x10000
	lbAltHmarkRnd            = 0x4c42414c
	lbAltHmarkSourcePortMask = 0xffff
)

// The route file of one connect generation on one host.
type LbAltRouteTable struct {
	SchemaVersion int    `json:"schema_version"`
	Env           string `json:"env"`
	Host          string `json:"host"`
	// the container name of the generation
	Generation string `json:"generation"`
	// the primary domain first, then the rest sorted
	Domains  []string           `json:"domains"`
	Upstream LbAltRouteUpstream `json:"upstream"`
	Lb       LbAltRouteLb       `json:"lb"`
	// sorted
	NoAccessLog []string `json:"no_access_log"`
	// every non-transparent lb interface of the host, lb_alt or not, sorted
	// by name
	Interfaces []LbAltRouteInterface `json:"interfaces"`
	Listen     LbAltRouteListen      `json:"listen"`
	Front      LbAltRouteFront       `json:"front"`
	// the services the nginx generator fronts on the host, sorted by name
	Services []LbAltRouteService `json:"services"`
}

// The services bridge the upstream blocks are reached on.
type LbAltRouteUpstream struct {
	// the docker network name, which keys nginx's consistent-hash ring
	// (<host>:<port>)
	Host string `json:"host"`
	Ipv4 string `json:"ipv4"`
}

// The lb names and their hidden routes.
type LbAltRouteLb struct {
	// in DomainNames order: the first is the tcp default server
	Names []string `json:"names"`
	// "/" + each hidden prefix, or [""] when there is none
	RoutePrefixes []string `json:"route_prefixes"`
}

// One lb interface of the host.
type LbAltRouteInterface struct {
	Name string `json:"name"`
	// the interface's lb block, <host>-<interface>
	Block string `json:"block"`
	// informational for connect, which binds every interface
	LbAlt bool `json:"lb_alt"`
	// the interface docker network's bridge addresses; "" when the family is
	// absent
	Ipv4      string              `json:"ipv4"`
	Ipv6      string              `json:"ipv6"`
	RateLimit LbAltRouteRateLimit `json:"rate_limit"`
}

// An interface's resolved per-address limits, nginx's zones of that
// interface.
type LbAltRouteRateLimit struct {
	// requests_per_second converted to a minute rate; may be fractional
	RequestsPerMinute float64 `json:"requests_per_minute"`
	Burst             int     `json:"burst"`
	NetConnections    int     `json:"net_connections"`
	// sorted
	ExcludeSubnets []string `json:"exclude_subnets"`
	// The front's limit per verified identity (services RateLimit), omitted
	// while off so a route file without it keeps its bytes and revision.
	IdentityRequestsPerMinute float64 `json:"identity_requests_per_minute,omitempty"`
	IdentityBurst             int     `json:"identity_burst,omitempty"`
	IdentityAddressFactor     int     `json:"identity_address_factor,omitempty"`
}

// connect's maxRouteIdentityAddressFactor (server nginx/route.go).
const lbAltRouteMaxIdentityAddressFactor = 1000

// The generation's internal ports, from WARP_PORTS.
type LbAltRouteListen struct {
	// service port 80
	HttpPort int `json:"http_port"`
	// service port 443, for tcp
	HttpsPort int `json:"https_port"`
	// service port 443, for udp
	QuicPort int `json:"quic_port"`
	// service port 4053
	WhodisPort int `json:"whodis_port"`
}

// The services the front treats specially, and the whodis tlds.
type LbAltRouteFront struct {
	ConnectService string `json:"connect_service"`
	ApiService     string `json:"api_service"`
	// sorted
	WhodisTlds []string `json:"whodis_tlds"`
}

// One service the front routes to. Every list is sorted, the structured ones
// by name or path.
type LbAltRouteService struct {
	Name      string `json:"name"`
	Exposed   bool   `json:"exposed"`
	LbExposed bool   `json:"lb_exposed"`
	// the raw services.yml status mode; "standard" denies /status on the
	// service names
	Status string `json:"status"`
	// the exact served names, in nginx's server_name forms
	Names           []string                  `json:"names"`
	RedirectAliases []LbAltRouteRedirectAlias `json:"redirect_aliases"`
	// the resolved allowlist; "*" is the wildcard mode
	CorsOrigins     []string `json:"cors_origins"`
	Websocket       bool     `json:"websocket"`
	Streamable      bool     `json:"streamable"`
	StreamablePaths []string `json:"streamable_paths"`
	Stateful        bool     `json:"stateful"`
	// "/" + each hidden prefix (the top-level ones, then the service's), or
	// [""] when there is none
	RoutePrefixes      []string                    `json:"route_prefixes"`
	RouteRateLimits    []LbAltRoutePathRateLimit   `json:"route_rate_limits"`
	RouteRequestBodies []LbAltRoutePathRequestBody `json:"route_request_bodies"`
	NoSuccessAccessLog []string                    `json:"no_success_access_log"`
	Keepalive          LbAltRouteKeepalive         `json:"keepalive"`
	// in services.ServiceBlockWeights order
	Blocks []LbAltRouteBlock `json:"blocks"`
}

// A redirect alias: the front answers 301 to the same scheme and uri on the
// target host.
type LbAltRouteRedirectAlias struct {
	Name   string `json:"name"`
	Target string `json:"target"`
}

// One exact route's own per-address limit (services.RouteRateLimit).
type LbAltRoutePathRateLimit struct {
	Path string `json:"path"`
	// requests_per_second converted to a minute rate; may be fractional
	RequestsPerMinute float64 `json:"requests_per_minute"`
	Burst             int     `json:"burst"`
}

// One exact route's own body buffer and stall timeout
// (services.RouteRequestBody), resolved.
type LbAltRoutePathRequestBody struct {
	Path string `json:"path"`
	// bytes
	ClientBodyBufferSize     int64 `json:"client_body_buffer_size"`
	ClientBodyTimeoutSeconds int   `json:"client_body_timeout_seconds"`
}

// The resolved upstream keepalive of a service; connections 0 means none.
type LbAltRouteKeepalive struct {
	Connections    int `json:"connections"`
	Requests       int `json:"requests"`
	TimeSeconds    int `json:"time_seconds"`
	TimeoutSeconds int `json:"timeout_seconds"`
}

// One upstream block of a service.
type LbAltRouteBlock struct {
	Name   string `json:"name"`
	Weight int    `json:"weight"`
	// the block's stable external port for service port 80, on the
	// upstream's address
	Port int `json:"port"`
}

// The route file's exact bytes: json.MarshalIndent(table, "", "  ") and a
// newline, the encoding both repos produce and compare. It refuses a table
// of another schema version, and a table with a null anywhere, which is how
// a nil slice encodes, since connect's strict parser refuses both.
func encodeLbAltRouteTable(table *LbAltRouteTable) ([]byte, error) {
	if table == nil {
		return nil, errors.New("lbalt route table is missing")
	}
	if table.SchemaVersion != LbAltRouteSchemaVersion {
		return nil, fmt.Errorf("lbalt route table has schema version %d, not %d", table.SchemaVersion, LbAltRouteSchemaVersion)
	}
	data, err := json.MarshalIndent(table, "", "  ")
	if err != nil {
		return nil, err
	}

	var decoded any
	if err := json.Unmarshal(data, &decoded); err != nil {
		return nil, err
	}
	// the path of the first null, keys in sorted order
	var findNull func(value any, path string) (string, bool)
	findNull = func(value any, path string) (string, bool) {
		switch v := value.(type) {
		case nil:
			return path, true
		case map[string]any:
			for _, key := range slices.Sorted(maps.Keys(v)) {
				keyPath := key
				if path != "" {
					keyPath = path + "." + key
				}
				if nullPath, ok := findNull(v[key], keyPath); ok {
					return nullPath, true
				}
			}
		case []any:
			for i, element := range v {
				if nullPath, ok := findNull(element, fmt.Sprintf("%s[%d]", path, i)); ok {
					return nullPath, true
				}
			}
		}
		return "", false
	}
	if nullPath, ok := findNull(decoded, ""); ok {
		return nil, fmt.Errorf("lbalt route table %s is null; an empty array must be []", nullPath)
	}
	return append(data, '\n'), nil
}
