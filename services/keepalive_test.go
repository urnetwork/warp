// Tests of reading an upstream keepalive as nginx applies it
// (Keepalive.Resolve), the form load's lb_alt checks and warpctl's lb_alt
// route file share.
package services

import (
	"strings"
	"testing"
)

// keepalive_time and keepalive_timeout are nginx's time syntax for a
// millisecond directive, read as whole seconds.
func TestParseNginxTimeSecondsReadsNginxTimes(t *testing.T) {
	cases := []struct {
		value   string
		seconds int
		ok      bool
	}{
		{value: "15m", seconds: 900, ok: true},
		{value: "1m", seconds: 60, ok: true},
		{value: "60", seconds: 60, ok: true},
		{value: "75s", seconds: 75, ok: true},
		{value: "1h30m", seconds: 5400, ok: true},
		{value: "1h 30m", seconds: 5400, ok: true},
		{value: "1d", seconds: 86400, ok: true},
		{value: "1w", seconds: 604800, ok: true},
		{value: "1m30", seconds: 90, ok: true},
		{value: "2000ms", seconds: 2, ok: true},
		{value: "1s500ms", seconds: 0, ok: false},
		{value: "0", seconds: 0, ok: true},
		{value: "", seconds: 0, ok: false},
		{value: "m", seconds: 0, ok: false},
		{value: "1M", seconds: 0, ok: false},
		{value: "1y", seconds: 0, ok: false},
		{value: "1m1h", seconds: 0, ok: false},
		{value: "1m1m", seconds: 0, ok: false},
		{value: "1 m", seconds: 0, ok: false},
		{value: "-1m", seconds: 0, ok: false},
		{value: "1.5m", seconds: 0, ok: false},
		{value: "99999999999999999999", seconds: 0, ok: false},
	}
	for _, c := range cases {
		seconds, err := parseNginxTimeSeconds(c.value)
		if c.ok != (err == nil) || seconds != c.seconds {
			t.Errorf("parseNginxTimeSeconds(%q) = %d, %v; want %d, ok %v", c.value, seconds, err, c.seconds, c.ok)
		}
	}
}

// Keepalives nginx applies alike resolve alike: times spelled apart but read
// alike, and every keepalive without connections, whose other values nginx
// never reads, even ones it could not parse. With connections, a time nginx
// would not read is refused, named by its directive.
func TestKeepaliveResolveReadsTheKeepaliveAsNginxApplies(t *testing.T) {
	none := ResolvedKeepalive{Connections: 0, Requests: 0, TimeSeconds: 0, TimeoutSeconds: 0}
	cases := []struct {
		name      string
		keepalive Keepalive
		want      ResolvedKeepalive
	}{
		{
			name:      "DefaultKeepalive",
			keepalive: *DefaultKeepalive(),
			want:      ResolvedKeepalive{Connections: 1024, Requests: 8192, TimeSeconds: 900, TimeoutSeconds: 60},
		},
		{
			name:      "DefaultKeepalive in seconds",
			keepalive: Keepalive{Keepalive: 1024, KeepaliveRequests: 8192, KeepaliveTime: "900s", KeepaliveTimeout: "60"},
			want:      ResolvedKeepalive{Connections: 1024, Requests: 8192, TimeSeconds: 900, TimeoutSeconds: 60},
		},
		{
			name:      "2m and 30s",
			keepalive: Keepalive{Keepalive: 64, KeepaliveRequests: 512, KeepaliveTime: "2m", KeepaliveTimeout: "30s"},
			want:      ResolvedKeepalive{Connections: 64, Requests: 512, TimeSeconds: 120, TimeoutSeconds: 30},
		},
		{
			name:      "120000ms and 30",
			keepalive: Keepalive{Keepalive: 64, KeepaliveRequests: 512, KeepaliveTime: "120000ms", KeepaliveTimeout: "30"},
			want:      ResolvedKeepalive{Connections: 64, Requests: 512, TimeSeconds: 120, TimeoutSeconds: 30},
		},
		{
			name:      "no connections",
			keepalive: Keepalive{Keepalive: 0, KeepaliveRequests: 5, KeepaliveTime: "2m", KeepaliveTimeout: "30s"},
			want:      none,
		},
		{
			name:      "negative connections and unreadable times",
			keepalive: Keepalive{Keepalive: -1, KeepaliveRequests: 5, KeepaliveTime: "soon", KeepaliveTimeout: ""},
			want:      none,
		},
	}
	for _, c := range cases {
		got, err := c.keepalive.Resolve()
		if err != nil || got != c.want {
			t.Errorf("%s: Resolve() = %+v, %v; want %+v", c.name, got, err, c.want)
		}
	}

	refusedCases := []struct {
		name      string
		keepalive Keepalive
		want      string
	}{
		{
			name:      "no keepalive_time",
			keepalive: Keepalive{Keepalive: 16, KeepaliveRequests: 0, KeepaliveTime: "", KeepaliveTimeout: "30s"},
			want:      `keepalive_time: "" is not an nginx time`,
		},
		{
			name:      "a keepalive_timeout of a fraction of a second",
			keepalive: Keepalive{Keepalive: 16, KeepaliveRequests: 100, KeepaliveTime: "2m", KeepaliveTimeout: "1500ms"},
			want:      `keepalive_timeout: nginx time "1500ms" is not a whole number of seconds`,
		},
	}
	for _, c := range refusedCases {
		got, err := c.keepalive.Resolve()
		if err == nil || !strings.Contains(err.Error(), c.want) || got != none {
			t.Errorf("%s: Resolve() = %+v, %v; want none and an error with %q", c.name, got, err, c.want)
		}
	}
}
