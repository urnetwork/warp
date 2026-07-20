package main

import (
	"net"
	"testing"

	"github.com/coreos/go-semver/semver"
	"github.com/go-playground/assert/v2"
)

// tests for the moved common helpers (ParseByteCount, ExpandPorts,
// ExpandAnyPorts, ExpandPortConfigPorts) live in the parent warp package

func oldGateway(ipNet net.IPNet) net.IP {
	ip := ipNet.IP.Mask(ipNet.Mask)
	ip[len(ip)-1] |= 0x01
	return ip
}

func TestGateway(t *testing.T) {
	tests := []struct {
		cidr string
	}{
		{"10.0.0.0/24"},
		{"10.0.0.0/16"},
		{"192.168.1.0/24"},
		{"172.16.0.0/12"},
		{"10.100.0.0/30"},
		{"fd00::/64"},
		{"2001:470:173:52::/64"},
		{"fd00:f1a4:349b:bc6e::/112"},
	}
	for _, tt := range tests {
		_, ipNet, err := net.ParseCIDR(tt.cidr)
		assert.Equal(t, err, nil)
		old := oldGateway(*ipNet)
		got := gateway(*ipNet)
		assert.Equal(t, old.Equal(got), true)
	}
}

func TestContainerIdsEqual(t *testing.T) {
	tests := []struct {
		a, b string
		want bool
	}{
		{"abc123def456", "abc123def456", true},
		{"abc123def456", "abc123", true},
		{"abc123", "abc123def456", true},
		{"abc", "abd", false},
		{"abc123", "xyz789", false},
		{"", "abc123", false},
		{"abc123", "", false},
		{"", "", false},
		{"a", "a", true},
		{"a", "b", false},
	}
	for _, tt := range tests {
		assert.Equal(t, containerIdsEqual(tt.a, tt.b), tt.want)
	}
}

func TestSemverCmpWithBuild(t *testing.T) {
	tests := []struct {
		a, b string
		want int
	}{
		{"1.0.0", "1.0.0", 0},
		{"1.0.0", "2.0.0", -1},
		{"2.0.0", "1.0.0", 1},
		{"1.0.0", "1.1.0", -1},
		{"1.0.0", "1.0.1", -1},
		// metadata breaks ties
		{"1.0.0+100", "1.0.0+200", -1},
		{"1.0.0+200", "1.0.0+100", 1},
		{"1.0.0+100", "1.0.0+100", 0},
		// metadata is string-compared (lexicographic)
		{"1.0.0+9", "1.0.0+10", 1},
		// major.minor.patch takes precedence over metadata
		{"1.0.0+999", "2.0.0+1", -1},
		// prerelease is ignored — same major.minor.patch compares metadata only
		{"1.0.0-beta+100", "1.0.0-rc+100", 0},
		{"1.0.0-beta+100", "1.0.0-rc+200", -1},
	}
	for _, tt := range tests {
		a := *semver.Must(semver.NewVersion(tt.a))
		b := *semver.Must(semver.NewVersion(tt.b))
		assert.Equal(t, semverCmpWithBuild(a, b), tt.want)
	}
}

func TestSemverSortWithBuild(t *testing.T) {
	versions := []semver.Version{
		*semver.Must(semver.NewVersion("2.0.0+300")),
		*semver.Must(semver.NewVersion("1.0.0+200")),
		*semver.Must(semver.NewVersion("1.0.0+100")),
		*semver.Must(semver.NewVersion("3.0.0+50")),
		*semver.Must(semver.NewVersion("1.0.0+300")),
	}

	semverSortWithBuild(versions)

	want := []string{
		"1.0.0+100",
		"1.0.0+200",
		"1.0.0+300",
		"2.0.0+300",
		"3.0.0+50",
	}
	for i, v := range versions {
		assert.Equal(t, v.String(), want[i])
	}
}

func TestSemverSortWithBuildPicksLatest(t *testing.T) {
	// simulate the pattern used in findLatestTls and deploy:
	// sort, then take the last element as "latest"
	versions := []semver.Version{
		*semver.Must(semver.NewVersion("0.1.0+1700000000")),
		*semver.Must(semver.NewVersion("0.1.0+1700000100")),
		*semver.Must(semver.NewVersion("0.2.0+1700000050")),
	}

	semverSortWithBuild(versions)
	latest := versions[len(versions)-1]
	assert.Equal(t, latest.String(), "0.2.0+1700000050")
}
