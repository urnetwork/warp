package main

import (
	"net"
	"slices"
	"testing"

	"github.com/coreos/go-semver/semver"
	"github.com/go-playground/assert/v2"
)

func TestByteCount(t *testing.T) {
	assert.Equal(t, ByteCountHumanReadable(ByteCount(0)), "0b")
	assert.Equal(t, ByteCountHumanReadable(ByteCount(5*1024*1024*1024*1024)), "5tib")

	count, err := ParseByteCount("2")
	assert.Equal(t, err, nil)
	assert.Equal(t, count, ByteCount(2))
	assert.Equal(t, ByteCountHumanReadable(count), "2b")

	count, err = ParseByteCount("5B")
	assert.Equal(t, err, nil)
	assert.Equal(t, count, ByteCount(5))
	assert.Equal(t, ByteCountHumanReadable(count), "5b")

	count, err = ParseByteCount("123KiB")
	assert.Equal(t, err, nil)
	assert.Equal(t, count, ByteCount(123*1024))
	assert.Equal(t, ByteCountHumanReadable(count), "123kib")

	count, err = ParseByteCount("5MiB")
	assert.Equal(t, err, nil)
	assert.Equal(t, count, ByteCount(5*1024*1024))
	assert.Equal(t, ByteCountHumanReadable(count), "5mib")

	count, err = ParseByteCount("1.7GiB")
	assert.Equal(t, err, nil)
	assert.Equal(t, count, ByteCount(17*1024*1024*1024)/ByteCount(10))
	assert.Equal(t, ByteCountHumanReadable(count), "1.7gib")

	count, err = ParseByteCount("13.1TiB")
	assert.Equal(t, err, nil)
	assert.Equal(t, count, ByteCount(131*1024*1024*1024*1024)/ByteCount(10))
	assert.Equal(t, ByteCountHumanReadable(count), "13.1tib")
}

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

func TestExpandPorts(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  []int
	}{
		{"single port", "80", []int{80}},
		{"two ports", "80,443", []int{80, 443}},
		{"range", "7000-7003", []int{7000, 7001, 7002, 7003}},
		{"range single", "80-80", []int{80}},
		{"mixed", "80,7000-7002,443", []int{80, 7000, 7001, 7002, 443}},
		{"whitespace", " 80 , 443 ", []int{80, 443}},
		{"multi range", "7000-7002,7443-7445", []int{7000, 7001, 7002, 7443, 7444, 7445}},
	}
	for _, tt := range tests {
		got, err := expandPorts(tt.input)
		assert.Equal(t, err, nil)
		assert.Equal(t, slices.Equal(got, tt.want), true)
	}
}

func TestExpandPortsError(t *testing.T) {
	badInputs := []string{"abc", "80-", "-80", "80+5"}
	for _, input := range badInputs {
		_, err := expandPorts(input)
		assert.NotEqual(t, err, nil)
	}
}

func TestExpandAnyPorts(t *testing.T) {
	got, err := expandAnyPorts("7000-7002,80")
	assert.Equal(t, err, nil)
	assert.Equal(t, slices.Equal(got, []int{7000, 7001, 7002, 80}), true)

	got, err = expandAnyPorts(443)
	assert.Equal(t, err, nil)
	assert.Equal(t, slices.Equal(got, []int{443}), true)

	_, err = expandAnyPorts(3.14)
	assert.NotEqual(t, err, nil)
}

func TestExpandPortConfigPorts(t *testing.T) {
	tests := []struct {
		name  string
		specs []string
		want  []int
	}{
		{"single", []string{"80"}, []int{80}},
		{"plus notation", []string{"5080+3"}, []int{5080, 5081, 5082, 5083}},
		{"plus zero", []string{"80+0"}, []int{80}},
		{"range", []string{"100-103"}, []int{100, 101, 102, 103}},
		{"mixed", []string{"80", "5080+2", "100-101"}, []int{80, 5080, 5081, 5082, 100, 101}},
		{"dedup", []string{"80", "80"}, []int{80}},
		{"dedup across types", []string{"80", "79-81"}, []int{80, 79, 81}},
	}
	for _, tt := range tests {
		got := expandPortConfigPorts(tt.specs...)
		assert.Equal(t, slices.Equal(got, tt.want), true)
	}
}

func TestExpandPortConfigPortsPanic(t *testing.T) {
	defer func() {
		assert.NotEqual(t, recover(), nil)
	}()
	expandPortConfigPorts("not_a_port")
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
