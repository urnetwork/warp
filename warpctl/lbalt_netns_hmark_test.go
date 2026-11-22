package main

// The bucket model of the lb_alt network-namespace harness
// (lbalt_netns_test.go): which HMARK bucket the split puts a source address
// in, or a flow's source address and port for a port-hash source (server
// LBALTOPT2 R16), and the client's source addresses, one in each bucket of
// each family. The harness checks every flow against the model, so it also
// checks that the kernel hashes the source address alone, with the split's
// seed, as the edges' kernel did in M7 (server/LBALT.md §7.1), and the source
// port too for a port-hash source.

import (
	"encoding/binary"
	"fmt"
	"math/bits"
	"net/netip"
	"testing"
)

// xt_HMARK's jhash (include/linux/jhash.h): JHASH_INITVAL, and the length in
// bytes jhash_3words adds to it.
const (
	lbAltNetnsJhashInitval = 0xdeadbeef
	lbAltNetnsJhash3Bytes  = 3 * 4
)

// The candidate source ranges of the client, TEST-NET space the topology
// leaves free. All three IPv4 ranges are needed to reach every bucket.
func lbAltNetnsSourceRanges(ipv6 bool) []netip.Prefix {
	if ipv6 {
		return []netip.Prefix{
			netip.MustParsePrefix("2001:db8:c::/112"),
		}
	}
	return []netip.Prefix{
		netip.MustParsePrefix("203.0.113.0/24"),
		netip.MustParsePrefix("198.51.100.128/25"),
		netip.MustParsePrefix("192.0.2.128/25"),
	}
}

// The client's source addresses of a family, one in each HMARK bucket, indexed
// by bucket: in each bucket, the first candidate in lbAltNetnsSourceRanges
// order. A range's first and last addresses are skipped, so no source is an
// IPv4 network or broadcast address.
func lbAltNetnsSources(ipv6 bool) ([]netip.Addr, error) {
	sources := make([]netip.Addr, lbAltHmarkMod)
	missingCount := len(sources)
	for _, sourceRange := range lbAltNetnsSourceRanges(ipv6) {
		first := sourceRange.Masked().Addr()
		for source := first.Next(); sourceRange.Contains(source.Next()) && 0 < missingCount; source = source.Next() {
			bucket := lbAltNetnsHmarkBucket(source)
			if !sources[bucket].IsValid() {
				sources[bucket] = source
				missingCount -= 1
			}
		}
	}
	if 0 < missingCount {
		return nil, fmt.Errorf("the source ranges leave %d buckets empty", missingCount)
	}
	return sources, nil
}

// jhash_3words of include/linux/jhash.h: lookup3's final mix of three words
// and a seed.
func lbAltNetnsJhash3Words(a uint32, b uint32, c uint32, seed uint32) uint32 {
	initval := seed + lbAltNetnsJhashInitval + lbAltNetnsJhash3Bytes
	a += initval
	b += initval
	c += initval
	c ^= b
	c -= bits.RotateLeft32(b, 14)
	a ^= c
	a -= bits.RotateLeft32(c, 11)
	b ^= a
	b -= bits.RotateLeft32(a, 25)
	c ^= b
	c -= bits.RotateLeft32(b, 16)
	a ^= c
	a -= bits.RotateLeft32(c, 4)
	b ^= a
	b -= bits.RotateLeft32(a, 14)
	c ^= b
	c -= bits.RotateLeft32(b, 24)
	return c
}

// The bucket the split's HMARK rule (hmarkRules) puts a source address in:
// xt_HMARK's hmark_hash with only the source prefix set. The source, an IPv6
// one folded to 32 bits by xor (hmark_addr6_mask), is ordered against the
// destination, which the rule masks to zero, so it is the second word; ports
// and protocol are masked to zero too. reciprocal_scale maps the hash onto the
// buckets. It depends on the seed and the address alone.
func lbAltNetnsHmarkBucket(source netip.Addr) int {
	hash := lbAltNetnsJhash3Words(0, lbAltNetnsFoldedSource(source), 0, lbAltHmarkRnd)
	return int((uint64(hash) * uint64(lbAltHmarkMod)) >> 32)
}

// The bucket a port-hash source's HMARK rule (hmarkRules) puts a flow in: as
// lbAltNetnsHmarkBucket, with the flow's source port in the third word.
// xt_HMARK's hmark_swap_ports puts the larger of the masked ports in the high
// half of that word, in host order, and the rule masks the destination port
// to zero, so the word is the source port shifted up 16 bits. It depends on
// the seed, the address and the source port alone.
func lbAltNetnsHmarkPortBucket(source netip.Addr, sourcePort uint16) int {
	hash := lbAltNetnsJhash3Words(0, lbAltNetnsFoldedSource(source), uint32(sourcePort)<<16, lbAltHmarkRnd)
	return int((uint64(hash) * uint64(lbAltHmarkMod)) >> 32)
}

// A source address as xt_HMARK hashes it, in host order: an IPv4 address
// whole, an IPv6 one folded to 32 bits by xor (hmark_addr6_mask).
func lbAltNetnsFoldedSource(source netip.Addr) uint32 {
	if source.Is4() {
		sourceBytes := source.As4()
		return binary.BigEndian.Uint32(sourceBytes[:])
	}
	var foldedSource uint32
	sourceBytes := source.As16()
	for i := 0; i < len(sourceBytes); i += 4 {
		foldedSource ^= binary.BigEndian.Uint32(sourceBytes[i : i+4])
	}
	return foldedSource
}

// The model gives the buckets the kernel gave: these addresses' marks under
// the split's HMARK rule on Linux 7.0 with iptables 1.8.10 (nf_tables), read
// back through conntrack, and M7's IPv4 split on edge-4 (Linux 6.8, the rule
// spelled --hmark-tuple src): 376 of its 800 loopback flows in buckets 0-49,
// and 88 buckets hit. The client's sources reach every bucket in each family.
func TestLbAltNetnsHmarkModelKeepsTheKernelsBuckets(t *testing.T) {
	cases := []struct {
		source string
		bucket int
	}{
		{source: "203.0.113.1", bucket: 74},
		{source: "203.0.113.2", bucket: 99},
		{source: "203.0.113.77", bucket: 70},
		{source: "203.0.113.254", bucket: 81},
		{source: "198.51.100.129", bucket: 70},
		{source: "198.51.100.200", bucket: 46},
		{source: "192.0.2.129", bucket: 31},
		{source: "192.0.2.250", bucket: 71},
		{source: "2001:db8:c::1", bucket: 36},
		{source: "2001:db8:c::2", bucket: 65},
		{source: "2001:db8:c::29e", bucket: 46},
		{source: "2001:db8:c:0:1:2:3:4", bucket: 53},
	}
	for _, c := range cases {
		if bucket := lbAltNetnsHmarkBucket(netip.MustParseAddr(c.source)); bucket != c.bucket {
			t.Errorf("%s: bucket %d, the kernel's is %d", c.source, bucket, c.bucket)
		}
	}

	// M7: three udp flows and one tcp connection from each of 127.0.0.2-201,
	// buckets 0-49 to listener A
	flowsOnA := 0
	bucketsHit := map[int]bool{}
	for n := 2; n <= 201; n += 1 {
		bucket := lbAltNetnsHmarkBucket(netip.AddrFrom4([4]byte{127, 0, 0, byte(n)}))
		bucketsHit[bucket] = true
		if bucket < 50 {
			flowsOnA += 4
		}
	}
	if flowsOnA != 376 || len(bucketsHit) != 88 {
		t.Errorf("M7's split: %d flows on A and %d buckets hit, edge-4's were 376 and 88", flowsOnA, len(bucketsHit))
	}

	for _, ipv6 := range []bool{false, true} {
		sources, err := lbAltNetnsSources(ipv6)
		if err != nil {
			t.Fatal(err)
		}
		seenSources := map[netip.Addr]bool{}
		for bucket, source := range sources {
			if source.Is6() != ipv6 || lbAltNetnsHmarkBucket(source) != bucket || seenSources[source] {
				t.Fatalf("source %s for bucket %d", source, bucket)
			}
			seenSources[source] = true
		}
	}
}

// The port model gives the buckets the kernel gave: the marks of these tcp
// flows under the split's rules, an address-only rule of tcp and of udp for
// every source and then a tcp port-hash rule for 203.0.113.0/27 and
// 2001:db8:c::/64, read back through conntrack (CONNMARK --save-mark on new
// flows) on Linux 7.0 with iptables 1.8.10 (nf_tables), in a container with
// only CAP_NET_ADMIN, on 2026-11-21. Forty tcp flows from 203.0.113.5 there
// hit 33 buckets, and forty from 2001:db8:c::5 31, each as the port model
// said, and an earlier probe's udp flows through a port-hash rule that took
// udp too hit the same buckets, since the protocol is outside the hash. The
// forty udp flows from each of those two sources all kept their address's
// bucket, and every flow from 192.0.2.77 and 2001:db8:d::7, outside the
// prefixes, hit its address's bucket.
func TestLbAltNetnsHmarkPortModelKeepsTheKernelsBuckets(t *testing.T) {
	for _, c := range []struct {
		source     string
		sourcePort uint16
		bucket     int
	}{
		{source: "203.0.113.5", sourcePort: 20000, bucket: 83},
		{source: "203.0.113.5", sourcePort: 20001, bucket: 91},
		{source: "203.0.113.5", sourcePort: 20002, bucket: 60},
		{source: "203.0.113.5", sourcePort: 20017, bucket: 95},
		{source: "203.0.113.5", sourcePort: 20039, bucket: 12},
		{source: "2001:db8:c::5", sourcePort: 20000, bucket: 97},
		{source: "2001:db8:c::5", sourcePort: 20001, bucket: 78},
		{source: "2001:db8:c::5", sourcePort: 20002, bucket: 13},
		{source: "2001:db8:c::5", sourcePort: 20017, bucket: 78},
		{source: "2001:db8:c::5", sourcePort: 20039, bucket: 48},
	} {
		if bucket := lbAltNetnsHmarkPortBucket(netip.MustParseAddr(c.source), c.sourcePort); bucket != c.bucket {
			t.Errorf("%s port %d: bucket %d, the kernel's is %d", c.source, c.sourcePort, bucket, c.bucket)
		}
	}
	for _, c := range []struct {
		source string
		bucket int
	}{
		{source: "192.0.2.77", bucket: 19},
		{source: "2001:db8:d::7", bucket: 5},
		// the udp flows of the port-hash sources
		{source: "203.0.113.5", bucket: 36},
		{source: "2001:db8:c::5", bucket: 66},
	} {
		if bucket := lbAltNetnsHmarkBucket(netip.MustParseAddr(c.source)); bucket != c.bucket {
			t.Errorf("%s: bucket %d, the kernel's is %d", c.source, bucket, c.bucket)
		}
	}
	for _, source := range []string{"203.0.113.5", "2001:db8:c::5"} {
		buckets := map[int]bool{}
		for sourcePort := uint16(20000); sourcePort < 20040; sourcePort += 1 {
			buckets[lbAltNetnsHmarkPortBucket(netip.MustParseAddr(source), sourcePort)] = true
		}
		if want := map[string]int{"203.0.113.5": 33, "2001:db8:c::5": 31}[source]; len(buckets) != want {
			t.Errorf("%s: forty ports hit %d buckets, the kernel's %d", source, len(buckets), want)
		}
	}
}
