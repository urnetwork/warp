package warp

// lbmap's render (§13.4, §19.5 W1, D-TLS-2, D-TLS-12): one version of the
// custom-host map into the two files nginx includes beside the SNI split.
//
// tls-custom-hosts.map holds one `<host> <edge upstream>;` line per active
// custom host, which the split's stream map includes, plus one line sending
// the version's probe name, `<digest[0:12]>.map.probe.invalid` (RFC 6761
// §6.4), to the edge, so the dns edges' route probes can tell which version an
// interface's nginx runs. tls-custom-hosts-80.conf holds one `server_name
// <host>;` line per host, which the port-80 redirect server includes: the
// redirect's custom names. Both files open with a comment naming the version
// and digest, which nginx ignores.
//
// The render refuses a whole version rather than a host of it: a host under
// one of the split's roots, which the split already sends to the edge and
// where an exact entry would take a platform name the split keeps; a host
// under a platform domain or a name the lb serves; a host under .invalid,
// where the probe names live; a name that is not a lowercase DNS name; a
// duplicate; a digest that does not match the hosts. What it guards against
// comes from warpctl's render of the same config (LbMapRenderConfig), so the
// two cannot drift apart.
//
// The digest (§12.8's "SHA-256 of the version's sorted host list") is SHA-256
// over the hosts in bytewise order, each followed by one 0x00 byte, written as
// 64 lowercase hex digits: the shape plan-TLS-small-readings #2 gives
// identifier_set_sha256. The dns API mints it; lbmap checks it.
//
// Nothing here logs. An error names a host by its index in the version's
// sorted list, never by name, since a custom host is a customer's name (I-13).

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// The custom-host map's wire format, which lbmap reads before anything else in
// an answer. An answer of a higher format stops lbmap rather than half-applying
// it (§12.6's N and N+1 rule).
const LbMapFormat = 1

// The zone of every version's probe name (RFC 6761 §6.4): nothing resolves
// there, so no custom host can be under it.
const LbMapProbeZone = "map.probe.invalid"

// The reserved top-level domain the probe zone sits under.
const lbMapInvalidZone = "invalid"

// How many hex digits of the digest a probe name takes.
const lbMapProbeDigestLength = 12

// The digest's length in lowercase hex.
const lbMapDigestLength = 2 * sha256.Size

// A DNS name's longest presentation form without its final dot, and a
// label's (RFC 1035 §2.3.4).
const (
	lbMapHostMaxByteCount  = 253
	lbMapLabelMaxByteCount = 63
)

// The comment warpctl's split render writes into the stream block, carrying
// LbMapRenderConfig as JSON on one line.
const lbMapMarkerPrefix = "# warp-lbmap: "

// A version the render refuses, whole. Its text names no custom host.
var ErrLbMapRefused = errors.New("lbmap refused the custom-host map")

// An answer whose format is above LbMapFormat.
var ErrLbMapFormatTooNew = errors.New("lbmap does not read the custom-host map's format")

// One version of the custom-host map (§12.8): the body of GET
// /dns/internal/custom-host-map.
type LbCustomHostMap struct {
	// Read first: a format above LbMapFormat stops the reader.
	Format int `json:"format"`
	// Raised by each change to the active rows, never lowered: a restore raises
	// it 2^24 above the restored one (§12.6).
	Version uint64 `json:"version"`
	// SHA-256 of Hosts, as LbCustomHostMapDigest computes it, in lowercase hex.
	Digest string `json:"digest"`
	// The active custom hosts, lowercase DNS names without a final dot, each
	// once, in any order.
	Hosts []string `json:"hosts"`
}

// The digest of a version's hosts: SHA-256 over them in bytewise order, each
// followed by one 0x00 byte, as 64 lowercase hex digits.
func LbCustomHostMapDigest(hosts []string) string {
	sortedHosts := slices.Clone(hosts)
	slices.Sort(sortedHosts)
	hash := sha256.New()
	for _, host := range sortedHosts {
		hash.Write([]byte(host))
		hash.Write([]byte{0})
	}
	return hex.EncodeToString(hash.Sum(nil))
}

// A version's probe name, `<digest[0:12]>.map.probe.invalid`, for a digest
// in lowercase hex.
func LbMapProbeName(digest string) string {
	return digest[:lbMapProbeDigestLength] + "." + LbMapProbeZone
}

// Whether text is a lowercase hex SHA-256.
func isLbMapDigest(text string) bool {
	if len(text) != lbMapDigestLength {
		return false
	}
	for index := range len(text) {
		c := text[index]
		if !('0' <= c && c <= '9') && !('a' <= c && c <= 'f') {
			return false
		}
	}
	return true
}

// Whether host is a name nginx's map and server_name take as one exact name:
// lowercase letters, digits and inner hyphens in labels of 1 to 63 bytes, at
// least two labels, at most 253 bytes, with no final dot. An IDN is in its
// A-label form already. No wildcard, underscore or upper case passes, so no
// line the render writes can be anything but one exact name.
func isLbMapHost(host string) bool {
	if len(host) == 0 || lbMapHostMaxByteCount < len(host) {
		return false
	}
	labels := strings.Split(host, ".")
	if len(labels) < 2 {
		return false
	}
	for _, label := range labels {
		if len(label) == 0 || lbMapLabelMaxByteCount < len(label) {
			return false
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for index := range len(label) {
			c := label[index]
			if !('a' <= c && c <= 'z') && !('0' <= c && c <= '9') && c != '-' {
				return false
			}
		}
	}
	return true
}

// Whether name is zone or a name under it.
func isLbMapNameUnder(name string, zone string) bool {
	return name == zone || strings.HasSuffix(name, "."+zone)
}

// What lbmap's render guards and routes to, as warpctl's split render wrote
// the config nginx runs (warpctl/config_tls_split.go), carried in that config
// as one comment line (Marker, FindLbMapRenderConfig).
type LbMapRenderConfig struct {
	// Read first, as the map's own format is.
	Format int `json:"format"`
	// The split's roots: every name under one already goes to the edge, and an
	// exact entry there would take a platform name the split keeps.
	Roots []string `json:"roots"`
	// The platform's domains and every name the lb's http servers serve, a
	// wildcard written as its zone: no custom host may be one or under one.
	PlatformDomains []string `json:"platform_domains"`
	// The stream upstream the split sends `*.<root>` to: the tls edge's 443.
	EdgeUpstream string `json:"edge_upstream"`
}

// Whether the config can guard and route: a format this release reads, at
// least one root, an upstream name nginx takes as one token, and every name a
// lowercase name.
func (self *LbMapRenderConfig) Validate() error {
	if self.Format <= 0 {
		return fmt.Errorf("lbmap render config: format %d", self.Format)
	}
	if LbMapFormat < self.Format {
		return fmt.Errorf("%w: render config format %d", ErrLbMapFormatTooNew, self.Format)
	}
	if len(self.Roots) == 0 {
		return errors.New("lbmap render config: no root")
	}
	for _, name := range append(slices.Clone(self.Roots), self.PlatformDomains...) {
		if name == "" || name != strings.ToLower(name) || strings.ContainsAny(name, " \t\r\n;{}#*\"'") || strings.HasSuffix(name, ".") {
			return fmt.Errorf("lbmap render config: %q is not a lowercase name", name)
		}
	}
	if self.EdgeUpstream == "" || strings.ContainsAny(self.EdgeUpstream, " \t\r\n;{}#\"'$") {
		return fmt.Errorf("lbmap render config: edge upstream %q", self.EdgeUpstream)
	}
	return nil
}

// The comment line warpctl's render writes into the stream block, without its
// indent or newline.
func (self *LbMapRenderConfig) Marker() (string, error) {
	if err := self.Validate(); err != nil {
		return "", err
	}
	data, err := json.Marshal(self)
	if err != nil {
		return "", err
	}
	return lbMapMarkerPrefix + string(data), nil
}

// The render config in an nginx config, from its one marker line, or nil when
// it has none: a config that renders no split, where lbmap has nothing to do.
// Two markers, or one that does not parse or validate, is an error.
func FindLbMapRenderConfig(nginxConfig []byte) (*LbMapRenderConfig, error) {
	var found *LbMapRenderConfig
	scanner := bufio.NewScanner(bytes.NewReader(nginxConfig))
	scanner.Buffer(make([]byte, 64*1024), len(nginxConfig)+1)
	for scanner.Scan() {
		text, ok := strings.CutPrefix(strings.TrimSpace(scanner.Text()), lbMapMarkerPrefix)
		if !ok {
			continue
		}
		if found != nil {
			return nil, errors.New("lbmap render config: the config holds two markers")
		}
		renderConfig := &LbMapRenderConfig{}
		decoder := json.NewDecoder(strings.NewReader(text))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(renderConfig); err != nil {
			return nil, fmt.Errorf("lbmap render config: %w", err)
		}
		if err := renderConfig.Validate(); err != nil {
			return nil, err
		}
		found = renderConfig
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return found, nil
}

// One version rendered: the two files' contents, and what they say.
type LbMapRender struct {
	Version   uint64
	Digest    string
	ProbeName string
	// The version's hosts in bytewise order.
	Hosts []string
	// tls-custom-hosts.map: the probe line, then one line per host.
	Map []byte
	// tls-custom-hosts-80.conf: one server_name line per host.
	Http80 []byte
}

// Renders one version, or refuses it whole: a format above LbMapFormat, a
// version of zero, more than maxHostCount hosts, a host that is not a
// lowercase DNS name, a duplicate, a digest that does not match, or a host
// under a root, a platform domain or .invalid. A refusal names a host only by
// its index in the sorted list.
func (self *LbMapRenderConfig) Render(customHostMap *LbCustomHostMap, maxHostCount int) (*LbMapRender, error) {
	refuse := func(format string, arguments ...any) error {
		return fmt.Errorf("%w: version %d: %s", ErrLbMapRefused, customHostMap.Version, fmt.Sprintf(format, arguments...))
	}
	if err := self.Validate(); err != nil {
		return nil, err
	}
	if customHostMap.Format <= 0 {
		return nil, refuse("format %d", customHostMap.Format)
	}
	if LbMapFormat < customHostMap.Format {
		return nil, fmt.Errorf("%w: version %d: format %d above %d", ErrLbMapFormatTooNew, customHostMap.Version, customHostMap.Format, LbMapFormat)
	}
	if customHostMap.Version == 0 {
		return nil, refuse("version zero")
	}
	if maxHostCount < len(customHostMap.Hosts) {
		return nil, refuse("%d hosts, above %d", len(customHostMap.Hosts), maxHostCount)
	}
	if !isLbMapDigest(customHostMap.Digest) {
		return nil, refuse("the digest is not a lowercase hex SHA-256")
	}
	hosts := slices.Clone(customHostMap.Hosts)
	slices.Sort(hosts)
	for index, host := range hosts {
		if !isLbMapHost(host) {
			return nil, refuse("host %d is not a lowercase DNS name", index)
		}
		if 0 < index && hosts[index-1] == host {
			return nil, refuse("host %d is listed twice", index)
		}
		if isLbMapNameUnder(host, lbMapInvalidZone) {
			return nil, refuse("host %d is under .%s, where the probe names are", index, lbMapInvalidZone)
		}
		for _, root := range self.Roots {
			if isLbMapNameUnder(host, root) {
				return nil, refuse("host %d is under the split's root %s", index, root)
			}
		}
		for _, platformDomain := range self.PlatformDomains {
			if isLbMapNameUnder(host, platformDomain) {
				return nil, refuse("host %d is under the platform name %s", index, platformDomain)
			}
		}
	}
	if digest := LbCustomHostMapDigest(hosts); digest != customHostMap.Digest {
		return nil, refuse("the digest does not match the hosts")
	}

	header := fmt.Sprintf("# lbmap: custom-host map version %d, digest %s (§13.4); lbmap rewrites this file whole\n", customHostMap.Version, customHostMap.Digest)
	probeName := LbMapProbeName(customHostMap.Digest)
	var mapText strings.Builder
	mapText.WriteString(header)
	fmt.Fprintf(&mapText, "%s %s;\n", probeName, self.EdgeUpstream)
	var http80Text strings.Builder
	http80Text.WriteString(header)
	for _, host := range hosts {
		fmt.Fprintf(&mapText, "%s %s;\n", host, self.EdgeUpstream)
		fmt.Fprintf(&http80Text, "server_name %s;\n", host)
	}
	return &LbMapRender{
		Version:   customHostMap.Version,
		Digest:    customHostMap.Digest,
		ProbeName: probeName,
		Hosts:     hosts,
		Map:       []byte(mapText.String()),
		Http80:    []byte(http80Text.String()),
	}, nil
}

// The custom hosts a tls-custom-hosts.map holds, in bytewise order: the first
// field of each line that is not blank or a comment, less the probe name.
// What the file held before lbmap first runs, for the hosts a load adds and
// drops. A line that is not `<name> <upstream>;` is an error, and the caller
// then knows nothing of what the file held.
func ParseLbMapHosts(mapText []byte) ([]string, error) {
	hosts := []string{}
	for index, line := range strings.Split(string(mapText), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 2 || !strings.HasSuffix(fields[1], ";") {
			return nil, fmt.Errorf("lbmap: line %d of the map is not `<name> <upstream>;`", index+1)
		}
		if isLbMapNameUnder(fields[0], LbMapProbeZone) {
			continue
		}
		hosts = append(hosts, fields[0])
	}
	slices.Sort(hosts)
	return slices.Compact(hosts), nil
}

// The hosts in next and not in previous, and those in previous and not in
// next, each in bytewise order: what a load adds and drops against the map it
// held.
func lbMapHostChanges(previous []string, next []string) (added []string, dropped []string) {
	previousHosts := map[string]bool{}
	for _, host := range previous {
		previousHosts[host] = true
	}
	nextHosts := map[string]bool{}
	for _, host := range next {
		nextHosts[host] = true
	}
	added = []string{}
	for _, host := range next {
		if !previousHosts[host] {
			added = append(added, host)
		}
	}
	dropped = []string{}
	for _, host := range previous {
		if !nextHosts[host] {
			dropped = append(dropped, host)
		}
	}
	slices.Sort(added)
	slices.Sort(dropped)
	return slices.Compact(added), slices.Compact(dropped)
}

// Writes data to path through a temp file beside it and a rename, so a reader
// such as `nginx -t` sees the old file or the new one, never half of one.
func writeLbMapFile(path string, data []byte) error {
	temp, err := os.CreateTemp(filepath.Dir(path), lbMapTempPattern(path))
	if err != nil {
		return err
	}
	tempPath := temp.Name()
	ok := false
	defer func() {
		if !ok {
			os.Remove(tempPath)
		}
	}()
	if _, err := temp.Write(data); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Chmod(0644); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tempPath, path); err != nil {
		return err
	}
	ok = true
	return nil
}

// The temp files writeLbMapFile makes beside path, hidden, so an include never
// matches one.
func lbMapTempPattern(path string) string {
	return "." + filepath.Base(path) + ".lbmap-*"
}

// Removes temp files a write that died left beside path.
func removeLbMapTempFiles(path string) error {
	leftovers, err := filepath.Glob(filepath.Join(filepath.Dir(path), lbMapTempPattern(path)))
	if err != nil {
		return err
	}
	for _, leftover := range leftovers {
		if err := os.Remove(leftover); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}
