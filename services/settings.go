package services

import (
	"fmt"
	"net/netip"
	"os"
	"regexp"
	"sort"
	"strings"

	"golang.org/x/exp/maps"
	"gopkg.in/yaml.v3"
)

// The lan_hosts block of config/<env>/settings.yml: the hosts on the lan
// routers' bridges with the addresses the routers' dhcp static mappings
// assign them. `run-routers.sh --update-settings` seeds it from the live
// routers, and `warpctl vyos` renders the lan routers from it. The block is
// rewritten textually, so the rest of the file (its anchors, merges and
// comments) stays byte for byte.

// LanHostsKey is the top level key of the block.
const LanHostsKey = "lan_hosts"

// LanHost is one lan host: its address on the bridge and the mac the
// router's dhcp pins it to.
type LanHost struct {
	Ip  string `yaml:"ip"`
	Mac string `yaml:"mac"`
}

var lanMacPattern = regexp.MustCompile(`^([0-9a-f]{2}:){5}[0-9a-f]{2}$`)

// SettingsPath returns config/<env>/settings.yml.
func SettingsPath(env string) (string, error) {
	return resolveConfigPath(configHomeRoot(), env, "settings.yml")
}

// ReadLanHosts returns the lan_hosts of a settings file, empty when the
// file has none.
func ReadLanHosts(path string) (map[string]*LanHost, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseLanHosts(data)
}

// ParseLanHosts returns the lan_hosts of a settings document.
func ParseLanHosts(data []byte) (map[string]*LanHost, error) {
	document := map[string]any{}
	if err := yaml.Unmarshal(data, &document); err != nil {
		return nil, fmt.Errorf("settings.yml: %w", err)
	}
	hosts := map[string]*LanHost{}
	raw, ok := document[LanHostsKey]
	if !ok || raw == nil {
		return hosts, nil
	}
	encoded, err := yaml.Marshal(raw)
	if err != nil {
		return nil, fmt.Errorf("settings.yml %s: %w", LanHostsKey, err)
	}
	if err := yaml.Unmarshal(encoded, &hosts); err != nil {
		return nil, fmt.Errorf("settings.yml %s: %w", LanHostsKey, err)
	}
	if err := ValidateLanHosts(hosts); err != nil {
		return nil, err
	}
	return hosts, nil
}

// ParseLanRoutes returns the `routes` map of the settings document: host
// name to lan address. The map is per host but identical across hosts (a
// yaml anchor), so the first host's block is authoritative; an absent or
// oddly shaped block yields an empty map.
func ParseLanRoutes(data []byte) map[string]string {
	routes := map[string]string{}
	document := map[string]any{}
	if err := yaml.Unmarshal(data, &document); err != nil {
		return routes
	}
	keys := maps.Keys(document)
	sort.Strings(keys)
	for _, key := range keys {
		hostSettings, ok := document[key].(map[string]any)
		if !ok {
			continue
		}
		hostRoutes, ok := hostSettings["routes"].(map[string]any)
		if !ok {
			continue
		}
		for name, ip := range hostRoutes {
			if value, ok := ip.(string); ok {
				routes[name] = value
			}
		}
		if 0 < len(routes) {
			break
		}
	}
	return routes
}

// ValidateLanHosts checks names, addresses and macs, and that no two hosts
// share an address or a mac.
func ValidateLanHosts(hosts map[string]*LanHost) error {
	names := maps.Keys(hosts)
	sort.Strings(names)
	ips := map[string]string{}
	macs := map[string]string{}
	for _, name := range names {
		host := hosts[name]
		if !lanHostNamePattern.MatchString(name) {
			return fmt.Errorf("%s %q is not a host name", LanHostsKey, name)
		}
		if host == nil {
			return fmt.Errorf("%s %s has no ip and mac", LanHostsKey, name)
		}
		ip, err := netip.ParseAddr(host.Ip)
		if err != nil || !ip.Is4() {
			return fmt.Errorf("%s %s ip %q is not an ipv4 address", LanHostsKey, name, host.Ip)
		}
		if !lanMacPattern.MatchString(host.Mac) {
			return fmt.Errorf("%s %s mac %q is not a lowercase colon separated mac", LanHostsKey, name, host.Mac)
		}
		if other, ok := ips[host.Ip]; ok {
			return fmt.Errorf("%s %s and %s share the ip %s", LanHostsKey, other, name, host.Ip)
		}
		ips[host.Ip] = name
		if other, ok := macs[host.Mac]; ok {
			return fmt.Errorf("%s %s and %s share the mac %s", LanHostsKey, other, name, host.Mac)
		}
		macs[host.Mac] = name
	}
	return nil
}

// LanHostsMerge is what MergeLanHosts did.
type LanHostsMerge struct {
	// hosts added to the block, by name
	Added []string
	// hosts whose live ip or mac differs from the block, left alone
	Conflicts []string
	// the block after the merge
	Hosts map[string]*LanHost
	// the document after the merge
	Document []byte
}

// MergeLanHosts adds the discovered hosts that the settings document lacks
// to its lan_hosts block and returns the new document. A host the block
// already has keeps the block's ip and mac: a difference is reported as a
// conflict, never applied. Nothing is removed. The block is rendered anew
// in place (or appended when absent) and every other byte of the document
// is kept.
func MergeLanHosts(document []byte, discovered map[string]*LanHost) (*LanHostsMerge, error) {
	if err := ValidateLanHosts(discovered); err != nil {
		return nil, err
	}
	existing, err := ParseLanHosts(document)
	if err != nil {
		return nil, err
	}
	merged := map[string]*LanHost{}
	for name, host := range existing {
		merged[name] = &LanHost{Ip: host.Ip, Mac: host.Mac}
	}
	result := &LanHostsMerge{Hosts: merged}
	names := maps.Keys(discovered)
	sort.Strings(names)
	for _, name := range names {
		host := discovered[name]
		if current, ok := merged[name]; ok {
			if current.Ip != host.Ip || current.Mac != host.Mac {
				result.Conflicts = append(result.Conflicts, fmt.Sprintf("%s: settings %s %s, router %s %s", name, current.Ip, current.Mac, host.Ip, host.Mac))
			}
			continue
		}
		merged[name] = &LanHost{Ip: host.Ip, Mac: host.Mac}
		result.Added = append(result.Added, name)
	}
	if err := ValidateLanHosts(merged); err != nil {
		return nil, fmt.Errorf("merging the live hosts into %s: %w", LanHostsKey, err)
	}
	result.Document = replaceLanHostsBlock(document, RenderLanHostsBlock(merged))
	return result, nil
}

// RenderLanHostsBlock renders the block, hosts in name order.
func RenderLanHostsBlock(hosts map[string]*LanHost) string {
	var out strings.Builder
	out.WriteString("# The hosts on the lan routers' bridges with the addresses their dhcp static\n")
	out.WriteString("# mappings assign. `run-routers.sh --update-settings` adds the hosts the live\n")
	out.WriteString("# routers know and never removes one; `warpctl vyos` renders the lan routers\n")
	out.WriteString("# from this block. A `routes` address inside a lan must match its entry here.\n")
	out.WriteString(LanHostsKey + ":\n")
	names := maps.Keys(hosts)
	sort.Strings(names)
	for _, name := range names {
		fmt.Fprintf(&out, "    %s:\n        ip: %s\n        mac: %s\n", name, hosts[name].Ip, hosts[name].Mac)
	}
	return out.String()
}

// replaceLanHostsBlock swaps the lan_hosts block (its leading comment lines
// included) for the rendered one, or appends the rendered block.
func replaceLanHostsBlock(document []byte, block string) []byte {
	lines := strings.Split(string(document), "\n")
	start := -1
	for i, line := range lines {
		if line == LanHostsKey+":" || strings.HasPrefix(line, LanHostsKey+": ") {
			start = i
			break
		}
	}
	if start < 0 {
		text := string(document)
		if text != "" && !strings.HasSuffix(text, "\n") {
			text += "\n"
		}
		if text != "" {
			text += "\n"
		}
		return []byte(text + block)
	}
	// the block runs while lines are indented or blank; the comment lines
	// directly above the key belong to it too
	end := start + 1
	for end < len(lines) && (lines[end] == "" || strings.HasPrefix(lines[end], " ") || strings.HasPrefix(lines[end], "\t")) {
		end++
	}
	// trailing blank lines stay outside the block
	for end > start+1 && lines[end-1] == "" {
		end--
	}
	commentStart := start
	for commentStart > 0 && strings.HasPrefix(lines[commentStart-1], "#") {
		commentStart--
	}
	var out strings.Builder
	if commentStart > 0 {
		out.WriteString(strings.Join(lines[:commentStart], "\n"))
		out.WriteString("\n")
	}
	out.WriteString(block)
	out.WriteString(strings.Join(lines[end:], "\n"))
	return []byte(out.String())
}
