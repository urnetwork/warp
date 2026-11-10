package services

// A fragment of a services.yml's top version, for the blocks the sidecar build adds
// (sidecar-blocks/README.md; plan-OPS-vault-blocks, QD-574). Nobody who writes a fragment may read the
// vault's services.yml, so a fragment is checked against a synthetic base where it is written, and
// ApplyServicesFragments merges it into the real file where the vault is, which is sidecarctl's
// `services apply-fragment`.
//
// A fragment only adds. Applying one appends a new version on top of the file's versions, as warp's
// README asks of every change: a copy of the current top version with each fragment merged in. A key
// the top version lacks is added whole, so a new service arrives as one block; a mapping it has is
// merged key by key; secret_files, cors_origins and expose_aliases gain what the fragment lists; and
// anything else the fragment names must already be what it says. A fragment that would change a value,
// or whose result breaks a rule the loader checks, is refused. Applying the same fragment twice adds
// nothing the second time, and then no version is added.
//
// Outside the versions a fragment may add two things, which warp keeps unversioned: registrar domains
// to `domains`, each with its registrar (W10's recurd.dev), and names to the dns block's `unproxied`
// (QD-012's key origin). A domain the file has must have the registrar the fragment gives, and a
// registrar must be one warpctl knows, so a placeholder the owner has not filled in is refused when it
// is applied, though it parses. These lines go in as the first entries of their mapping or list, or as
// a block of their own above `versions` when the file has none, and they add no version of their own.
//
// The new version is spliced in as text above the old top version, so every other byte of the file
// stays as it was, comments and anchors included. The copy expands the old top version's aliases and
// merge keys, so the new version stands alone and a later edit cannot reach into another version
// through an anchor. Then the result is checked three ways before it is returned: it parses with
// every check the loader makes, the versions under it decode as they did and everything outside them
// as it did but for the domains and names the fragments add, and warp's allocator, run on both, gives
// every port block the file had the same external and internal ports, routing table and types it had,
// since warp's rules never let a block's port move.

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"reflect"
	"slices"
	"sort"
	"strings"

	"golang.org/x/exp/maps"
	"gopkg.in/yaml.v3"
)

// What a fragment's yaml holds: the mapping merged into the top version, and the registrar domains and
// dns names it adds outside the versions. Nothing else.
type servicesFragmentYaml struct {
	Domains yaml.Node `yaml:"domains"`
	Dns     yaml.Node `yaml:"dns"`
	Version yaml.Node `yaml:"version"`
}

// The one part of the dns block a fragment adds to.
type servicesFragmentDnsYaml struct {
	Unproxied []string `yaml:"unproxied"`
}

// A registrar domain a fragment adds, with its registrar as the fragment writes it.
type servicesFragmentDomain struct {
	name      string
	registrar string
}

// One fragment, parsed and checked as a version on its own.
type ServicesFragment struct {
	// where it came from, in messages
	Name    string
	version *yaml.Node
	// the registrar domains it adds, in its order
	domains []servicesFragmentDomain
	// the names it adds to dns.unproxied, in its order
	dnsUnproxied []string
}

// The registrars `warpctl certs issue` and `warpctl dns` know (warpctl/main.go, warpctl/dns_cmd.go): a
// domain with any other is one neither can serve, so a fragment's registrar is one of these.
var servicesFragmentRegistrars = []string{"cloudflare", "route53"}

// The sequences a fragment extends rather than leaves alone: the fragment's entries join what the top
// version has. secret_files stays sorted, which the loader requires.
var servicesFragmentUnionKeys = map[string]bool{
	"secret_files":   true,
	"cors_origins":   true,
	"expose_aliases": true,
}

// ErrServicesFragment is a fragment that cannot be applied. Nothing is written.
var ErrServicesFragment = errors.New("services fragment refused")

// A fragment's text, read and checked: one `version` mapping, whose keys are a version's, each spelled
// as the loader reads it, and beside it at most a `domains` mapping and a `dns` block holding only
// `unproxied`. A registrar is checked when the fragment is applied, so a placeholder parses.
func ParseServicesFragment(name string, data []byte) (*ServicesFragment, error) {
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	var fragmentYaml servicesFragmentYaml
	if err := decoder.Decode(&fragmentYaml); err != nil {
		return nil, fmt.Errorf("%w: %s: %v", ErrServicesFragment, name, err)
	}
	version := copyServicesFragmentNode(&fragmentYaml.Version)
	if version.Kind != yaml.MappingNode || len(version.Content) == 0 {
		return nil, fmt.Errorf("%w: %s holds no version mapping", ErrServicesFragment, name)
	}
	// a key the loader would not read is a typo that would silently do nothing
	text, err := encodeServicesFragmentNode(version)
	if err != nil {
		return nil, err
	}
	versionDecoder := yaml.NewDecoder(bytes.NewReader(text))
	versionDecoder.KnownFields(true)
	if err := versionDecoder.Decode(&ServicesConfigVersion{}); err != nil {
		return nil, fmt.Errorf("%w: %s's version: %v", ErrServicesFragment, name, err)
	}
	domains, err := parseServicesFragmentDomains(&fragmentYaml.Domains)
	if err != nil {
		return nil, fmt.Errorf("%w: %s's domains: %v", ErrServicesFragment, name, err)
	}
	dnsUnproxied, err := parseServicesFragmentDns(&fragmentYaml.Dns)
	if err != nil {
		return nil, fmt.Errorf("%w: %s's dns: %v", ErrServicesFragment, name, err)
	}
	return &ServicesFragment{Name: name, version: version, domains: domains, dnsUnproxied: dnsUnproxied}, nil
}

// A fragment's domains: each an exact lowercase domain, listed once, with a registrar written as a
// string. Absent, it adds none.
func parseServicesFragmentDomains(node *yaml.Node) ([]servicesFragmentDomain, error) {
	if node.Kind == 0 {
		return nil, nil
	}
	if node.Kind != yaml.MappingNode || len(node.Content) == 0 {
		return nil, errors.New("not a mapping of domains to their registrars")
	}
	domains := []servicesFragmentDomain{}
	for index := 0; index+1 < len(node.Content); index += 2 {
		key := node.Content[index]
		value := node.Content[index+1]
		if key.Kind != yaml.ScalarNode || value.Kind != yaml.ScalarNode || value.ShortTag() != "!!str" || value.Value == "" {
			return nil, fmt.Errorf("line %d is not a domain and its registrar", key.Line)
		}
		// an exact host, as no_access_log's are
		if !noAccessLogHostRegex.MatchString(key.Value) {
			return nil, fmt.Errorf("%q is not a lowercase domain", key.Value)
		}
		if slices.ContainsFunc(domains, func(domain servicesFragmentDomain) bool { return domain.name == key.Value }) {
			return nil, fmt.Errorf("%s is listed twice", key.Value)
		}
		domains = append(domains, servicesFragmentDomain{name: key.Value, registrar: value.Value})
	}
	return domains, nil
}

// A fragment's dns block: only unproxied, each an exact lowercase host, listed once. Absent, it adds
// none.
func parseServicesFragmentDns(node *yaml.Node) ([]string, error) {
	if node.Kind == 0 {
		return nil, nil
	}
	text, err := encodeServicesFragmentNode(node)
	if err != nil {
		return nil, err
	}
	decoder := yaml.NewDecoder(bytes.NewReader(text))
	decoder.KnownFields(true)
	var dnsYaml servicesFragmentDnsYaml
	if err := decoder.Decode(&dnsYaml); err != nil {
		return nil, err
	}
	if len(dnsYaml.Unproxied) == 0 {
		return nil, errors.New("adds no unproxied name, and that is the one list of the dns block a fragment adds to")
	}
	for index, host := range dnsYaml.Unproxied {
		if !noAccessLogHostRegex.MatchString(host) {
			return nil, fmt.Errorf("unproxied %q is not an exact lowercase host", host)
		}
		if slices.Contains(dnsYaml.Unproxied[:index], host) {
			return nil, fmt.Errorf("unproxied lists %s twice", host)
		}
	}
	return dnsYaml.Unproxied, nil
}

// A fragment file, read and checked.
func LoadServicesFragment(path string) (*ServicesFragment, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseServicesFragment(path, data)
}

// What applying fragments did.
type ServicesFragmentResult struct {
	// the services.yml with the new top version and the added domains and dns names, every other byte
	// as it was; the input itself when nothing changed
	Text []byte
	// the new top version as spliced in, empty when no version changed
	VersionText []byte
	// what each fragment added, one line each, such as "services.evs",
	// "services.api.secret_files: file-clusters-api.yml" or "domains.example.org: route53"
	Changes []string
	// each port block of the new version the file did not have, one line each
	AddedPortBlocks []string
}

// Whether the fragments changed anything.
func (self *ServicesFragmentResult) Changed() bool {
	return 0 < len(self.Changes)
}

// The fragments, in order, applied to a services.yml's text as one new top version. servicesConfigPath names the text in errors.
func ApplyServicesFragments(servicesYaml []byte, servicesConfigPath string, fragments ...*ServicesFragment) (*ServicesFragmentResult, error) {
	before, err := ParseServicesConfig(servicesYaml, servicesConfigPath)
	if err != nil {
		return nil, err
	}

	var document yaml.Node
	if err := yaml.Unmarshal(servicesYaml, &document); err != nil {
		return nil, err
	}
	if document.Kind != yaml.DocumentNode || len(document.Content) != 1 || document.Content[0].Kind != yaml.MappingNode {
		return nil, fmt.Errorf("%w: %s is not one yaml mapping", ErrServicesFragment, servicesConfigPath)
	}
	versions := servicesFragmentMappingValue(document.Content[0], "versions")
	if versions == nil || versions.Kind != yaml.SequenceNode || len(versions.Content) == 0 {
		return nil, fmt.Errorf("%w: %s has no versions", ErrServicesFragment, servicesConfigPath)
	}
	top := versions.Content[0]
	if top.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("%w: %s's top version is not written out as a mapping", ErrServicesFragment, servicesConfigPath)
	}

	newTop := copyServicesFragmentNode(top)
	// the copy must mean what the top version means, before anything merges into it
	var topVersion, copyVersion ServicesConfigVersion
	if err := top.Decode(&topVersion); err != nil {
		return nil, err
	}
	if err := newTop.Decode(&copyVersion); err != nil {
		return nil, err
	}
	if !reflect.DeepEqual(topVersion, copyVersion) {
		return nil, fmt.Errorf("%w: %s's top version does not copy to itself", ErrServicesFragment, servicesConfigPath)
	}

	result := &ServicesFragmentResult{Text: servicesYaml}
	additions := &servicesFragmentAdditions{}
	versionChanged := false
	for _, fragment := range fragments {
		outsideChanges, err := additions.merge(before, fragment)
		if err != nil {
			return nil, fmt.Errorf("%w: %s: %v", ErrServicesFragment, fragment.Name, err)
		}
		result.Changes = append(result.Changes, outsideChanges...)
		changes, err := mergeServicesFragmentNode(newTop, fragment.version, nil)
		if err != nil {
			return nil, fmt.Errorf("%w: %s: %v", ErrServicesFragment, fragment.Name, err)
		}
		result.Changes = append(result.Changes, changes...)
		versionChanged = versionChanged || 0 < len(changes)
	}
	if !result.Changed() {
		return result, nil
	}

	lines := strings.SplitAfter(string(servicesYaml), "\n")
	insertions, err := additions.insertions(document.Content[0])
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %v", ErrServicesFragment, servicesConfigPath, err)
	}
	var versionText []byte
	var splicedTop *yaml.Node
	if versionChanged {
		versionText, err = encodeServicesFragmentNode(newTop)
		if err != nil {
			return nil, err
		}
		insertion, err := servicesFragmentVersionInsertion(lines, top, versionText)
		if err != nil {
			return nil, fmt.Errorf("%w: %s: %v", ErrServicesFragment, servicesConfigPath, err)
		}
		insertions = append(insertions, insertion)
		splicedTop = newTop
	}
	text := spliceServicesFragmentLines(lines, insertions)

	after, err := ParseServicesConfig(text, servicesConfigPath)
	if err != nil {
		return nil, fmt.Errorf("%w: the merged file: %v", ErrServicesFragment, err)
	}
	if err := checkServicesFragmentSplice(servicesYaml, text, splicedTop, additions); err != nil {
		return nil, fmt.Errorf("%w: %s: %v", ErrServicesFragment, servicesConfigPath, err)
	}
	addedPortBlocks, err := compareServicesFragmentPortBlocks(before, after)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrServicesFragment, err)
	}

	result.Text = text
	result.VersionText = versionText
	result.AddedPortBlocks = addedPortBlocks
	return result, nil
}

// What fragments add outside the versions, in the order they add it.
type servicesFragmentAdditions struct {
	domains      []servicesFragmentDomain
	dnsUnproxied []string
}

// Takes what fragment adds outside the versions beyond what the file and earlier fragments hold, and
// returns it, one line each. A registrar warpctl does not know, such as a placeholder left unfilled,
// and a domain the file or an earlier fragment gives another registrar are refused.
func (self *servicesFragmentAdditions) merge(servicesConfig *ServicesConfig, fragment *ServicesFragment) ([]string, error) {
	changes := []string{}
	for _, domain := range fragment.domains {
		if !slices.Contains(servicesFragmentRegistrars, domain.registrar) {
			return nil, fmt.Errorf("domains.%s's registrar is %q: fill in %s, the registrars warpctl certs issue and warpctl dns know", domain.name, domain.registrar, strings.Join(servicesFragmentRegistrars, " or "))
		}
		registrar, held := servicesConfig.Domains[domain.name]
		where := "the file"
		for _, added := range self.domains {
			if added.name == domain.name {
				registrar, held, where = added.registrar, true, "an earlier fragment"
			}
		}
		if held {
			if registrar != domain.registrar {
				return nil, fmt.Errorf("domains.%s is %q in %s, and a fragment adds and never changes (the fragment says %q)", domain.name, registrar, where, domain.registrar)
			}
			continue
		}
		self.domains = append(self.domains, domain)
		changes = append(changes, fmt.Sprintf("domains.%s: %s", domain.name, domain.registrar))
	}
	heldHosts := servicesConfig.DnsUnproxiedHosts()
	for _, host := range fragment.dnsUnproxied {
		if slices.Contains(heldHosts, host) || slices.Contains(self.dnsUnproxied, host) {
			continue
		}
		self.dnsUnproxied = append(self.dnsUnproxied, host)
		changes = append(changes, fmt.Sprintf("dns.unproxied: %s", host))
	}
	return changes, nil
}

// Text put in before a line of the file, counted from 0.
type servicesFragmentInsertion struct {
	line int
	text string
}

// Where the additions go in the file root's text: the domains as the first entries of `domains`, the
// names as the first items of the dns block's `unproxied`, which goes in as the dns block's first
// entry when the block lacks it, and `domains` or the dns block as a block of its own just above
// `versions` when the file has none. Only block style takes a line, so a flow mapping or list there is
// refused.
func (self *servicesFragmentAdditions) insertions(root *yaml.Node) ([]servicesFragmentInsertion, error) {
	insertions := []servicesFragmentInsertion{}
	versionsKey, _ := servicesFragmentMappingEntry(root, "versions")
	if versionsKey == nil {
		return nil, errors.New("the file has no versions")
	}
	isBlock := func(node *yaml.Node, kind yaml.Kind) bool {
		return node.Kind == kind && node.Style&yaml.FlowStyle == 0 && 0 < len(node.Content)
	}
	indent := func(node *yaml.Node) string {
		return strings.Repeat(" ", node.Column-1)
	}

	if 0 < len(self.domains) {
		entries := func(prefix string) string {
			var builder strings.Builder
			for _, domain := range self.domains {
				fmt.Fprintf(&builder, "%s%s: %s\n", prefix, domain.name, domain.registrar)
			}
			return builder.String()
		}
		key, value := servicesFragmentMappingEntry(root, "domains")
		switch {
		case key == nil:
			insertions = append(insertions, servicesFragmentInsertion{line: versionsKey.Line - 1, text: "domains:\n" + entries("    ")})
		case isBlock(value, yaml.MappingNode) && key.Line < value.Line:
			insertions = append(insertions, servicesFragmentInsertion{line: key.Line, text: entries(indent(value))})
		default:
			return nil, errors.New("its domains is not a block mapping a line can join")
		}
	}

	if 0 < len(self.dnsUnproxied) {
		items := func(prefix string) string {
			var builder strings.Builder
			for _, host := range self.dnsUnproxied {
				fmt.Fprintf(&builder, "%s- %s\n", prefix, host)
			}
			return builder.String()
		}
		dnsKey, dnsValue := servicesFragmentMappingEntry(root, "dns")
		switch {
		case dnsKey == nil:
			insertions = append(insertions, servicesFragmentInsertion{line: versionsKey.Line - 1, text: "dns:\n    unproxied:\n" + items("        ")})
		case isBlock(dnsValue, yaml.MappingNode) && dnsKey.Line < dnsValue.Line:
			unproxiedKey, unproxiedValue := servicesFragmentMappingEntry(dnsValue, "unproxied")
			switch {
			case unproxiedKey == nil:
				insertions = append(insertions, servicesFragmentInsertion{line: dnsKey.Line, text: indent(dnsValue) + "unproxied:\n" + items(indent(dnsValue)+"    ")})
			case isBlock(unproxiedValue, yaml.SequenceNode) && unproxiedKey.Line < unproxiedValue.Line:
				insertions = append(insertions, servicesFragmentInsertion{line: unproxiedKey.Line, text: items(indent(unproxiedValue))})
			default:
				return nil, errors.New("its dns block's unproxied is not a block list a line can join")
			}
		default:
			return nil, errors.New("its dns block is not a block mapping a line can join")
		}
	}
	return insertions, nil
}

// The decoded file, outside its versions, as the additions leave it: each domain in `domains`, and the
// names ahead of the dns block's own unproxied names, as the text puts them.
func (self *servicesFragmentAdditions) applyTo(servicesConfig *ServicesConfig) {
	if 0 < len(self.domains) {
		if servicesConfig.Domains == nil {
			servicesConfig.Domains = map[string]string{}
		}
		for _, domain := range self.domains {
			servicesConfig.Domains[domain.name] = domain.registrar
		}
	}
	if 0 < len(self.dnsUnproxied) {
		if servicesConfig.Dns == nil {
			servicesConfig.Dns = &DnsConfig{}
		}
		servicesConfig.Dns.Unproxied = append(slices.Clone(self.dnsUnproxied), servicesConfig.Dns.Unproxied...)
	}
}

// The value under key in a mapping node, or nil.
func servicesFragmentMappingValue(mapping *yaml.Node, key string) *yaml.Node {
	_, value := servicesFragmentMappingEntry(mapping, key)
	return value
}

// The key node and value node of key in a mapping node, or nils.
func servicesFragmentMappingEntry(mapping *yaml.Node, key string) (*yaml.Node, *yaml.Node) {
	for index := 0; index+1 < len(mapping.Content); index += 2 {
		if mapping.Content[index].Value == key {
			return mapping.Content[index], mapping.Content[index+1]
		}
	}
	return nil, nil
}

// A deep copy that stands alone: aliases replaced by copies of what they name, merge keys (<<) expanded
// into the keys they bring, which the mapping's own keys override, as yaml's merge does, and no anchor,
// comment or position kept.
func copyServicesFragmentNode(node *yaml.Node) *yaml.Node {
	if node.Kind == yaml.AliasNode {
		return copyServicesFragmentNode(node.Alias)
	}
	copied := &yaml.Node{
		Kind:  node.Kind,
		Style: node.Style &^ (yaml.TaggedStyle | yaml.FlowStyle),
		Tag:   node.Tag,
		Value: node.Value,
	}
	if node.Kind != yaml.MappingNode {
		for _, child := range node.Content {
			copied.Content = append(copied.Content, copyServicesFragmentNode(child))
		}
		return copied
	}
	merged := []*yaml.Node{}
	for index := 0; index+1 < len(node.Content); index += 2 {
		key := node.Content[index]
		if key.Kind == yaml.ScalarNode && key.Tag == "!!merge" {
			merged = append(merged, node.Content[index+1])
			continue
		}
		copied.Content = append(copied.Content, copyServicesFragmentNode(key), copyServicesFragmentNode(node.Content[index+1]))
	}
	// each merged mapping in order, a key taken only where nothing before set it
	for _, value := range merged {
		sources := []*yaml.Node{value}
		if resolved := servicesFragmentResolve(value); resolved.Kind == yaml.SequenceNode {
			sources = resolved.Content
		}
		for _, source := range sources {
			mergedMapping := copyServicesFragmentNode(source)
			for index := 0; index+1 < len(mergedMapping.Content); index += 2 {
				if servicesFragmentMappingValue(copied, mergedMapping.Content[index].Value) == nil {
					copied.Content = append(copied.Content, mergedMapping.Content[index], mergedMapping.Content[index+1])
				}
			}
		}
	}
	return copied
}

// What an alias names, or the node itself.
func servicesFragmentResolve(node *yaml.Node) *yaml.Node {
	for node.Kind == yaml.AliasNode {
		node = node.Alias
	}
	return node
}

// A node's text, as the version's own yaml, indented by four as warp's services.yml is.
func encodeServicesFragmentNode(node *yaml.Node) ([]byte, error) {
	var buffer bytes.Buffer
	encoder := yaml.NewEncoder(&buffer)
	encoder.SetIndent(4)
	if err := encoder.Encode(node); err != nil {
		return nil, err
	}
	if err := encoder.Close(); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

// A scalar's value as yaml resolves it, so 80 and "80", or yes and true, are told apart as the loader
// tells them apart.
func servicesFragmentScalarValue(node *yaml.Node) (any, error) {
	var value any
	if err := node.Decode(&value); err != nil {
		return nil, err
	}
	return value, nil
}

// Merges src into dst, returning what it added. path is where dst is, for messages.
func mergeServicesFragmentNode(dst *yaml.Node, src *yaml.Node, path []string) ([]string, error) {
	where := strings.Join(path, ".")
	if where == "" {
		where = "the version"
	}
	if dst.Kind != src.Kind {
		return nil, fmt.Errorf("%s is a %s in the top version and a %s in the fragment", where, servicesFragmentKindName(dst), servicesFragmentKindName(src))
	}
	switch dst.Kind {
	case yaml.MappingNode:
		changes := []string{}
		for index := 0; index+1 < len(src.Content); index += 2 {
			key := src.Content[index]
			if key.Kind != yaml.ScalarNode {
				return nil, fmt.Errorf("%s has a key that is not a scalar", where)
			}
			keyPath := append(slices.Clone(path), key.Value)
			existing := servicesFragmentMappingValue(dst, key.Value)
			if existing == nil {
				dst.Content = append(dst.Content, copyServicesFragmentNode(key), copyServicesFragmentNode(src.Content[index+1]))
				changes = append(changes, strings.Join(keyPath, "."))
				continue
			}
			keyChanges, err := mergeServicesFragmentNode(existing, src.Content[index+1], keyPath)
			if err != nil {
				return nil, err
			}
			changes = append(changes, keyChanges...)
		}
		return changes, nil

	case yaml.SequenceNode:
		key := ""
		if 0 < len(path) {
			key = path[len(path)-1]
		}
		if !servicesFragmentUnionKeys[key] {
			if !servicesFragmentNodesEqual(dst, src) {
				return nil, fmt.Errorf("%s differs from the top version's, and a fragment only adds to %v", where, maps.Keys(servicesFragmentUnionKeys))
			}
			return nil, nil
		}
		changes := []string{}
		for _, item := range src.Content {
			if item.Kind != yaml.ScalarNode {
				return nil, fmt.Errorf("%s lists something that is not a scalar", where)
			}
			if !slices.ContainsFunc(dst.Content, func(existing *yaml.Node) bool { return servicesFragmentNodesEqual(existing, item) }) {
				dst.Content = append(dst.Content, copyServicesFragmentNode(item))
				changes = append(changes, fmt.Sprintf("%s: %s", where, item.Value))
			}
		}
		if key == "secret_files" {
			sort.SliceStable(dst.Content, func(i int, j int) bool {
				return dst.Content[i].Value < dst.Content[j].Value
			})
		}
		return changes, nil

	case yaml.ScalarNode:
		if !servicesFragmentNodesEqual(dst, src) {
			return nil, fmt.Errorf("%s is %q in the top version, and a fragment adds and never changes (the fragment says %q)", where, dst.Value, src.Value)
		}
		return nil, nil
	}
	return nil, fmt.Errorf("%s is a %s, which a fragment cannot merge", where, servicesFragmentKindName(dst))
}

// Whether two nodes mean the same yaml value.
func servicesFragmentNodesEqual(a *yaml.Node, b *yaml.Node) bool {
	aValue, aErr := servicesFragmentScalarValue(a)
	bValue, bErr := servicesFragmentScalarValue(b)
	return aErr == nil && bErr == nil && reflect.DeepEqual(aValue, bValue)
}

// A node's kind, in words, for messages.
func servicesFragmentKindName(node *yaml.Node) string {
	switch node.Kind {
	case yaml.MappingNode:
		return "mapping"
	case yaml.SequenceNode:
		return "list"
	case yaml.ScalarNode:
		return "value"
	case yaml.AliasNode:
		return "alias"
	}
	return "node"
}

// versionText as a new first item of versions, put in above the line top, the current first item,
// starts on, at the same indentation as its dash. lines is the file's text split after each newline.
func servicesFragmentVersionInsertion(lines []string, top *yaml.Node, versionText []byte) (servicesFragmentInsertion, error) {
	if top.Line < 1 || len(lines) < top.Line {
		return servicesFragmentInsertion{}, fmt.Errorf("the top version's line %d is not in the file", top.Line)
	}
	// the dash is on the top version's first line, or alone on the line before
	dashLine := top.Line - 1
	line := lines[dashLine]
	indent := len(line) - len(strings.TrimLeft(line, " "))
	if !strings.HasPrefix(line[indent:], "-") || top.Column-1 <= indent {
		if 0 < dashLine && strings.TrimSpace(lines[dashLine-1]) == "-" {
			dashLine -= 1
			line = lines[dashLine]
			indent = len(line) - len(strings.TrimLeft(line, " "))
		} else {
			return servicesFragmentInsertion{}, fmt.Errorf("found no dash before the top version on line %d", top.Line)
		}
	}
	prefix := strings.Repeat(" ", indent)
	var item strings.Builder
	for index, versionLine := range strings.SplitAfter(strings.TrimSuffix(string(versionText), "\n"), "\n") {
		if index == 0 {
			item.WriteString(prefix + "-   " + versionLine)
		} else if strings.TrimSpace(versionLine) == "" {
			item.WriteString(versionLine)
		} else {
			item.WriteString(prefix + "    " + versionLine)
		}
	}
	item.WriteString("\n")
	return servicesFragmentInsertion{line: dashLine, text: item.String()}, nil
}

// The file's lines with each insertion's text put in before its line, those at one line in the order
// given. Every other byte stays.
func spliceServicesFragmentLines(lines []string, insertions []servicesFragmentInsertion) []byte {
	lineTexts := map[int]string{}
	for _, insertion := range insertions {
		lineTexts[insertion.line] += insertion.text
	}
	var spliced strings.Builder
	for index, line := range lines {
		spliced.WriteString(lineTexts[index])
		spliced.WriteString(line)
	}
	return []byte(spliced.String())
}

// The spliced text means what was meant: its top version is newTop, or it has no new version when
// newTop is nil, every version under it decodes as the input's did, and everything outside the versions
// decodes as the input's did with the additions applied.
func checkServicesFragmentSplice(original []byte, spliced []byte, newTop *yaml.Node, additions *servicesFragmentAdditions) error {
	var originalConfig, splicedConfig ServicesConfig
	if err := yaml.Unmarshal(original, &originalConfig); err != nil {
		return err
	}
	if err := yaml.Unmarshal(spliced, &splicedConfig); err != nil {
		return err
	}
	added := 0
	if newTop != nil {
		added = 1
	}
	if len(splicedConfig.Versions) != len(originalConfig.Versions)+added {
		return fmt.Errorf("the merged file has %d versions, want %d", len(splicedConfig.Versions), len(originalConfig.Versions)+added)
	}
	if newTop != nil {
		var wantTop ServicesConfigVersion
		if err := newTop.Decode(&wantTop); err != nil {
			return err
		}
		if !reflect.DeepEqual(*splicedConfig.Versions[0], wantTop) {
			return errors.New("the new version decodes otherwise in place than alone")
		}
	}
	for index, version := range originalConfig.Versions {
		if !reflect.DeepEqual(*splicedConfig.Versions[index+added], *version) {
			return fmt.Errorf("version %d decodes otherwise under the new version", index)
		}
	}
	originalConfig.Versions = nil
	splicedConfig.Versions = nil
	additions.applyTo(&originalConfig)
	if !reflect.DeepEqual(originalConfig, splicedConfig) {
		return errors.New("the merged file changes something outside its versions beyond the domains and dns names the fragments add")
	}
	return nil
}

// Every port block before keeps its ports after; returns the blocks after that before lacked.
func compareServicesFragmentPortBlocks(before *ServicesConfig, after *ServicesConfig) ([]string, error) {
	quiet := func(format string, a ...any) {}
	beforePortBlocks, err := AllocatePortBlocks(before, quiet)
	if err != nil {
		return nil, fmt.Errorf("the file's ports: %w", err)
	}
	afterPortBlocks, err := AllocatePortBlocks(after, quiet)
	if err != nil {
		return nil, fmt.Errorf("the merged file's ports: %w", err)
	}
	describe := func(host string, portBlock *PortBlock) string {
		where := portBlock.Service
		if host != "" {
			where = host + " " + portBlock.Service
		}
		internalPorts := slices.Clone(portBlock.InternalPorts)
		slices.Sort(internalPorts)
		internal := ""
		if 0 < len(internalPorts) {
			internal = fmt.Sprintf("%d-%d", internalPorts[0], internalPorts[len(internalPorts)-1])
			if len(internalPorts) == 1 {
				internal = fmt.Sprintf("%d", internalPorts[0])
			}
		}
		return fmt.Sprintf("%s %s port %d: external %d, internal %s", where, portBlock.Block, portBlock.Port, portBlock.ExternalPort, internal)
	}
	same := func(a *PortBlock, b *PortBlock) bool {
		return a.ExternalPort == b.ExternalPort &&
			slices.Equal(a.InternalPorts, b.InternalPorts) &&
			a.RoutingTable == b.RoutingTable &&
			reflect.DeepEqual(a.ExternalPortTypes, b.ExternalPortTypes) &&
			reflect.DeepEqual(a.LbTypes, b.LbTypes)
	}
	moved := []string{}
	added := []string{}
	hosts := maps.Keys(afterPortBlocks)
	for host := range beforePortBlocks {
		if !slices.Contains(hosts, host) {
			hosts = append(hosts, host)
		}
	}
	sort.Strings(hosts)
	for _, host := range hosts {
		services := maps.Keys(afterPortBlocks[host])
		for service := range beforePortBlocks[host] {
			if !slices.Contains(services, service) {
				services = append(services, service)
			}
		}
		sort.Strings(services)
		for _, service := range services {
			blocks := maps.Keys(afterPortBlocks[host][service])
			for block := range beforePortBlocks[host][service] {
				if !slices.Contains(blocks, block) {
					blocks = append(blocks, block)
				}
			}
			sort.Strings(blocks)
			for _, block := range blocks {
				ports := maps.Keys(afterPortBlocks[host][service][block])
				for port := range beforePortBlocks[host][service][block] {
					if !slices.Contains(ports, port) {
						ports = append(ports, port)
					}
				}
				sort.Ints(ports)
				for _, port := range ports {
					beforePortBlock := beforePortBlocks[host][service][block][port]
					afterPortBlock := afterPortBlocks[host][service][block][port]
					switch {
					case beforePortBlock == nil:
						added = append(added, describe(host, afterPortBlock))
					case afterPortBlock == nil:
						moved = append(moved, describe(host, beforePortBlock)+", gone")
					case !same(beforePortBlock, afterPortBlock):
						moved = append(moved, describe(host, beforePortBlock)+", now "+describe(host, afterPortBlock))
					}
				}
			}
		}
	}
	if 0 < len(moved) {
		return nil, fmt.Errorf("the new version would move ports warp's rules fix: %s", strings.Join(moved, "; "))
	}
	return added, nil
}
