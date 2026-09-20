// Package vyos models EdgeOS (Vyatta) configuration trees: the brace format
// written to /config/config.boot and printed by `show configuration` and by
// `show` in configure mode.
//
// The tree keeps three kinds of children under a container:
//
//   - a leaf with one or more values (`address 10.0.0.1/24`, printed one
//     value per line, in the order the values were set),
//   - a valueless leaf (`enable-default-log`),
//   - a container, optionally a tag instance (`rule 10 { ... }`).
//
// Serialization reproduces the device's own rendering byte for byte: four
// space indents, children ordered with the Debian package version comparison
// that Vyatta's config store uses (so `rule 10` sorts before `rule 100`,
// `ipv6-name` before `ip-src-route` and `http-port` before `https-port`),
// and values quoted only when the device would quote them.
package vyos

import (
	"errors"
	"fmt"
	"sort"
	"strings"
)

// MaskedSecret is what `show` prints in place of a secret value such as an
// encrypted password. A capture that carries it does not reveal the value, so
// the differ treats it as unknown rather than as a change.
const MaskedSecret = "****************"

// Key identifies a container child of a node. Tag is empty for a plain
// container (`firewall {`) and set for a tag instance (`rule 10 {`).
type Key struct {
	Name string
	Tag  string
}

// String renders the key the way the device prints it before the brace.
func (k Key) String() string {
	if k.Tag == "" {
		return k.Name
	}
	return k.Name + " " + Quote(k.Tag)
}

// Leaf is a leaf node. An empty Values slice is a valueless leaf.
type Leaf struct {
	Values []string
}

// Node is a container in the configuration tree.
type Node struct {
	leaves     map[string]*Leaf
	containers map[Key]*Node
}

// Config is a parsed configuration: the tree plus the trailing comment lines
// that config.boot carries (the vyatta-config-version and release markers).
type Config struct {
	Root     *Node
	Comments []string
}

// NewNode returns an empty container.
func NewNode() *Node {
	return &Node{
		leaves:     map[string]*Leaf{},
		containers: map[Key]*Node{},
	}
}

// Child returns the plain container `name`, creating it when absent.
func (n *Node) Child(name string) *Node {
	return n.Tag(name, "")
}

// Tag returns the tag instance `name tag`, creating it when absent.
func (n *Node) Tag(name string, tag string) *Node {
	key := Key{Name: name, Tag: tag}
	child, ok := n.containers[key]
	if !ok {
		child = NewNode()
		n.containers[key] = child
	}
	return child
}

// SetLeaf replaces the leaf `name` with the given values. No values makes a
// valueless leaf. Duplicate values are dropped, first occurrence wins.
func (n *Node) SetLeaf(name string, values ...string) {
	leaf := &Leaf{}
	for _, value := range values {
		leaf.add(value)
	}
	n.leaves[name] = leaf
}

// AddLeafValue appends a value to the leaf `name`, creating the leaf when
// absent and ignoring a value that is already present.
func (n *Node) AddLeafValue(name string, value string) {
	leaf, ok := n.leaves[name]
	if !ok {
		leaf = &Leaf{}
		n.leaves[name] = leaf
	}
	leaf.add(value)
}

func (l *Leaf) add(value string) {
	for _, existing := range l.Values {
		if existing == value {
			return
		}
	}
	l.Values = append(l.Values, value)
}

// Leaf returns the leaf `name`, or nil.
func (n *Node) Leaf(name string) *Leaf {
	return n.leaves[name]
}

// LeafValues returns the values of the leaf at path (the last element is the
// leaf name), or nil when there is no such leaf. Containers along the path
// are resolved by name and, when the next element is not a child name, by
// `name tag` pairs.
func (n *Node) LeafValues(path ...string) []string {
	if len(path) == 0 {
		return nil
	}
	parent := n.Lookup(path[:len(path)-1]...)
	if parent == nil {
		return nil
	}
	leaf := parent.leaves[path[len(path)-1]]
	if leaf == nil {
		return nil
	}
	return append([]string{}, leaf.Values...)
}

// HasLeaf reports whether the leaf at path exists.
func (n *Node) HasLeaf(path ...string) bool {
	if len(path) == 0 {
		return false
	}
	parent := n.Lookup(path[:len(path)-1]...)
	if parent == nil {
		return false
	}
	_, ok := parent.leaves[path[len(path)-1]]
	return ok
}

// Container returns the container child for key, or nil.
func (n *Node) Container(key Key) *Node {
	return n.containers[key]
}

// Lookup walks containers by path. Each element is a container name; a name
// that is a tag node consumes the following element as its tag. Returns nil
// when the path does not resolve to a container.
func (n *Node) Lookup(path ...string) *Node {
	current := n
	for i := 0; i < len(path); i++ {
		if child, ok := current.containers[Key{Name: path[i]}]; ok {
			current = child
			continue
		}
		if i+1 < len(path) {
			if child, ok := current.containers[Key{Name: path[i], Tag: path[i+1]}]; ok {
				current = child
				i++
				continue
			}
		}
		return nil
	}
	return current
}

// Empty reports whether the container has no children.
func (n *Node) Empty() bool {
	return len(n.leaves) == 0 && len(n.containers) == 0
}

// LeafNames returns the leaf names in device order.
func (n *Node) LeafNames() []string {
	names := make([]string, 0, len(n.leaves))
	for name := range n.leaves {
		names = append(names, name)
	}
	sort.Slice(names, func(i int, j int) bool {
		return Compare(names[i], names[j]) < 0
	})
	return names
}

// ContainerKeys returns the container keys in device order.
func (n *Node) ContainerKeys() []Key {
	keys := make([]Key, 0, len(n.containers))
	for key := range n.containers {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i int, j int) bool {
		return lessKey(keys[i], keys[j])
	})
	return keys
}

// lessKey orders siblings as the device does: by node name, then for tag
// instances of one node by tag value.
func lessKey(a Key, b Key) bool {
	if c := Compare(a.Name, b.Name); c != 0 {
		return c < 0
	}
	return Compare(a.Tag, b.Tag) < 0
}

// Equal reports whether two trees hold the same leaves (values compared as
// ordered lists) and containers.
func (n *Node) Equal(other *Node) bool {
	if n == nil || other == nil {
		return n == other
	}
	if len(n.leaves) != len(other.leaves) || len(n.containers) != len(other.containers) {
		return false
	}
	for name, leaf := range n.leaves {
		otherLeaf, ok := other.leaves[name]
		if !ok || len(leaf.Values) != len(otherLeaf.Values) {
			return false
		}
		for i := range leaf.Values {
			if leaf.Values[i] != otherLeaf.Values[i] {
				return false
			}
		}
	}
	for key, child := range n.containers {
		otherChild, ok := other.containers[key]
		if !ok || !child.Equal(otherChild) {
			return false
		}
	}
	return true
}

// Paths lists every leaf value, valueless leaf and empty container as a path,
// in device order. `set` of each path reproduces the tree.
func (n *Node) Paths() [][]string {
	paths := [][]string{}
	n.appendPaths(nil, &paths)
	return paths
}

func (n *Node) appendPaths(prefix []string, paths *[][]string) {
	if n.Empty() && len(prefix) != 0 {
		*paths = append(*paths, append([]string{}, prefix...))
		return
	}
	for _, entry := range n.orderedChildren() {
		if entry.leaf != nil {
			if len(entry.leaf.Values) == 0 {
				*paths = append(*paths, append(append([]string{}, prefix...), entry.key.Name))
				continue
			}
			for _, value := range entry.leaf.Values {
				*paths = append(*paths, append(append([]string{}, prefix...), entry.key.Name, value))
			}
			continue
		}
		childPrefix := append(append([]string{}, prefix...), entry.key.Name)
		if entry.key.Tag != "" {
			childPrefix = append(childPrefix, entry.key.Tag)
		}
		entry.container.appendPaths(childPrefix, paths)
	}
}

type childEntry struct {
	key       Key
	leaf      *Leaf
	container *Node
}

// orderedChildren interleaves leaves and containers in device order.
func (n *Node) orderedChildren() []childEntry {
	entries := make([]childEntry, 0, len(n.leaves)+len(n.containers))
	for name, leaf := range n.leaves {
		entries = append(entries, childEntry{key: Key{Name: name}, leaf: leaf})
	}
	for key, container := range n.containers {
		entries = append(entries, childEntry{key: key, container: container})
	}
	sort.Slice(entries, func(i int, j int) bool {
		if lessKey(entries[i].key, entries[j].key) {
			return true
		}
		if lessKey(entries[j].key, entries[i].key) {
			return false
		}
		// a leaf and a plain container of the same name: print the leaf first
		return entries[i].leaf != nil && entries[j].leaf == nil
	})
	return entries
}

// String renders the tree in the device's brace format.
func (n *Node) String() string {
	var out strings.Builder
	n.render(&out, 0)
	return out.String()
}

func (n *Node) render(out *strings.Builder, indent int) {
	pad := strings.Repeat(" ", indent)
	for _, entry := range n.orderedChildren() {
		if entry.leaf != nil {
			if len(entry.leaf.Values) == 0 {
				out.WriteString(pad)
				out.WriteString(entry.key.Name)
				out.WriteString("\n")
				continue
			}
			for _, value := range entry.leaf.Values {
				out.WriteString(pad)
				out.WriteString(entry.key.Name)
				out.WriteString(" ")
				out.WriteString(Quote(value))
				out.WriteString("\n")
			}
			continue
		}
		out.WriteString(pad)
		out.WriteString(entry.key.String())
		out.WriteString(" {\n")
		entry.container.render(out, indent+4)
		out.WriteString(pad)
		out.WriteString("}\n")
	}
}

// String renders the config as a config.boot file: the tree, then the
// comment lines after two blank lines, as the device writes them.
func (c *Config) String() string {
	text := c.Root.String()
	if len(c.Comments) == 0 {
		return text
	}
	return text + "\n\n" + strings.Join(c.Comments, "\n") + "\n"
}

// Quote wraps a value in double quotes exactly when the device would: the
// value is empty or contains whitespace or one of `*{};`. The device does
// not escape anything inside the quotes.
func Quote(value string) string {
	if value == "" || strings.ContainsAny(value, "*{}; \t\n\v\f\r") {
		return "\"" + value + "\""
	}
	return value
}

// ErrUncommitted reports a capture taken from a configure session with
// uncommitted changes (`+`, `-` or `>` change markers).
var ErrUncommitted = errors.New("configuration has uncommitted changes")

// Parse reads the brace format. It accepts config.boot files (comment lines
// are collected into Comments) and the output of `show configuration` or a
// configure-mode `show` (a trailing `[edit]` prompt line is ignored). A
// capture with change markers is rejected with ErrUncommitted.
func Parse(text string) (*Config, error) {
	config := &Config{Root: NewNode()}
	stack := []*Node{config.Root}
	lines := strings.Split(text, "\n")
	for i := 0; i < len(lines); i++ {
		line := strings.TrimRight(lines[i], "\r")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if strings.HasPrefix(trimmed, "/*") {
			comment := trimmed
			for !strings.HasSuffix(comment, "*/") {
				i++
				if i >= len(lines) {
					return nil, fmt.Errorf("line %d: unterminated comment", i)
				}
				comment += "\n" + strings.TrimRight(lines[i], "\r")
			}
			config.Comments = append(config.Comments, comment)
			continue
		}
		if strings.HasPrefix(trimmed, "[edit") {
			continue
		}
		switch line[0] {
		case '+', '-', '>':
			return nil, fmt.Errorf("line %d: %w", i+1, ErrUncommitted)
		}
		if trimmed == "}" {
			if len(stack) == 1 {
				return nil, fmt.Errorf("line %d: unexpected }", i+1)
			}
			stack = stack[:len(stack)-1]
			continue
		}
		tokens, err := tokenize(trimmed)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", i+1, err)
		}
		current := stack[len(stack)-1]
		if tokens[len(tokens)-1].text == "{" && !tokens[len(tokens)-1].quoted {
			tokens = tokens[:len(tokens)-1]
			switch len(tokens) {
			case 1:
				stack = append(stack, current.Child(tokens[0].text))
			case 2:
				stack = append(stack, current.Tag(tokens[0].text, tokens[1].text))
			default:
				return nil, fmt.Errorf("line %d: a container opens with a name and at most one tag: %q", i+1, trimmed)
			}
			continue
		}
		switch len(tokens) {
		case 1:
			if _, ok := current.leaves[tokens[0].text]; !ok {
				current.leaves[tokens[0].text] = &Leaf{}
			}
		case 2:
			leaf, ok := current.leaves[tokens[0].text]
			if !ok {
				leaf = &Leaf{}
				current.leaves[tokens[0].text] = leaf
			}
			leaf.Values = append(leaf.Values, tokens[1].text)
		default:
			return nil, fmt.Errorf("line %d: a leaf has a name and at most one value: %q", i+1, trimmed)
		}
	}
	if len(stack) != 1 {
		return nil, errors.New("unbalanced braces: missing }")
	}
	return config, nil
}

type token struct {
	text   string
	quoted bool
}

// tokenize splits a config line on whitespace, keeping a double-quoted
// span as one token (without its quotes). `\"` inside quotes yields a quote.
func tokenize(line string) ([]token, error) {
	tokens := []token{}
	var current strings.Builder
	inToken := false
	quoted := false
	inQuotes := false
	flush := func() {
		if inToken {
			tokens = append(tokens, token{text: current.String(), quoted: quoted})
			current.Reset()
			inToken = false
			quoted = false
		}
	}
	for i := 0; i < len(line); i++ {
		c := line[i]
		if inQuotes {
			switch {
			case c == '\\' && i+1 < len(line) && line[i+1] == '"':
				current.WriteByte('"')
				i++
			case c == '"':
				inQuotes = false
			default:
				current.WriteByte(c)
			}
			continue
		}
		switch c {
		case ' ', '\t':
			flush()
		case '"':
			inQuotes = true
			inToken = true
			quoted = true
		default:
			inToken = true
			current.WriteByte(c)
		}
	}
	if inQuotes {
		return nil, fmt.Errorf("unterminated quote: %q", line)
	}
	flush()
	if len(tokens) == 0 {
		return nil, fmt.Errorf("empty line")
	}
	return tokens, nil
}

// Compare orders two names the way the device orders sibling nodes: the
// Debian package version comparison. Each name splits at its last hyphen
// into a version and a revision, compared in turn with dpkg's verrevcmp:
// digit runs compare numerically, letters sort before non-letters, a
// shorter string sorts before its extension, and `~` sorts before
// everything. It returns -1, 0 or 1.
func Compare(a string, b string) int {
	aVersion, aRevision := splitRevision(a)
	bVersion, bRevision := splitRevision(b)
	if c := verrevcmp(aVersion, bVersion); c != 0 {
		return c
	}
	return verrevcmp(aRevision, bRevision)
}

func splitRevision(s string) (string, string) {
	if i := strings.LastIndexByte(s, '-'); i >= 0 {
		return s[:i], s[i+1:]
	}
	return s, ""
}

func verrevcmp(a string, b string) int {
	i, j := 0, 0
	for i < len(a) || j < len(b) {
		firstDiff := 0
		for (i < len(a) && !isDigit(a[i])) || (j < len(b) && !isDigit(b[j])) {
			ac := order(byteAt(a, i))
			bc := order(byteAt(b, j))
			if ac != bc {
				return sign(ac - bc)
			}
			i++
			j++
		}
		for i < len(a) && a[i] == '0' {
			i++
		}
		for j < len(b) && b[j] == '0' {
			j++
		}
		for i < len(a) && isDigit(a[i]) && j < len(b) && isDigit(b[j]) {
			if firstDiff == 0 {
				firstDiff = int(a[i]) - int(b[j])
			}
			i++
			j++
		}
		if i < len(a) && isDigit(a[i]) {
			return 1
		}
		if j < len(b) && isDigit(b[j]) {
			return -1
		}
		if firstDiff != 0 {
			return sign(firstDiff)
		}
	}
	return 0
}

func byteAt(s string, i int) byte {
	if i < len(s) {
		return s[i]
	}
	return 0
}

func isDigit(c byte) bool {
	return '0' <= c && c <= '9'
}

func isAlpha(c byte) bool {
	return ('a' <= c && c <= 'z') || ('A' <= c && c <= 'Z')
}

func order(c byte) int {
	switch {
	case isDigit(c):
		return 0
	case isAlpha(c):
		return int(c)
	case c == '~':
		return -1
	case c != 0:
		return int(c) + 256
	default:
		return 0
	}
}

func sign(v int) int {
	switch {
	case v < 0:
		return -1
	case v > 0:
		return 1
	default:
		return 0
	}
}
