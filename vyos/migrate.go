package vyos

import (
	"fmt"
	"strings"
)

// Command is one configure-mode command.
type Command struct {
	// Op is "set" or "delete".
	Op   string
	Path []string
}

// String renders the command for a vbash configure session. Path elements
// are single-quoted when they carry characters the shell would interpret,
// so a password hash with `$` or a description with spaces survives intact.
func (c Command) String() string {
	parts := make([]string, 0, 1+len(c.Path))
	parts = append(parts, c.Op)
	for _, element := range c.Path {
		parts = append(parts, ShellQuote(element))
	}
	return strings.Join(parts, " ")
}

// ShellQuote quotes a word for bash unless it is made only of characters
// that need no quoting.
func ShellQuote(word string) string {
	if word != "" && isShellSafe(word) {
		return word
	}
	return "'" + strings.ReplaceAll(word, "'", `'\''`) + "'"
}

func isShellSafe(word string) bool {
	for i := 0; i < len(word); i++ {
		c := word[i]
		switch {
		case 'a' <= c && c <= 'z', 'A' <= c && c <= 'Z', '0' <= c && c <= '9':
		case strings.IndexByte("._:/@+=,%-", c) >= 0:
		default:
			return false
		}
	}
	return true
}

// Migration is the ordered set of commands that turns a live configuration
// into the desired one: every delete first, then every set, each in device
// order.
type Migration struct {
	Deletes []Command
	Sets    []Command
}

// Commands returns deletes followed by sets.
func (m *Migration) Commands() []Command {
	commands := make([]Command, 0, len(m.Deletes)+len(m.Sets))
	commands = append(commands, m.Deletes...)
	commands = append(commands, m.Sets...)
	return commands
}

// Empty reports whether the live configuration already matches.
func (m *Migration) Empty() bool {
	return len(m.Deletes) == 0 && len(m.Sets) == 0
}

// MigrateOptions tunes Migrate.
type MigrateOptions struct {
	// Protected lists path prefixes that a migration must never delete
	// under, such as the WAN interface address or the ssh service. A
	// migration that would is refused, since applying it could lock the
	// operator out of a remote router.
	Protected [][]string
}

// ProtectedPathError reports a refused delete.
type ProtectedPathError struct {
	Command Command
	Prefix  []string
}

func (e *ProtectedPathError) Error() string {
	return fmt.Sprintf("migration would delete under the protected path %q: %s", strings.Join(e.Prefix, " "), e.Command.String())
}

// Migrate computes the commands that change live into desired.
//
// A container present only in live is deleted with one command for the
// whole subtree. A leaf value present only in live is deleted by value, so
// a multi-valued leaf keeps its other values, and a single-valued leaf whose
// value changes is deleted then set rather than set twice, which on a
// multi-valued node would have added a second value. A live leaf whose one
// value is MaskedSecret is taken to equal a single desired value, since the
// capture does not reveal it.
func Migrate(live *Node, desired *Node, opts MigrateOptions) (*Migration, error) {
	migration := &Migration{}
	migrateNode(nil, live, desired, migration)
	for _, command := range migration.Deletes {
		for _, prefix := range opts.Protected {
			if hasPrefix(command.Path, prefix) {
				return nil, &ProtectedPathError{Command: command, Prefix: prefix}
			}
		}
	}
	return migration, nil
}

func hasPrefix(path []string, prefix []string) bool {
	if len(path) < len(prefix) {
		return false
	}
	for i := range prefix {
		if path[i] != prefix[i] {
			return false
		}
	}
	return true
}

func joinPath(prefix []string, elements ...string) []string {
	path := make([]string, 0, len(prefix)+len(elements))
	path = append(path, prefix...)
	path = append(path, elements...)
	return path
}

func keyPath(prefix []string, key Key) []string {
	if key.Tag == "" {
		return joinPath(prefix, key.Name)
	}
	return joinPath(prefix, key.Name, key.Tag)
}

func migrateNode(prefix []string, live *Node, desired *Node, migration *Migration) {
	for _, entry := range unionChildren(live, desired) {
		if entry.leaf {
			migrateLeaf(joinPath(prefix, entry.key.Name), live.leaves[entry.key.Name], desired.leaves[entry.key.Name], migration)
			continue
		}
		path := keyPath(prefix, entry.key)
		liveChild := live.containers[entry.key]
		desiredChild := desired.containers[entry.key]
		switch {
		case desiredChild == nil:
			migration.Deletes = append(migration.Deletes, Command{Op: "delete", Path: path})
		case liveChild == nil:
			setSubtree(path, desiredChild, migration)
		default:
			migrateNode(path, liveChild, desiredChild, migration)
		}
	}
}

func setSubtree(path []string, node *Node, migration *Migration) {
	for _, leafPath := range node.Paths() {
		migration.Sets = append(migration.Sets, Command{Op: "set", Path: joinPath(path, leafPath...)})
	}
	if node.Empty() {
		migration.Sets = append(migration.Sets, Command{Op: "set", Path: path})
	}
}

func migrateLeaf(path []string, live *Leaf, desired *Leaf, migration *Migration) {
	switch {
	case desired == nil:
		migration.Deletes = append(migration.Deletes, Command{Op: "delete", Path: path})
		return
	case live == nil:
		setLeaf(path, desired, migration)
		return
	}
	if len(live.Values) == 0 || len(desired.Values) == 0 {
		if len(live.Values) != len(desired.Values) {
			migration.Deletes = append(migration.Deletes, Command{Op: "delete", Path: path})
			setLeaf(path, desired, migration)
		}
		return
	}
	if len(live.Values) == 1 && live.Values[0] == MaskedSecret {
		if len(desired.Values) == 1 {
			return
		}
		migration.Deletes = append(migration.Deletes, Command{Op: "delete", Path: path})
		setLeaf(path, desired, migration)
		return
	}
	for _, value := range live.Values {
		if !contains(desired.Values, value) {
			migration.Deletes = append(migration.Deletes, Command{Op: "delete", Path: joinPath(path, value)})
		}
	}
	for _, value := range desired.Values {
		if !contains(live.Values, value) {
			migration.Sets = append(migration.Sets, Command{Op: "set", Path: joinPath(path, value)})
		}
	}
}

func setLeaf(path []string, leaf *Leaf, migration *Migration) {
	if len(leaf.Values) == 0 {
		migration.Sets = append(migration.Sets, Command{Op: "set", Path: path})
		return
	}
	for _, value := range leaf.Values {
		migration.Sets = append(migration.Sets, Command{Op: "set", Path: joinPath(path, value)})
	}
}

func contains(values []string, value string) bool {
	for _, existing := range values {
		if existing == value {
			return true
		}
	}
	return false
}

type unionEntry struct {
	key  Key
	leaf bool
}

// unionChildren lists the children of both nodes once each, in device order.
func unionChildren(a *Node, b *Node) []unionEntry {
	seenLeaves := map[string]bool{}
	seenContainers := map[Key]bool{}
	entries := []unionEntry{}
	for _, node := range []*Node{a, b} {
		for _, entry := range node.orderedChildren() {
			if entry.leaf != nil {
				if !seenLeaves[entry.key.Name] {
					seenLeaves[entry.key.Name] = true
					entries = append(entries, unionEntry{key: entry.key, leaf: true})
				}
				continue
			}
			if !seenContainers[entry.key] {
				seenContainers[entry.key] = true
				entries = append(entries, unionEntry{key: entry.key})
			}
		}
	}
	sortUnion(entries)
	return entries
}

func sortUnion(entries []unionEntry) {
	for i := 1; i < len(entries); i++ {
		for j := i; j > 0 && lessUnion(entries[j], entries[j-1]); j-- {
			entries[j], entries[j-1] = entries[j-1], entries[j]
		}
	}
}

func lessUnion(a unionEntry, b unionEntry) bool {
	if lessKey(a.key, b.key) {
		return true
	}
	if lessKey(b.key, a.key) {
		return false
	}
	return a.leaf && !b.leaf
}

// ScriptOptions describes the migration script header and commit mode.
type ScriptOptions struct {
	Router string
	Env    string
	// CommitConfirmMinutes replaces `commit` with `commit-confirm <n>`, so
	// the router reboots into its saved configuration unless `confirm` runs
	// within n minutes. Zero commits without a timer. EdgeOS v3.0.1 has no
	// commit-confirm: its script-template defines neither it nor confirm,
	// so a script asking for it fails before commit on such a router.
	CommitConfirmMinutes int
}

// ChangesHeader is the machine readable summary line in every script.
const ChangesHeader = "# warpctl-vyos-migration changes="

// Script renders the migration as a vbash configure session using the
// device's /opt/vyatta/etc/functions/script-template, whose `set`, `delete`
// and `commit` aliases wrap my_set, my_delete and my_commit. Every command
// aborts on failure, tearing the session down before commit, so nothing is
// committed unless every set and delete was accepted; a successful commit
// tears the session down with configure_exit. The script ends without
// `save`: the caller installs the generated config.boot after verifying the
// running configuration converged.
func (m *Migration) Script(opts ScriptOptions) string {
	var out strings.Builder
	out.WriteString("#!/bin/vbash\n")
	fmt.Fprintf(&out, "# warpctl vyos migration: router %s env %s\n", opts.Router, opts.Env)
	fmt.Fprintf(&out, "%s%d deletes=%d sets=%d\n", ChangesHeader, len(m.Deletes)+len(m.Sets), len(m.Deletes), len(m.Sets))
	if m.Empty() {
		out.WriteString("# The live configuration already matches; nothing to apply.\n")
		out.WriteString("exit 0\n")
		return out.String()
	}
	out.WriteString("# Run on the router as `vbash <this file>`. A failed command ends the\n")
	out.WriteString("# configure session before commit, so a partial migration is never applied.\n")
	out.WriteString("source /opt/vyatta/etc/functions/script-template\n")
	out.WriteString("fail() {\n")
	out.WriteString("    echo \"warp migration failed at line $1\" >&2\n")
	out.WriteString("    eval \"$(vyatta_exit_configure)\"\n")
	out.WriteString("    builtin exit 1\n")
	out.WriteString("}\n")
	out.WriteString("configure\n")
	for _, command := range m.Commands() {
		out.WriteString(command.String())
		out.WriteString(" || fail $LINENO\n")
	}
	if opts.CommitConfirmMinutes > 0 {
		fmt.Fprintf(&out, "commit-confirm %d || fail $LINENO\n", opts.CommitConfirmMinutes)
	} else {
		out.WriteString("commit || fail $LINENO\n")
	}
	out.WriteString("configure_exit\n")
	return out.String()
}
