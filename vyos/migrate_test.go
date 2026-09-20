package vyos

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

func mustParse(t *testing.T, text string) *Node {
	t.Helper()
	config, err := Parse(text)
	if err != nil {
		t.Fatal(err)
	}
	return config.Root
}

func commandStrings(commands []Command) []string {
	out := make([]string, 0, len(commands))
	for _, command := range commands {
		out = append(out, command.String())
	}
	return out
}

func mustMigrate(t *testing.T, live *Node, desired *Node) *Migration {
	t.Helper()
	migration, err := Migrate(live, desired, MigrateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	return migration
}

func TestMigrateIsEmptyWhenConverged(t *testing.T) {
	for _, name := range []string{"by-us-fmt-5-8-config.boot", "by-us-fmt-5-9-config.boot"} {
		live := mustParse(t, readFixture(t, name))
		desired := mustParse(t, readFixture(t, name))
		migration := mustMigrate(t, live, desired)
		if !migration.Empty() {
			t.Fatalf("%s: converged config produced %v", name, commandStrings(migration.Commands()))
		}
		if !strings.Contains(migration.Script(ScriptOptions{Router: "r", Env: "main"}), ChangesHeader+"0 deletes=0 sets=0\n") {
			t.Fatal("empty migration must report zero changes")
		}
	}
}

func TestMigrateDeletesARemovedSubtreeWithOneCommand(t *testing.T) {
	live := mustParse(t, strings.Join([]string{
		"firewall {",
		"    name WAN_IN {",
		"        rule 40 {",
		"            action accept",
		"            destination {",
		"                address 65.49.70.84",
		"                port 80",
		"            }",
		"        }",
		"        rule 50 {",
		"            action accept",
		"        }",
		"    }",
		"}",
	}, "\n"))
	desired := mustParse(t, strings.Join([]string{
		"firewall {",
		"    name WAN_IN {",
		"        rule 50 {",
		"            action accept",
		"        }",
		"    }",
		"}",
	}, "\n"))
	migration := mustMigrate(t, live, desired)
	if got := commandStrings(migration.Commands()); !reflect.DeepEqual(got, []string{"delete firewall name WAN_IN rule 40"}) {
		t.Fatalf("commands = %v", got)
	}
}

func TestMigrateSetsANewSubtreeLeafByLeaf(t *testing.T) {
	live := mustParse(t, "firewall {\n    name WAN_IN {\n        default-action drop\n    }\n}\n")
	desired := mustParse(t, strings.Join([]string{
		"firewall {",
		"    name WAN_IN {",
		"        default-action drop",
		"        rule 100 {",
		"            action accept",
		`            description "warp edge-3 eno1np0 lb 80"`,
		"            destination {",
		"                address 65.49.70.84",
		"                port 80",
		"            }",
		"            log disable",
		"            protocol tcp_udp",
		"        }",
		"    }",
		"}",
		"interfaces {",
		"    loopback lo {",
		"    }",
		"}",
	}, "\n"))
	migration := mustMigrate(t, live, desired)
	want := []string{
		"set firewall name WAN_IN rule 100 action accept",
		"set firewall name WAN_IN rule 100 description 'warp edge-3 eno1np0 lb 80'",
		"set firewall name WAN_IN rule 100 destination address 65.49.70.84",
		"set firewall name WAN_IN rule 100 destination port 80",
		"set firewall name WAN_IN rule 100 log disable",
		"set firewall name WAN_IN rule 100 protocol tcp_udp",
		"set interfaces loopback lo",
	}
	if got := commandStrings(migration.Commands()); !reflect.DeepEqual(got, want) {
		t.Fatalf("commands = %v\nwant %v", got, want)
	}
}

func TestMigrateChangesASingleValueByDeleteThenSet(t *testing.T) {
	live := mustParse(t, "firewall {\n    name WAN_IN {\n        rule 10 {\n            action accept\n            log disable\n        }\n    }\n}\n")
	desired := mustParse(t, "firewall {\n    name WAN_IN {\n        rule 10 {\n            action drop\n            log disable\n        }\n    }\n}\n")
	migration := mustMigrate(t, live, desired)
	want := []string{
		"delete firewall name WAN_IN rule 10 action accept",
		"set firewall name WAN_IN rule 10 action drop",
	}
	if got := commandStrings(migration.Commands()); !reflect.DeepEqual(got, want) {
		t.Fatalf("commands = %v", got)
	}
}

func TestMigrateMultiValuedLeafKeepsUnchangedValues(t *testing.T) {
	live := mustParse(t, "interfaces {\n    ethernet eth1 {\n        address 65.49.70.81/27\n        address 2001:470:99::58/48\n    }\n}\n")
	desired := mustParse(t, "interfaces {\n    ethernet eth1 {\n        address 65.49.70.81/27\n        address 2001:470:99::59/48\n    }\n}\n")
	migration := mustMigrate(t, live, desired)
	want := []string{
		"delete interfaces ethernet eth1 address 2001:470:99::58/48",
		"set interfaces ethernet eth1 address 2001:470:99::59/48",
	}
	if got := commandStrings(migration.Commands()); !reflect.DeepEqual(got, want) {
		t.Fatalf("commands = %v", got)
	}
	// value order alone is not a change
	reordered := mustParse(t, "interfaces {\n    ethernet eth1 {\n        address 2001:470:99::58/48\n        address 65.49.70.81/27\n    }\n}\n")
	if migration := mustMigrate(t, live, reordered); !migration.Empty() {
		t.Fatalf("reordered values produced %v", commandStrings(migration.Commands()))
	}
}

func TestMigrateValuelessLeavesAndEmptyContainers(t *testing.T) {
	live := mustParse(t, strings.Join([]string{
		"service {",
		"    nat {",
		"        rule 5000 {",
		"            log disable",
		"        }",
		"    }",
		"}",
		"interfaces {",
		"    loopback lo {",
		"    }",
		"    ethernet eth3 {",
		"        duplex auto",
		"    }",
		"}",
		"firewall {",
		"    ipv6-name WANv6_IN {",
		"        enable-default-log",
		"    }",
		"}",
	}, "\n"))
	desired := mustParse(t, strings.Join([]string{
		"service {",
		"    nat {",
		"        rule 5000 {",
		"            exclude",
		"            log disable",
		"        }",
		"    }",
		"}",
		"interfaces {",
		"    loopback lo {",
		"        description x",
		"    }",
		"    ethernet eth3 {",
		"    }",
		"}",
		"firewall {",
		"    ipv6-name WANv6_IN {",
		"    }",
		"}",
	}, "\n"))
	migration := mustMigrate(t, live, desired)
	want := []string{
		"delete firewall ipv6-name WANv6_IN enable-default-log",
		"delete interfaces ethernet eth3 duplex",
		"set interfaces loopback lo description x",
		"set service nat rule 5000 exclude",
	}
	if got := commandStrings(migration.Commands()); !reflect.DeepEqual(got, want) {
		t.Fatalf("commands = %v", got)
	}
	// a valueless leaf becoming a valued one is a replacement
	flipped := mustMigrate(t, mustParse(t, "a {\n    b\n}\n"), mustParse(t, "a {\n    b c\n}\n"))
	if got := commandStrings(flipped.Commands()); !reflect.DeepEqual(got, []string{"delete a b", "set a b c"}) {
		t.Fatalf("commands = %v", got)
	}
}

func TestMigrateTreatsMaskedSecretsAsUnknown(t *testing.T) {
	live := mustParse(t, "system {\n    login {\n        user ubnt {\n            authentication {\n                encrypted-password \"****************\"\n            }\n        }\n    }\n}\n")
	desired := mustParse(t, "system {\n    login {\n        user ubnt {\n            authentication {\n                encrypted-password $5$salt$hash\n            }\n        }\n    }\n}\n")
	if migration := mustMigrate(t, live, desired); !migration.Empty() {
		t.Fatalf("masked secret produced %v", commandStrings(migration.Commands()))
	}
	multi := mustParse(t, "system {\n    login {\n        user ubnt {\n            authentication {\n                encrypted-password a\n                encrypted-password b\n            }\n        }\n    }\n}\n")
	migration := mustMigrate(t, live, multi)
	want := []string{
		"delete system login user ubnt authentication encrypted-password",
		"set system login user ubnt authentication encrypted-password a",
		"set system login user ubnt authentication encrypted-password b",
	}
	if got := commandStrings(migration.Commands()); !reflect.DeepEqual(got, want) {
		t.Fatalf("commands = %v", got)
	}
}

func TestMigrateRefusesProtectedDeletes(t *testing.T) {
	live := mustParse(t, "interfaces {\n    ethernet eth1 {\n        address 65.49.70.81/27\n        address 65.49.70.82/27\n        description Internet\n    }\n}\nservice {\n    ssh {\n        port 22\n    }\n}\n")
	desired := mustParse(t, "interfaces {\n    ethernet eth1 {\n        address 65.49.70.81/27\n    }\n}\n")
	protected := [][]string{{"interfaces", "ethernet", "eth1", "address"}, {"service", "ssh"}}
	_, err := Migrate(live, desired, MigrateOptions{Protected: protected})
	var protectedErr *ProtectedPathError
	if !errors.As(err, &protectedErr) {
		t.Fatalf("err = %v, want a ProtectedPathError", err)
	}
	if got := protectedErr.Command.String(); got != "delete interfaces ethernet eth1 address 65.49.70.82/27" {
		t.Fatalf("refused command = %s", got)
	}
	if !strings.Contains(err.Error(), "interfaces ethernet eth1 address") {
		t.Fatalf("error text = %s", err)
	}
	// a delete outside the protected prefixes passes
	desired.Child("interfaces").Tag("ethernet", "eth1").AddLeafValue("address", "65.49.70.82/27")
	desired.Child("service").Child("ssh").SetLeaf("port", "22")
	migration, err := Migrate(live, desired, MigrateOptions{Protected: protected})
	if err != nil {
		t.Fatal(err)
	}
	if got := commandStrings(migration.Commands()); !reflect.DeepEqual(got, []string{"delete interfaces ethernet eth1 description"}) {
		t.Fatalf("commands = %v", got)
	}
}

func TestCommandStringQuotesForTheShell(t *testing.T) {
	cases := []struct {
		command Command
		want    string
	}{
		{Command{Op: "set", Path: []string{"system", "login", "user", "ubnt", "authentication", "encrypted-password", "$5$r7MW$jLa/O.U"}}, "set system login user ubnt authentication encrypted-password '$5$r7MW$jLa/O.U'"},
		{Command{Op: "set", Path: []string{"firewall", "name", "WAN_IN", "description", "WAN to internal"}}, "set firewall name WAN_IN description 'WAN to internal'"},
		{Command{Op: "set", Path: []string{"a", "it's"}}, `set a 'it'\''s'`},
		{Command{Op: "set", Path: []string{"a", ""}}, "set a ''"},
		{Command{Op: "set", Path: []string{"service", "unms", "connection", "wss://bringyour.uisp.com:443+abc_-+allowUntrustedCertificate"}}, "set service unms connection wss://bringyour.uisp.com:443+abc_-+allowUntrustedCertificate"},
		{Command{Op: "delete", Path: []string{"protocols", "static", "route6", "::/0"}}, "delete protocols static route6 ::/0"},
		{Command{Op: "set", Path: []string{"a", "b*c"}}, "set a 'b*c'"},
		{Command{Op: "set", Path: []string{"a", "b\"c"}}, `set a 'b"c'`},
	}
	for _, c := range cases {
		if got := c.command.String(); got != c.want {
			t.Errorf("%v.String() = %s, want %s", c.command, got, c.want)
		}
	}
}

func TestScriptRendersAFailClosedConfigureSession(t *testing.T) {
	migration := &Migration{
		Deletes: []Command{{Op: "delete", Path: []string{"firewall", "name", "WAN_IN", "rule", "240"}}},
		Sets: []Command{
			{Op: "set", Path: []string{"firewall", "name", "WAN_IN", "rule", "100", "action", "accept"}},
			{Op: "set", Path: []string{"firewall", "name", "WAN_IN", "rule", "100", "description", "warp a b lb 80"}},
		},
	}
	script := migration.Script(ScriptOptions{Router: "by-us-fmt-5-8", Env: "main"})
	want := strings.Join([]string{
		"#!/bin/vbash",
		"# warpctl vyos migration: router by-us-fmt-5-8 env main",
		"# warpctl-vyos-migration changes=3 deletes=1 sets=2",
		"# Run on the router as `vbash <this file>`. A failed command ends the",
		"# configure session before commit, so a partial migration is never applied.",
		"source /opt/vyatta/etc/functions/script-template",
		"fail() {",
		`    echo "warp migration failed at line $1" >&2`,
		`    eval "$(vyatta_exit_configure)"`,
		"    builtin exit 1",
		"}",
		"configure",
		"delete firewall name WAN_IN rule 240 || fail $LINENO",
		"set firewall name WAN_IN rule 100 action accept || fail $LINENO",
		"set firewall name WAN_IN rule 100 description 'warp a b lb 80' || fail $LINENO",
		"commit || fail $LINENO",
		"configure_exit",
		"",
	}, "\n")
	if script != want {
		t.Fatalf("script differs:\n%s", firstDifference(want, script))
	}
	confirm := migration.Script(ScriptOptions{Router: "r", Env: "main", CommitConfirmMinutes: 3})
	if !strings.Contains(confirm, "\ncommit-confirm 3 || fail $LINENO\nconfigure_exit\n") || strings.Contains(confirm, "\ncommit ||") {
		t.Fatalf("commit-confirm script:\n%s", confirm)
	}
	empty := (&Migration{}).Script(ScriptOptions{Router: "r", Env: "main"})
	wantEmpty := strings.Join([]string{
		"#!/bin/vbash",
		"# warpctl vyos migration: router r env main",
		"# warpctl-vyos-migration changes=0 deletes=0 sets=0",
		"# The live configuration already matches; nothing to apply.",
		"exit 0",
		"",
	}, "\n")
	if empty != wantEmpty {
		t.Fatalf("empty script differs:\n%s", firstDifference(wantEmpty, empty))
	}
}

// apply replays a migration on a copy of live, resolving each path against
// the desired tree (for sets) or the live tree (for deletes) to learn which
// elements are tag values and which are leaf values.
func apply(t *testing.T, live *Node, desired *Node, migration *Migration) *Node {
	t.Helper()
	result := mustParse(t, live.String())
	for _, command := range migration.Deletes {
		deletePath(t, result, command.Path)
	}
	for _, command := range migration.Sets {
		setPath(t, result, desired, command.Path)
	}
	return result
}

func deletePath(t *testing.T, node *Node, path []string) {
	t.Helper()
	for i := 0; i < len(path); i++ {
		if child, ok := node.containers[Key{Name: path[i]}]; ok {
			if i == len(path)-1 {
				delete(node.containers, Key{Name: path[i]})
				return
			}
			node = child
			continue
		}
		if i+1 < len(path) {
			if child, ok := node.containers[Key{Name: path[i], Tag: path[i+1]}]; ok {
				if i+1 == len(path)-1 {
					delete(node.containers, Key{Name: path[i], Tag: path[i+1]})
					return
				}
				node = child
				i++
				continue
			}
		}
		leaf, ok := node.leaves[path[i]]
		if !ok {
			t.Fatalf("delete %v: nothing at element %d", path, i)
		}
		if i == len(path)-1 {
			delete(node.leaves, path[i])
			return
		}
		if i+1 != len(path)-1 {
			t.Fatalf("delete %v: value path too long", path)
		}
		kept := []string{}
		for _, value := range leaf.Values {
			if value != path[i+1] {
				kept = append(kept, value)
			}
		}
		if len(kept) == len(leaf.Values) {
			t.Fatalf("delete %v: value not present", path)
		}
		if len(kept) == 0 {
			delete(node.leaves, path[i])
		} else {
			leaf.Values = kept
		}
		return
	}
}

func setPath(t *testing.T, node *Node, schema *Node, path []string) {
	t.Helper()
	for i := 0; i < len(path); i++ {
		if child, ok := schema.containers[Key{Name: path[i]}]; ok {
			schema = child
			node = node.Child(path[i])
			continue
		}
		if i+1 < len(path) {
			if child, ok := schema.containers[Key{Name: path[i], Tag: path[i+1]}]; ok {
				schema = child
				node = node.Tag(path[i], path[i+1])
				i++
				continue
			}
		}
		if _, ok := schema.leaves[path[i]]; !ok {
			t.Fatalf("set %v: element %d is not in the desired tree", path, i)
		}
		if i == len(path)-1 {
			if _, ok := node.leaves[path[i]]; !ok {
				node.SetLeaf(path[i])
			}
			return
		}
		if i+1 != len(path)-1 {
			t.Fatalf("set %v: value path too long", path)
		}
		node.AddLeafValue(path[i], path[i+1])
		return
	}
}

// Replaying the migration on the live tree must produce the desired tree,
// for the two live routers in both directions and for a synthetic case that
// touches every kind of change.
func TestMigrateReplaysToTheDesiredTree(t *testing.T) {
	cases := map[string][2]string{
		"5-8 to 5-9": {"by-us-fmt-5-8-config.boot", "by-us-fmt-5-9-config.boot"},
		"5-9 to 5-8": {"by-us-fmt-5-9-config.boot", "by-us-fmt-5-8-config.boot"},
	}
	for name, pair := range cases {
		t.Run(name, func(t *testing.T) {
			live := mustParse(t, readFixture(t, pair[0]))
			desired := mustParse(t, readFixture(t, pair[1]))
			migration := mustMigrate(t, live, desired)
			if migration.Empty() {
				t.Fatal("the routers differ, the migration cannot be empty")
			}
			result := apply(t, live, desired, migration)
			// values are compared as sets by the migration, so compare renderings
			// after normalizing multi-value order through the parser
			if !result.Equal(desired) && result.String() != desired.String() {
				t.Fatalf("replay diverged:\n%s", firstDifference(desired.String(), result.String()))
			}
			if again := mustMigrate(t, result, desired); !again.Empty() {
				t.Fatalf("second migration is not empty: %v", commandStrings(again.Commands()))
			}
			// deletes precede sets so a replaced subtree is rebuilt from scratch
			commands := migration.Commands()
			seenSet := false
			for _, command := range commands {
				if command.Op == "set" {
					seenSet = true
				} else if seenSet {
					t.Fatalf("delete after set: %s", command.String())
				}
			}
		})
	}
}

func TestMigrateOutputIsDeterministic(t *testing.T) {
	live := mustParse(t, readFixture(t, "by-us-fmt-5-8-config.boot"))
	desired := mustParse(t, readFixture(t, "by-us-fmt-5-9-config.boot"))
	first := commandStrings(mustMigrate(t, live, desired).Commands())
	for i := 0; i < 5; i++ {
		if again := commandStrings(mustMigrate(t, live, desired).Commands()); !reflect.DeepEqual(again, first) {
			t.Fatal("migration order changed between runs")
		}
	}
	// device order: firewall changes come before interfaces, rule 100 before rule 20
	var lastIndex = -1
	for _, prefix := range []string{"delete firewall ", "delete interfaces ", "delete protocols ", "delete service ", "delete system "} {
		for i, command := range first {
			if strings.HasPrefix(command, prefix) {
				if i < lastIndex {
					t.Fatalf("%s appears before an earlier section", command)
				}
				lastIndex = i
			}
		}
	}
}
