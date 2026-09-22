// Migration safety controls preserve management subtrees and expose concealed
// comparisons without treating a masked value as authority to rotate it.
package vyos

import (
	"errors"
	"strings"
	"testing"
)

// Removing an ancestor removes the protected subtree just as surely as a
// descendant delete, even when the diff emits one whole-container command.
func TestMigrateRefusesProtectedAncestor(t *testing.T) {
	for _, testCase := range []struct {
		live      string
		protected []string
	}{
		{live: "service {\n    ssh {\n        port 22\n    }\n}\n", protected: []string{"service", "ssh"}},
		{live: "interfaces {\n    openvpn vtun1 {\n        config-file /config/synthetic.ovpn\n    }\n}\n", protected: []string{"interfaces", "openvpn"}},
		{live: "system {\n    login {\n        user synthetic {\n            level admin\n        }\n    }\n}\n", protected: []string{"system", "login"}},
	} {
		_, err := Migrate(mustParse(t, testCase.live), NewNode(), MigrateOptions{Protected: [][]string{testCase.protected}})
		var protectedErr *ProtectedPathError
		if !errors.As(err, &protectedErr) {
			t.Errorf("ancestor of %v was not protected", testCase.protected)
		}
	}
}

// Both an unchanged and a changed concealed value are unknown: the capture
// cannot distinguish them. Neither comparison is permission to set a secret.
func TestMigrateMaskedSecretReportsUnverifiedComparison(t *testing.T) {
	live := mustParse(t, "system {\n    synthetic-secret ****************\n}\n")
	for _, desiredValue := range []string{"synthetic-secret-a", "synthetic-secret-b"} {
		desired := NewNode()
		desired.Child("system").SetLeaf("synthetic-secret", desiredValue)
		migration := mustMigrate(t, live, desired)
		if !migration.Empty() {
			t.Fatal("concealed comparison attempted a secret change")
		}
		script := migration.Script(ScriptOptions{Router: "synthetic-router", Env: "synthetic"})
		if !strings.Contains(script, "unverified=1") {
			t.Error("concealed comparison was presented as verified convergence")
		}
		if strings.Contains(script, desiredValue) {
			t.Error("concealed comparison disclosed a desired secret")
		}
	}
}

// A fully visible unchanged value is verified rather than blanket-unknown.
func TestMigrateVisibleSecretComparisonIsVerified(t *testing.T) {
	root := mustParse(t, "system {\n    synthetic-secret synthetic-secret-a\n}\n")
	migration := mustMigrate(t, root, root)
	if !migration.Empty() {
		t.Fatal("identical visible configuration changed")
	}
	if !strings.Contains(migration.Script(ScriptOptions{Router: "synthetic-router", Env: "synthetic"}), "unverified=0") {
		t.Fatal("visible comparison did not report its verified boundary")
	}
}

func TestMigrateProtectedErrorDoesNotDiscloseVisibleSecret(t *testing.T) {
	const sentinel = "synthetic-secret-never-in-diagnostics"
	live := NewNode()
	live.Child("system").Child("login").Tag("user", "synthetic").Child("authentication").SetLeaf("encrypted-password", sentinel)
	desired := NewNode()
	desired.Child("system").Child("login").Tag("user", "synthetic").Child("authentication").SetLeaf("encrypted-password", "synthetic-replacement")
	_, err := Migrate(live, desired, MigrateOptions{Protected: [][]string{{"system", "login"}}})
	var protectedErr *ProtectedPathError
	if !errors.As(err, &protectedErr) {
		t.Fatal("visible protected credential change was not refused")
	}
	if strings.Contains(err.Error(), sentinel) || strings.Contains(err.Error(), "synthetic-replacement") {
		t.Fatal("protected-path error disclosed a credential")
	}
	if !strings.Contains(protectedErr.Command.String(), sentinel) {
		t.Fatal("structured private command was unexpectedly lost")
	}
}

func TestMigrateMaskedDesiredValueNeverBecomesASecret(t *testing.T) {
	for _, live := range []*Node{NewNode(), mustParse(t, "system {\n    synthetic-secret visible-synthetic-secret\n}\n")} {
		desired := mustParse(t, "system {\n    synthetic-secret ****************\n}\n")
		migration := mustMigrate(t, live, desired)
		if !migration.Empty() || migration.UnverifiedComparisons != 1 {
			t.Fatal("masked desired value was treated as a literal credential")
		}
	}
}
