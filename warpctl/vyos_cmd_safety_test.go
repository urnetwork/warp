// Desired-snapshot controls keep migration and protection on rendered bytes,
// independently of later changes to the configuration input authority.
package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/docopt/docopt-go"
	"github.com/urnetwork/warp/vyos"
)

func syntheticMigrationConfig(uplink string, address string) *vyos.Config {
	root := vyos.NewNode()
	iface := root.Child("interfaces").Tag("ethernet", uplink)
	iface.SetLeaf("address", address)
	iface.Child("firewall").Child("local").SetLeaf("name", "WAN_LOCAL")
	root.Child("service").Child("ssh").SetLeaf("port", "22")
	root.Child("system").SetLeaf("host-name", "synthetic-router")
	return &vyos.Config{Root: root}
}

func writeSyntheticMigrationConfig(t *testing.T, directory string, name string, config *vyos.Config) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(directory, name), []byte(config.String()), 0600); err != nil {
		t.Fatal(err)
	}
}

func TestVyosDesiredSnapshotIgnoresMutableInputAuthority(t *testing.T) {
	liveDir, desiredDir, outDir := t.TempDir(), t.TempDir(), t.TempDir()
	live := syntheticMigrationConfig("eth1", "203.0.113.9/27")
	desired := syntheticMigrationConfig("eth1", "203.0.113.9/27")
	desired.Root.Child("system").SetLeaf("description", "synthetic-target-a")
	writeSyntheticMigrationConfig(t, liveDir, vyosLiveFileName("synthetic-router"), live)
	writeSyntheticMigrationConfig(t, desiredDir, vyosConfigFileName("synthetic-router"), desired)
	// No services or settings exist here. The actual command must not reload
	// either authority after the desired file has been rendered.
	t.Setenv("WARP_HOME", t.TempDir())
	vyosCreateMigration(docopt.Opts{
		"<env>": "synthetic", "<router>": "synthetic-router", "--in": liveDir,
		"--desired": desiredDir, "--out": outDir,
	})
	script, err := os.ReadFile(filepath.Join(outDir, vyosMigrationFileName("synthetic-router")))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(script), "set system description synthetic-target-a") {
		t.Fatal("migration did not use the rendered desired target")
	}
	writeSyntheticMigrationConfig(t, liveDir, vyosLiveFileName("synthetic-router"), desired)
	_, migration, err := vyosMigrationFromDesired("synthetic", "synthetic-router", liveDir, desiredDir, 0)
	if err != nil || !migration.Empty() || migration.UnverifiedComparisons != 0 {
		t.Fatalf("verification did not converge to the same rendered bytes: %v", err)
	}
}

func TestVyosDesiredSnapshotRefusesOldUplinkRemoval(t *testing.T) {
	liveDir, desiredDir := t.TempDir(), t.TempDir()
	writeSyntheticMigrationConfig(t, liveDir, vyosLiveFileName("synthetic-router"), syntheticMigrationConfig("eth1", "203.0.113.9/27"))
	writeSyntheticMigrationConfig(t, desiredDir, vyosConfigFileName("synthetic-router"), syntheticMigrationConfig("eth2", "203.0.113.9/27"))
	_, _, err := vyosMigrationFromDesired("synthetic", "synthetic-router", liveDir, desiredDir, 0)
	var protectedErr *vyos.ProtectedPathError
	if !errors.As(err, &protectedErr) {
		t.Fatalf("deleting the identifiable live uplink was not refused: %v", err)
	}
}

func TestVyosDesiredSnapshotAllowsSameFamilyAddressReplacement(t *testing.T) {
	liveDir, desiredDir := t.TempDir(), t.TempDir()
	writeSyntheticMigrationConfig(t, liveDir, vyosLiveFileName("synthetic-router"), syntheticMigrationConfig("eth1", "203.0.113.9/27"))
	writeSyntheticMigrationConfig(t, desiredDir, vyosConfigFileName("synthetic-router"), syntheticMigrationConfig("eth1", "203.0.113.10/27"))
	_, migration, err := vyosMigrationFromDesired("synthetic", "synthetic-router", liveDir, desiredDir, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(migration.Deletes) != 1 || len(migration.Sets) != 1 {
		t.Fatal("supported same-family replacement was changed")
	}
}

func TestVyosDesiredSnapshotRejectsMismatchedHostname(t *testing.T) {
	desiredDir := t.TempDir()
	desired := syntheticMigrationConfig("eth1", "203.0.113.9/27")
	desired.Root.Child("system").SetLeaf("host-name", "other-synthetic-router")
	writeSyntheticMigrationConfig(t, desiredDir, vyosConfigFileName("synthetic-router"), desired)
	_, _, err := vyosMigrationFromDesired("synthetic", "synthetic-router", t.TempDir(), desiredDir, 0)
	if err == nil || !strings.Contains(err.Error(), "host-name") {
		t.Fatal("mismatched desired target was not refused")
	}
}

func TestVyosDesiredSnapshotRequiresIdentifiableDesiredUplink(t *testing.T) {
	root := vyos.NewNode()
	root.Child("interfaces").Tag("ethernet", "eth1").SetLeaf("address", "203.0.113.9/27")
	if _, err := vyosSnapshotProtectedPaths(root); err == nil {
		t.Fatal("missing desired management authority was silently accepted")
	}
}

func TestVyosDesiredSnapshotQualifiesUnknownLiveUplink(t *testing.T) {
	liveDir, desiredDir := t.TempDir(), t.TempDir()
	live := &vyos.Config{Root: vyos.NewNode()}
	live.Root.Child("system").SetLeaf("host-name", "synthetic-router")
	writeSyntheticMigrationConfig(t, liveDir, vyosLiveFileName("synthetic-router"), live)
	writeSyntheticMigrationConfig(t, desiredDir, vyosConfigFileName("synthetic-router"), syntheticMigrationConfig("eth1", "203.0.113.9/27"))
	script, _, err := vyosMigrationFromDesired("synthetic", "synthetic-router", liveDir, desiredDir, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(script, "Live management uplink not identifiable") {
		t.Fatal("unknown live management authority was not qualified")
	}
}
