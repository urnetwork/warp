package main

// Regression tests for the per-service container privilege and logging
// contract used by every generated systemd unit.

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// A normal service must not inherit network-administration authority.
func TestContainerIsolationArgsDefaultHasNoCapability(t *testing.T) {
	args, err := containerIsolationArgs("api", false, "", MOUNT_MODE_NO)
	if err != nil {
		t.Fatal(err)
	}
	if slices.Contains(args, "--cap-add=CAP_NET_ADMIN") {
		t.Fatalf("default isolation args grant CAP_NET_ADMIN: %v", args)
	}
}

// The explicit proxy exception must retain the Ubuntu 22.04 SO_MARK capability.
func TestContainerIsolationArgsExplicitCapability(t *testing.T) {
	args, err := containerIsolationArgs("proxy", true, "", MOUNT_MODE_NO)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(args, "--cap-add=CAP_NET_ADMIN") {
		t.Fatalf("explicit isolation args omit CAP_NET_ADMIN: %v", args)
	}
}

// A stale non-proxy unit cannot bypass the loader's capability allowlist.
func TestContainerIsolationArgsRejectsNonProxyCapability(t *testing.T) {
	if _, err := containerIsolationArgs("api", true, "", MOUNT_MODE_NO); err == nil {
		t.Fatal("expected a non-proxy capability request to fail")
	}
}

// The outbound mail edge is given the capability for SO_MARK, still under its
// unprivileged user (sidecar DESIGN §19.4, plan-OPS-small-readings #14).
func TestContainerIsolationArgsGrantsSmtpEdgeItsCapability(t *testing.T) {
	args, err := containerIsolationArgs("smtpedge", true, "65532:65532", MOUNT_MODE_NO)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(args, "--cap-add=CAP_NET_ADMIN") {
		t.Fatalf("smtpedge's isolation args omit CAP_NET_ADMIN: %v", args)
	}
	if index := slices.Index(args, "--user"); index == -1 || index+1 == len(args) || args[index+1] != "65532:65532" {
		t.Fatalf("smtpedge's isolation args drop its user: %v", args)
	}
	// without the request it holds none, as every service
	args, err = containerIsolationArgs("smtpedge", false, "65532:65532", MOUNT_MODE_NO)
	if err != nil {
		t.Fatal(err)
	}
	if slices.Contains(args, "--cap-add=CAP_NET_ADMIN") {
		t.Fatalf("smtpedge holds CAP_NET_ADMIN unasked: %v", args)
	}
}

// Extending the exception to the outbound mail edge extends it to no other
// service: api, the other edges and every name near an allowed one are
// refused at run, whatever a stale or hand-written unit asks.
func TestContainerIsolationArgsRejectsEveryOtherServiceCapability(t *testing.T) {
	for _, service := range []string{"api", "tlsedge", "mxedge", "mxedge-platform", "sockets", "evs", "gkm", "dns", "dnsedge-1", "taskworker", "lb", "smtpedge-2", "smtp", "proxy-2", ""} {
		if args, err := containerIsolationArgs(service, true, "65532:65532", MOUNT_MODE_NO); err == nil {
			t.Errorf("%q was granted CAP_NET_ADMIN: %v", service, args)
		}
	}
}

// The former Grafana socket path must fail closed even if a stale unit asks for it.
func TestContainerIsolationArgsRejectsDockerSocket(t *testing.T) {
	if _, err := containerIsolationArgs("grafana", false, "65532:65532", MOUNT_MODE_YES); err == nil {
		t.Fatal("expected a Docker API socket request to fail")
	}
}

// A direct run invocation cannot escape the vault through a scoped filename.
func TestScopedSecretMountArgsRejectsTraversal(t *testing.T) {
	if _, err := scopedSecretMountArgs(t.TempDir(), "main", []string{"../pg.yml"}); err == nil {
		t.Fatal("expected scoped secret traversal to fail")
	}
}

// A symlink cannot turn an approved basename into an arbitrary host file.
func TestScopedSecretMountArgsRejectsSymlink(t *testing.T) {
	vaultHome := t.TempDir()
	envHome := filepath.Join(vaultHome, "main")
	if err := os.Mkdir(envHome, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(vaultHome, "outside.yml"), filepath.Join(envHome, "grafana.yml")); err != nil {
		t.Fatal(err)
	}
	if _, err := scopedSecretMountArgs(vaultHome, "main", []string{"grafana.yml"}); err == nil {
		t.Fatal("expected a scoped secret symlink to fail")
	}
}

// Repeating a mount target is rejected instead of relying on Docker ordering.
func TestScopedSecretMountArgsRejectsDuplicate(t *testing.T) {
	vaultHome := t.TempDir()
	secretPath := filepath.Join(vaultHome, "grafana.yml")
	if err := os.WriteFile(secretPath, []byte("secret"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := scopedSecretMountArgs(vaultHome, "main", []string{"grafana.yml", "grafana.yml"}); err == nil {
		t.Fatal("expected a duplicate scoped secret to fail")
	}
}

// A regular environment secret becomes one exact read-only bind.
func TestScopedSecretMountArgsMountsRegularFileReadOnly(t *testing.T) {
	vaultHome := t.TempDir()
	envHome := filepath.Join(vaultHome, "main")
	if err := os.Mkdir(envHome, 0700); err != nil {
		t.Fatal(err)
	}
	secretPath := filepath.Join(envHome, "grafana.yml")
	if err := os.WriteFile(secretPath, []byte("secret"), 0600); err != nil {
		t.Fatal(err)
	}
	args, err := scopedSecretMountArgs(vaultHome, "main", []string{"grafana.yml"})
	if err != nil {
		t.Fatal(err)
	}
	if len(args) != 2 || args[0] != "--mount" || !strings.Contains(args[1], "source="+secretPath) || !strings.HasSuffix(args[1], ",readonly") {
		t.Fatalf("scoped secret args = %v", args)
	}
}

// Journald tags are the collector's deterministic env/service/block identity.
func TestContainerLogArgsUseJournaldTag(t *testing.T) {
	want := []string{"--log-driver=journald", "--log-opt", "tag=warp|main|api|g1"}
	if args := containerLogArgs("main", "api", "g1"); !slices.Equal(args, want) {
		t.Fatalf("log args = %v, want %v", args, want)
	}
}
