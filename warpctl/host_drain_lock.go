package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Host-level rollout stagger (CONNECTDRAIN2.md §3.4). Each block/group on a
// host is an independent warpctl run worker, so a version publish makes every
// group on the host replace its old container at once. The 2026-07-18 incident
// drained g1 and g4 of one host simultaneously, so the host lost all local
// capacity while both drained blind.
//
// An advisory file lock serializes candidate warmup and promotion across the
// groups. A worker acquires it before starting its replacement and releases it
// after the ready candidate's redirect and settling interval. During the
// 2026-08-31 proxy rollout all ten workers first launched memory-heavy
// replacements, so Fireside briefly ran nearly two complete generations,
// exhausted RAM and swap, and dropped WireGuard UDP before the kernel OOM
// killer ran. Candidate start must remain inside the lease: at most one group
// may warm a replacement at a time. Ready replacements and retiring old
// containers may overlap across groups. Holding this lease through their full
// graceful drain instead delays urgent sibling rollouts by up to an hour each.
//
// The lock is scoped to one env+service, NOT the whole host. A single file per
// host serialized unrelated services behind each other, and because the wait
// bound is DrainTimeout+5m (65m) while deploys arrive far more often, the
// queued drains never ran: on 2026-08-11 seven warpctl workers shared one lock
// file on an edge, a connect drain (which legitimately waits up to DrainTimeout
// for client connections to finish) held it, and grafana's old containers piled
// up five deep until they were stopped by hand. Serializing across services
// buys nothing anyway — the capacity the stagger protects is per service, so
// only the groups of one service need to take turns.

// The existing filename stays stable so a newly upgraded worker synchronizes
// with an older worker that is already draining. The file lives under WARP_HOME
// so every group's run worker for a service on the host shares it; different
// hosts, and different services on one host, have independent files.
const hostDrainLockFilePrefix = "warpctl-host-drain"

// hostDrainLockFileName builds the per-service lock file name. Parts are
// sanitized so a name can never traverse out of WARP_HOME or collide with
// another name through path syntax.
func hostDrainLockFileName(env string, service string) string {
	return fmt.Sprintf(
		"%s-%s-%s.lock",
		hostDrainLockFilePrefix,
		sanitizeHostDrainLockNamePart(env),
		sanitizeHostDrainLockNamePart(service),
	)
}

func sanitizeHostDrainLockNamePart(part string) string {
	safe := strings.Map(func(r rune) rune {
		switch {
		case 'a' <= r && r <= 'z', 'A' <= r && r <= 'Z', '0' <= r && r <= '9', r == '-', r == '_':
			return r
		}
		return '_'
	}, part)
	if safe == "" {
		return "_"
	}
	return safe
}

// Retain the existing wait bound while older workers may still hold this same
// file through a full graceful drain. A replacement that cannot acquire the
// lease is deferred; it must never start a candidate outside the stagger.
const hostDrainLockTimeout = DrainTimeout + 5*time.Minute

// After promotion, allow the load balancer and conntrack to settle before the
// next group starts a candidate. Old-container retirement follows independently.
const hostDrainSettleTimeout = 5 * time.Second

type hostDrainLock struct {
	path string
	file *os.File
}

func newHostDrainLock(warpHome string, env string, service string) *hostDrainLock {
	return &hostDrainLock{
		path: filepath.Join(warpHome, hostDrainLockFileName(env, service)),
	}
}

// how often to retry the non-blocking flock while waiting for the lock
const hostDrainLockPollInterval = 200 * time.Millisecond

// lock blocks until the host drain lock is acquired or `timeout` elapses.
// Returns true when the lock is held (the caller must Unlock), false on
// timeout (the caller must defer candidate startup). A zero or negative
// timeout blocks indefinitely.
//
// Uses a non-blocking flock in a poll loop rather than a blocking flock: a
// blocked flock cannot be reliably abandoned on timeout (closing the fd from
// another goroutine does not interrupt the syscall on every platform), which
// would leak a pending lock request.
func (self *hostDrainLock) lock(timeout time.Duration) bool {
	file, err := os.OpenFile(self.path, os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		// Fail closed: runRollout must not start a candidate without its lease.
		return false
	}

	var deadline time.Time
	if 0 < timeout {
		deadline = time.Now().Add(timeout)
	}
	for {
		err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			self.file = file
			return true
		}
		if err != syscall.EWOULDBLOCK {
			// An unexpected flock error must also defer candidate startup.
			file.Close()
			return false
		}
		if !deadline.IsZero() && !deadline.After(time.Now()) {
			file.Close()
			return false
		}
		time.Sleep(hostDrainLockPollInterval)
	}
}

// unlock releases the host drain lock. Safe to call when the lock is not held.
func (self *hostDrainLock) unlock() {
	if self.file != nil {
		// closing the fd releases the flock
		self.file.Close()
		self.file = nil
	}
}

// Holds the service lease until successful promotion explicitly releases it.
// On failure the callback must finish candidate cleanup before returning. The
// fallback release is idempotent, so an old drain finishing later cannot close
// a newly acquired lease, even if the same lock object has been reused.
func (self *hostDrainLock) runRollout(timeout time.Duration, rollout func(release func()) error) error {
	if !self.lock(timeout) {
		return fmt.Errorf("host rollout lock not acquired within %s", timeout)
	}
	release := sync.OnceFunc(self.unlock)
	defer release()
	return rollout(release)
}
