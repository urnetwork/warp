package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// Host-level rollout stagger (CONNECTDRAIN2.md §3.4). Each block/group on a
// host is an independent warpctl run worker, so a version publish makes every
// group on the host replace its old container at once. The 2026-07-18 incident
// drained g1 and g4 of one host simultaneously, so the host lost all local
// capacity while both drained blind.
//
// An advisory file lock serializes the complete overlap across the groups: a
// worker acquires it before starting its replacement and releases it after the
// old container drains. Locking only the drain is not enough. During the
// 2026-08-31 proxy rollout all ten workers first launched memory-heavy
// replacements, so Fireside briefly ran nearly two complete generations,
// exhausted RAM and swap, and dropped WireGuard UDP before the kernel OOM
// killer ran. Covering candidate start through drain bounds each service to one
// overlapping block while its sibling capacity remains available.
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

// How long to wait for the host rollout lock. A replacement that reaches this
// bound is deferred; only orphan cleanup, which starts no candidate and reduces
// memory, may proceed without the stagger. The bound is generous relative to a
// healthy drain (Track A prompt-exit), so a timeout identifies a genuinely
// wedged or unexpectedly long rollout.
const hostDrainLockTimeout = DrainTimeout + 5*time.Minute

// after a drain completes, wait this long before releasing the lock so the
// next group's drain does not begin until the load balancer and conntrack
// have settled onto the surviving capacity
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
// timeout (the caller proceeds without the stagger). A zero or negative
// timeout blocks indefinitely.
//
// Uses a non-blocking flock in a poll loop rather than a blocking flock: a
// blocked flock cannot be reliably abandoned on timeout (closing the fd from
// another goroutine does not interrupt the syscall on every platform), which
// would leak a pending lock request.
func (self *hostDrainLock) lock(timeout time.Duration) bool {
	file, err := os.OpenFile(self.path, os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		// cannot open the lock file: proceed without staggering rather than
		// block the deploy
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
			// an unexpected flock error: proceed without staggering
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

// Holds the service-scoped lease across the complete replacement callback.
// A timeout refuses the rollout instead of running outside the lease: delayed
// convergence is safer than recreating the memory/capacity overlap the lease
// exists to prevent.
func (self *hostDrainLock) runRollout(timeout time.Duration, rollout func() error) error {
	if !self.lock(timeout) {
		return fmt.Errorf("host rollout lock not acquired within %s", timeout)
	}
	defer self.unlock()
	return rollout()
}
