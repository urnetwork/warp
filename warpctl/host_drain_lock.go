package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// Host-level drain stagger (CONNECTDRAIN2.md §3.4). Each block/group on a host
// is an independent warpctl run worker, so a version publish makes every group
// on the host deploy — and drain its old container — at once. The 2026-07-18
// incident drained g1 and g4 of one host simultaneously, so the host lost all
// local capacity while both drained blind.
//
// An advisory file lock serializes the drain step across the groups: each
// worker deploys its new container and takes traffic first (no lock), then
// acquires this lock before draining its old container, so at most one group
// drains at a time and sibling capacity persists. A worker blocked on the lock
// queues until the current drain finishes plus a settle delay.
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

// the lock file lives under WARP_HOME so every group's run worker for a service
// on the host shares it; different hosts, and different services on one host,
// have independent files
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

// how long to wait for the host drain lock before proceeding anyway. A wedged
// drain must not block a rollout forever: past this bound the worker drains
// without the stagger (logged), trading serialization for rollout liveness.
// Generous relative to a healthy drain (Track A prompt-exit) so the fallback
// is rare.
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
