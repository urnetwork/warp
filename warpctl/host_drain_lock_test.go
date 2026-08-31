package main

import (
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-playground/assert/v2"
)

// The host drain lock serializes drains across a service's groups on a host: at
// most one holder at a time, and a waiter blocks until the holder releases
// (CONNECTDRAIN2.md §3.4).
func TestHostDrainLockMutualExclusion(t *testing.T) {
	dir := t.TempDir()
	warpHome := dir

	// separate lock objects on the same path model two run-worker processes
	// for two groups of one service on the same host
	lockA := newHostDrainLock(warpHome, "main", "connect")
	lockB := newHostDrainLock(warpHome, "main", "connect")

	assert.Equal(t, filepath.Join(dir, hostDrainLockFileName("main", "connect")), lockA.path)

	// A acquires
	assert.Equal(t, true, lockA.lock(5*time.Second))

	// B cannot acquire while A holds it (short timeout -> false)
	assert.Equal(t, false, lockB.lock(200*time.Millisecond))

	// once A releases, B acquires
	var bHeld atomic.Bool
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		if lockB.lock(5 * time.Second) {
			bHeld.Store(true)
		}
	}()

	// B is still blocked
	select {
	case <-time.After(200 * time.Millisecond):
	}
	assert.Equal(t, false, bHeld.Load())

	lockA.unlock()
	wg.Wait()
	assert.Equal(t, true, bHeld.Load())
	lockB.unlock()

	// after everyone releases, a fresh acquire succeeds immediately
	lockC := newHostDrainLock(warpHome, "main", "connect")
	assert.Equal(t, true, lockC.lock(5*time.Second))
	lockC.unlock()
}

// unlock is safe when the lock is not held, and lock is re-acquirable after
// unlock
func TestHostDrainLockReentrantAfterUnlock(t *testing.T) {
	warpHome := t.TempDir()
	lock := newHostDrainLock(warpHome, "main", "connect")

	// unlock without holding: no panic
	lock.unlock()

	assert.Equal(t, true, lock.lock(time.Second))
	lock.unlock()
	// re-acquire the same object
	assert.Equal(t, true, lock.lock(time.Second))
	lock.unlock()
}

// serialize N concurrent holders and assert they never overlap
func TestHostDrainLockNoOverlap(t *testing.T) {
	warpHome := t.TempDir()

	var concurrent atomic.Int32
	var maxConcurrent atomic.Int32
	var completed atomic.Int32

	workerCount := 5
	var wg sync.WaitGroup
	for range workerCount {
		wg.Add(1)
		go func() {
			defer wg.Done()
			lock := newHostDrainLock(warpHome, "main", "connect")
			if !lock.lock(30 * time.Second) {
				return
			}
			defer lock.unlock()

			n := concurrent.Add(1)
			for {
				m := maxConcurrent.Load()
				if n <= m || maxConcurrent.CompareAndSwap(m, n) {
					break
				}
			}
			// hold briefly so overlap would be observed
			select {
			case <-time.After(50 * time.Millisecond):
			}
			concurrent.Add(-1)
			completed.Add(1)
		}()
	}
	wg.Wait()

	assert.Equal(t, int32(workerCount), completed.Load())
	// never more than one holder at a time
	assert.Equal(t, int32(1), maxConcurrent.Load())
}

// The stagger only needs to serialize the groups of ONE service, because the
// capacity it protects is per service. A single host-wide lock file made
// unrelated services queue behind each other, and since the wait bound is
// DrainTimeout+5m (65m) while deploys arrive far more often, those queued
// drains never ran: on 2026-08-11 a connect drain held the shared file on an
// edge and grafana's old containers piled up five deep until they were stopped
// by hand.
func TestHostDrainLockIsScopedPerService(t *testing.T) {
	warpHome := t.TempDir()

	connectG1 := newHostDrainLock(warpHome, "main", "connect")
	connectG4 := newHostDrainLock(warpHome, "main", "connect")
	grafana := newHostDrainLock(warpHome, "main", "grafana")

	// groups of one service share a file; a different service does not
	assert.Equal(t, connectG1.path, connectG4.path)
	assert.NotEqual(t, connectG1.path, grafana.path)

	assert.Equal(t, true, connectG1.lock(5*time.Second))
	defer connectG1.unlock()

	// a held connect drain must not block grafana's drain
	assert.Equal(t, true, grafana.lock(200*time.Millisecond))
	grafana.unlock()

	// but it still blocks another connect group, which is the point
	assert.Equal(t, false, connectG4.lock(200*time.Millisecond))
}

// env is part of the scope, so two envs sharing a host never share a lock
func TestHostDrainLockIsScopedPerEnv(t *testing.T) {
	warpHome := t.TempDir()

	main := newHostDrainLock(warpHome, "main", "connect")
	beta := newHostDrainLock(warpHome, "beta", "connect")
	assert.NotEqual(t, main.path, beta.path)

	assert.Equal(t, true, main.lock(5*time.Second))
	defer main.unlock()
	assert.Equal(t, true, beta.lock(200*time.Millisecond))
	beta.unlock()
}

// The 2026-08-31 proxy OOM happened because the old scope began only after the
// replacement was already running. Keep the competing service group excluded
// for the entire callback, which models candidate start through old drain, and
// require it to enter immediately after that scope returns.
func TestHostDrainLockCoversReplacementOverlap(t *testing.T) {
	warpHome := t.TempDir()
	first := newHostDrainLock(warpHome, "main", "proxy")
	second := newHostDrainLock(warpHome, "main", "proxy")

	replacementRunning := false
	drainComplete := false
	if err := first.runRollout(time.Second, func() error {
		replacementRunning = true
		if second.lock(100 * time.Millisecond) {
			second.unlock()
			t.Fatal("another block entered while the replacement overlap was live")
		}
		drainComplete = true
		return nil
	}); err != nil {
		t.Fatalf("first rollout: %v", err)
	}
	if !replacementRunning || !drainComplete {
		t.Fatal("rollout callback did not cover candidate start through drain")
	}
	if !second.lock(time.Second) {
		t.Fatal("next block could not enter after the complete overlap ended")
	}
	second.unlock()
}

// A failed lease acquisition must not run the replacement callback. The old
// drain behavior proceeded without staggering after its timeout, recreating
// exactly the unsafe overlap when the host was already most constrained.
func TestHostDrainLockTimeoutRefusesReplacement(t *testing.T) {
	warpHome := t.TempDir()
	held := newHostDrainLock(warpHome, "main", "proxy")
	waiting := newHostDrainLock(warpHome, "main", "proxy")
	if !held.lock(time.Second) {
		t.Fatal("could not acquire fixture lock")
	}
	defer held.unlock()

	callbackCalled := false
	err := waiting.runRollout(100*time.Millisecond, func() error {
		callbackCalled = true
		return nil
	})
	if err == nil {
		t.Fatal("rollout proceeded without the host lease")
	}
	if callbackCalled {
		t.Fatal("replacement callback ran after lease timeout")
	}
}

// a name carrying path syntax cannot place the lock outside WARP_HOME
func TestHostDrainLockNameSanitized(t *testing.T) {
	warpHome := t.TempDir()

	lock := newHostDrainLock(warpHome, "main", "../../etc/evil")
	assert.Equal(t, warpHome, filepath.Dir(lock.path))
	assert.Equal(t, false, strings.Contains(filepath.Base(lock.path), "/"))
	// still usable
	assert.Equal(t, true, lock.lock(time.Second))
	lock.unlock()
}
