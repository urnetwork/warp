package main

import (
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-playground/assert/v2"
)

// The host drain lock serializes drains across a host's groups: at most one
// holder at a time, and a waiter blocks until the holder releases
// (CONNECTDRAIN2.md §3.4).
func TestHostDrainLockMutualExclusion(t *testing.T) {
	dir := t.TempDir()
	warpHome := dir

	// separate lock objects on the same path model two run-worker processes
	// on the same host
	lockA := newHostDrainLock(warpHome)
	lockB := newHostDrainLock(warpHome)

	assert.Equal(t, filepath.Join(dir, hostDrainLockFileName), lockA.path)

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
	lockC := newHostDrainLock(warpHome)
	assert.Equal(t, true, lockC.lock(5*time.Second))
	lockC.unlock()
}

// unlock is safe when the lock is not held, and lock is re-acquirable after
// unlock
func TestHostDrainLockReentrantAfterUnlock(t *testing.T) {
	warpHome := t.TempDir()
	lock := newHostDrainLock(warpHome)

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
			lock := newHostDrainLock(warpHome)
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
