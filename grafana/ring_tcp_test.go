package main

import (
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type observedRingConn struct {
	net.Conn
	readStarted        chan struct{}
	readStartedOnce    sync.Once
	readDeadlineCalls  atomic.Int32
	writeDeadlineCalls atomic.Int32
}

func (c *observedRingConn) Read(buffer []byte) (int, error) {
	c.readStartedOnce.Do(func() { close(c.readStarted) })
	return c.Conn.Read(buffer)
}

func (c *observedRingConn) SetReadDeadline(deadline time.Time) error {
	c.readDeadlineCalls.Add(1)
	return c.Conn.SetReadDeadline(deadline)
}

func (c *observedRingConn) SetWriteDeadline(deadline time.Time) error {
	c.writeDeadlineCalls.Add(1)
	return c.Conn.SetWriteDeadline(deadline)
}

// A Loki tail opens one long-lived gRPC stream per backend. A quiet backend is
// valid and must remain connected; the old copy loop set a 60-second read
// deadline before every Read and deterministically closed that stream on an
// idle grid. Dead-peer detection belongs to TCP keepalive, while a blocked
// destination still receives a bounded write deadline.
func TestCopyRingTcpDoesNotExpireIdleGrpcStream(t *testing.T) {
	source, sourcePeer := net.Pipe()
	destination, destinationPeer := net.Pipe()
	defer sourcePeer.Close()
	defer destinationPeer.Close()

	observedSource := &observedRingConn{Conn: source, readStarted: make(chan struct{})}
	observedDestination := &observedRingConn{Conn: destination, readStarted: make(chan struct{})}
	done := make(chan struct{})
	go func() {
		copyRingTcp(observedDestination, observedSource)
		close(done)
	}()

	select {
	case <-observedSource.readStarted:
	case <-time.After(time.Second):
		t.Fatal("copy loop did not begin reading")
	}
	if calls := observedSource.readDeadlineCalls.Load(); calls != 0 {
		t.Fatalf("idle gRPC source received %d read deadline(s); want none", calls)
	}

	writeDone := make(chan error, 1)
	go func() {
		_, err := sourcePeer.Write([]byte("tail"))
		writeDone <- err
	}()
	buffer := make([]byte, 4)
	if _, err := io.ReadFull(destinationPeer, buffer); err != nil {
		t.Fatal(err)
	}
	if string(buffer) != "tail" {
		t.Fatalf("forwarded payload = %q, want tail", buffer)
	}
	if err := <-writeDone; err != nil {
		t.Fatal(err)
	}
	if calls := observedDestination.writeDeadlineCalls.Load(); calls == 0 {
		t.Fatal("blocked destination has no bounded write deadline")
	}

	sourcePeer.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("copy loop did not stop when its source closed")
	}
}

type recordingKeepAliveConn struct {
	net.Conn
	enabled bool
	period  time.Duration
}

func (c *recordingKeepAliveConn) SetKeepAlive(enabled bool) error {
	c.enabled = enabled
	return nil
}

func (c *recordingKeepAliveConn) SetKeepAlivePeriod(period time.Duration) error {
	c.period = period
	return nil
}

func TestEnableRingTcpKeepAliveDetectsDeadIdlePeers(t *testing.T) {
	connection, peer := net.Pipe()
	defer connection.Close()
	defer peer.Close()
	recording := &recordingKeepAliveConn{Conn: connection}

	enableRingTcpKeepAlive(recording)
	if !recording.enabled {
		t.Fatal("TCP keepalive was not enabled")
	}
	if recording.period != ringTcpKeepAlivePeriod {
		t.Fatalf("TCP keepalive period = %s, want %s", recording.period, ringTcpKeepAlivePeriod)
	}
}
