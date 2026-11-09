//go:build linux || darwin

package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"sync"
	"time"

	"github.com/urnetwork/warp/lb/splittest"
)

// The load one side takes: connect-shaped upgraded connections, each echoing
// messages as connect's H1 transport carries frames over WebSocket and TLS,
// beside api-shaped HTTPS requests on keep-alive connections.
type LoadSettings struct {
	// Upgraded connections at once, each a visitor: the client count.
	Clients int
	// Messages each sends and waits for the echo of, one at a time.
	MessagesPerClient int
	// Bytes in each message.
	MessageByteCount int
	// api-shaped requests, spread over ApiClients keep-alive connections.
	ApiRequests int
	ApiClients  int
	// The name each visitor asks for: a platform name, which the split sends
	// to the http servers, so A and B serve the same requests.
	ServerName string
	// The most one message or request may take before the run counts it failed.
	OperationTimeout time.Duration
}

// What one side's load measured.
type LoadResult struct {
	// Bytes echoed through upgraded connections, both directions.
	ByteCount int64
	Elapsed   time.Duration
	// Each message's round trip.
	ConnectLatencies []time.Duration
	// Each api-shaped request's round trip.
	ApiLatencies []time.Duration
	Errors       int
}

// Runs settings' load against lb and waits for all of it.
func RunLoad(ctx context.Context, lb *splittest.Lb, settings *LoadSettings) (*LoadResult, error) {
	if settings.Clients < 1 || settings.MessagesPerClient < 1 || settings.MessageByteCount < 1 || settings.ApiClients < 1 {
		return nil, errors.New("load needs at least one client, message, byte and api client")
	}
	result := &LoadResult{}
	var stateLock sync.Mutex
	record := func(byteCount int64, connect []time.Duration, api []time.Duration, failed int) {
		stateLock.Lock()
		defer stateLock.Unlock()
		result.ByteCount += byteCount
		result.ConnectLatencies = append(result.ConnectLatencies, connect...)
		result.ApiLatencies = append(result.ApiLatencies, api...)
		result.Errors += failed
	}

	start := time.Now()
	var wait sync.WaitGroup
	for range settings.Clients {
		wait.Add(1)
		go func() {
			defer wait.Done()
			byteCount, latencies, err := runUpgradedClient(ctx, lb, settings)
			failed := 0
			if err != nil {
				failed = 1
			}
			record(byteCount, latencies, nil, failed)
		}()
	}
	transport := &http.Transport{
		DialTLSContext: func(ctx context.Context, network string, address string) (net.Conn, error) {
			return lb.DialHttps("tcp4", settings.ServerName, false)
		},
		MaxConnsPerHost:     settings.ApiClients,
		MaxIdleConnsPerHost: settings.ApiClients,
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: settings.OperationTimeout}
	requests := make(chan int)
	for range settings.ApiClients {
		wait.Add(1)
		go func() {
			defer wait.Done()
			for i := range requests {
				requestStart := time.Now()
				err := apiRequest(ctx, client, settings.ServerName, i)
				failed := 0
				var latencies []time.Duration
				if err != nil {
					failed = 1
				} else {
					latencies = []time.Duration{time.Since(requestStart)}
				}
				record(0, nil, latencies, failed)
			}
		}()
	}
	for i := range settings.ApiRequests {
		select {
		case requests <- i:
		case <-ctx.Done():
		}
	}
	close(requests)
	wait.Wait()
	result.Elapsed = time.Since(start)
	return result, ctx.Err()
}

// One api-shaped request: a small GET whose answer is read whole.
func apiRequest(ctx context.Context, client *http.Client, serverName string, i int) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("https://%s/api/request-%d", serverName, i), nil)
	if err != nil {
		return err
	}
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if _, err := io.Copy(io.Discard, response.Body); err != nil {
		return err
	}
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("status %d", response.StatusCode)
	}
	return nil
}

// One upgraded connection: TLS, the upgrade, then each message and its echo,
// timed.
func runUpgradedClient(ctx context.Context, lb *splittest.Lb, settings *LoadSettings) (int64, []time.Duration, error) {
	conn, err := lb.DialHttps("tcp4", settings.ServerName, false)
	if err != nil {
		return 0, nil, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(settings.OperationTimeout))
	fmt.Fprintf(conn, "GET /ws HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n", settings.ServerName)
	reader := bufio.NewReader(conn)
	response, err := http.ReadResponse(reader, nil)
	if err != nil {
		return 0, nil, err
	}
	if response.StatusCode != http.StatusSwitchingProtocols {
		return 0, nil, fmt.Errorf("upgrade answered %d", response.StatusCode)
	}
	message := make([]byte, settings.MessageByteCount)
	rand.Read(message)
	echo := make([]byte, settings.MessageByteCount)
	latencies := make([]time.Duration, 0, settings.MessagesPerClient)
	var byteCount int64
	for range settings.MessagesPerClient {
		if ctx.Err() != nil {
			return byteCount, latencies, ctx.Err()
		}
		conn.SetDeadline(time.Now().Add(settings.OperationTimeout))
		messageStart := time.Now()
		if _, err := conn.Write(message); err != nil {
			return byteCount, latencies, err
		}
		if _, err := io.ReadFull(reader, echo); err != nil {
			return byteCount, latencies, err
		}
		latencies = append(latencies, time.Since(messageStart))
		if !bytes.Equal(echo, message) {
			return byteCount, latencies, errors.New("echo differs")
		}
		byteCount += int64(2 * len(message))
	}
	return byteCount, latencies, nil
}

// The p-th percentile, 0 < p <= 100, by nearest rank; 0 with none.
func Percentile(latencies []time.Duration, p float64) time.Duration {
	if len(latencies) == 0 {
		return 0
	}
	sorted := append([]time.Duration{}, latencies...)
	sort.Slice(sorted, func(i int, j int) bool { return sorted[i] < sorted[j] })
	rank := int(float64(len(sorted))*p/100+0.999999999) - 1
	if rank < 0 {
		rank = 0
	}
	if len(sorted) <= rank {
		rank = len(sorted) - 1
	}
	return sorted[rank]
}
