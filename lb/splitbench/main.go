//go:build linux || darwin

// splitbench runs §13.4's gate (W1): the same nginx binary and the same
// config, once unsplit and once with the SNI split in front of the http
// server, at one client count, under connect-shaped load (upgraded
// connections echoing messages, as connect's H1 transport carries WebSocket
// over TLS) and api-shaped HTTPS requests. It reports throughput, connect's
// and api's p99, CPU per Gbit/s, the largest resident set and the split's
// buffer sizes, takes head-to-hint p99 as measured elsewhere, and scores the
// gate's limits: at most 5% less throughput, at most 1 ms more p99, head-to-
// hint p99 at most 2 s, at most 15% more CPU per Gbit/s, and memory within the
// host's headroom. It exits 1 when a limit fails, so nothing flips.
//
// Both sides run lb/splittest's harness on loopback, whose config carries the
// render's split directives; the evidence run, on one test interface at the
// observed peak and at 786,432 clients, is the owner's (SPLIT-ROLLOUT.md).
//
//	splitbench --memory-headroom=<bytes> --head-to-hint-p99=<duration>
//	    [--binary=<nginx>] [--clients=<n>] [--messages=<n>] [--message-bytes=<n>]
//	    [--api-requests=<n>] [--api-clients=<n>] [--proxy-buffer-bytes=<n>]
//	    [--timeout=<duration>] [--out=<report.json>]
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/urnetwork/warp/lb/splittest"
)

// What one run takes: the load, the split's buffers, and the gate's inputs.
type BenchSettings struct {
	Binary string
	Load   *LoadSettings
	// The split stream server's proxy_buffer_size; 0 leaves nginx's 16k.
	ProxyBufferByteCount int
	HeadToHintP99        time.Duration
	Limits               *Limits
}

// Runs the unsplit side, then the split one, on the same binary and config,
// and scores them.
func RunBench(ctx context.Context, settings *BenchSettings) (*Report, error) {
	measurements := map[bool]*Measurement{}
	for _, split := range []bool{false, true} {
		lbSettings := splittest.DefaultSettings(settings.Binary)
		lbSettings.Split = split
		lbSettings.ProxyBufferByteCount = settings.ProxyBufferByteCount
		measurement, err := measure(ctx, lbSettings, settings.Load)
		if err != nil {
			return nil, fmt.Errorf("split %t: %w", split, err)
		}
		measurements[split] = measurement
	}
	return NewReport(settings.Binary, measurements[true], measurements[false], settings.HeadToHintP99, settings.Limits), nil
}

// One side: nginx up, the load, nginx drained, its resource use read.
func measure(ctx context.Context, lbSettings *splittest.Settings, load *LoadSettings) (*Measurement, error) {
	lb, err := splittest.Start(lbSettings)
	if err != nil {
		return nil, err
	}
	result, loadErr := RunLoad(ctx, lb, load)
	closeErr := lb.Close()
	if loadErr != nil {
		return nil, loadErr
	}
	if closeErr != nil {
		return nil, closeErr
	}
	cpu, rssByteCount, err := lb.Usage()
	if err != nil {
		return nil, err
	}
	measurement := &Measurement{
		ConnectP99:   Percentile(result.ConnectLatencies, 99),
		ApiP99:       Percentile(result.ApiLatencies, 99),
		RssByteCount: rssByteCount,
		Clients:      load.Clients,
		Errors:       result.Errors,
	}
	if 0 < result.Elapsed {
		measurement.ThroughputBytesPerSecond = float64(result.ByteCount) / result.Elapsed.Seconds()
	}
	if gbit := float64(result.ByteCount) * 8 / 1e9; 0 < gbit {
		measurement.CpuSecondsPerGbit = cpu.Seconds() / gbit
	}
	if lbSettings.Split {
		measurement.ProxyBufferByteCount = lbSettings.ProxyBufferByteCount
		measurement.PrereadBufferByteCount = lbSettings.ClientHelloMaxBytes
	}
	return measurement, nil
}

func main() {
	binary := flag.String("binary", "", "the nginx binary; else "+splittest.BinaryEnv+", then lb's nginx_local, then nginx")
	clients := flag.Int("clients", 64, "upgraded connections at once")
	messages := flag.Int("messages", 200, "messages each connection echoes")
	messageBytes := flag.Int("message-bytes", 4000, "bytes in each message")
	apiRequests := flag.Int("api-requests", 2000, "api-shaped requests")
	apiClients := flag.Int("api-clients", 16, "keep-alive connections for them")
	proxyBufferBytes := flag.Int("proxy-buffer-bytes", 0, "the split's proxy_buffer_size; 0 leaves nginx's")
	headToHintP99 := flag.Duration("head-to-hint-p99", 0, "head-to-hint p99, measured on its own (required)")
	memoryHeadroom := flag.Int64("memory-headroom", 0, "bytes of memory the host has for the split to add (required)")
	timeout := flag.Duration("timeout", 30*time.Second, "the most one message or request may take")
	out := flag.String("out", "", "write the report as JSON here too")
	flag.Parse()

	if *headToHintP99 <= 0 || *memoryHeadroom <= 0 {
		fmt.Fprintln(os.Stderr, "splitbench: --head-to-hint-p99 and --memory-headroom are the gate's measured inputs, and both are required")
		os.Exit(64)
	}
	nginxBinary := *binary
	if nginxBinary == "" {
		found, err := splittest.FindBinary([]string{"build/nginx-local/sbin/nginx", "nginx"})
		if err != nil {
			fmt.Fprintln(os.Stderr, "splitbench:", err)
			os.Exit(64)
		}
		nginxBinary = found
	} else if err := splittest.CheckBinary(nginxBinary); err != nil {
		fmt.Fprintln(os.Stderr, "splitbench:", err)
		os.Exit(64)
	}

	report, err := RunBench(context.Background(), &BenchSettings{
		Binary: nginxBinary,
		Load: &LoadSettings{
			Clients:           *clients,
			MessagesPerClient: *messages,
			MessageByteCount:  *messageBytes,
			ApiRequests:       *apiRequests,
			ApiClients:        *apiClients,
			ServerName:        "api.root.example",
			OperationTimeout:  *timeout,
		},
		ProxyBufferByteCount: *proxyBufferBytes,
		HeadToHintP99:        *headToHintP99,
		Limits:               DefaultLimits(*memoryHeadroom),
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "splitbench:", err)
		os.Exit(1)
	}
	fmt.Print(report.Text())
	if *out != "" {
		encoded, err := json.MarshalIndent(report, "", "  ")
		if err == nil {
			err = os.WriteFile(*out, append(encoded, '\n'), 0644)
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, "splitbench:", errors.Join(errors.New("write the report"), err))
			os.Exit(1)
		}
	}
	if !report.Pass {
		os.Exit(1)
	}
}
