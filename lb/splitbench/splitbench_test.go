//go:build linux || darwin

package main

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/urnetwork/warp/lb/splittest"
)

// A pair of measurements and inputs that pass every limit, for a test to
// break one limit at a time.
func passingSides() (*Measurement, *Measurement, time.Duration, *Limits) {
	unsplit := &Measurement{
		ThroughputBytesPerSecond: 1e9,
		ConnectP99:               4 * time.Millisecond,
		ApiP99:                   6 * time.Millisecond,
		CpuSecondsPerGbit:        2.0,
		RssByteCount:             400 * 1024 * 1024,
		Clients:                  64,
	}
	split := *unsplit
	split.ThroughputBytesPerSecond = 0.97e9
	split.ConnectP99 = 4*time.Millisecond + 500*time.Microsecond
	split.ApiP99 = 6*time.Millisecond + 500*time.Microsecond
	split.CpuSecondsPerGbit = 2.2
	split.RssByteCount = 450 * 1024 * 1024
	return &split, unsplit, 1500 * time.Millisecond, DefaultLimits(100 * 1024 * 1024)
}

// The verdicts by limit, and which failed.
func failedLimits(verdicts []Verdict) []string {
	failed := []string{}
	for _, verdict := range verdicts {
		if !verdict.Pass {
			failed = append(failed, verdict.Limit)
		}
	}
	return failed
}

func TestDefaultLimitsAreTheGates(t *testing.T) {
	limits := DefaultLimits(7)
	if limits.MaxThroughputLossFraction != 0.05 || limits.MaxP99Increase != time.Millisecond || limits.MaxHeadToHintP99 != 2*time.Second ||
		limits.MaxCpuPerGbitIncreaseFraction != 0.15 || limits.MemoryHeadroomByteCount != 7 {
		t.Errorf("limits %+v", limits)
	}
}

// A synthetic regression past each limit fails that limit and no other.
func TestScoreFailsEachLimitAlone(t *testing.T) {
	split, unsplit, headToHint, limits := passingSides()
	verdicts := Score(split, unsplit, headToHint, limits)
	if len(verdicts) != 5 || 0 < len(failedLimits(verdicts)) {
		t.Fatalf("the passing pair: %+v", verdicts)
	}
	for _, c := range []struct {
		limit   string
		regress func(split *Measurement, headToHint *time.Duration)
	}{
		{limit: LimitThroughput, regress: func(split *Measurement, headToHint *time.Duration) { split.ThroughputBytesPerSecond = 0.94e9 }},
		{limit: LimitP99, regress: func(split *Measurement, headToHint *time.Duration) { split.ConnectP99 += 600 * time.Microsecond }},
		{limit: LimitP99, regress: func(split *Measurement, headToHint *time.Duration) { split.ApiP99 += 600 * time.Microsecond }},
		{limit: LimitHeadToHint, regress: func(split *Measurement, headToHint *time.Duration) { *headToHint = 2100 * time.Millisecond }},
		{limit: LimitCpu, regress: func(split *Measurement, headToHint *time.Duration) { split.CpuSecondsPerGbit = 2.4 }},
		{limit: LimitMemory, regress: func(split *Measurement, headToHint *time.Duration) { split.RssByteCount = 501 * 1024 * 1024 }},
	} {
		split, unsplit, headToHint, limits := passingSides()
		c.regress(split, &headToHint)
		if failed := failedLimits(Score(split, unsplit, headToHint, limits)); !slices.Equal(failed, []string{c.limit}) {
			t.Errorf("a regression in %s failed %v", c.limit, failed)
		}
		if report := NewReport("nginx", split, unsplit, headToHint, limits); report.Pass || !strings.Contains(report.Text(), "FAIL "+c.limit) {
			t.Errorf("the report of a %s regression:\n%s", c.limit, report.Text())
		}
	}
}

// A limit at its bound passes; one step past it fails.
func TestScoreHoldsEachLimitAtItsBound(t *testing.T) {
	split, unsplit, _, limits := passingSides()
	split.ThroughputBytesPerSecond = 0.95e9
	split.ConnectP99 = unsplit.ConnectP99 + time.Millisecond
	split.ApiP99 = unsplit.ApiP99 + time.Millisecond
	split.CpuSecondsPerGbit = 2.3
	split.RssByteCount = unsplit.RssByteCount + limits.MemoryHeadroomByteCount
	if failed := failedLimits(Score(split, unsplit, 2*time.Second, limits)); 0 < len(failed) {
		t.Errorf("at the bounds %v failed", failed)
	}
	split.ConnectP99 += time.Nanosecond
	if failed := failedLimits(Score(split, unsplit, 2*time.Second, limits)); !slices.Equal(failed, []string{LimitP99}) {
		t.Errorf("a nanosecond past the p99 bound: %v", failed)
	}
	if failed := failedLimits(Score(split, unsplit, 2*time.Second+time.Nanosecond, limits)); !slices.Contains(failed, LimitHeadToHint) {
		t.Errorf("a nanosecond past head-to-hint: %v", failed)
	}
}

// A run that saw errors or carried nothing proves nothing: every limit it
// feeds fails, and a missing head-to-hint or headroom input fails its own.
func TestScoreFailsABrokenRun(t *testing.T) {
	split, unsplit, headToHint, limits := passingSides()
	split.Errors = 1
	if failed := failedLimits(Score(split, unsplit, headToHint, limits)); !slices.Equal(failed, []string{LimitThroughput, LimitP99, LimitCpu, LimitMemory}) {
		t.Errorf("errors: %v", failed)
	}
	split, unsplit, headToHint, limits = passingSides()
	unsplit.ThroughputBytesPerSecond = 0
	if failed := failedLimits(Score(split, unsplit, headToHint, limits)); len(failed) != 4 {
		t.Errorf("no throughput: %v", failed)
	}
	split, unsplit, _, limits = passingSides()
	if failed := failedLimits(Score(split, unsplit, 0, limits)); !slices.Equal(failed, []string{LimitHeadToHint}) {
		t.Errorf("no head-to-hint input: %v", failed)
	}
	split, unsplit, headToHint, _ = passingSides()
	if failed := failedLimits(Score(split, unsplit, headToHint, DefaultLimits(0))); !slices.Equal(failed, []string{LimitMemory}) {
		t.Errorf("no headroom input: %v", failed)
	}
}

func TestPercentile(t *testing.T) {
	latencies := []time.Duration{}
	for i := 100; 0 < i; i -= 1 {
		latencies = append(latencies, time.Duration(i)*time.Millisecond)
	}
	if Percentile(latencies, 99) != 99*time.Millisecond || Percentile(latencies, 100) != 100*time.Millisecond || Percentile(latencies, 50) != 50*time.Millisecond {
		t.Errorf("p99 %v, p100 %v, p50 %v", Percentile(latencies, 99), Percentile(latencies, 100), Percentile(latencies, 50))
	}
	if Percentile(nil, 99) != 0 || Percentile([]time.Duration{time.Second}, 99) != time.Second {
		t.Error("edges")
	}
}

// The binary the scaled-down run takes, as lb's tests choose it.
func benchBinary(t *testing.T) string {
	t.Helper()
	binary, err := splittest.FindBinary([]string{filepath.Join("..", "build", "nginx-local", "sbin", "nginx"), "nginx"})
	if errors.Is(err, splittest.ErrNoBinary) {
		t.Skip(err)
	}
	if err != nil {
		t.Fatal(err)
	}
	return binary
}

// The two sides run the same binary and the same config but for the split:
// every line of the unsplit config but its listens is in the split one.
func TestBenchSidesShareTheirConfig(t *testing.T) {
	binary := benchBinary(t)
	normalize := regexp.MustCompile(`/[^ ;]*warp-lb[^ ;/]*|127\.0\.0\.1:\d+|\[::1\]:\d+`)
	configs := map[bool][]string{}
	for _, split := range []bool{false, true} {
		settings := splittest.DefaultSettings(binary)
		settings.Split = split
		lb, err := splittest.Start(settings)
		if err != nil {
			t.Fatal(err)
		}
		config, err := lb.Config()
		lb.Close()
		if err != nil {
			t.Fatal(err)
		}
		for _, line := range strings.Split(normalize.ReplaceAllString(config, "<x>"), "\n") {
			configs[split] = append(configs[split], strings.TrimSpace(line))
		}
	}
	for _, line := range configs[false] {
		if !strings.HasPrefix(line, "listen ") && !slices.Contains(configs[true], line) {
			t.Errorf("the unsplit side's %q is not in the split side's config", line)
		}
	}
}

// A scaled-down run of both sides through real nginx: the harness drives the
// load, both sides measure every number the gate reads, and the report scores
// all five limits. The numbers themselves prove nothing at this size; the
// evidence run is external.
func TestSplitbenchScaledDownRun(t *testing.T) {
	binary := benchBinary(t)
	report, err := RunBench(context.Background(), &BenchSettings{
		Binary: binary,
		Load: &LoadSettings{
			Clients:           4,
			MessagesPerClient: 20,
			MessageByteCount:  1024,
			ApiRequests:       40,
			ApiClients:        2,
			ServerName:        "api.root.example",
			OperationTimeout:  10 * time.Second,
		},
		ProxyBufferByteCount: 32 * 1024,
		HeadToHintP99:        time.Second,
		Limits:               DefaultLimits(1024 * 1024 * 1024),
	})
	if err != nil {
		t.Fatal(err)
	}
	for name, m := range map[string]*Measurement{"split": report.Split, "unsplit": report.Unsplit} {
		if m.Errors != 0 || m.ThroughputBytesPerSecond <= 0 || m.ConnectP99 <= 0 || m.ApiP99 <= 0 || m.CpuSecondsPerGbit <= 0 || m.RssByteCount <= 0 || m.Clients != 4 {
			t.Errorf("%s measured %+v", name, m)
		}
	}
	if report.Split.ProxyBufferByteCount != 32*1024 || report.Split.PrereadBufferByteCount != 16384 || report.Unsplit.ProxyBufferByteCount != 0 {
		t.Errorf("buffers split %d/%d, unsplit %d", report.Split.ProxyBufferByteCount, report.Split.PrereadBufferByteCount, report.Unsplit.ProxyBufferByteCount)
	}
	if len(report.Verdicts) != 5 || !strings.Contains(report.Text(), "splitbench: §13.4's gate") {
		t.Errorf("report:\n%s", report.Text())
	}
	if _, err := json.Marshal(report); err != nil {
		t.Fatal(err)
	}
	t.Logf("scaled-down run, which proves the harness and not the gate:\n%s", report.Text())
}
