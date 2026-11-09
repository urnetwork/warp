//go:build linux || darwin

package main

import (
	"fmt"
	"strings"
	"time"
)

// One side's numbers: what §13.4's gate reads.
type Measurement struct {
	// Bytes a second through the upgraded connections, both directions.
	ThroughputBytesPerSecond float64 `json:"throughput_bytes_per_second"`
	// p99 of one message's round trip on an upgraded connection: connect's.
	ConnectP99 time.Duration `json:"connect_p99_ns"`
	// p99 of one api-shaped request.
	ApiP99 time.Duration `json:"api_p99_ns"`
	// nginx's CPU time, master and workers, for each Gbit the upgraded
	// connections carried: CPU per Gbit/s, since both run as long.
	CpuSecondsPerGbit float64 `json:"cpu_seconds_per_gbit"`
	// The largest resident set among nginx's processes.
	RssByteCount int64 `json:"rss_byte_count"`
	// The split stream server's buffers: proxy_buffer_size and
	// preread_buffer_size, 0 where nginx's default or no split applies.
	ProxyBufferByteCount   int `json:"proxy_buffer_byte_count"`
	PrereadBufferByteCount int `json:"preread_buffer_byte_count"`
	Clients                int `json:"clients"`
	Errors                 int `json:"errors"`
}

// §13.4's gate: what the split may cost against the same nginx unsplit.
type Limits struct {
	// The most throughput the split may lose, as a fraction of the
	// unsplit's: 0.05.
	MaxThroughputLossFraction float64 `json:"max_throughput_loss_fraction"`
	// The most the split may add to connect's and api's p99: 1 ms.
	MaxP99Increase time.Duration `json:"max_p99_increase_ns"`
	// The most head-to-hint p99, measured on its own and given: 2 s.
	MaxHeadToHintP99 time.Duration `json:"max_head_to_hint_p99_ns"`
	// The most the split may add to CPU per Gbit/s, as a fraction: 0.15.
	MaxCpuPerGbitIncreaseFraction float64 `json:"max_cpu_per_gbit_increase_fraction"`
	// The most memory the split may add over the unsplit: the host's
	// headroom, which the run is given, since it depends on the host.
	MemoryHeadroomByteCount int64 `json:"memory_headroom_byte_count"`
}

// §13.4's numbers, with the host's memory headroom.
func DefaultLimits(memoryHeadroomByteCount int64) *Limits {
	return &Limits{
		MaxThroughputLossFraction:     0.05,
		MaxP99Increase:                1 * time.Millisecond,
		MaxHeadToHintP99:              2 * time.Second,
		MaxCpuPerGbitIncreaseFraction: 0.15,
		MemoryHeadroomByteCount:       memoryHeadroomByteCount,
	}
}

// The gate's limits by name, in the order a report lists them.
const (
	LimitThroughput = "throughput"
	LimitP99        = "p99"
	LimitHeadToHint = "head-to-hint p99"
	LimitCpu        = "cpu per gbit/s"
	LimitMemory     = "memory"
)

// One limit's verdict.
type Verdict struct {
	Limit  string `json:"limit"`
	Pass   bool   `json:"pass"`
	Detail string `json:"detail"`
}

// Scores split against unsplit under limits, one verdict per limit. A limit
// at its bound passes; a side that saw errors, or measured nothing, fails
// every limit it feeds, since a comparison of a broken run says nothing.
func Score(split *Measurement, unsplit *Measurement, headToHintP99 time.Duration, limits *Limits) []Verdict {
	broken := func() string {
		switch {
		case 0 < split.Errors || 0 < unsplit.Errors:
			return fmt.Sprintf("errors: split %d, unsplit %d", split.Errors, unsplit.Errors)
		case split.ThroughputBytesPerSecond <= 0 || unsplit.ThroughputBytesPerSecond <= 0:
			return "a side measured no throughput"
		}
		return ""
	}()
	verdicts := []Verdict{}
	add := func(limit string, pass bool, detail string) {
		if broken != "" && limit != LimitHeadToHint {
			verdicts = append(verdicts, Verdict{Limit: limit, Pass: false, Detail: broken})
			return
		}
		verdicts = append(verdicts, Verdict{Limit: limit, Pass: pass, Detail: detail})
	}

	// compared by multiplying, so a run exactly at a bound is not refused by a
	// rounding of the quotient
	loss := 0.0
	if 0 < unsplit.ThroughputBytesPerSecond {
		loss = 1 - split.ThroughputBytesPerSecond/unsplit.ThroughputBytesPerSecond
	}
	add(LimitThroughput, unsplit.ThroughputBytesPerSecond*(1-limits.MaxThroughputLossFraction) <= split.ThroughputBytesPerSecond,
		fmt.Sprintf("split %.0f B/s, unsplit %.0f B/s: %.2f%% lost, at most %.2f%%", split.ThroughputBytesPerSecond, unsplit.ThroughputBytesPerSecond, 100*loss, 100*limits.MaxThroughputLossFraction))

	connectIncrease := split.ConnectP99 - unsplit.ConnectP99
	apiIncrease := split.ApiP99 - unsplit.ApiP99
	add(LimitP99, connectIncrease <= limits.MaxP99Increase && apiIncrease <= limits.MaxP99Increase,
		fmt.Sprintf("connect p99 %v (+%v), api p99 %v (+%v), at most +%v", split.ConnectP99, connectIncrease, split.ApiP99, apiIncrease, limits.MaxP99Increase))

	add(LimitHeadToHint, 0 < headToHintP99 && headToHintP99 <= limits.MaxHeadToHintP99,
		fmt.Sprintf("head-to-hint p99 %v, measured on its own, at most %v", headToHintP99, limits.MaxHeadToHintP99))

	cpuIncrease := 0.0
	if 0 < unsplit.CpuSecondsPerGbit {
		cpuIncrease = split.CpuSecondsPerGbit/unsplit.CpuSecondsPerGbit - 1
	}
	add(LimitCpu, 0 < unsplit.CpuSecondsPerGbit && split.CpuSecondsPerGbit <= unsplit.CpuSecondsPerGbit*(1+limits.MaxCpuPerGbitIncreaseFraction),
		fmt.Sprintf("split %.3f, unsplit %.3f cpu s/Gbit: %+.2f%%, at most +%.2f%%", split.CpuSecondsPerGbit, unsplit.CpuSecondsPerGbit, 100*cpuIncrease, 100*limits.MaxCpuPerGbitIncreaseFraction))

	memoryIncrease := split.RssByteCount - unsplit.RssByteCount
	add(LimitMemory, 0 < limits.MemoryHeadroomByteCount && memoryIncrease <= limits.MemoryHeadroomByteCount,
		fmt.Sprintf("split %d B, unsplit %d B rss: %+d B, headroom %d B", split.RssByteCount, unsplit.RssByteCount, memoryIncrease, limits.MemoryHeadroomByteCount))
	return verdicts
}

// §13.4's gate report: both sides, the limits and the verdicts.
type Report struct {
	Binary        string        `json:"binary"`
	Split         *Measurement  `json:"split"`
	Unsplit       *Measurement  `json:"unsplit"`
	HeadToHintP99 time.Duration `json:"head_to_hint_p99_ns"`
	Limits        *Limits       `json:"limits"`
	Verdicts      []Verdict     `json:"verdicts"`
	Pass          bool          `json:"pass"`
}

// Scores the two sides into a report.
func NewReport(binary string, split *Measurement, unsplit *Measurement, headToHintP99 time.Duration, limits *Limits) *Report {
	report := &Report{
		Binary:        binary,
		Split:         split,
		Unsplit:       unsplit,
		HeadToHintP99: headToHintP99,
		Limits:        limits,
		Verdicts:      Score(split, unsplit, headToHintP99, limits),
		Pass:          true,
	}
	for _, verdict := range report.Verdicts {
		report.Pass = report.Pass && verdict.Pass
	}
	return report
}

// The report for a person: each side, then each limit's verdict.
func (self *Report) Text() string {
	lines := []string{
		fmt.Sprintf("splitbench: §13.4's gate, %s", self.Binary),
	}
	for _, side := range []struct {
		name        string
		measurement *Measurement
	}{
		{name: "unsplit", measurement: self.Unsplit},
		{name: "split", measurement: self.Split},
	} {
		m := side.measurement
		lines = append(lines, fmt.Sprintf(
			"  %-7s clients %d, %.0f B/s, connect p99 %v, api p99 %v, %.3f cpu s/Gbit, rss %d B, proxy buffer %d B, preread buffer %d B, errors %d",
			side.name, m.Clients, m.ThroughputBytesPerSecond, m.ConnectP99, m.ApiP99, m.CpuSecondsPerGbit, m.RssByteCount, m.ProxyBufferByteCount, m.PrereadBufferByteCount, m.Errors,
		))
	}
	for _, verdict := range self.Verdicts {
		mark := "FAIL"
		if verdict.Pass {
			mark = "pass"
		}
		lines = append(lines, fmt.Sprintf("  %s %-16s %s", mark, verdict.Limit, verdict.Detail))
	}
	if self.Pass {
		lines = append(lines, "  the gate passes")
	} else {
		lines = append(lines, "  the gate fails: no interface flips")
	}
	return strings.Join(lines, "\n") + "\n"
}
