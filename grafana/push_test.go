package main

import (
	"math"
	"strings"
	"testing"

	"github.com/go-playground/assert/v2"
	"google.golang.org/protobuf/encoding/protowire"
)

func TestParsePushPath(t *testing.T) {
	labels, err := parsePushPath("/metrics/job/api/env/main/block/g1/host/edge-3")
	assert.Equal(t, nil, err)
	assert.Equal(t, map[string]string{
		"job":   "api",
		"env":   "main",
		"block": "g1",
		"host":  "edge-3",
	}, labels)

	// base64 encoded values (the prometheus push client uses these
	// for values with slashes)
	labels, err = parsePushPath("/metrics/job/api/path@base64/L2FwaS92MQ==")
	assert.Equal(t, nil, err)
	assert.Equal(t, "/api/v1", labels["path"])

	_, err = parsePushPath("/otherpath/job/api")
	assert.NotEqual(t, nil, err)

	_, err = parsePushPath("/metrics/job/api/dangling")
	assert.NotEqual(t, nil, err)
}

func TestConvertToTimeSeries(t *testing.T) {
	exposition := `
# TYPE process_cpu_seconds_total counter
process_cpu_seconds_total 42.5
# TYPE go_goroutines gauge
go_goroutines 91
# TYPE request_duration_seconds histogram
request_duration_seconds_bucket{le="0.1"} 8
request_duration_seconds_bucket{le="1"} 10
request_duration_seconds_sum 3.5
request_duration_seconds_count 10
`
	metricFamilies, err := parseExposition("text/plain", strings.NewReader(exposition))
	assert.Equal(t, nil, err)
	assert.Equal(t, 3, len(metricFamilies))

	groupingLabels := map[string]string{
		"job":     "api",
		"env":     "main",
		"service": "api",
		"block":   "g1",
		"host":    "edge-3",
	}
	allTimeSeries := convertToTimeSeries(metricFamilies, groupingLabels, 1751500000000)

	byName := map[string][]timeSeries{}
	for _, ts := range allTimeSeries {
		var name string
		for _, label := range ts.labels {
			if label.name == "__name__" {
				name = label.value
			}
		}
		byName[name] = append(byName[name], ts)
	}

	assert.Equal(t, 42.5, byName["process_cpu_seconds_total"][0].value)
	assert.Equal(t, float64(91), byName["go_goroutines"][0].value)
	// the +Inf bucket is synthesized from the sample count
	assert.Equal(t, 3, len(byName["request_duration_seconds_bucket"]))
	infBucket := false
	for _, ts := range byName["request_duration_seconds_bucket"] {
		for _, label := range ts.labels {
			if label.name == "le" && label.value == "+Inf" {
				infBucket = true
				assert.Equal(t, float64(10), ts.value)
			}
		}
	}
	assert.Equal(t, true, infBucket)
	assert.Equal(t, 3.5, byName["request_duration_seconds_sum"][0].value)

	// grouping labels are attached to every series, sorted with __name__
	goroutines := byName["go_goroutines"][0]
	assert.Equal(t, int64(1751500000000), goroutines.millis)
	labelValues := map[string]string{}
	previousName := ""
	for _, label := range goroutines.labels {
		assert.Equal(t, true, previousName < label.name)
		previousName = label.name
		labelValues[label.name] = label.value
	}
	assert.Equal(t, "main", labelValues["env"])
	assert.Equal(t, "edge-3", labelValues["host"])
	assert.Equal(t, "g1", labelValues["block"])
}

func TestEncodeWriteRequest(t *testing.T) {
	allTimeSeries := []timeSeries{
		{
			labels: []label{
				{name: "__name__", value: "go_goroutines"},
				{name: "env", value: "main"},
			},
			value:  91,
			millis: 1751500000000,
		},
	}
	out := encodeWriteRequest(allTimeSeries)

	// decode the protobuf wire format:
	// WriteRequest.timeseries[0].labels + samples
	fieldNumber, fieldType, n := protowire.ConsumeTag(out)
	assert.Equal(t, protowire.Number(1), fieldNumber)
	assert.Equal(t, protowire.BytesType, fieldType)
	tsBytes, _ := protowire.ConsumeBytes(out[n:])

	labelNames := []string{}
	var value float64
	var millis int64
	for 0 < len(tsBytes) {
		fieldNumber, _, n := protowire.ConsumeTag(tsBytes)
		tsBytes = tsBytes[n:]
		switch fieldNumber {
		case 1:
			labelBytes, n := protowire.ConsumeBytes(tsBytes)
			tsBytes = tsBytes[n:]
			for 0 < len(labelBytes) {
				labelFieldNumber, _, n := protowire.ConsumeTag(labelBytes)
				labelBytes = labelBytes[n:]
				stringValue, n := protowire.ConsumeBytes(labelBytes)
				labelBytes = labelBytes[n:]
				if labelFieldNumber == 1 {
					labelNames = append(labelNames, string(stringValue))
				}
			}
		case 2:
			sampleBytes, n := protowire.ConsumeBytes(tsBytes)
			tsBytes = tsBytes[n:]
			for 0 < len(sampleBytes) {
				sampleFieldNumber, sampleFieldType, n := protowire.ConsumeTag(sampleBytes)
				sampleBytes = sampleBytes[n:]
				switch sampleFieldType {
				case protowire.Fixed64Type:
					bits, n := protowire.ConsumeFixed64(sampleBytes)
					sampleBytes = sampleBytes[n:]
					if sampleFieldNumber == 1 {
						value = math.Float64frombits(bits)
					}
				case protowire.VarintType:
					varint, n := protowire.ConsumeVarint(sampleBytes)
					sampleBytes = sampleBytes[n:]
					if sampleFieldNumber == 2 {
						millis = int64(varint)
					}
				}
			}
		}
	}
	assert.Equal(t, []string{"__name__", "env"}, labelNames)
	assert.Equal(t, float64(91), value)
	assert.Equal(t, int64(1751500000000), millis)
}
