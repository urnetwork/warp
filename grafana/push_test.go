package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-playground/assert/v2"
	"github.com/urnetwork/warp"
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

const (
	mimirSeriesLimitFixture    = "per-user series limit of 7 exceeded (err-mimir-max-series-per-user). To adjust the related per-tenant limit, configure -ingester.max-global-series-per-user, or contact your service administrator."
	mimirIngestionRateFixture  = "the request has been rejected because the tenant exceeded the ingestion rate limit, set to 2.5 items/s with a maximum allowed burst of 7. This limit is applied on the total number of samples, exemplars and metadata received across all distributors (err-mimir-tenant-max-ingestion-rate). To adjust the related per-tenant limits, configure -distributor.ingestion-rate-limit and -distributor.ingestion-burst-size, or contact your service administrator."
	mimirIngestionBurstFixture = "the request has been rejected because the tenant exceeded the ingestion burst size limit, set to 7, with 8 items. This limit is applied on the total number of samples, exemplars and metadata received across all distributors (err-mimir-tenant-max-ingestion-rate). To adjust the related per-tenant limit, configure -distributor.ingestion-burst-size, or contact your service administrator."
)

func TestMimirRejectionReasonUsesFixedVocabulary(t *testing.T) {
	tests := []struct {
		name   string
		status int
		body   string
		want   string
	}{
		{name: "series", status: http.StatusBadRequest, body: mimirSeriesLimitFixture, want: "series-limit"},
		{name: "wrapped series", status: http.StatusBadRequest, body: "failed pushing to ingester ingester.example.test: user=synthetic-tenant: " + mimirSeriesLimitFixture + "\n", want: "series-limit"},
		{name: "rate", status: http.StatusTooManyRequests, body: mimirIngestionRateFixture, want: "rate-limit"},
		{name: "burst", status: http.StatusTooManyRequests, body: mimirIngestionBurstFixture, want: "rate-limit"},
		{name: "client", status: http.StatusBadRequest, body: "synthetic client rejection", want: "other-client"},
		{name: "server", status: http.StatusServiceUnavailable, body: "synthetic upstream failure", want: "server"},
	}
	for _, test := range tests {
		if got := mimirRejectionReason(test.status, []byte(test.body)); got != test.want {
			t.Errorf("%s: reason=%q, want %q", test.name, got, test.want)
		}
	}
}

// Arbitrary response labels, request-rate errors and incompatible status codes
// cannot claim the tenant-series or sample-ingestion mechanism.
func TestMimirRejectionReasonRejectsSpoofedOrIncompatibleBodies(t *testing.T) {
	for _, test := range []struct {
		name   string
		status int
		body   string
		want   string
	}{
		{name: "echoed series phrase", status: 400, body: `invalid sample series={note="per-user series limit exceeded"}`, want: "other-client"},
		{name: "echoed rate phrase", status: 400, body: `invalid sample series={note="rate_limited rate limit"}`, want: "other-client"},
		{name: "echoed complete series error", status: 400, body: `invalid sample series={note="` + mimirSeriesLimitFixture + `"}`, want: "other-client"},
		{name: "echoed complete rate error", status: 429, body: `invalid sample series={note="` + mimirIngestionRateFixture + `"}`, want: "other-client"},
		{name: "wrong series status", status: 503, body: mimirSeriesLimitFixture, want: "server"},
		{name: "wrong rate status", status: 400, body: mimirIngestionRateFixture, want: "other-client"},
		{name: "wrong series ID", status: 400, body: strings.Replace(mimirSeriesLimitFixture, "err-mimir-max-series-per-user", "err-mimir-max-series-per-metric", 1), want: "other-client"},
		{name: "request rate", status: 429, body: "the request has been rejected because the tenant exceeded the request rate limit, set to 2 requests/s across all distributors with a maximum allowed burst of 7 (err-mimir-tenant-max-request-rate).", want: "other-client"},
		{name: "unknown rate", status: 429, body: "synthetic rate limit", want: "other-client"},
		{name: "extra private suffix", status: 400, body: mimirSeriesLimitFixture + " series={private=fixture}", want: "other-client"},
		{name: "oversize", status: 400, body: mimirSeriesLimitFixture + strings.Repeat(" ", maxMimirRejectionBodyBytes), want: "other-client"},
	} {
		if got := mimirRejectionReason(test.status, []byte(test.body)); got != test.want {
			t.Errorf("%s: reason=%q, want %q", test.name, got, test.want)
		}
	}
}

func TestStatsPushRejectionDiagnosticIsBoundedAndPrivate(t *testing.T) {
	const (
		privateResponse = "failed pushing to ingester ingester.example.test: user=synthetic-private-tenant: " + mimirSeriesLimitFixture
		privateJob      = "synthetic-private-job"
		privateFamily   = "synthetic_private_family"
		privateLabel    = "synthetic-private-label"
	)
	mimir := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, privateResponse, http.StatusBadRequest)
	}))
	defer mimir.Close()

	var diagnostic bytes.Buffer
	previousLogger := warp.Err
	warp.Err = log.New(&diagnostic, "", 0)
	t.Cleanup(func() { warp.Err = previousLogger })

	handler := &statsPushHandler{mimirPushUrl: mimir.URL, httpClient: mimir.Client()}
	exposition := fmt.Sprintf(`# TYPE redis_commands_latencies_usec gauge
redis_commands_latencies_usec{command="fixture"} 1
# TYPE %s gauge
%s{token="%s"} 1
`, privateFamily, privateFamily, privateLabel)
	request := httptest.NewRequest(
		http.MethodPost,
		"/metrics/job/"+privateJob+"/host/synthetic-host.example.test",
		strings.NewReader(exposition),
	)
	request.Header.Set("Content-Type", "text/plain")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if response.Code != http.StatusBadGateway {
		t.Fatalf("response status=%d, want %d", response.Code, http.StatusBadGateway)
	}
	logged := diagnostic.String()
	for _, want := range []string{
		"Stats push rejected status=400",
		"reason=series-limit",
		"job=other",
		"metric_families=2",
		"time_series=2",
		"family_classes=other:1,redis-command-latency:1",
		"family_classes_truncated=false",
	} {
		if !strings.Contains(logged, want) {
			t.Errorf("diagnostic lacks %q: %q", want, logged)
		}
	}
	for _, forbidden := range []string{
		privateResponse, "synthetic-private-tenant", "192.0.2.123", privateJob,
		privateFamily, privateLabel, "synthetic-host.example.test", "ingester.example.test",
	} {
		if strings.Contains(logged, forbidden) {
			t.Errorf("diagnostic leaked %q: %q", forbidden, logged)
		}
	}
}

type statsPushRoundTripperFunc func(*http.Request) (*http.Response, error)

func (self statsPushRoundTripperFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return self(request)
}

type statsPushFailedBodyReader struct{}

func (statsPushFailedBodyReader) Read([]byte) (int, error) {
	return 0, errors.New("synthetic-private-read-error")
}

func TestStatsPushRejectionTruncatedOrFailedBodyCannotClaimTypedReason(t *testing.T) {
	for _, test := range []struct {
		name string
		body io.Reader
	}{
		{name: "overflow after complete prefix", body: strings.NewReader(mimirSeriesLimitFixture + strings.Repeat(" ", maxMimirRejectionBodyBytes) + "synthetic-private-body")},
		{name: "failed read after complete prefix", body: io.MultiReader(strings.NewReader(mimirSeriesLimitFixture), statsPushFailedBodyReader{})},
	} {
		var diagnostic bytes.Buffer
		previousLogger := warp.Err
		warp.Err = log.New(&diagnostic, "", 0)
		handler := &statsPushHandler{
			mimirPushUrl: "http://mimir.example.test/api/v1/push",
			httpClient: &http.Client{Transport: statsPushRoundTripperFunc(func(*http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: http.StatusBadRequest, Body: io.NopCloser(test.body)}, nil
			})},
		}
		request := httptest.NewRequest(http.MethodPost, "/metrics/job/api", strings.NewReader("# TYPE process_cpu_seconds_total counter\nprocess_cpu_seconds_total 1\n"))
		request.Header.Set("Content-Type", "text/plain")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		warp.Err = previousLogger
		if response.Code != http.StatusBadGateway || !strings.Contains(diagnostic.String(), "reason=other-client") {
			t.Fatalf("%s: incomplete body claimed a typed mechanism: status=%d", test.name, response.Code)
		}
		if strings.Contains(diagnostic.String(), "synthetic-private") || strings.Contains(diagnostic.String(), "mimir.example.test") || diagnostic.Len() > 512 {
			t.Fatalf("%s: unknown response did not retain bounded private reduction", test.name)
		}
	}
}

func TestSuccessfulStatsPushEmitsNoRejectionDiagnostic(t *testing.T) {
	mimir := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer mimir.Close()

	var diagnostic bytes.Buffer
	previousLogger := warp.Err
	warp.Err = log.New(&diagnostic, "", 0)
	t.Cleanup(func() { warp.Err = previousLogger })

	handler := &statsPushHandler{mimirPushUrl: mimir.URL, httpClient: mimir.Client()}
	request := httptest.NewRequest(
		http.MethodPost,
		"/metrics/job/api",
		strings.NewReader("# TYPE process_cpu_seconds_total counter\nprocess_cpu_seconds_total 1\n"),
	)
	request.Header.Set("Content-Type", "text/plain")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if response.Code != http.StatusAccepted {
		t.Fatalf("response status=%d, want %d", response.Code, http.StatusAccepted)
	}
	if diagnostic.Len() != 0 {
		t.Fatalf("successful push emitted diagnostic: %q", diagnostic.String())
	}
}
