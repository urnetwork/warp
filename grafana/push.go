package main

// stats push receiver.
// implements the pushgateway push api surface
// (PUT/POST /metrics/job/<job>[/<label>/<value>...], exposition format body)
// and forwards the metrics to mimir as prometheus remote write,
// stamped with the receive time.
// services push with the standard prometheus client push package
// (see server/grafana.go in the server repo).
// unlike a pushgateway, nothing is stored here: series go stale in mimir
// when a service stops pushing

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"math"
	"mime"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/golang/snappy"
	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/expfmt"
	"google.golang.org/protobuf/encoding/protowire"

	"github.com/urnetwork/warp"
)

const maxPushBodyBytes = 8 * 1024 * 1024

type statsPushHandler struct {
	mimirPushUrl string
	httpClient   *http.Client
}

func newStatsPushHandler(mimirUrl *url.URL) *statsPushHandler {
	return &statsPushHandler{
		mimirPushUrl: mimirUrl.JoinPath("/api/v1/push").String(),
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

func (self *statsPushHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "PUT", "POST":
	default:
		http.Error(w, "Method not allowed.", http.StatusMethodNotAllowed)
		return
	}

	groupingLabels, err := parsePushPath(r.URL.EscapedPath())
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	body := http.MaxBytesReader(w, r.Body, maxPushBodyBytes)
	metricFamilies, err := parseExposition(r.Header.Get("Content-Type"), body)
	if err != nil {
		http.Error(w, fmt.Sprintf("Could not parse metrics (%s).", err), http.StatusBadRequest)
		return
	}

	timestampMillis := time.Now().UnixMilli()
	allTimeSeries := convertToTimeSeries(metricFamilies, groupingLabels, timestampMillis)
	if len(allTimeSeries) == 0 {
		w.WriteHeader(http.StatusAccepted)
		return
	}

	writeRequest := snappy.Encode(nil, encodeWriteRequest(allTimeSeries))

	pushRequest, err := http.NewRequestWithContext(r.Context(), "POST", self.mimirPushUrl, strings.NewReader(string(writeRequest)))
	if err != nil {
		http.Error(w, "Bad gateway.", http.StatusBadGateway)
		return
	}
	pushRequest.Header.Set("Content-Type", "application/x-protobuf")
	pushRequest.Header.Set("Content-Encoding", "snappy")
	pushRequest.Header.Set("X-Prometheus-Remote-Write-Version", "0.1.0")

	pushResponse, err := self.httpClient.Do(pushRequest)
	if err != nil {
		warp.Err.Printf("Stats push error (%s)\n", err)
		http.Error(w, "Bad gateway.", http.StatusBadGateway)
		return
	}
	defer pushResponse.Body.Close()
	if 400 <= pushResponse.StatusCode {
		responseBody, _ := io.ReadAll(io.LimitReader(pushResponse.Body, 1024))
		warp.Err.Printf("Stats push rejected (%d): %s\n", pushResponse.StatusCode, strings.TrimSpace(string(responseBody)))
		http.Error(w, "Bad gateway.", http.StatusBadGateway)
		return
	}

	w.WriteHeader(http.StatusAccepted)
}

// parsePushPath parses the pushgateway url scheme
// /metrics/job/<job>[/<label>/<value>...]
// a label name with an @base64 suffix has a base64 (url safe) encoded value
func parsePushPath(escapedPath string) (map[string]string, error) {
	labelsPath, ok := strings.CutPrefix(escapedPath, "/metrics/job/")
	if !ok {
		return nil, errors.New("Push path must be /metrics/job/<job>/...")
	}
	parts := strings.Split(labelsPath, "/")
	if len(parts)%2 != 1 {
		return nil, errors.New("Push path labels must be pairs.")
	}

	labels := map[string]string{}
	decodeValue := func(name string, escapedValue string) (string, string, error) {
		if base64Name, ok := strings.CutSuffix(name, "@base64"); ok {
			// pushgateway pads with = to a multiple of 4, or accepts unpadded
			value, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(escapedValue, "="))
			if err != nil {
				return "", "", err
			}
			return base64Name, string(value), nil
		}
		value, err := url.PathUnescape(escapedValue)
		if err != nil {
			return "", "", err
		}
		return name, value, nil
	}

	_, job, err := decodeValue("job", parts[0])
	if err != nil {
		return nil, err
	}
	labels["job"] = job
	for i := 1; i+1 < len(parts); i += 2 {
		name, value, err := decodeValue(parts[i], parts[i+1])
		if err != nil {
			return nil, err
		}
		labels[name] = value
	}
	return labels, nil
}

func parseExposition(contentType string, body io.Reader) ([]*dto.MetricFamily, error) {
	format := expfmt.NewFormat(expfmt.TypeTextPlain)
	if mediaType, _, err := mime.ParseMediaType(contentType); err == nil {
		if mediaType == "application/vnd.google.protobuf" {
			format = expfmt.NewFormat(expfmt.TypeProtoDelim)
		}
	}

	metricFamilies := []*dto.MetricFamily{}
	decoder := expfmt.NewDecoder(body, format)
	for {
		metricFamily := &dto.MetricFamily{}
		if err := decoder.Decode(metricFamily); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, err
		}
		metricFamilies = append(metricFamilies, metricFamily)
	}
	return metricFamilies, nil
}

type timeSeries struct {
	// sorted by name, including __name__
	labels []label
	value  float64
	millis int64
}

type label struct {
	name  string
	value string
}

// convertToTimeSeries flattens metric families into remote write series.
// the grouping labels override any metric labels with the same name,
// and every sample is stamped with the receive time
func convertToTimeSeries(metricFamilies []*dto.MetricFamily, groupingLabels map[string]string, millis int64) []timeSeries {
	allTimeSeries := []timeSeries{}

	add := func(name string, metric *dto.Metric, extraLabels map[string]string, value float64) {
		if math.IsNaN(value) {
			// grafana handles missing points better than nan
			return
		}
		labelValues := map[string]string{}
		for _, labelPair := range metric.GetLabel() {
			labelValues[labelPair.GetName()] = labelPair.GetValue()
		}
		for labelName, labelValue := range extraLabels {
			labelValues[labelName] = labelValue
		}
		for labelName, labelValue := range groupingLabels {
			labelValues[labelName] = labelValue
		}
		labelValues["__name__"] = name

		labels := []label{}
		for labelName, labelValue := range labelValues {
			labels = append(labels, label{name: labelName, value: labelValue})
		}
		sort.Slice(labels, func(i int, j int) bool {
			return labels[i].name < labels[j].name
		})

		allTimeSeries = append(allTimeSeries, timeSeries{
			labels: labels,
			value:  value,
			millis: millis,
		})
	}

	for _, metricFamily := range metricFamilies {
		name := metricFamily.GetName()
		for _, metric := range metricFamily.GetMetric() {
			switch metricFamily.GetType() {
			case dto.MetricType_COUNTER:
				add(name, metric, nil, metric.GetCounter().GetValue())
			case dto.MetricType_GAUGE:
				add(name, metric, nil, metric.GetGauge().GetValue())
			case dto.MetricType_UNTYPED:
				add(name, metric, nil, metric.GetUntyped().GetValue())
			case dto.MetricType_SUMMARY:
				summary := metric.GetSummary()
				for _, quantile := range summary.GetQuantile() {
					add(name, metric, map[string]string{
						"quantile": fmt.Sprintf("%v", quantile.GetQuantile()),
					}, quantile.GetValue())
				}
				add(name+"_sum", metric, nil, summary.GetSampleSum())
				add(name+"_count", metric, nil, float64(summary.GetSampleCount()))
			case dto.MetricType_HISTOGRAM:
				histogram := metric.GetHistogram()
				infBucket := false
				for _, bucket := range histogram.GetBucket() {
					upperBound := bucket.GetUpperBound()
					if math.IsInf(upperBound, 1) {
						infBucket = true
					}
					add(name+"_bucket", metric, map[string]string{
						"le": fmt.Sprintf("%v", upperBound),
					}, float64(bucket.GetCumulativeCount()))
				}
				if !infBucket {
					add(name+"_bucket", metric, map[string]string{
						"le": "+Inf",
					}, float64(histogram.GetSampleCount()))
				}
				add(name+"_sum", metric, nil, histogram.GetSampleSum())
				add(name+"_count", metric, nil, float64(histogram.GetSampleCount()))
			}
		}
	}
	return allTimeSeries
}

// encodeWriteRequest encodes the prometheus remote write protobuf,
// prompb.WriteRequest:
//
//	WriteRequest { repeated TimeSeries timeseries = 1 }
//	TimeSeries { repeated Label labels = 1, repeated Sample samples = 2 }
//	Label { string name = 1, string value = 2 }
//	Sample { double value = 1, int64 timestamp = 2 }
func encodeWriteRequest(allTimeSeries []timeSeries) []byte {
	out := []byte{}
	for _, ts := range allTimeSeries {
		tsBytes := []byte{}
		for _, label := range ts.labels {
			labelBytes := []byte{}
			labelBytes = protowire.AppendTag(labelBytes, 1, protowire.BytesType)
			labelBytes = protowire.AppendString(labelBytes, label.name)
			labelBytes = protowire.AppendTag(labelBytes, 2, protowire.BytesType)
			labelBytes = protowire.AppendString(labelBytes, label.value)

			tsBytes = protowire.AppendTag(tsBytes, 1, protowire.BytesType)
			tsBytes = protowire.AppendBytes(tsBytes, labelBytes)
		}
		sampleBytes := []byte{}
		sampleBytes = protowire.AppendTag(sampleBytes, 1, protowire.Fixed64Type)
		sampleBytes = protowire.AppendFixed64(sampleBytes, math.Float64bits(ts.value))
		sampleBytes = protowire.AppendTag(sampleBytes, 2, protowire.VarintType)
		sampleBytes = protowire.AppendVarint(sampleBytes, uint64(ts.millis))
		tsBytes = protowire.AppendTag(tsBytes, 2, protowire.BytesType)
		tsBytes = protowire.AppendBytes(tsBytes, sampleBytes)

		out = protowire.AppendTag(out, 1, protowire.BytesType)
		out = protowire.AppendBytes(out, tsBytes)
	}
	return out
}
