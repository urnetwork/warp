package loki

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"strings"
	"testing"

	"github.com/go-playground/assert/v2"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (self roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return self(request)
}

func TestBuildQuery(t *testing.T) {
	query := buildQuery("main", "api", []string{}, "")
	assert.Equal(t, `{env="main", service="api"}`, query)

	query = buildQuery("main", "api", []string{"g2", "g1"}, "")
	assert.Equal(t, `{env="main", service="api", block=~"g1|g2"}`, query)

	query = buildQuery("main", "api", []string{"beta"}, `token "abc"`)
	assert.Equal(t, `{env="main", service="api", block=~"beta"} |= "token \"abc\""`, query)

	// regex meta characters in block names are quoted
	query = buildQuery("main", "api", []string{"g.1"}, "")
	assert.Equal(t, `{env="main", service="api", block=~"g\\.1"}`, query)
}

func TestFlattenStreams(t *testing.T) {
	body := `{
		"status": "success",
		"data": {
			"resultType": "streams",
			"result": [
				{
					"stream": {"env": "main", "service": "api", "block": "g1"},
					"values": [
						["1751486399123456789", "line a"],
						["1751486401123456789", "line c"]
					]
				},
				{
					"stream": {"env": "main", "service": "api", "block": "g2"},
					"values": [
						["1751486400123456789", "line b"]
					]
				}
			]
		}
	}`

	var response queryRangeResponse
	err := json.Unmarshal([]byte(body), &response)
	assert.Equal(t, nil, err)
	assert.Equal(t, "success", response.Status)
	assert.Equal(t, "streams", response.Data.ResultType)

	entries := flattenStreams(response.Data.Result, true)
	assert.Equal(t, 3, len(entries))
	// interleaved across streams in ascending time order
	assert.Equal(t, "line a", entries[0].line)
	assert.Equal(t, "g1", entries[0].block)
	assert.Equal(t, "line b", entries[1].line)
	assert.Equal(t, "g2", entries[1].block)
	assert.Equal(t, "line c", entries[2].line)
	assert.Equal(t, int64(1751486399123456789), entries[0].timestamp)

	descending := flattenStreams(response.Data.Result, false)
	assert.Equal(t, "line c", descending[0].line)
	assert.Equal(t, "line a", descending[2].line)
}

func TestTailDroppedEntriesAreReportedWithoutLabelsOrTimestamps(t *testing.T) {
	body := `{
		"streams": [],
		"dropped_entries": [
			{"labels": {"client": "sensitive-client-a"}, "timestamp": "1756686150123456789"},
			{"labels": {"client": "sensitive-client-b"}, "timestamp": "1756686151123456789"}
		]
	}`
	var response tailResponse
	if err := json.Unmarshal([]byte(body), &response); err != nil {
		t.Fatal(err)
	}

	var output bytes.Buffer
	client := &Client{outLog: log.New(&output, "", 0)}
	client.printTailResponse("proxy", response, 123)

	want := "[warpctl][loki-tail-dropped-entries] service=proxy count=2\n"
	if output.String() != want {
		t.Fatalf("dropped-entry report = %q, want %q", output.String(), want)
	}
	for _, sensitive := range []string{
		"sensitive-client-a",
		"sensitive-client-b",
		"1756686150123456789",
		"1756686151123456789",
	} {
		if strings.Contains(output.String(), sensitive) {
			t.Fatalf("dropped-entry report exposed %q: %s", sensitive, output.String())
		}
	}
}

func TestTailDroppedEntriesDoNotReportAnEmptyResponse(t *testing.T) {
	var output bytes.Buffer
	client := &Client{outLog: log.New(&output, "", 0)}
	client.printTailResponse("proxy", tailResponse{}, 123)
	if output.Len() != 0 {
		t.Fatalf("empty dropped-entry response emitted %q", output.String())
	}
}

func TestQueryRangeRetriesHTTP2GoAway(t *testing.T) {
	attempts := 0
	client := &Client{
		baseUrl: "https://loki.example",
		errLog:  log.New(io.Discard, "", 0),
		httpClient: &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
			attempts += 1
			if attempts == 1 {
				return nil, errors.New(`http2: server sent GOAWAY and closed the connection; LastStreamID=1, ErrCode=NO_ERROR`)
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body: io.NopCloser(strings.NewReader(
					`{"status":"success","data":{"resultType":"streams","result":[]}}`,
				)),
				Request: request,
			}, nil
		})},
	}

	response, err := client.queryRange(
		context.Background(),
		`{env="main", service="taskworker"}`,
		1,
		2,
		100,
		"forward",
	)
	if err != nil {
		t.Fatal(err)
	}
	if attempts != 2 {
		t.Fatalf("query attempts = %d, want 2", attempts)
	}
	if response.Status != "success" {
		t.Fatalf("query status = %q, want success", response.Status)
	}
}
