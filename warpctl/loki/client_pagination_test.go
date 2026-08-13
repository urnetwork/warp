package loki

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-playground/assert/v2"
)

type fakeEntry struct {
	timestamp int64
	line      string
}

// newFakeLoki serves query_range over entries (ascending), honoring the
// inclusive start, exclusive end, and limit parameters like the real api.
// Requests with a limit above maxEntries fail like
// limits_config.max_entries_limit_per_query.
func newFakeLoki(entries []fakeEntry, maxEntries int, requests *atomic.Int32) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		values := r.URL.Query()
		start, _ := strconv.ParseInt(values.Get("start"), 10, 64)
		end, _ := strconv.ParseInt(values.Get("end"), 10, 64)
		limit, _ := strconv.Atoi(values.Get("limit"))
		if maxEntries < limit {
			http.Error(
				w,
				fmt.Sprintf("max entries limit per query exceeded, limit > max_entries_limit_per_query (%d > %d)", limit, maxEntries),
				http.StatusBadRequest,
			)
			return
		}
		resultValues := [][2]string{}
		for _, entry := range entries {
			if start <= entry.timestamp && entry.timestamp < end {
				resultValues = append(resultValues, [2]string{
					strconv.FormatInt(entry.timestamp, 10),
					entry.line,
				})
				if limit <= len(resultValues) {
					break
				}
			}
		}
		response := queryRangeResponse{Status: "success"}
		response.Data.ResultType = "streams"
		response.Data.Result = []streamResult{{
			Stream: map[string]string{"block": "b0"},
			Values: resultValues,
		}}
		json.NewEncoder(w).Encode(response)
	}))
}

func searchOutput(server *httptest.Server, limit int) (string, string, error) {
	var out bytes.Buffer
	var errOut bytes.Buffer
	client := NewClient(
		server.URL,
		"",
		"",
		time.UTC,
		log.New(&out, "", 0),
		log.New(&errOut, "", 0),
	)
	err := client.Search(context.Background(), "main", "api", nil, "", time.Now().Add(-time.Hour), limit)
	return out.String(), errOut.String(), err
}

// more entries at one timestamp than the batch size page via the
// single-nanosecond drain query
func TestSearchDrainsLargeEqualTimestampGroup(t *testing.T) {
	timestamp := time.Now().Add(-time.Minute).UnixNano()
	entries := []fakeEntry{}
	for i := range 2500 {
		entries = append(entries, fakeEntry{timestamp, fmt.Sprintf("line-%d", i)})
	}

	var requests atomic.Int32
	server := newFakeLoki(entries, 20000, &requests)
	defer server.Close()

	out, errOut, err := searchOutput(server, 10000)
	assert.Equal(t, nil, err)
	assert.Equal(t, 2500, strings.Count(out, "\n"))
	for _, i := range []int{0, 1, 999, 1000, 1001, 2499} {
		assert.Equal(t, 1, strings.Count(out, fmt.Sprintf("]line-%d\n", i)))
	}
	assert.Equal(t, "", errOut)
	// batch, drain, empty window
	assert.Equal(t, int32(3), requests.Load())
}

// repeated identical lines at one timestamp are all printed:
// the batch boundary dedup counts occurrences instead of collapsing keys
func TestSearchPreservesDuplicateLinesAtOneTimestamp(t *testing.T) {
	timestamp := time.Now().Add(-time.Minute).UnixNano()
	entries := []fakeEntry{}
	for range 1500 {
		entries = append(entries, fakeEntry{timestamp, "same-line"})
	}

	var requests atomic.Int32
	server := newFakeLoki(entries, 20000, &requests)
	defer server.Close()

	out, errOut, err := searchOutput(server, 10000)
	assert.Equal(t, nil, err)
	assert.Equal(t, 1500, strings.Count(out, "]same-line\n"))
	assert.Equal(t, "", errOut)
	assert.Equal(t, int32(3), requests.Load())
}

// when the server entry limit cuts off a timestamp, the search warns,
// skips the rest of that timestamp, and continues
func TestSearchWarnsWhenTimestampExceedsServerLimit(t *testing.T) {
	timestamp := time.Now().Add(-time.Minute).UnixNano()
	entries := []fakeEntry{}
	for i := range 5000 {
		entries = append(entries, fakeEntry{timestamp, fmt.Sprintf("line-%d", i)})
	}
	entries = append(entries, fakeEntry{timestamp + time.Second.Nanoseconds(), "after-line"})

	var requests atomic.Int32
	server := newFakeLoki(entries, 1200, &requests)
	defer server.Close()

	out, errOut, err := searchOutput(server, 10000)
	assert.Equal(t, nil, err)
	// the first batch, then the entry past the cut timestamp
	assert.Equal(t, 1001, strings.Count(out, "\n"))
	assert.Equal(t, 1, strings.Count(out, "]after-line\n"))
	assert.Equal(t, true, strings.Contains(errOut, "skipping the rest of this timestamp"))
	// batch, drain backing off 10000 -> 5000 -> 2500 -> 1250 -> 1000, final batch
	assert.Equal(t, int32(7), requests.Load())
}

// --limit truncates inside a timestamp group without a warning
func TestSearchStopsAtLimitMidTimestamp(t *testing.T) {
	timestamp := time.Now().Add(-time.Minute).UnixNano()
	entries := []fakeEntry{}
	for i := range 1500 {
		entries = append(entries, fakeEntry{timestamp, fmt.Sprintf("line-%d", i)})
	}

	var requests atomic.Int32
	server := newFakeLoki(entries, 20000, &requests)
	defer server.Close()

	out, errOut, err := searchOutput(server, 1200)
	assert.Equal(t, nil, err)
	assert.Equal(t, 1200, strings.Count(out, "\n"))
	assert.Equal(t, 1, strings.Count(out, "]line-1199\n"))
	assert.Equal(t, 0, strings.Count(out, "]line-1200\n"))
	assert.Equal(t, "", errOut)
	assert.Equal(t, int32(2), requests.Load())
}

// distinct timestamps page in ascending order across batches
func TestSearchPagesDistinctTimestamps(t *testing.T) {
	base := time.Now().Add(-time.Minute).UnixNano()
	entries := []fakeEntry{}
	for i := range 2500 {
		entries = append(entries, fakeEntry{base + int64(i), fmt.Sprintf("line-%d", i)})
	}

	var requests atomic.Int32
	server := newFakeLoki(entries, 20000, &requests)
	defer server.Close()

	out, errOut, err := searchOutput(server, 10000)
	assert.Equal(t, nil, err)
	assert.Equal(t, 2500, strings.Count(out, "\n"))
	assert.Equal(t, 1, strings.Count(out, "]line-0\n"))
	assert.Equal(t, 1, strings.Count(out, "]line-2499\n"))
	assert.Equal(t, true, strings.Index(out, "]line-999\n") < strings.Index(out, "]line-1000\n"))
	assert.Equal(t, "", errOut)
	// batch, drain, batch, drain, final short batch
	assert.Equal(t, int32(5), requests.Load())
}
