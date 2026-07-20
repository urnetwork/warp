package loki

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync/atomic"
	"testing"
	"time"
)

func TestSearchReportsIncompleteEqualTimestampPage(t *testing.T) {
	const (
		pageSize  = 1000
		timestamp = int64(123456789)
	)

	values := make([][2]string, 0, pageSize)
	for i := range pageSize {
		values = append(values, [2]string{
			strconv.FormatInt(timestamp, 10),
			"line-" + strconv.Itoa(i),
		})
	}

	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if got := r.URL.Query().Get("start"); got != strconv.FormatInt(timestamp, 10) && requests.Load() > 1 {
			t.Errorf("second request start = %q, want inclusive boundary %d", got, timestamp)
		}
		response := queryRangeResponse{Status: "success"}
		response.Data.ResultType = "streams"
		response.Data.Result = []streamResult{{
			Stream: map[string]string{"block": "b0"},
			Values: values,
		}}
		if err := json.NewEncoder(w).Encode(response); err != nil {
			t.Error(err)
		}
	}))
	defer server.Close()

	var output bytes.Buffer
	client := NewClient(
		server.URL,
		"",
		"",
		log.New(&output, "", 0),
		log.New(io.Discard, "", 0),
	)
	err := client.Search(
		context.Background(),
		"main",
		"api",
		nil,
		"",
		time.Hour,
		pageSize+1,
	)
	if !errors.Is(err, ErrSearchIncomplete) {
		t.Fatalf("Search error = %v, want ErrSearchIncomplete", err)
	}
	if got := requests.Load(); got != 2 {
		t.Fatalf("request count = %d, want 2", got)
	}
	if bytes.Contains(output.Bytes(), []byte("skipping the remainder")) {
		t.Fatal("Search reported a successful skip")
	}
}
