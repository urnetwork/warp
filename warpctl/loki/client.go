package loki

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/websocket"
)

// Client queries the loki api bundled in the warp grafana service,
// via the lb at https://<env>-grafana.<domain>
// see https://grafana.com/docs/loki/latest/reference/loki-http-api/
type Client struct {
	outLog *log.Logger
	errLog *log.Logger

	// e.g. https://main-grafana.bringyour.com
	baseUrl  string
	username string
	password string

	httpClient *http.Client
}

// ErrSearchIncomplete means Loki could not page through every entry at an
// inclusive timestamp boundary. Callers must not treat the printed prefix as a
// complete search result.
var ErrSearchIncomplete = errors.New("Loki search result is incomplete")

func NewClient(baseUrl string, username string, password string, outLog *log.Logger, errLog *log.Logger) *Client {
	return &Client{
		outLog:   outLog,
		errLog:   errLog,
		baseUrl:  strings.TrimSuffix(baseUrl, "/"),
		username: username,
		password: password,
		httpClient: &http.Client{
			Timeout: 60 * time.Second,
		},
	}
}

// buildQuery maps the warp log identity to logql
// each log line carries the labels {env, service, block, host}
func buildQuery(env string, service string, blocks []string, filter string) string {
	matchers := []string{
		fmt.Sprintf("env=%q", env),
		fmt.Sprintf("service=%q", service),
	}
	if 0 < len(blocks) {
		quotedBlocks := []string{}
		for _, block := range blocks {
			quotedBlocks = append(quotedBlocks, regexp.QuoteMeta(block))
		}
		slices.Sort(quotedBlocks)
		// label regexes are fully anchored
		matchers = append(matchers, fmt.Sprintf("block=~%q", strings.Join(quotedBlocks, "|")))
	}
	query := fmt.Sprintf("{%s}", strings.Join(matchers, ", "))
	if 0 < len(filter) {
		query = fmt.Sprintf("%s |= %q", query, filter)
	}
	return query
}

type logEntry struct {
	// unix nanos
	timestamp int64
	line      string
	block     string
}

func (self *logEntry) key() string {
	return fmt.Sprintf("%s\x00%s", self.block, self.line)
}

type queryRangeResponse struct {
	Status string `json:"status"`
	Data   struct {
		ResultType string         `json:"resultType"`
		Result     []streamResult `json:"result"`
	} `json:"data"`
}

type streamResult struct {
	Stream map[string]string `json:"stream"`
	Values [][2]string       `json:"values"`
}

func flattenStreams(results []streamResult, ascending bool) []*logEntry {
	entries := []*logEntry{}
	for _, result := range results {
		block := result.Stream["block"]
		for _, value := range result.Values {
			timestamp, err := strconv.ParseInt(value[0], 10, 64)
			if err != nil {
				continue
			}
			entries = append(entries, &logEntry{
				timestamp: timestamp,
				line:      value[1],
				block:     block,
			})
		}
	}
	// interleave the streams
	sort.SliceStable(entries, func(i int, j int) bool {
		if ascending {
			return entries[i].timestamp < entries[j].timestamp
		}
		return entries[j].timestamp < entries[i].timestamp
	})
	return entries
}

func (self *Client) printEntry(entry *logEntry) {
	self.outLog.Printf("[%s][%s]%s\n", entry.block, time.Unix(0, entry.timestamp), entry.line)
}

func (self *Client) queryRange(
	ctx context.Context,
	query string,
	start int64,
	end int64,
	limit int,
	direction string,
) (*queryRangeResponse, error) {
	values := url.Values{}
	values.Set("query", query)
	values.Set("start", strconv.FormatInt(start, 10))
	values.Set("end", strconv.FormatInt(end, 10))
	values.Set("limit", strconv.Itoa(limit))
	values.Set("direction", direction)

	requestUrl := fmt.Sprintf("%s/loki/api/v1/query_range?%s", self.baseUrl, values.Encode())
	request, err := http.NewRequestWithContext(ctx, "GET", requestUrl, nil)
	if err != nil {
		return nil, err
	}
	if self.username != "" {
		request.SetBasicAuth(self.username, self.password)
	}

	response, err := self.httpClient.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}
	if response.StatusCode != 200 {
		return nil, errors.New(fmt.Sprintf("Loki query error (%d): %s", response.StatusCode, strings.TrimSpace(string(body))))
	}

	var queryRangeResponse queryRangeResponse
	if err := json.Unmarshal(body, &queryRangeResponse); err != nil {
		return nil, err
	}
	return &queryRangeResponse, nil
}

// Search prints matching log lines in ascending time order,
// starting at now-since, up to limit lines.
// Pages the same way logcli does: move the window forward to the last
// timestamp, re-fetch the boundary, and drop the already printed entries.
func (self *Client) Search(
	ctx context.Context,
	env string,
	service string,
	blocks []string,
	query string,
	since time.Duration,
	limit int,
) error {
	logql := buildQuery(env, service, blocks, query)

	end := time.Now().UnixNano()
	start := time.Now().Add(-since).UnixNano()

	batchSize := min(1000, limit)

	// entries at the boundary timestamp that were already printed
	boundaryTimestamp := int64(-1)
	boundaryKeys := map[string]bool{}

	count := 0
	for count < limit {
		fetchLimit := min(batchSize, limit-count)
		response, err := self.queryRange(ctx, logql, start, end, fetchLimit, "forward")
		if err != nil {
			return err
		}

		entries := flattenStreams(response.Data.Result, true)

		printedCount := 0
		for _, entry := range entries {
			if entry.timestamp == boundaryTimestamp && boundaryKeys[entry.key()] {
				// already printed at the batch boundary
				continue
			}
			self.printEntry(entry)
			printedCount += 1
			count += 1

			if entry.timestamp != boundaryTimestamp {
				boundaryTimestamp = entry.timestamp
				clear(boundaryKeys)
			}
			boundaryKeys[entry.key()] = true

			if limit <= count {
				break
			}
		}

		if len(entries) < fetchLimit {
			// the window is exhausted
			break
		}
		if printedCount == 0 {
			// The range API has no secondary cursor. Advancing by a
			// nanosecond here could silently skip entries Loki has not yet
			// returned, so surface the partial result to callers instead.
			return fmt.Errorf(
				"%w: more than %d entries at timestamp %d cannot be paged safely",
				ErrSearchIncomplete,
				batchSize,
				boundaryTimestamp,
			)
		}

		// the start is inclusive, so the boundary entries are fetched again and deduped
		start = boundaryTimestamp
	}
	return nil
}

type tailResponse struct {
	Streams        []streamResult `json:"streams"`
	DroppedEntries []struct {
		Labels    map[string]string `json:"labels"`
		Timestamp string            `json:"timestamp"`
	} `json:"dropped_entries"`
}

// LiveTail follows the log streams until the context is done.
// The server closes tail connections after tail_max_duration (default 1h),
// so reconnect from the last seen timestamp.
func (self *Client) LiveTail(
	ctx context.Context,
	env string,
	service string,
	blocks []string,
	query string,
) error {
	logql := buildQuery(env, service, blocks, query)

	start := time.Now().UnixNano()

	connectAttempt := 0
	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		conn, err := self.dialTail(ctx, logql, start)
		if err != nil {
			connectAttempt += 1
			if 5 <= connectAttempt {
				return err
			}
			backoff := time.Duration(connectAttempt) * time.Second
			self.errLog.Printf("Tail connect error (%s). Reconnecting in %s.\n", err, backoff)
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(backoff):
			}
			continue
		}

		closeCtx, closeCancel := context.WithCancel(ctx)
		go func() {
			<-closeCtx.Done()
			conn.Close()
		}()

		gotData := false
		for {
			var tailResponse tailResponse
			if err := conn.ReadJSON(&tailResponse); err != nil {
				closeCancel()
				select {
				case <-ctx.Done():
					return nil
				default:
				}
				if gotData {
					// normal rotation (tail_max_duration); resume immediately
					self.errLog.Printf("Tail read error (%s). Reconnecting.\n", err)
				} else {
					// closed before any data, e.g. an rpc error like the
					// concurrent-tail limit; retrying instantly hammers the
					// server and spams the same error
					connectAttempt += 1
					backoff := min(time.Duration(connectAttempt)*time.Second, 10*time.Second)
					self.errLog.Printf("Tail read error (%s). Reconnecting in %s.\n", err, backoff)
					select {
					case <-ctx.Done():
						return nil
					case <-time.After(backoff):
					}
				}
				break
			}
			gotData = true
			connectAttempt = 0

			entries := flattenStreams(tailResponse.Streams, true)
			for _, entry := range entries {
				self.printEntry(entry)
				if start <= entry.timestamp {
					// resume after this entry on reconnect
					start = entry.timestamp + 1
				}
			}
		}
	}
}

func (self *Client) dialTail(ctx context.Context, logql string, start int64) (*websocket.Conn, error) {
	baseUrl, err := url.Parse(self.baseUrl)
	if err != nil {
		return nil, err
	}
	switch baseUrl.Scheme {
	case "https":
		baseUrl.Scheme = "wss"
	case "http":
		baseUrl.Scheme = "ws"
	}

	values := url.Values{}
	values.Set("query", logql)
	values.Set("start", strconv.FormatInt(start, 10))
	values.Set("limit", "100")

	tailUrl := fmt.Sprintf("%s/loki/api/v1/tail?%s", baseUrl.String(), values.Encode())

	header := http.Header{}
	if self.username != "" {
		basicRequest, err := http.NewRequest("GET", tailUrl, nil)
		if err != nil {
			return nil, err
		}
		basicRequest.SetBasicAuth(self.username, self.password)
		header.Set("Authorization", basicRequest.Header.Get("Authorization"))
	}

	dialer := &websocket.Dialer{
		HandshakeTimeout: 30 * time.Second,
	}
	conn, _, err := dialer.DialContext(ctx, tailUrl, header)
	if err != nil {
		return nil, err
	}
	return conn, nil
}
