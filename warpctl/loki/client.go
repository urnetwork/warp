package loki

import (
	"cmp"
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

	// timezone for printed timestamps, e.g. time.Local or time.UTC
	location *time.Location

	httpClient *http.Client
}

// maxQueryEntries caps a single query_range request. It matches
// limits_config.max_entries_limit_per_query in the warp grafana service.
// drainTimestamp backs off if the server limit is lower.
const maxQueryEntries = 20000

func NewClient(baseUrl string, username string, password string, location *time.Location, outLog *log.Logger, errLog *log.Logger) *Client {
	return &Client{
		outLog:   outLog,
		errLog:   errLog,
		baseUrl:  strings.TrimSuffix(baseUrl, "/"),
		username: username,
		password: password,
		location: location,
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
	host      string
	service   string
	block     string
	cid       string
}

func (self *logEntry) key() string {
	return strings.Join([]string{self.host, self.service, self.block, self.cid, self.line}, "\x00")
}

// unwrapJournalRecord converts a line stored by the pre-cid pipeline, which
// serialized the whole journal record as json, into the message plus the
// record's short container id. Entries from the current pipeline carry a cid
// label and store the raw message, so this only runs when the cid label is
// absent.
func (self *logEntry) unwrapJournalRecord() {
	if !strings.HasPrefix(self.line, "{") {
		return
	}
	var record map[string]any
	if err := json.Unmarshal([]byte(self.line), &record); err != nil {
		return
	}
	message, ok := record["MESSAGE"].(string)
	if !ok {
		return
	}
	self.line = message
	if cid, ok := record["CONTAINER_ID"].(string); ok {
		self.cid = cid
	}
}

// unquoteLine unwraps a line stored as a bare json string, which the loki
// output produced for a window while it ran drop_single_key on instead of
// raw. A raw line is only affected if the whole line is one valid json
// string, which the services never emit.
func (self *logEntry) unquoteLine() {
	if !strings.HasPrefix(self.line, "\"") {
		return
	}
	var line string
	if err := json.Unmarshal([]byte(self.line), &line); err != nil {
		return
	}
	self.line = line
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
		host := result.Stream["host"]
		service := result.Stream["service"]
		block := result.Stream["block"]
		cid, hasCid := result.Stream["cid"]
		for _, value := range result.Values {
			timestamp, err := strconv.ParseInt(value[0], 10, 64)
			if err != nil {
				continue
			}
			entry := &logEntry{
				timestamp: timestamp,
				line:      value[1],
				host:      host,
				service:   service,
				block:     block,
				cid:       cid,
			}
			if !hasCid {
				entry.unwrapJournalRecord()
			}
			entry.unquoteLine()
			entries = append(entries, entry)
		}
	}
	// interleave the streams
	slices.SortStableFunc(entries, func(a *logEntry, b *logEntry) int {
		if ascending {
			return cmp.Compare(a.timestamp, b.timestamp)
		}
		return cmp.Compare(b.timestamp, a.timestamp)
	})
	return entries
}

// glog headers look like `I0810 22:04:44.138794       1 transport.go:498] `:
// level+date, time, pid, file:line. The pid is always 1 (the service is its
// container's init process) and the timestamp repeats the journal time, so
// only the level and file:line carry information.
var glogHeaderRe = regexp.MustCompile(`^([IWEF])\d{4} \d{2}:\d{2}:\d{2}\.\d{6}\s+\d+ (\S+:\d+)\] ?`)

// printEntry prints
// [host][service][block][cid:<container id>][<level>][<time>][<file:line>]<message>,
// dropping the brackets for identity labels the stream does not carry. The
// timestamp prints in the client location (utc renders a Z suffix, other
// zones their offset). A glog header on the message supplies the level and
// file:line brackets and is stripped; lines without one print with just the
// timestamp bracket.
func (self *Client) printEntry(entry *logEntry) {
	var prefix strings.Builder
	if entry.host != "" {
		fmt.Fprintf(&prefix, "[%s]", entry.host)
	}
	if entry.service != "" {
		fmt.Fprintf(&prefix, "[%s]", entry.service)
	}
	if entry.block != "" {
		fmt.Fprintf(&prefix, "[%s]", entry.block)
	}
	if entry.cid != "" {
		fmt.Fprintf(&prefix, "[cid:%s]", entry.cid)
	}
	line := entry.line
	fileLine := ""
	if m := glogHeaderRe.FindStringSubmatch(line); m != nil {
		fmt.Fprintf(&prefix, "[%s]", m[1])
		fileLine = m[2]
		line = line[len(m[0]):]
	}
	fmt.Fprintf(&prefix, "[%s]", time.Unix(0, entry.timestamp).In(self.location).Format("2006-01-02T15:04:05.000000Z07:00"))
	if fileLine != "" {
		fmt.Fprintf(&prefix, "[%s]", fileLine)
	}
	self.outLog.Printf("%s%s\n", prefix.String(), line)
}

type queryError struct {
	statusCode int
	message    string
}

func (self *queryError) Error() string {
	return fmt.Sprintf("Loki query error (%d): %s", self.statusCode, self.message)
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
		return nil, &queryError{
			statusCode: response.StatusCode,
			message:    strings.TrimSpace(string(body)),
		}
	}

	var queryRangeResponse queryRangeResponse
	if err := json.Unmarshal(body, &queryRangeResponse); err != nil {
		return nil, err
	}
	return &queryRangeResponse, nil
}

// Search prints matching log lines in ascending time order,
// starting at startTime, up to limit lines.
// Pages forward in batches. A batch boundary can split the entries at one
// timestamp, and the range api has no cursor within a timestamp, so after
// each full batch the boundary nanosecond is drained with a larger limit
// before moving the window past it.
func (self *Client) Search(
	ctx context.Context,
	env string,
	service string,
	blocks []string,
	query string,
	startTime time.Time,
	limit int,
) error {
	logql := buildQuery(env, service, blocks, query)

	end := time.Now().UnixNano()
	start := startTime.UnixNano()

	batchSize := min(1000, limit)

	count := 0
	for count < limit {
		fetchLimit := min(batchSize, limit-count)
		response, err := self.queryRange(ctx, logql, start, end, fetchLimit, "forward")
		if err != nil {
			return err
		}

		entries := flattenStreams(response.Data.Result, true)

		// the window start is past every previously printed entry
		for _, entry := range entries {
			self.printEntry(entry)
			count += 1
			if limit <= count {
				break
			}
		}

		if len(entries) < fetchLimit {
			// the window is exhausted
			break
		}
		if limit <= count {
			break
		}

		// a full batch can split the entries at the boundary timestamp
		boundary := entries[len(entries)-1].timestamp
		printed := map[string]int{}
		printedCount := 0
		for i := len(entries) - 1; 0 <= i && entries[i].timestamp == boundary; i -= 1 {
			printed[entries[i].key()] += 1
			printedCount += 1
		}
		drained, err := self.drainTimestamp(ctx, logql, boundary, printed, printedCount, limit-count, fetchLimit)
		if err != nil {
			return err
		}
		count += drained
		start = boundary + 1
	}
	return nil
}

// drainTimestamp prints the entries at the single nanosecond
// [timestamp, timestamp+1) that were not already printed, up to budget, and
// returns the printed count.
// printed counts the entries already printed at the timestamp, by key.
// Entries with equal keys print identically, so they are interchangeable and
// deduped by count.
// If the server will not return the whole nanosecond in one response, the
// remainder is skipped with a warning: the range api cannot page it.
func (self *Client) drainTimestamp(
	ctx context.Context,
	logql string,
	timestamp int64,
	printed map[string]int,
	printedCount int,
	budget int,
	minFetchLimit int,
) (int, error) {
	// enough for the already printed entries plus the remaining budget
	fetchLimit := min(printedCount+budget, maxQueryEntries)
	var entries []*logEntry
	for {
		response, err := self.queryRange(ctx, logql, timestamp, timestamp+1, fetchLimit, "forward")
		if err != nil {
			var queryErr *queryError
			if errors.As(err, &queryErr) &&
				queryErr.statusCode == http.StatusBadRequest &&
				strings.Contains(queryErr.message, "max entries") &&
				minFetchLimit < fetchLimit {
				// the server entry limit is below maxQueryEntries.
				// minFetchLimit already succeeded, so stop backing off there.
				fetchLimit = max(fetchLimit/2, minFetchLimit)
				continue
			}
			return 0, err
		}
		entries = flattenStreams(response.Data.Result, true)
		break
	}

	drained := 0
	for _, entry := range entries {
		if 0 < printed[entry.key()] {
			printed[entry.key()] -= 1
			continue
		}
		self.printEntry(entry)
		drained += 1
		if budget <= drained {
			break
		}
	}
	if len(entries) == fetchLimit && drained < budget {
		self.errLog.Printf(
			"Warning: at least %d entries at %s. The range api cannot page within one nanosecond; skipping the rest of this timestamp.\n",
			fetchLimit,
			time.Unix(0, timestamp),
		)
	}
	return drained, nil
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
