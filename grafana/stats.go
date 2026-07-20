package main

// the flat public stats feed, merged into /stats.json (see main.go).
// the feed implements the network operator stats contract consumed by
// ur.xyz (react/src/lib/network.js): block accumulators plus cumulative
// totals, derived from mimir with instant queries at serve time.
//
//	users                      <- max(urnetwork_stats_block_users)
//	data_gib                   <- sum(increase(urnetwork_connect_transfer_bytes[<block elapsed>])) / 2^30
//	total_networks             <- max(urnetwork_stats_total_networks)
//	countries                  <- max(urnetwork_stats_countries)
//	staked_alpha               <- max(urnetwork_stats_staked_alpha)
//	demand_deposits_alpha      <- max(urnetwork_stats_block_demand_deposits_alpha)
//	miner_emissions_alpha      <- max(urnetwork_stats_block_miner_emissions_alpha)
//	alpha_usd                  <- max(urnetwork_stats_alpha_usd)
//	prev_users                 <- max(urnetwork_stats_prev_block_users)
//	prev_data_gib              <- the transfer counter over the previous block window (offset)
//	prev_demand_deposits_alpha <- max(urnetwork_stats_prev_block_demand_deposits_alpha)
//	prev_miner_emissions_alpha <- max(urnetwork_stats_prev_block_miner_emissions_alpha)
//
// the prev_* fields carry the last FINISHED block: the block accumulators
// reset at every rollover, so consumers show the finished block next to
// the running one as a stable reference. during block 1 there is no
// finished block and the prev_* series have no samples, so the fields
// self-omit
//
// the urnetwork_stats_* gauges are pushed by the server repo's stats
// collector (controller.StartStatsCollector in the server repo) already
// scoped to the block window. every collector host recomputes and pushes
// the same value, but a pushed registry can carry a gauge a host never
// set, so max — never avg or sum — is the aggregation that reads the real
// value without double counting or zero skew. pushed series go stale in
// mimir when the collector stops, which drops the field from the feed
// rather than freezing a number. a field with no samples is omitted from
// the json: the consumer contract treats a missing accumulator as 0

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/urnetwork/warp"
)

// the application layer block clock: 1-based, 7 days per block, every
// block opening and closing at 00:00 UTC Sunday. block 1 opened Sunday
// June 28 2026 — the Sunday of the launch week. this must match the
// consumer's clock (ur.xyz react/src/lib/network.js BLOCK_GENESIS_MS)
var statsBlockGenesis = time.Date(2026, time.June, 28, 0, 0, 0, 0, time.UTC)

const statsBlockDuration = 7 * 24 * time.Hour

const statsFeedTtl = 15 * time.Second
const statsQueryTimeout = 10 * time.Second

// statsBlockAt returns the 1-based block number and the block start at
// now. before the genesis the clock pins to block 1
func statsBlockAt(now time.Time) (int, time.Time) {
	elapsed := now.Sub(statsBlockGenesis)
	if elapsed < 0 {
		return 1, statsBlockGenesis
	}
	index := int(elapsed / statsBlockDuration)
	return index + 1, statsBlockGenesis.Add(time.Duration(index) * statsBlockDuration)
}

// statsQueries returns the mimir instant query for each contract field
func statsQueries(env string, blockElapsed time.Duration) map[string]string {
	m := func(metric string) string {
		return fmt.Sprintf(`max(%s{env=%q})`, metric, env)
	}
	// the transfer counters are summed only over series with a per-process
	// instance label (server repo grafana.go): during a redeploy overlap
	// the old and new containers push concurrently, and before the
	// instance label they wrote the SAME series — the interleaved counter
	// values read as resets and increase() inflated by the old counter's
	// total on every interleave. the matcher also fences off that
	// corrupted unlabeled history: a window that spans the cutover counts
	// only labeled traffic and becomes exact at the next block rollover
	transferSelector := fmt.Sprintf(`urnetwork_connect_transfer_bytes{env=%q,instance!=""}`, env)

	// increase() needs a window wide enough to hold two samples; right
	// after a block opens the accumulators are ~0 anyway
	windowSeconds := max(int64(blockElapsed/time.Second), 60)
	// the previous block is the full block duration ending at the current
	// block's open — an offset instant query. before the genesis the
	// offset window predates every sample and the field self-omits
	offsetSeconds := max(int64(blockElapsed/time.Second), 0)
	return map[string]string{
		"users":                 m("urnetwork_stats_block_users"),
		"data_gib":              fmt.Sprintf(`sum(increase(%s[%ds])) / (1024 * 1024 * 1024)`, transferSelector, windowSeconds),
		"total_networks":        m("urnetwork_stats_total_networks"),
		"countries":             m("urnetwork_stats_countries"),
		"staked_alpha":          m("urnetwork_stats_staked_alpha"),
		"demand_deposits_alpha": m("urnetwork_stats_block_demand_deposits_alpha"),
		"miner_emissions_alpha": m("urnetwork_stats_block_miner_emissions_alpha"),
		"alpha_usd":             m("urnetwork_stats_alpha_usd"),
		"prev_users":            m("urnetwork_stats_prev_block_users"),
		"prev_data_gib": fmt.Sprintf(
			`sum(increase(%s[%ds] offset %ds)) / (1024 * 1024 * 1024)`,
			transferSelector,
			int64(statsBlockDuration/time.Second),
			offsetSeconds,
		),
		"prev_demand_deposits_alpha": m("urnetwork_stats_prev_block_demand_deposits_alpha"),
		"prev_miner_emissions_alpha": m("urnetwork_stats_prev_block_miner_emissions_alpha"),
	}
}

// the operator stats contract fields. a nil field had no samples in mimir
// (collector not deployed, series stale, or pre-launch) and is omitted
// from the json
type statsSnapshot struct {
	Block               int      `json:"block"`
	Users               *float64 `json:"users,omitempty"`
	DataGib             *float64 `json:"data_gib,omitempty"`
	TotalNetworks       *float64 `json:"total_networks,omitempty"`
	Countries           *float64 `json:"countries,omitempty"`
	StakedAlpha         *float64 `json:"staked_alpha,omitempty"`
	DemandDepositsAlpha *float64 `json:"demand_deposits_alpha,omitempty"`
	MinerEmissionsAlpha *float64 `json:"miner_emissions_alpha,omitempty"`
	AlphaUsd            *float64 `json:"alpha_usd,omitempty"`

	// the last finished block (see the package comment)
	PrevUsers               *float64 `json:"prev_users,omitempty"`
	PrevDataGib             *float64 `json:"prev_data_gib,omitempty"`
	PrevDemandDepositsAlpha *float64 `json:"prev_demand_deposits_alpha,omitempty"`
	PrevMinerEmissionsAlpha *float64 `json:"prev_miner_emissions_alpha,omitempty"`
}

type statsFeed struct {
	queryUrl string
	env      string
	// injectable for tests
	now        func() time.Time
	httpClient *http.Client

	mu         sync.Mutex
	cached     statsSnapshot
	cachedAt   time.Time
	haveCached bool
}

func newStatsFeed(mimirUrl *url.URL, env string) *statsFeed {
	return &statsFeed{
		queryUrl: mimirUrl.JoinPath("/prometheus/api/v1/query").String(),
		env:      env,
		now:      time.Now,
		httpClient: &http.Client{
			Timeout: statsQueryTimeout,
		},
	}
}

// snapshot returns the feed values, cached for statsFeedTtl. a refresh is
// all or nothing so a mimir flap can never zero individual accumulators:
// on error a stale snapshot is served if present, and the error return
// always carries the current block number
func (self *statsFeed) snapshot(ctx context.Context) (statsSnapshot, error) {
	self.mu.Lock()
	if self.haveCached && self.now().Sub(self.cachedAt) < statsFeedTtl {
		cached := self.cached
		self.mu.Unlock()
		return cached, nil
	}
	self.mu.Unlock()

	snapshot, err := self.refresh(ctx)
	if err != nil {
		self.mu.Lock()
		defer self.mu.Unlock()
		if self.haveCached {
			return self.cached, nil
		}
		return snapshot, err
	}

	self.mu.Lock()
	self.cached = snapshot
	self.cachedAt = self.now()
	self.haveCached = true
	self.mu.Unlock()
	return snapshot, nil
}

func (self *statsFeed) refresh(ctx context.Context) (statsSnapshot, error) {
	now := self.now()
	blockNumber, blockStart := statsBlockAt(now)
	queries := statsQueries(self.env, now.Sub(blockStart))

	var mu sync.Mutex
	values := map[string]*float64{}
	var firstErr error
	wg := &sync.WaitGroup{}
	for field, query := range queries {
		wg.Add(1)
		go func() {
			defer wg.Done()
			value, ok, err := self.query(ctx, query)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				if firstErr == nil {
					firstErr = err
				}
				return
			}
			if ok {
				values[field] = &value
			}
		}()
	}
	wg.Wait()

	if firstErr != nil {
		return statsSnapshot{Block: blockNumber}, firstErr
	}
	return statsSnapshot{
		Block:               blockNumber,
		Users:               values["users"],
		DataGib:             values["data_gib"],
		TotalNetworks:       values["total_networks"],
		Countries:           values["countries"],
		StakedAlpha:         values["staked_alpha"],
		DemandDepositsAlpha: values["demand_deposits_alpha"],
		MinerEmissionsAlpha: values["miner_emissions_alpha"],
		AlphaUsd:            values["alpha_usd"],

		PrevUsers:               values["prev_users"],
		PrevDataGib:             values["prev_data_gib"],
		PrevDemandDepositsAlpha: values["prev_demand_deposits_alpha"],
		PrevMinerEmissionsAlpha: values["prev_miner_emissions_alpha"],
	}, nil
}

// query runs an instant query and returns the single scalar result.
// ok is false when the query matches no samples (an absent series)
func (self *statsFeed) query(ctx context.Context, promQuery string) (float64, bool, error) {
	form := url.Values{}
	form.Set("query", promQuery)
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, self.queryUrl, strings.NewReader(form.Encode()))
	if err != nil {
		return 0, false, err
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	response, err := self.httpClient.Do(request)
	if err != nil {
		return 0, false, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return 0, false, fmt.Errorf("stats query (%d)", response.StatusCode)
	}

	var result struct {
		Status string `json:"status"`
		Data   struct {
			Result []struct {
				Value []any `json:"value"`
			} `json:"result"`
		} `json:"data"`
	}
	if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
		return 0, false, err
	}
	if result.Status != "success" {
		return 0, false, fmt.Errorf("stats query status %s", result.Status)
	}
	if len(result.Data.Result) == 0 {
		return 0, false, nil
	}
	value := result.Data.Result[0].Value
	if len(value) != 2 {
		return 0, false, fmt.Errorf("stats query malformed value")
	}
	text, ok := value[1].(string)
	if !ok {
		return 0, false, fmt.Errorf("stats query malformed value")
	}
	number, err := strconv.ParseFloat(text, 64)
	if err != nil {
		return 0, false, err
	}
	if math.IsNaN(number) || math.IsInf(number, 0) {
		return 0, false, nil
	}
	return number, true, nil
}

// a public dashboard entry in the /stats.json directory. each dashboard's
// data is available from grafana's public api under dataApiUrl
type statsDashboard struct {
	Title       string `json:"title"`
	Uid         string `json:"uid"`
	AccessToken string `json:"accessToken"`
	ViewUrl     string `json:"viewUrl"`
	DataApiUrl  string `json:"dataApiUrl"`
}

// statsJson is the /stats.json body: the operator stats contract fields
// with the public dashboards directory
type statsJson struct {
	statsSnapshot
	Dashboards []statsDashboard `json:"dashboards"`
}

// serveStatsJson serves /stats.json. the stats side and the dashboards
// directory degrade independently — each falls back to its zero value
// while the other still serves — and only a total failure errors
func serveStatsJson(w http.ResponseWriter, r *http.Request, index *publicIndex, feed *statsFeed) {
	snapshot, statsErr := feed.snapshot(r.Context())
	dashboards, dashboardsErr := index.list()
	if statsErr != nil && dashboardsErr != nil {
		warp.Err.Printf("Public stats feed error (%s; %s)\n", statsErr, dashboardsErr)
		http.Error(w, `{"error":"stats unavailable"}`, http.StatusBadGateway)
		return
	}
	if statsErr != nil {
		warp.Err.Printf("Public stats feed mimir error (%s)\n", statsErr)
	}
	if dashboardsErr != nil {
		warp.Err.Printf("Public stats index error (%s)\n", dashboardsErr)
	}

	// absolute urls against the external host (the front is exposed only
	// via the https lb) so a site can consume the feed directly
	base := "https://" + r.Host
	body := statsJson{
		statsSnapshot: snapshot,
		Dashboards:    []statsDashboard{},
	}
	for _, d := range dashboards {
		body.Dashboards = append(body.Dashboards, statsDashboard{
			Title:       d.Title,
			Uid:         d.DashboardUid,
			AccessToken: d.AccessToken,
			ViewUrl:     fmt.Sprintf("%s/public-dashboards/%s", base, d.AccessToken),
			DataApiUrl:  fmt.Sprintf("%s/api/public/dashboards/%s", base, d.AccessToken),
		})
	}

	bodyJson, err := json.Marshal(body)
	if err != nil {
		http.Error(w, `{"error":"encode"}`, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	// cross-origin browser consumption (the operator directory sites) is
	// enabled by the warp lb, which reflects the origins allowlisted in the
	// service's cors_origins (services.yml). the front must NOT add its own
	// Access-Control-Allow-Origin: nginx add_header appends rather than
	// replaces, and a response with two values fails the browser cors check
	// for exactly the allowlisted origins. a deployment without the warp lb
	// must supply the cors headers itself
	w.Write(bodyJson)
}
