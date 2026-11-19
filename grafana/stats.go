package main

// the flat public stats feed, merged into /stats.json (see main.go).
// the feed implements the network operator stats contract consumed by
// the network site (react/src/lib/network.js) and the current-inventory
// counters on the main site: settlement epoch accumulators plus cumulative
// totals, derived from mimir with instant queries at serve time.
//
//	epoch                      <- max(urnetwork_stats_epoch_number), else the built-in clock below
//	epoch_start                <- max(urnetwork_stats_epoch_start_seconds), unix seconds
//	epoch_end                  <- max(urnetwork_stats_epoch_end_seconds), unix seconds, projected
//	epoch_start_block          <- max(urnetwork_stats_epoch_start_block)
//	epoch_end_block            <- max(urnetwork_stats_epoch_end_block), the next epoch's first block
//	block                      <- epoch, a deprecated alias kept for older consumers
//	users                      <- max(urnetwork_stats_epoch_users)
//	data_gib                   <- sum(increase(urnetwork_connect_transfer_bytes[<epoch elapsed>])) / 2^30
//	total_networks             <- max(urnetwork_stats_total_networks)
//	online_providers           <- max(urnetwork_stats_online_providers)
//	online_extenders           <- max(urnetwork_stats_online_extenders)
//	online_providers_ipv4      <- max(urnetwork_stats_online_providers_by_ip_family{ip_family="ipv4"})
//	online_providers_ipv6      <- the same gauge with ip_family="ipv6"
//	online_providers_dualstack <- the same gauge with ip_family="dualstack"
//	online_extenders_ipv4      <- max(urnetwork_stats_online_extenders_by_ip_family{ip_family="ipv4"})
//	online_extenders_ipv6      <- the same gauge with ip_family="ipv6"
//	online_extenders_dualstack <- the same gauge with ip_family="dualstack"
//	countries                  <- max(urnetwork_stats_countries)
//	staked_alpha               <- max(urnetwork_stats_staked_alpha)
//	demand_deposits_alpha      <- max(urnetwork_stats_epoch_demand_deposits_alpha)
//	miner_emissions_alpha      <- max(urnetwork_stats_epoch_miner_emissions_alpha)
//	alpha_usd                  <- max(urnetwork_stats_alpha_usd)
//	prev_users                 <- max(urnetwork_stats_prev_epoch_users)
//	prev_data_gib              <- the transfer counter over the previous epoch's window (offset)
//	prev_demand_deposits_alpha <- max(urnetwork_stats_prev_epoch_demand_deposits_alpha)
//	prev_miner_emissions_alpha <- max(urnetwork_stats_prev_epoch_miner_emissions_alpha)
//
// the window is the SN25 settlement epoch: the span of chain blocks the
// subnet coordinator (0xC18925925E2B7bb9059b7d696b8c92762AE86406) counts as
// one epoch, numbered from 0. the server repo's stats collector reads the
// coordinator's schedule and the finalized chain head, and publishes the
// current epoch as the urnetwork_stats_epoch_* gauges: its blocks, its start
// block's timestamp, and its end projected from the head at 12 s a block. the
// feed takes the epoch from those gauges. while they have no samples (a
// collector deployed before the epoch clock, or none running) the feed falls
// back to the mainnet schedule built in below, projected from epoch 1's
// start; the collector's epoch accumulators are then absent too, so the
// epoch fields still serve and the accumulators self-omit rather than
// describe some other window
//
// the prev_* fields carry the last FINISHED epoch: the epoch accumulators
// reset at every rollover, so consumers show the finished epoch next to the
// running one as a stable reference. during epoch 0 there is no finished
// epoch and the prev_* fields are not queried, so they self-omit. the
// collector publishes prev_users only from a snapshot it took of that epoch
// itself, so prev_users also self-omits until the first rollover after the
// collector's deploy
//
// the extender and ip family fields carry the extender network (the
// connect repo's EXTENDER.md, section M). an online extender is an active
// extender record with at least one active address; a population's family
// is dualstack when it has both families, else the one it has, so the
// three family fields of a population sum to its total. the collector
// always pushes all three family series, so a family with no members
// reads 0 rather than dropping out of the feed
//
// the urnetwork_stats_* gauges are pushed by the server repo's stats
// collector (controller.StartStatsCollector in the server repo) already
// scoped to the epoch window. every collector host recomputes and pushes
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

const statsFeedTtl = 15 * time.Second
const statsQueryTimeout = 10 * time.Second

// statsEpoch is a settlement epoch: the chain blocks [StartBlock, EndBlock)
// and their times. HasPrev is false in epoch 0; otherwise the previous
// epoch ran from PrevStart to Start
type statsEpoch struct {
	Number     uint64
	StartBlock uint64
	EndBlock   uint64
	Start      time.Time
	End        time.Time
	HasPrev    bool
	PrevStart  time.Time
}

// statsEpochPolicy is one policy of the coordinator's schedule: from
// EffectiveEpoch on, epoch e starts at block
// EffectiveBlock + (e - EffectiveEpoch) * EpochBlocks
type statsEpochPolicy struct {
	EffectiveEpoch uint64
	EffectiveBlock uint64
	EpochBlocks    uint64
}

// the built-in clock: the SN25 mainnet coordinator's schedule as launched
// (policyByIndex 0 and 1). epoch 0 was the 7,200-block bootstrap epoch from
// block 9,240,028, and the policy the governance Safe scheduled at block
// 9,240,407 made every epoch from 1 on 50,400 blocks from block 9,247,228.
// the server repo's controller/stats_epoch_clock.go holds the same schedule
// and reads the live one from the coordinator
var statsEpochSchedule = []statsEpochPolicy{
	{EffectiveEpoch: 0, EffectiveBlock: 9_240_028, EpochBlocks: 7_200},
	{EffectiveEpoch: 1, EffectiveBlock: 9_247_228, EpochBlocks: 50_400},
}

// the header timestamps of the mined boundaries the clock knows: epoch 0
// started at 2026-10-08 18:08:12 UTC and epoch 1 at 2026-10-09 18:09:00 UTC
var statsEpochBlockTimes = map[uint64]time.Time{
	9_240_028: time.Unix(1_791_482_892, 0).UTC(),
	9_247_228: time.Unix(1_791_569_340, 0).UTC(),
}

// the built-in clock projects every other block from epoch 1's start at 12 s
// a block. the chain averaged 12.0003 s a block over epoch 1's first 39,298
// blocks, so the projection drifts by about 15 s an epoch
const statsEpochAnchorBlock = 9_247_228

var statsEpochAnchorTime = time.Unix(1_791_569_340, 0).UTC()

const statsEpochBlockDuration = 12 * time.Second

// statsEpochPolicyAt is the coordinator's policyAt: the last policy in
// effect by epoch
func statsEpochPolicyAt(epoch uint64) (statsEpochPolicy, bool) {
	for index := len(statsEpochSchedule); index != 0; index -= 1 {
		if statsEpochSchedule[index-1].EffectiveEpoch <= epoch {
			return statsEpochSchedule[index-1], true
		}
	}
	return statsEpochPolicy{}, false
}

// statsEpochStartBlock is the coordinator's epochStartBlock
func statsEpochStartBlock(epoch uint64) (uint64, bool) {
	policy, ok := statsEpochPolicyAt(epoch)
	if !ok {
		return 0, false
	}
	return policy.EffectiveBlock + (epoch-policy.EffectiveEpoch)*policy.EpochBlocks, true
}

// statsEpochAtBlock is the coordinator's currentEpoch at block; ok is false
// before the first policy takes effect
func statsEpochAtBlock(block uint64) (uint64, bool) {
	for index := len(statsEpochSchedule); index != 0; index -= 1 {
		policy := statsEpochSchedule[index-1]
		if policy.EffectiveBlock <= block {
			return policy.EffectiveEpoch + (block-policy.EffectiveBlock)/policy.EpochBlocks, true
		}
	}
	return 0, false
}

// statsEpochBlockTime is a known boundary's header timestamp, else the block's
// time projected from the anchor
func statsEpochBlockTime(block uint64) time.Time {
	if blockTime, ok := statsEpochBlockTimes[block]; ok {
		return blockTime
	}
	return statsEpochAnchorTime.Add(time.Duration(int64(block)-statsEpochAnchorBlock) * statsEpochBlockDuration)
}

// statsEpochBlockAt is the block the chain is projected to be at, at `at`:
// the last block whose projected time is not after it
func statsEpochBlockAt(at time.Time) uint64 {
	if !at.Before(statsEpochAnchorTime) {
		return statsEpochAnchorBlock + uint64(at.Sub(statsEpochAnchorTime)/statsEpochBlockDuration)
	}
	back := uint64((statsEpochAnchorTime.Sub(at) + statsEpochBlockDuration - 1) / statsEpochBlockDuration)
	if statsEpochAnchorBlock < back {
		return 0
	}
	return statsEpochAnchorBlock - back
}

// statsEpochAt is the built-in clock's epoch at now. before the schedule's
// first block it pins to epoch 0, not yet open
func statsEpochAt(now time.Time) statsEpoch {
	number, ok := statsEpochAtBlock(statsEpochBlockAt(now))
	if !ok {
		number = statsEpochSchedule[0].EffectiveEpoch
	}
	policy, _ := statsEpochPolicyAt(number)
	start, _ := statsEpochStartBlock(number)
	epoch := statsEpoch{
		Number:     number,
		StartBlock: start,
		EndBlock:   start + policy.EpochBlocks,
		Start:      statsEpochBlockTime(start),
		End:        statsEpochBlockTime(start + policy.EpochBlocks),
	}
	if 0 < number {
		if prevStart, ok := statsEpochStartBlock(number - 1); ok {
			epoch.HasPrev = true
			epoch.PrevStart = statsEpochBlockTime(prevStart)
		}
	}
	return epoch
}

// statsWholeNumber reads a gauge value as a whole number that a float64
// carries exactly
func statsWholeNumber(value *float64) (uint64, bool) {
	if value == nil || *value < 0 || (1<<53) < *value || *value != math.Trunc(*value) {
		return 0, false
	}
	return uint64(*value), true
}

// statsEpochFromGauges is the epoch the collector publishes, when its clock
// gauges all have samples and describe one epoch. max across the collector
// hosts reads the newest epoch in each gauge, and every clock gauge rises
// with the epoch, so the maxima belong together
func statsEpochFromGauges(values map[string]*float64) (statsEpoch, bool) {
	number, numberOk := statsWholeNumber(values["epoch"])
	start, startOk := statsWholeNumber(values["epoch_start"])
	end, endOk := statsWholeNumber(values["epoch_end"])
	startBlock, startBlockOk := statsWholeNumber(values["epoch_start_block"])
	endBlock, endBlockOk := statsWholeNumber(values["epoch_end_block"])
	if !numberOk || !startOk || !endOk || !startBlockOk || !endBlockOk || end <= start || endBlock <= startBlock {
		return statsEpoch{}, false
	}
	epoch := statsEpoch{
		Number:     number,
		StartBlock: startBlock,
		EndBlock:   endBlock,
		Start:      time.Unix(int64(start), 0).UTC(),
		End:        time.Unix(int64(end), 0).UTC(),
	}
	if prevStart, ok := statsWholeNumber(values["prev_epoch_start"]); ok && 0 < number && prevStart < start {
		epoch.HasPrev = true
		epoch.PrevStart = time.Unix(int64(prevStart), 0).UTC()
	}
	return epoch, true
}

// statsEpochQueries returns the mimir instant queries for the epoch the
// collector publishes
func statsEpochQueries(env string) map[string]string {
	m := func(metric string) string {
		return fmt.Sprintf(`max(%s{env=%q})`, metric, env)
	}
	return map[string]string{
		"epoch":             m("urnetwork_stats_epoch_number"),
		"epoch_start":       m("urnetwork_stats_epoch_start_seconds"),
		"epoch_end":         m("urnetwork_stats_epoch_end_seconds"),
		"epoch_start_block": m("urnetwork_stats_epoch_start_block"),
		"epoch_end_block":   m("urnetwork_stats_epoch_end_block"),
		"prev_epoch_start":  m("urnetwork_stats_prev_epoch_start_seconds"),
	}
}

// statsQueries returns the mimir instant query for each contract field,
// windowed by epoch at now
func statsQueries(env string, epoch statsEpoch, now time.Time) map[string]string {
	m := func(metric string) string {
		return fmt.Sprintf(`max(%s{env=%q})`, metric, env)
	}
	// the ip family gauges carry one series per family: the family
	// matcher joins env inside the one selector, which is the only
	// selector a metric gets
	mFamily := func(metric string, family string) string {
		return fmt.Sprintf(`max(%s{env=%q,ip_family=%q})`, metric, env, family)
	}
	// the transfer counters are summed only over series with a per-process
	// instance label (server repo grafana.go): during a redeploy overlap
	// the old and new containers push concurrently, and before the
	// instance label they wrote the SAME series — the interleaved counter
	// values read as resets and increase() inflated by the old counter's
	// total on every interleave. the matcher also fences off that
	// corrupted unlabeled history: a window that spans the cutover counts
	// only labeled traffic and becomes exact at the next epoch rollover
	transferSelector := fmt.Sprintf(`urnetwork_connect_transfer_bytes{env=%q,instance!=""}`, env)

	elapsedSeconds := int64(now.Sub(epoch.Start) / time.Second)
	// increase() needs a window wide enough to hold two samples; right
	// after an epoch starts the accumulators are ~0 anyway
	windowSeconds := max(elapsedSeconds, 60)
	queries := map[string]string{
		"users":                      m("urnetwork_stats_epoch_users"),
		"data_gib":                   fmt.Sprintf(`sum(increase(%s[%ds])) / (1024 * 1024 * 1024)`, transferSelector, windowSeconds),
		"total_networks":             m("urnetwork_stats_total_networks"),
		"online_providers":           m("urnetwork_stats_online_providers"),
		"online_extenders":           m("urnetwork_stats_online_extenders"),
		"online_providers_ipv4":      mFamily("urnetwork_stats_online_providers_by_ip_family", "ipv4"),
		"online_providers_ipv6":      mFamily("urnetwork_stats_online_providers_by_ip_family", "ipv6"),
		"online_providers_dualstack": mFamily("urnetwork_stats_online_providers_by_ip_family", "dualstack"),
		"online_extenders_ipv4":      mFamily("urnetwork_stats_online_extenders_by_ip_family", "ipv4"),
		"online_extenders_ipv6":      mFamily("urnetwork_stats_online_extenders_by_ip_family", "ipv6"),
		"online_extenders_dualstack": mFamily("urnetwork_stats_online_extenders_by_ip_family", "dualstack"),
		"countries":                  m("urnetwork_stats_countries"),
		"staked_alpha":               m("urnetwork_stats_staked_alpha"),
		"demand_deposits_alpha":      m("urnetwork_stats_epoch_demand_deposits_alpha"),
		"miner_emissions_alpha":      m("urnetwork_stats_epoch_miner_emissions_alpha"),
		"alpha_usd":                  m("urnetwork_stats_alpha_usd"),
	}
	if epoch.HasPrev {
		// the previous epoch is its whole span, from its start to the
		// current epoch's start — an offset instant query. epoch 0 was one
		// day, every later epoch about seven
		prevSeconds := max(int64(epoch.Start.Sub(epoch.PrevStart)/time.Second), 60)
		offsetSeconds := max(elapsedSeconds, 0)
		queries["prev_users"] = m("urnetwork_stats_prev_epoch_users")
		queries["prev_data_gib"] = fmt.Sprintf(
			`sum(increase(%s[%ds] offset %ds)) / (1024 * 1024 * 1024)`,
			transferSelector,
			prevSeconds,
			offsetSeconds,
		)
		queries["prev_demand_deposits_alpha"] = m("urnetwork_stats_prev_epoch_demand_deposits_alpha")
		queries["prev_miner_emissions_alpha"] = m("urnetwork_stats_prev_epoch_miner_emissions_alpha")
	}
	return queries
}

// the operator stats contract fields. a nil field had no samples in mimir
// (collector not deployed, series stale, or pre-launch) and is omitted
// from the json
type statsSnapshot struct {
	// the current settlement epoch (see the package comment): its number,
	// its start and end as unix seconds (the end projected), and its first
	// block and the next epoch's. block is the deprecated name of epoch and
	// always equals it
	Block           uint64 `json:"block"`
	Epoch           uint64 `json:"epoch"`
	EpochStart      int64  `json:"epoch_start"`
	EpochEnd        int64  `json:"epoch_end"`
	EpochStartBlock uint64 `json:"epoch_start_block"`
	EpochEndBlock   uint64 `json:"epoch_end_block"`

	Users               *float64 `json:"users,omitempty"`
	DataGib             *float64 `json:"data_gib,omitempty"`
	TotalNetworks       *float64 `json:"total_networks,omitempty"`
	OnlineProviders     *float64 `json:"online_providers,omitempty"`
	Countries           *float64 `json:"countries,omitempty"`
	StakedAlpha         *float64 `json:"staked_alpha,omitempty"`
	DemandDepositsAlpha *float64 `json:"demand_deposits_alpha,omitempty"`
	MinerEmissionsAlpha *float64 `json:"miner_emissions_alpha,omitempty"`
	AlphaUsd            *float64 `json:"alpha_usd,omitempty"`

	// the extender network and the ip family split of each population
	// (see the package comment)
	OnlineExtenders          *float64 `json:"online_extenders,omitempty"`
	OnlineProvidersIpv4      *float64 `json:"online_providers_ipv4,omitempty"`
	OnlineProvidersIpv6      *float64 `json:"online_providers_ipv6,omitempty"`
	OnlineProvidersDualstack *float64 `json:"online_providers_dualstack,omitempty"`
	OnlineExtendersIpv4      *float64 `json:"online_extenders_ipv4,omitempty"`
	OnlineExtendersIpv6      *float64 `json:"online_extenders_ipv6,omitempty"`
	OnlineExtendersDualstack *float64 `json:"online_extenders_dualstack,omitempty"`

	// the last finished epoch (see the package comment)
	PrevUsers               *float64 `json:"prev_users,omitempty"`
	PrevDataGib             *float64 `json:"prev_data_gib,omitempty"`
	PrevDemandDepositsAlpha *float64 `json:"prev_demand_deposits_alpha,omitempty"`
	PrevMinerEmissionsAlpha *float64 `json:"prev_miner_emissions_alpha,omitempty"`
}

// statsEpochSnapshot is a snapshot with only the epoch fields
func statsEpochSnapshot(epoch statsEpoch) statsSnapshot {
	return statsSnapshot{
		Block:           epoch.Number,
		Epoch:           epoch.Number,
		EpochStart:      epoch.Start.Unix(),
		EpochEnd:        epoch.End.Unix(),
		EpochStartBlock: epoch.StartBlock,
		EpochEndBlock:   epoch.EndBlock,
	}
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
// always carries the current epoch
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

// refresh reads the epoch the collector publishes, then every field
// windowed by it
func (self *statsFeed) refresh(ctx context.Context) (statsSnapshot, error) {
	now := self.now()
	epoch := statsEpochAt(now)
	clock, err := self.queryAll(ctx, statsEpochQueries(self.env))
	if err != nil {
		return statsEpochSnapshot(epoch), err
	}
	if published, ok := statsEpochFromGauges(clock); ok {
		epoch = published
	}

	values, err := self.queryAll(ctx, statsQueries(self.env, epoch, now))
	if err != nil {
		return statsEpochSnapshot(epoch), err
	}
	snapshot := statsEpochSnapshot(epoch)
	snapshot.Users = values["users"]
	snapshot.DataGib = values["data_gib"]
	snapshot.TotalNetworks = values["total_networks"]
	snapshot.OnlineProviders = values["online_providers"]
	snapshot.Countries = values["countries"]
	snapshot.StakedAlpha = values["staked_alpha"]
	snapshot.DemandDepositsAlpha = values["demand_deposits_alpha"]
	snapshot.MinerEmissionsAlpha = values["miner_emissions_alpha"]
	snapshot.AlphaUsd = values["alpha_usd"]

	snapshot.OnlineExtenders = values["online_extenders"]
	snapshot.OnlineProvidersIpv4 = values["online_providers_ipv4"]
	snapshot.OnlineProvidersIpv6 = values["online_providers_ipv6"]
	snapshot.OnlineProvidersDualstack = values["online_providers_dualstack"]
	snapshot.OnlineExtendersIpv4 = values["online_extenders_ipv4"]
	snapshot.OnlineExtendersIpv6 = values["online_extenders_ipv6"]
	snapshot.OnlineExtendersDualstack = values["online_extenders_dualstack"]

	snapshot.PrevUsers = values["prev_users"]
	snapshot.PrevDataGib = values["prev_data_gib"]
	snapshot.PrevDemandDepositsAlpha = values["prev_demand_deposits_alpha"]
	snapshot.PrevMinerEmissionsAlpha = values["prev_miner_emissions_alpha"]
	return snapshot, nil
}

// queryAll runs the queries concurrently. a field whose query matches no
// samples is absent from the result; any query error fails the whole set
func (self *statsFeed) queryAll(ctx context.Context, queries map[string]string) (map[string]*float64, error) {
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
		return nil, firstErr
	}
	return values, nil
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
