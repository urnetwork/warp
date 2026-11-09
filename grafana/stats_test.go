package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-playground/assert/v2"
)

// the mainnet boundaries as the coordinator reports them, with the two
// mined start times
var (
	testEpoch0Start = time.Unix(1_791_482_892, 0).UTC() // block 9,240,028, 2026-10-08 18:08:12
	testEpoch1Start = time.Unix(1_791_569_340, 0).UTC() // block 9,247,228, 2026-10-09 18:09:00
	// 50,400 blocks at 12 s
	testEpochWeek = 50_400 * 12 * time.Second
)

// The built-in clock is the coordinator's schedule, rolling 0 -> 1 -> 2 -> 3
// at its boundary blocks, projected at 12 s a block from epoch 1's start.
func TestStatsEpochAt(t *testing.T) {
	week := testEpochWeek
	for _, c := range []struct {
		name       string
		at         time.Time
		number     uint64
		startBlock uint64
		endBlock   uint64
		start      time.Time
		end        time.Time
		hasPrev    bool
		prevStart  time.Time
	}{
		{"before the deploy", testEpoch0Start.Add(-24 * time.Hour), 0, 9_240_028, 9_247_228, testEpoch0Start, testEpoch1Start, false, time.Time{}},
		{"epoch 0", testEpoch0Start.Add(time.Hour), 0, 9_240_028, 9_247_228, testEpoch0Start, testEpoch1Start, false, time.Time{}},
		{"epoch 0's last second", testEpoch1Start.Add(-time.Second), 0, 9_240_028, 9_247_228, testEpoch0Start, testEpoch1Start, false, time.Time{}},
		{"epoch 1 starts", testEpoch1Start, 1, 9_247_228, 9_297_628, testEpoch1Start, testEpoch1Start.Add(week), true, testEpoch0Start},
		{"epoch 1's last second", testEpoch1Start.Add(week - time.Second), 1, 9_247_228, 9_297_628, testEpoch1Start, testEpoch1Start.Add(week), true, testEpoch0Start},
		{"epoch 2 starts", testEpoch1Start.Add(week), 2, 9_297_628, 9_348_028, testEpoch1Start.Add(week), testEpoch1Start.Add(2 * week), true, testEpoch1Start},
		// settlement v2's first epoch
		{"epoch 3 starts", testEpoch1Start.Add(2 * week), 3, 9_348_028, 9_398_428, testEpoch1Start.Add(2 * week), testEpoch1Start.Add(3 * week), true, testEpoch1Start.Add(week)},
	} {
		epoch := statsEpochAt(c.at)
		if epoch.Number != c.number || epoch.StartBlock != c.startBlock || epoch.EndBlock != c.endBlock {
			t.Fatalf("%s: epoch %d [%d, %d), want %d [%d, %d)", c.name, epoch.Number, epoch.StartBlock, epoch.EndBlock, c.number, c.startBlock, c.endBlock)
		}
		if !epoch.Start.Equal(c.start) || !epoch.End.Equal(c.end) || epoch.HasPrev != c.hasPrev || !epoch.PrevStart.Equal(c.prevStart) {
			t.Fatalf("%s: %+v", c.name, epoch)
		}
	}
}

// The collector's epoch is used only when every clock gauge has a whole,
// consistent value; the previous start only when it precedes the epoch.
func TestStatsEpochFromGauges(t *testing.T) {
	value := func(v float64) *float64 {
		return &v
	}
	published := func() map[string]*float64 {
		return map[string]*float64{
			"epoch":             value(2),
			"epoch_start":       value(1_792_174_260),
			"epoch_end":         value(1_792_779_090),
			"epoch_start_block": value(9_297_628),
			"epoch_end_block":   value(9_348_028),
			"prev_epoch_start":  value(1_791_569_340),
		}
	}
	epoch, ok := statsEpochFromGauges(published())
	assert.Equal(t, true, ok)
	assert.Equal(t, uint64(2), epoch.Number)
	assert.Equal(t, uint64(9_297_628), epoch.StartBlock)
	assert.Equal(t, uint64(9_348_028), epoch.EndBlock)
	assert.Equal(t, int64(1_792_174_260), epoch.Start.Unix())
	assert.Equal(t, int64(1_792_779_090), epoch.End.Unix())
	assert.Equal(t, true, epoch.HasPrev)
	assert.Equal(t, testEpoch1Start, epoch.PrevStart)

	// a withdrawn previous start (no samples) leaves no previous epoch
	values := published()
	delete(values, "prev_epoch_start")
	epoch, ok = statsEpochFromGauges(values)
	assert.Equal(t, true, ok)
	assert.Equal(t, false, epoch.HasPrev)

	for name, change := range map[string]func(map[string]*float64){
		"no epoch":            func(v map[string]*float64) { delete(v, "epoch") },
		"no end block":        func(v map[string]*float64) { delete(v, "epoch_end_block") },
		"fractional epoch":    func(v map[string]*float64) { v["epoch"] = value(2.5) },
		"negative start":      func(v map[string]*float64) { v["epoch_start"] = value(-1) },
		"end before start":    func(v map[string]*float64) { v["epoch_end"] = value(1_792_174_000) },
		"blocks out of order": func(v map[string]*float64) { v["epoch_end_block"] = value(9_297_628) },
	} {
		values := published()
		change(values)
		if _, ok := statsEpochFromGauges(values); ok {
			t.Errorf("%s: an inconsistent clock was used", name)
		}
	}
}

func TestStatsQueries(t *testing.T) {
	epoch := statsEpochAt(testEpoch1Start.Add(30 * time.Hour))
	queries := statsQueries("main", epoch, testEpoch1Start.Add(30*time.Hour))
	assert.Equal(t, `max(urnetwork_stats_epoch_users{env="main"})`, queries["users"])
	assert.Equal(t, `max(urnetwork_stats_prev_epoch_users{env="main"})`, queries["prev_users"])
	assert.Equal(t, `max(urnetwork_stats_epoch_demand_deposits_alpha{env="main"})`, queries["demand_deposits_alpha"])
	assert.Equal(t, `max(urnetwork_stats_epoch_miner_emissions_alpha{env="main"})`, queries["miner_emissions_alpha"])
	assert.Equal(t, `max(urnetwork_stats_prev_epoch_demand_deposits_alpha{env="main"})`, queries["prev_demand_deposits_alpha"])
	assert.Equal(t, `max(urnetwork_stats_prev_epoch_miner_emissions_alpha{env="main"})`, queries["prev_miner_emissions_alpha"])
	assert.Equal(t, `max(urnetwork_stats_online_providers{env="main"})`, queries["online_providers"])
	assert.Equal(t, `max(urnetwork_stats_online_extenders{env="main"})`, queries["online_extenders"])
	// the family matcher joins env in the one selector
	assert.Equal(t, `max(urnetwork_stats_online_providers_by_ip_family{env="main",ip_family="ipv4"})`, queries["online_providers_ipv4"])
	assert.Equal(t, `max(urnetwork_stats_online_providers_by_ip_family{env="main",ip_family="ipv6"})`, queries["online_providers_ipv6"])
	assert.Equal(t, `max(urnetwork_stats_online_providers_by_ip_family{env="main",ip_family="dualstack"})`, queries["online_providers_dualstack"])
	assert.Equal(t, `max(urnetwork_stats_online_extenders_by_ip_family{env="main",ip_family="ipv4"})`, queries["online_extenders_ipv4"])
	assert.Equal(t, `max(urnetwork_stats_online_extenders_by_ip_family{env="main",ip_family="ipv6"})`, queries["online_extenders_ipv6"])
	assert.Equal(t, `max(urnetwork_stats_online_extenders_by_ip_family{env="main",ip_family="dualstack"})`, queries["online_extenders_dualstack"])
	// the current epoch's transfer window is the time since its start
	assert.Equal(t, true, strings.Contains(queries["data_gib"], `urnetwork_connect_transfer_bytes{env="main",instance!=""}[108000s]`))
	// the previous epoch is epoch 0's whole day, ending at epoch 1's start
	assert.Equal(t, true, strings.Contains(queries["prev_data_gib"], `[86448s] offset 108000s`))

	// in epoch 2 the previous epoch is epoch 1's whole week
	epoch = statsEpochAt(testEpoch1Start.Add(testEpochWeek + time.Hour))
	queries = statsQueries("main", epoch, testEpoch1Start.Add(testEpochWeek+time.Hour))
	assert.Equal(t, true, strings.Contains(queries["prev_data_gib"], `[604800s] offset 3600s`))

	// the increase window never collapses below one scrape interval, and
	// the previous epoch offset never goes negative
	queries = statsQueries("main", epoch, epoch.Start)
	assert.Equal(t, true, strings.Contains(queries["data_gib"], "[60s]"))
	assert.Equal(t, true, strings.Contains(queries["prev_data_gib"], "offset 0s"))

	// epoch 0 has no finished predecessor, so nothing previous is queried
	epoch = statsEpochAt(testEpoch0Start.Add(time.Hour))
	queries = statsQueries("main", epoch, testEpoch0Start.Add(time.Hour))
	for _, field := range []string{"prev_users", "prev_data_gib", "prev_demand_deposits_alpha", "prev_miner_emissions_alpha"} {
		if _, ok := queries[field]; ok {
			t.Errorf("epoch 0 queries %s", field)
		}
	}
	assert.Equal(t, true, strings.Contains(queries["data_gib"], "[3600s]"))
}

// newMimirStub serves the mimir instant query api, answering each metric
// from values and leaving any other query without samples
func newMimirStub(t *testing.T, values map[string]string, requests *atomic.Int64) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/prometheus/api/v1/query" {
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		if requests != nil {
			requests.Add(1)
		}
		if err := r.ParseForm(); err != nil {
			t.Error(err)
		}
		query := r.PostForm.Get("query")
		result := "[]"
		// the longest matching fragment wins, so a metric name that is
		// the prefix of another (online_providers and
		// online_providers_by_ip_family) never shadows it whichever way
		// the map happens to iterate
		matched := ""
		for fragment, value := range values {
			if strings.Contains(query, fragment) && len(matched) < len(fragment) {
				matched = fragment
				result = fmt.Sprintf(`[{"metric":{},"value":[1752984000, %q]}]`, value)
			}
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"status":"success","data":{"resultType":"vector","result":%s}}`, result)
	}))
}

func testStatsFeed(mimirServer *httptest.Server, now time.Time) *statsFeed {
	mimirUrl, err := url.Parse(mimirServer.URL)
	if err != nil {
		panic(err)
	}
	feed := newStatsFeed(mimirUrl, "main")
	feed.now = func() time.Time {
		return now
	}
	return feed
}

// the clock a collector publishes 30 hours into epoch 2 on a chain that ran
// two minutes behind the built-in projection
var testPublishedEpoch2 = map[string]string{
	"urnetwork_stats_epoch_number{":             "2",
	"urnetwork_stats_epoch_start_seconds{":      "1792174260",
	"urnetwork_stats_epoch_end_seconds{":        "1792779090",
	"urnetwork_stats_epoch_start_block{":        "9297628",
	"urnetwork_stats_epoch_end_block{":          "9348028",
	"urnetwork_stats_prev_epoch_start_seconds{": "1791569340",
}

var testPublishedEpoch2Now = time.Unix(1_792_174_260+108_000, 0).UTC()

func testWithPublishedEpoch2(values map[string]string) map[string]string {
	for fragment, value := range testPublishedEpoch2 {
		values[fragment] = value
	}
	return values
}

func TestStatsFeedSnapshot(t *testing.T) {
	requests := &atomic.Int64{}
	// the windows follow the published start: 108000s into epoch 2, and
	// epoch 1's whole 604920s before it. the built-in clock would have
	// windowed 108120s
	mimirServer := newMimirStub(t, testWithPublishedEpoch2(map[string]string{
		"[108000s])":                                   "345.75",
		"[604920s] offset 108000s":                     "512.25",
		"urnetwork_stats_total_networks":               "250000",
		"urnetwork_stats_online_providers{":            "95000",
		"urnetwork_stats_online_extenders{":            "1800",
		"urnetwork_stats_epoch_users{":                 "125000",
		"urnetwork_stats_prev_epoch_users{":            "118000",
		"urnetwork_stats_countries":                    "123",
		"urnetwork_stats_alpha_usd":                    "1.75",
		"urnetwork_stats_epoch_miner_emissions_alpha{": "8000.5",
		"urnetwork_stats_epoch_demand_deposits_alpha{": "0",
		"urnetwork_stats_staked_alpha{":                "0",
		// the deprecated block names are never read
		"urnetwork_stats_block_users{":      "1",
		"urnetwork_stats_prev_block_users{": "1",
		// the family gauges are selected one series at a time; the three
		// provider families sum to the provider total
		`urnetwork_stats_online_providers_by_ip_family{env="main",ip_family="ipv4"}`:      "60000",
		`urnetwork_stats_online_providers_by_ip_family{env="main",ip_family="ipv6"}`:      "5000",
		`urnetwork_stats_online_providers_by_ip_family{env="main",ip_family="dualstack"}`: "30000",
		`urnetwork_stats_online_extenders_by_ip_family{env="main",ip_family="ipv4"}`:      "1200",
		`urnetwork_stats_online_extenders_by_ip_family{env="main",ip_family="ipv6"}`:      "100",
		// the previous alpha and the dualstack extenders are left absent
	}), requests)
	defer mimirServer.Close()

	feed := testStatsFeed(mimirServer, testPublishedEpoch2Now)

	snapshot, err := feed.snapshot(context.Background())
	assert.Equal(t, nil, err)
	assert.Equal(t, uint64(2), snapshot.Epoch)
	assert.Equal(t, snapshot.Epoch, snapshot.Block)
	assert.Equal(t, int64(1_792_174_260), snapshot.EpochStart)
	assert.Equal(t, int64(1_792_779_090), snapshot.EpochEnd)
	assert.Equal(t, uint64(9_297_628), snapshot.EpochStartBlock)
	assert.Equal(t, uint64(9_348_028), snapshot.EpochEndBlock)
	assert.Equal(t, 345.75, *snapshot.DataGib)
	assert.Equal(t, 512.25, *snapshot.PrevDataGib)
	assert.Equal(t, 250000.0, *snapshot.TotalNetworks)
	assert.Equal(t, 95000.0, *snapshot.OnlineProviders)
	assert.Equal(t, 125000.0, *snapshot.Users)
	assert.Equal(t, 118000.0, *snapshot.PrevUsers)
	assert.Equal(t, 123.0, *snapshot.Countries)
	assert.Equal(t, 1.75, *snapshot.AlphaUsd)
	assert.Equal(t, 8000.5, *snapshot.MinerEmissionsAlpha)
	// a measured zero is published, not omitted
	assert.Equal(t, 0.0, *snapshot.DemandDepositsAlpha)
	assert.Equal(t, 0.0, *snapshot.StakedAlpha)
	assert.Equal(t, 1800.0, *snapshot.OnlineExtenders)
	assert.Equal(t, 60000.0, *snapshot.OnlineProvidersIpv4)
	assert.Equal(t, 5000.0, *snapshot.OnlineProvidersIpv6)
	assert.Equal(t, 30000.0, *snapshot.OnlineProvidersDualstack)
	assert.Equal(t, 1200.0, *snapshot.OnlineExtendersIpv4)
	assert.Equal(t, 100.0, *snapshot.OnlineExtendersIpv6)
	if snapshot.OnlineExtendersDualstack != nil {
		t.Errorf("an absent family series must stay nil")
	}
	if snapshot.PrevDemandDepositsAlpha != nil || snapshot.PrevMinerEmissionsAlpha != nil {
		t.Errorf("absent prev series must stay nil")
	}

	// a second snapshot inside the ttl is served from cache
	requestsAfterFirst := requests.Load()
	snapshot, err = feed.snapshot(context.Background())
	assert.Equal(t, nil, err)
	assert.Equal(t, requestsAfterFirst, requests.Load())

	// the omitted fields stay out of the json, and block equals epoch
	bodyJson, err := json.Marshal(snapshot)
	assert.Equal(t, nil, err)
	body := map[string]any{}
	assert.Equal(t, nil, json.Unmarshal(bodyJson, &body))
	assert.Equal(t, 2.0, body["epoch"])
	assert.Equal(t, 2.0, body["block"])
	assert.Equal(t, 1_792_174_260.0, body["epoch_start"])
	assert.Equal(t, 1_792_779_090.0, body["epoch_end"])
	assert.Equal(t, 9_297_628.0, body["epoch_start_block"])
	assert.Equal(t, 9_348_028.0, body["epoch_end_block"])
	assert.Equal(t, 345.75, body["data_gib"])
	assert.Equal(t, 95000.0, body["online_providers"])
	assert.Equal(t, 1800.0, body["online_extenders"])
	assert.Equal(t, 60000.0, body["online_providers_ipv4"])
	assert.Equal(t, 5000.0, body["online_providers_ipv6"])
	assert.Equal(t, 30000.0, body["online_providers_dualstack"])
	assert.Equal(t, 1200.0, body["online_extenders_ipv4"])
	assert.Equal(t, 100.0, body["online_extenders_ipv6"])
	if _, ok := body["prev_miner_emissions_alpha"]; ok {
		t.Errorf("prev_miner_emissions_alpha must be omitted")
	}
	if _, ok := body["online_extenders_dualstack"]; ok {
		t.Errorf("online_extenders_dualstack must be omitted")
	}
}

// A collector deployed before the epoch clock publishes no epoch gauges: the
// feed serves the built-in epoch and windows data_gib by it, and omits the
// accumulators rather than serve its Sunday block values under an epoch.
func TestStatsFeedFallsBackToTheBuiltInEpoch(t *testing.T) {
	now := testEpoch1Start.Add(30 * time.Hour)
	mimirServer := newMimirStub(t, map[string]string{
		"[108000s])":                        "345.75",
		"[86448s] offset 108000s":           "40.5",
		"urnetwork_stats_total_networks":    "250000",
		"urnetwork_stats_online_providers{": "95000",
		// an older collector's block gauges
		"urnetwork_stats_block_number{":                "16",
		"urnetwork_stats_block_users{":                 "125000",
		"urnetwork_stats_prev_block_users{":            "118000",
		"urnetwork_stats_block_demand_deposits_alpha{": "0",
	}, nil)
	defer mimirServer.Close()

	snapshot, err := testStatsFeed(mimirServer, now).snapshot(context.Background())
	assert.Equal(t, nil, err)
	assert.Equal(t, uint64(1), snapshot.Epoch)
	assert.Equal(t, uint64(1), snapshot.Block)
	assert.Equal(t, testEpoch1Start.Unix(), snapshot.EpochStart)
	assert.Equal(t, testEpoch1Start.Add(testEpochWeek).Unix(), snapshot.EpochEnd)
	assert.Equal(t, uint64(9_247_228), snapshot.EpochStartBlock)
	assert.Equal(t, uint64(9_297_628), snapshot.EpochEndBlock)
	assert.Equal(t, 345.75, *snapshot.DataGib)
	assert.Equal(t, 40.5, *snapshot.PrevDataGib)
	assert.Equal(t, 95000.0, *snapshot.OnlineProviders)
	if snapshot.Users != nil || snapshot.PrevUsers != nil || snapshot.DemandDepositsAlpha != nil {
		t.Errorf("an older collector's block accumulators must not be served as the epoch's")
	}
}

func TestStatsFeedStaleOnError(t *testing.T) {
	mimirServer := newMimirStub(t, testWithPublishedEpoch2(map[string]string{
		"urnetwork_connect_transfer_bytes": "345.75",
	}), nil)

	feed := testStatsFeed(mimirServer, testPublishedEpoch2Now)

	snapshot, err := feed.snapshot(context.Background())
	assert.Equal(t, nil, err)
	assert.Equal(t, 345.75, *snapshot.DataGib)

	// mimir goes away past the cache ttl: the stale snapshot keeps serving
	mimirServer.Close()
	feed.now = func() time.Time {
		return testPublishedEpoch2Now.Add(time.Minute)
	}
	snapshot, err = feed.snapshot(context.Background())
	assert.Equal(t, nil, err)
	assert.Equal(t, 345.75, *snapshot.DataGib)
	assert.Equal(t, uint64(2), snapshot.Epoch)
}

// With mimir down and nothing cached, the error still carries the epoch.
func TestStatsFeedErrorCarriesTheEpoch(t *testing.T) {
	mimirServer := newMimirStub(t, map[string]string{}, nil)
	mimirServer.Close()

	snapshot, err := testStatsFeed(mimirServer, testEpoch1Start.Add(time.Hour)).snapshot(context.Background())
	if err == nil {
		t.Fatal("a feed with no mimir must report the error")
	}
	assert.Equal(t, uint64(1), snapshot.Epoch)
	assert.Equal(t, uint64(1), snapshot.Block)
	assert.Equal(t, testEpoch1Start.Unix(), snapshot.EpochStart)
}

func TestServeStatsJson(t *testing.T) {
	mimirServer := newMimirStub(t, testWithPublishedEpoch2(map[string]string{
		"urnetwork_connect_transfer_bytes":                                                "345.75",
		"urnetwork_stats_online_extenders{":                                               "1800",
		`urnetwork_stats_online_providers_by_ip_family{env="main",ip_family="ipv4"}`:      "60000",
		`urnetwork_stats_online_providers_by_ip_family{env="main",ip_family="ipv6"}`:      "5000",
		`urnetwork_stats_online_providers_by_ip_family{env="main",ip_family="dualstack"}`: "30000",
		`urnetwork_stats_online_extenders_by_ip_family{env="main",ip_family="ipv4"}`:      "1200",
		`urnetwork_stats_online_extenders_by_ip_family{env="main",ip_family="ipv6"}`:      "100",
		`urnetwork_stats_online_extenders_by_ip_family{env="main",ip_family="dualstack"}`: "500",
	}), nil)
	defer mimirServer.Close()

	grafanaServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/dashboards/public-dashboards":
			fmt.Fprint(w, `{"publicDashboards":[{"accessToken":"token123","title":"network stats","dashboardUid":"uid1","isEnabled":true}]}`)
		case "/api/search":
			// no dashboard is tagged unlisted
			fmt.Fprint(w, `[]`)
		default:
			t.Errorf("unexpected grafana path %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer grafanaServer.Close()

	grafanaUrl, err := url.Parse(grafanaServer.URL)
	assert.Equal(t, nil, err)
	index := newPublicIndex(grafanaUrl, "password")
	feed := testStatsFeed(mimirServer, testPublishedEpoch2Now)

	request := httptest.NewRequest("GET", "https://main-grafana.example.com/stats.json", nil)
	recorder := httptest.NewRecorder()
	serveStatsJson(recorder, request, index, feed)

	assert.Equal(t, http.StatusOK, recorder.Code)
	// cors is owned by the warp lb (cors_origins allowlist); a front header
	// would duplicate it and fail the browser check
	assert.Equal(t, "", recorder.Header().Get("Access-Control-Allow-Origin"))

	body := map[string]any{}
	assert.Equal(t, nil, json.Unmarshal(recorder.Body.Bytes(), &body))
	// the epoch, and block as its deprecated alias
	assert.Equal(t, 2.0, body["epoch"])
	assert.Equal(t, body["epoch"], body["block"])
	assert.Equal(t, 1_792_174_260.0, body["epoch_start"])
	assert.Equal(t, 1_792_779_090.0, body["epoch_end"])
	assert.Equal(t, 9_297_628.0, body["epoch_start_block"])
	assert.Equal(t, 9_348_028.0, body["epoch_end_block"])
	assert.Equal(t, 345.75, body["data_gib"])
	assert.Equal(t, 1800.0, body["online_extenders"])
	assert.Equal(t, 60000.0, body["online_providers_ipv4"])
	assert.Equal(t, 5000.0, body["online_providers_ipv6"])
	assert.Equal(t, 30000.0, body["online_providers_dualstack"])
	assert.Equal(t, 1200.0, body["online_extenders_ipv4"])
	assert.Equal(t, 100.0, body["online_extenders_ipv6"])
	assert.Equal(t, 500.0, body["online_extenders_dualstack"])
	dashboards := body["dashboards"].([]any)
	assert.Equal(t, 1, len(dashboards))
	dashboard := dashboards[0].(map[string]any)
	assert.Equal(t, "network stats", dashboard["title"])
	assert.Equal(t, "https://main-grafana.example.com/public-dashboards/token123", dashboard["viewUrl"])
}

// /stats.json lists the public dashboards that are not tagged unlisted, and
// the unlisted one's token appears nowhere in it.
func TestServeStatsJsonLeavesOutUnlistedDashboards(t *testing.T) {
	mimirServer := newMimirStub(t, testWithPublishedEpoch2(map[string]string{}), nil)
	defer mimirServer.Close()
	fake, grafanaUrl := newPublicIndexListedAndUnlistedFake(t)
	index := newPublicIndex(grafanaUrl, publicIndexTestAdminPassword)
	feed := testStatsFeed(mimirServer, testPublishedEpoch2Now)

	recorder := httptest.NewRecorder()
	serveStatsJson(recorder, httptest.NewRequest("GET", "https://main-grafana.example.com/stats.json", nil), index, feed)

	assert.Equal(t, http.StatusOK, recorder.Code)
	if strings.Contains(recorder.Body.String(), "syntheticUnlistedToken01") || strings.Contains(recorder.Body.String(), "synthetic unlisted proxy test") {
		t.Fatalf("/stats.json shows the unlisted dashboard: %s", recorder.Body.String())
	}
	var body struct {
		Epoch      uint64           `json:"epoch"`
		Dashboards []statsDashboard `json:"dashboards"`
	}
	assert.Equal(t, nil, json.Unmarshal(recorder.Body.Bytes(), &body))
	assert.Equal(t, uint64(2), body.Epoch)
	assert.Equal(t, []statsDashboard{{
		Title:       "synthetic listed stats",
		Uid:         "synthetic-listed",
		AccessToken: "syntheticListedToken01",
		ViewUrl:     "https://main-grafana.example.com/public-dashboards/syntheticListedToken01",
		DataApiUrl:  "https://main-grafana.example.com/api/public/dashboards/syntheticListedToken01",
	}}, body.Dashboards)
	fake.requireNoUnexpectedRequest(t)
}

// When the unlisted search fails, /stats.json lists no dashboard, and the
// stats fields still serve.
func TestServeStatsJsonListsNoDashboardWhenTheUnlistedSearchFails(t *testing.T) {
	mimirServer := newMimirStub(t, testWithPublishedEpoch2(map[string]string{
		"urnetwork_connect_transfer_bytes": "345.75",
	}), nil)
	defer mimirServer.Close()
	fake, grafanaUrl := newPublicIndexListedAndUnlistedFake(t)
	fake.setSearchStatus(http.StatusBadGateway)
	index := newPublicIndex(grafanaUrl, publicIndexTestAdminPassword)
	feed := testStatsFeed(mimirServer, testPublishedEpoch2Now)

	recorder := httptest.NewRecorder()
	serveStatsJson(recorder, httptest.NewRequest("GET", "https://main-grafana.example.com/stats.json", nil), index, feed)

	assert.Equal(t, http.StatusOK, recorder.Code)
	if strings.Contains(recorder.Body.String(), "public-dashboards/") {
		t.Fatalf("/stats.json listed dashboards without the unlisted search: %s", recorder.Body.String())
	}
	body := map[string]any{}
	assert.Equal(t, nil, json.Unmarshal(recorder.Body.Bytes(), &body))
	assert.Equal(t, 345.75, body["data_gib"])
	assert.Equal(t, []any{}, body["dashboards"])
	fake.requireNoUnexpectedRequest(t)
}
