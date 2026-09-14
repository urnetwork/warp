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

func TestStatsBlockAt(t *testing.T) {
	// every block opens and closes at 00:00 UTC Sunday; the genesis is
	// Sunday June 28 2026
	assert.Equal(t, time.Sunday, statsBlockGenesis.Weekday())

	// before the genesis the clock pins to block 1
	number, start := statsBlockAt(time.Date(2026, time.June, 15, 12, 0, 0, 0, time.UTC))
	assert.Equal(t, 1, number)
	assert.Equal(t, statsBlockGenesis, start)

	number, start = statsBlockAt(statsBlockGenesis)
	assert.Equal(t, 1, number)
	assert.Equal(t, statsBlockGenesis, start)

	// the last instant of block 1 (Saturday night)
	number, _ = statsBlockAt(time.Date(2026, time.July, 4, 23, 59, 59, 0, time.UTC))
	assert.Equal(t, 1, number)

	// block 2 opens exactly 7 days after the genesis, on a Sunday
	number, start = statsBlockAt(time.Date(2026, time.July, 5, 0, 0, 0, 0, time.UTC))
	assert.Equal(t, 2, number)
	assert.Equal(t, time.Date(2026, time.July, 5, 0, 0, 0, 0, time.UTC), start)
	assert.Equal(t, time.Sunday, start.Weekday())

	number, start = statsBlockAt(time.Date(2026, time.July, 20, 6, 30, 0, 0, time.UTC))
	assert.Equal(t, 4, number)
	assert.Equal(t, time.Date(2026, time.July, 19, 0, 0, 0, 0, time.UTC), start)
	assert.Equal(t, time.Sunday, start.Weekday())
}

func TestStatsQueries(t *testing.T) {
	queries := statsQueries("main", 120*time.Hour)
	assert.Equal(t, `max(urnetwork_stats_block_users{env="main"})`, queries["users"])
	assert.Equal(t, `max(urnetwork_stats_prev_block_users{env="main"})`, queries["prev_users"])
	assert.Equal(t, `max(urnetwork_stats_online_providers{env="main"})`, queries["online_providers"])
	assert.Equal(t, `max(urnetwork_stats_online_extenders{env="main"})`, queries["online_extenders"])
	// the family matcher joins env in the one selector
	assert.Equal(t, `max(urnetwork_stats_online_providers_by_ip_family{env="main",ip_family="ipv4"})`, queries["online_providers_ipv4"])
	assert.Equal(t, `max(urnetwork_stats_online_providers_by_ip_family{env="main",ip_family="ipv6"})`, queries["online_providers_ipv6"])
	assert.Equal(t, `max(urnetwork_stats_online_providers_by_ip_family{env="main",ip_family="dualstack"})`, queries["online_providers_dualstack"])
	assert.Equal(t, `max(urnetwork_stats_online_extenders_by_ip_family{env="main",ip_family="ipv4"})`, queries["online_extenders_ipv4"])
	assert.Equal(t, `max(urnetwork_stats_online_extenders_by_ip_family{env="main",ip_family="ipv6"})`, queries["online_extenders_ipv6"])
	assert.Equal(t, `max(urnetwork_stats_online_extenders_by_ip_family{env="main",ip_family="dualstack"})`, queries["online_extenders_dualstack"])
	assert.Equal(t, true, strings.Contains(queries["data_gib"], `urnetwork_connect_transfer_bytes{env="main",instance!=""}[432000s]`))
	// the previous block is the full block window ending at the current
	// block's open
	assert.Equal(t, true, strings.Contains(queries["prev_data_gib"], `[604800s] offset 432000s`))

	// the increase window never collapses below one scrape interval, and
	// the previous block offset never goes negative
	queries = statsQueries("main", 0)
	assert.Equal(t, true, strings.Contains(queries["data_gib"], "[60s]"))
	assert.Equal(t, true, strings.Contains(queries["prev_data_gib"], "offset 0s"))
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

func TestStatsFeedSnapshot(t *testing.T) {
	requests := &atomic.Int64{}
	// now is 30h into block 4 (opened Sunday July 19), so the current
	// transfer window is [108000s] and the previous block window carries
	// an offset
	mimirServer := newMimirStub(t, map[string]string{
		"[108000s])":                        "345.75",
		"[604800s] offset 108000s":          "512.25",
		"urnetwork_stats_total_networks":    "250000",
		"urnetwork_stats_online_providers{": "95000",
		"urnetwork_stats_online_extenders{": "1800",
		"urnetwork_stats_block_users":       "125000",
		"urnetwork_stats_countries":         "123",
		"urnetwork_stats_alpha_usd":         "1.75",
		// the family gauges are selected one series at a time; the three
		// provider families sum to the provider total
		`urnetwork_stats_online_providers_by_ip_family{env="main",ip_family="ipv4"}`:      "60000",
		`urnetwork_stats_online_providers_by_ip_family{env="main",ip_family="ipv6"}`:      "5000",
		`urnetwork_stats_online_providers_by_ip_family{env="main",ip_family="dualstack"}`: "30000",
		`urnetwork_stats_online_extenders_by_ip_family{env="main",ip_family="ipv4"}`:      "1200",
		`urnetwork_stats_online_extenders_by_ip_family{env="main",ip_family="ipv6"}`:      "100",
		// the chain gauges, the prev users snapshot and the dualstack
		// extenders are left absent, like a pre-launch feed
	}, requests)
	defer mimirServer.Close()

	now := time.Date(2026, time.July, 20, 6, 0, 0, 0, time.UTC)
	feed := testStatsFeed(mimirServer, now)

	snapshot, err := feed.snapshot(context.Background())
	assert.Equal(t, nil, err)
	assert.Equal(t, 4, snapshot.Block)
	assert.Equal(t, 345.75, *snapshot.DataGib)
	assert.Equal(t, 250000.0, *snapshot.TotalNetworks)
	assert.Equal(t, 95000.0, *snapshot.OnlineProviders)
	assert.Equal(t, 125000.0, *snapshot.Users)
	assert.Equal(t, 123.0, *snapshot.Countries)
	assert.Equal(t, 1.75, *snapshot.AlphaUsd)
	assert.Equal(t, 512.25, *snapshot.PrevDataGib)
	assert.Equal(t, 1800.0, *snapshot.OnlineExtenders)
	assert.Equal(t, 60000.0, *snapshot.OnlineProvidersIpv4)
	assert.Equal(t, 5000.0, *snapshot.OnlineProvidersIpv6)
	assert.Equal(t, 30000.0, *snapshot.OnlineProvidersDualstack)
	assert.Equal(t, 1200.0, *snapshot.OnlineExtendersIpv4)
	assert.Equal(t, 100.0, *snapshot.OnlineExtendersIpv6)
	if snapshot.OnlineExtendersDualstack != nil {
		t.Errorf("an absent family series must stay nil")
	}
	if snapshot.StakedAlpha != nil || snapshot.DemandDepositsAlpha != nil || snapshot.MinerEmissionsAlpha != nil {
		t.Errorf("absent series must stay nil")
	}
	if snapshot.PrevUsers != nil || snapshot.PrevDemandDepositsAlpha != nil || snapshot.PrevMinerEmissionsAlpha != nil {
		t.Errorf("absent prev series must stay nil")
	}

	// a second snapshot inside the ttl is served from cache
	requestsAfterFirst := requests.Load()
	snapshot, err = feed.snapshot(context.Background())
	assert.Equal(t, nil, err)
	assert.Equal(t, requestsAfterFirst, requests.Load())

	// the omitted fields stay out of the json
	bodyJson, err := json.Marshal(snapshot)
	assert.Equal(t, nil, err)
	body := map[string]any{}
	assert.Equal(t, nil, json.Unmarshal(bodyJson, &body))
	assert.Equal(t, 4.0, body["block"])
	assert.Equal(t, 345.75, body["data_gib"])
	assert.Equal(t, 95000.0, body["online_providers"])
	assert.Equal(t, 1800.0, body["online_extenders"])
	assert.Equal(t, 60000.0, body["online_providers_ipv4"])
	assert.Equal(t, 5000.0, body["online_providers_ipv6"])
	assert.Equal(t, 30000.0, body["online_providers_dualstack"])
	assert.Equal(t, 1200.0, body["online_extenders_ipv4"])
	assert.Equal(t, 100.0, body["online_extenders_ipv6"])
	if _, ok := body["staked_alpha"]; ok {
		t.Errorf("staked_alpha must be omitted")
	}
	if _, ok := body["online_extenders_dualstack"]; ok {
		t.Errorf("online_extenders_dualstack must be omitted")
	}
}

func TestStatsFeedStaleOnError(t *testing.T) {
	mimirServer := newMimirStub(t, map[string]string{
		"urnetwork_connect_transfer_bytes": "345.75",
	}, nil)

	now := time.Date(2026, time.July, 20, 6, 0, 0, 0, time.UTC)
	feed := testStatsFeed(mimirServer, now)

	snapshot, err := feed.snapshot(context.Background())
	assert.Equal(t, nil, err)
	assert.Equal(t, 345.75, *snapshot.DataGib)

	// mimir goes away past the cache ttl: the stale snapshot keeps serving
	mimirServer.Close()
	feed.now = func() time.Time {
		return now.Add(time.Minute)
	}
	snapshot, err = feed.snapshot(context.Background())
	assert.Equal(t, nil, err)
	assert.Equal(t, 345.75, *snapshot.DataGib)
}

func TestServeStatsJson(t *testing.T) {
	mimirServer := newMimirStub(t, map[string]string{
		"urnetwork_connect_transfer_bytes":                                                "345.75",
		"urnetwork_stats_online_extenders{":                                               "1800",
		`urnetwork_stats_online_providers_by_ip_family{env="main",ip_family="ipv4"}`:      "60000",
		`urnetwork_stats_online_providers_by_ip_family{env="main",ip_family="ipv6"}`:      "5000",
		`urnetwork_stats_online_providers_by_ip_family{env="main",ip_family="dualstack"}`: "30000",
		`urnetwork_stats_online_extenders_by_ip_family{env="main",ip_family="ipv4"}`:      "1200",
		`urnetwork_stats_online_extenders_by_ip_family{env="main",ip_family="ipv6"}`:      "100",
		`urnetwork_stats_online_extenders_by_ip_family{env="main",ip_family="dualstack"}`: "500",
	}, nil)
	defer mimirServer.Close()

	grafanaServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/dashboards/public-dashboards", r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"publicDashboards":[{"accessToken":"token123","title":"network stats","dashboardUid":"uid1","isEnabled":true}]}`)
	}))
	defer grafanaServer.Close()

	grafanaUrl, err := url.Parse(grafanaServer.URL)
	assert.Equal(t, nil, err)
	index := newPublicIndex(grafanaUrl, "password")
	feed := testStatsFeed(mimirServer, time.Date(2026, time.July, 20, 6, 0, 0, 0, time.UTC))

	request := httptest.NewRequest("GET", "https://main-grafana.example.com/stats.json", nil)
	recorder := httptest.NewRecorder()
	serveStatsJson(recorder, request, index, feed)

	assert.Equal(t, http.StatusOK, recorder.Code)
	// cors is owned by the warp lb (cors_origins allowlist); a front header
	// would duplicate it and fail the browser check
	assert.Equal(t, "", recorder.Header().Get("Access-Control-Allow-Origin"))

	body := map[string]any{}
	assert.Equal(t, nil, json.Unmarshal(recorder.Body.Bytes(), &body))
	assert.Equal(t, 4.0, body["block"])
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
