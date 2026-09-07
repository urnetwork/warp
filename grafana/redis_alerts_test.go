package main

import (
	"os"
	"strings"
	"testing"
)

func TestRedisAvailabilityAlertsDoNotResolveOnNoData(t *testing.T) {
	data, err := os.ReadFile("alerting/redis-cluster.yml")
	if err != nil {
		t.Fatal(err)
	}

	config := string(data)
	for _, uid := range []string{
		"redis-node-down",
		"redis-cluster-state-not-ok",
	} {
		start := strings.Index(config, "- uid: "+uid)
		if start < 0 {
			t.Fatalf("missing Redis availability alert %q", uid)
		}
		block := config[start:]
		if next := strings.Index(block[1:], "\n      - uid: "); next >= 0 {
			block = block[:next+1]
		}
		if !strings.Contains(block, "noDataState: Alerting") {
			t.Errorf("Redis availability alert %q must alert on missing telemetry", uid)
		}
	}
}

func TestRedisRateAlertsCoverStaggeredScrapes(t *testing.T) {
	data, err := os.ReadFile("alerting/redis-cluster.yml")
	if err != nil {
		t.Fatal(err)
	}

	config := string(data)
	start := strings.Index(config, "- uid: redis-node-wedged")
	if start < 0 {
		t.Fatal("missing Redis node wedged alert")
	}
	block := config[start:]
	if next := strings.Index(block[1:], "\n      - uid: "); next >= 0 {
		block = block[:next+1]
	}
	for _, metric := range []string{
		"redis_commands_duration_seconds_total[5m]",
		"redis_commands_processed_total[5m]",
	} {
		if !strings.Contains(block, metric) {
			t.Errorf("Redis node wedged alert does not use the five-minute range for %s", metric)
		}
	}
	if strings.Contains(block, "[2m]") {
		t.Error("Redis node wedged alert uses a range that can contain fewer than two staggered scrape samples")
	}
}
