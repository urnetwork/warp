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
