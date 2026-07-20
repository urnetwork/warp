package main

import (
	"os"
	"strings"
	"testing"
)

func TestContractFailureAlertsUseLosslessBoundedCounter(t *testing.T) {
	data, err := os.ReadFile("alerting/contract-failures.yml")
	if err != nil {
		t.Fatal(err)
	}

	config := string(data)
	for _, want := range []string{
		`urnetwork_connect_contract_failures_total{cause="insufficient_balance"}`,
		`urnetwork_connect_contract_failures_total{cause="missing_companion_origin"}`,
		"uid: contract-insufficient-balance-spike",
		"uid: contract-missing-companion-origin-spike",
	} {
		if !strings.Contains(config, want) {
			t.Errorf("contract alert configuration is missing %q", want)
		}
	}
}
