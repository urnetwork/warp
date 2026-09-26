package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadCartoAPIKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "carto.yml")
	if err := os.WriteFile(path, []byte("api_key: synthetic-test-key\n"), 0600); err != nil {
		t.Fatal(err)
	}
	key, err := loadCartoAPIKey(path)
	if err != nil || key != "synthetic-test-key" {
		t.Fatalf("key = %q, err = %v", key, err)
	}
	if err := os.WriteFile(path, []byte("api_key: \n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadCartoAPIKey(path); err == nil {
		t.Fatal("empty key accepted")
	}
	if err := os.WriteFile(path, []byte("api_key: [unterminated\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadCartoAPIKey(path); err == nil || strings.Contains(err.Error(), "unterminated") {
		t.Fatalf("YAML parse error leaked secret content: %v", err)
	}
}

func TestCartoGeomapSectionEscapesKey(t *testing.T) {
	const key = "synthetic&=key\n[security]"
	section, err := renderCartoGeomapSection(key)
	if err != nil {
		t.Fatal(err)
	}
	const prefix = "[geomap]\ndefault_baselayer_config = "
	if !strings.HasPrefix(section, prefix) || strings.Contains(section, "\n[security]") {
		t.Fatalf("invalid or injected geomap section: %q", section)
	}
	var baselayer struct {
		Type   string `json:"type"`
		Config struct {
			URL string `json:"url"`
		} `json:"config"`
	}
	if err := json.Unmarshal([]byte(strings.TrimPrefix(section, prefix)), &baselayer); err != nil {
		t.Fatal(err)
	}
	if baselayer.Type != "xyz" || !strings.HasSuffix(baselayer.Config.URL, "?key=synthetic%26%3Dkey%0A%5Bsecurity%5D") {
		t.Fatalf("unexpected baselayer: %+v", baselayer)
	}
	section, err = renderCartoGeomapSection("")
	if err != nil || section != "" {
		t.Fatalf("non-Main baselayer should be absent: %q, %v", section, err)
	}
}
