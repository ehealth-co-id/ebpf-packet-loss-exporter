package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

const sampleConfig = `
source_zone: e
listen: :9435
poll_interval: 15s

zones:
  c: [192.168.0.0/24]
  d: [192.168.1.0/24]
  e: [192.168.3.0/24, 192.168.4.0/24]
  f: [192.168.5.0/24, 192.168.6.0/24]

ema_half_life: 5m
`

func TestLoadAndValidate(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yml")
	if err := os.WriteFile(path, []byte(sampleConfig), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if cfg.SourceZone != "e" {
		t.Fatalf("source_zone = %q", cfg.SourceZone)
	}
	if cfg.PollInterval != 15*time.Second {
		t.Fatalf("poll_interval = %v", cfg.PollInterval)
	}

	entries, err := cfg.ZoneLPMEntries()
	if err != nil {
		t.Fatalf("ZoneLPMEntries: %v", err)
	}
	if len(entries) != 4 {
		t.Fatalf("expected 4 remote zone entries, got %d", len(entries))
	}

	srcEntries, err := cfg.SourceZoneLPMEntries()
	if err != nil {
		t.Fatalf("SourceZoneLPMEntries: %v", err)
	}
	if len(srcEntries) != 2 {
		t.Fatalf("expected 2 source zone entries, got %d", len(srcEntries))
	}

	zones := cfg.RemoteZones()
	if len(zones) != 3 {
		t.Fatalf("expected 3 remote zones, got %d", len(zones))
	}

	alpha := cfg.Alpha(15 * time.Second)
	if alpha <= 0 || alpha >= 1 {
		t.Fatalf("alpha out of range: %f", alpha)
	}
}

func TestAutoZoneIDs(t *testing.T) {
	cfg := &Config{
		SourceZone:   "e",
		PollInterval: time.Second,
		EMAHalfLife:  5 * time.Minute,
		Zones: map[string][]string{
			"f": {"192.168.5.0/24"},
			"c": {"192.168.0.0/24"},
			"e": {"192.168.3.0/24"},
		},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}

	want := map[string]uint8{"c": 1, "e": 2, "f": 3}
	for name, wantID := range want {
		got, ok := cfg.ZoneID(name)
		if !ok {
			t.Fatalf("zone %q has no id", name)
		}
		if got != wantID {
			t.Fatalf("zone %q id = %d, want %d", name, got, wantID)
		}
	}
}

func TestShouldIgnore(t *testing.T) {
	patterns := []string{"lo", "br-*", "veth123"}
	if !ShouldIgnore("lo", patterns) {
		t.Fatal("lo should be ignored")
	}
	if !ShouldIgnore("br-abc", patterns) {
		t.Fatal("br-abc should be ignored")
	}
	if !ShouldIgnore("veth123", patterns) {
		t.Fatal("veth123 should be ignored")
	}
	if ShouldIgnore("ens21", patterns) {
		t.Fatal("ens21 should not be ignored")
	}
}
