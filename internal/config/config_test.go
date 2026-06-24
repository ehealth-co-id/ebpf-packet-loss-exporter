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

interfaces:
  wireguard: [wg0]
  l2: [ens21]
  ignore: [lo, docker0, br-*]

zones:
  c:
    id: 1
    subnets: [192.168.0.0/24]
  d:
    id: 2
    subnets: [192.168.1.0/24]
  e:
    id: 3
    subnets: [192.168.3.0/24, 192.168.4.0/24]
  f:
    id: 4
    subnets: [192.168.5.0/24, 192.168.6.0/24]

targets:
  - name: c-ehealth-id-wireguard
    dst_zone: c
    path: wireguard
  - name: f-ehealth-id-l2
    dst_zone: f
    path: l2

ema:
  half_life: 5m
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

	alpha := cfg.Alpha(15 * time.Second)
	if alpha <= 0 || alpha >= 1 {
		t.Fatalf("alpha out of range: %f", alpha)
	}
}

func TestResolveTargets(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yml")
	if err := os.WriteFile(path, []byte(sampleConfig), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}

	targets, err := cfg.ResolveTargets(map[string]int{"wg0": 11, "ens21": 22})
	if err != nil {
		t.Fatalf("ResolveTargets: %v", err)
	}
	if len(targets) != 2 {
		t.Fatalf("expected 2 targets, got %d", len(targets))
	}
	if targets[0].IfIndex != 11 || targets[1].IfIndex != 22 {
		t.Fatalf("unexpected ifindexes: %+v", targets)
	}
}
