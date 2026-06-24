package metrics

import (
	"testing"
	"time"

	"github.com/ehealth-id/ebpf-packet-loss-exporter/internal/config"
)

func TestEMAUpdateAndHold(t *testing.T) {
	cfg := &config.Config{
		PollInterval: 15 * time.Second,
		EMA: config.EMAConfig{
			HalfLife: 5 * time.Minute,
		},
	}
	targets := []config.ResolvedTarget{{
		Name:       "f-ehealth-id-l2",
		DstZone:    "f",
		Path:       "l2",
		ZoneID:     4,
		IfIndex:    22,
		SourceZone: "e",
	}}
	store := NewEMAStore(cfg, targets)
	now := time.Now()

	store.Update(now, map[string]CounterSnapshot{
		"f-ehealth-id-l2": {Segments: 100, Retrans: 10},
	})
	snap := store.Snapshot()
	if len(snap) != 1 {
		t.Fatalf("expected 1 snapshot, got %d", len(snap))
	}
	if snap[0].InstantPercent != 10.0 {
		t.Fatalf("instant = %f, want 10", snap[0].InstantPercent)
	}
	if snap[0].EMAPercent != 10.0 {
		t.Fatalf("ema = %f, want 10 on first sample", snap[0].EMAPercent)
	}

	// No new segments: hold EMA.
	store.Update(now.Add(15*time.Second), map[string]CounterSnapshot{
		"f-ehealth-id-l2": {Segments: 100, Retrans: 10},
	})
	snap = store.Snapshot()
	if snap[0].EMAPercent != 10.0 {
		t.Fatalf("ema should hold at 10, got %f", snap[0].EMAPercent)
	}

	// More traffic with 20% loss.
	store.Update(now.Add(30*time.Second), map[string]CounterSnapshot{
		"f-ehealth-id-l2": {Segments: 200, Retrans: 30},
	})
	snap = store.Snapshot()
	if snap[0].InstantPercent != 20.0 {
		t.Fatalf("instant = %f, want 20", snap[0].InstantPercent)
	}
	if snap[0].EMAPercent <= 10.0 || snap[0].EMAPercent >= 20.0 {
		t.Fatalf("ema should be between 10 and 20, got %f", snap[0].EMAPercent)
	}
}

func TestAlphaFromHalfLife(t *testing.T) {
	alpha := AlphaFromHalfLife(15*time.Second, 5*time.Minute)
	if alpha <= 0 || alpha >= 1 {
		t.Fatalf("alpha = %f", alpha)
	}
}

func TestInstantPercentSlidingWindow(t *testing.T) {
	cfg := &config.Config{
		PollInterval:  1 * time.Second,
		InstantWindow: 3 * time.Second,
		EMA: config.EMAConfig{
			HalfLife: 5 * time.Minute,
		},
	}
	targets := []config.ResolvedTarget{{
		Name:       "f-ehealth-id-wireguard",
		DstZone:    "f",
		Path:       "wireguard",
		ZoneID:     4,
		IfIndex:    11,
		SourceZone: "e",
	}}
	store := NewEMAStore(cfg, targets)
	now := time.Now()

	// Window: 10 seg / 1 ret = 10%
	store.Update(now, map[string]CounterSnapshot{
		"f-ehealth-id-wireguard": {Segments: 10, Retrans: 1},
	})
	snap := store.Snapshot()
	if snap[0].InstantPercent != 10.0 {
		t.Fatalf("instant = %f, want 10", snap[0].InstantPercent)
	}

	// Window: 20 seg / 1 ret = 5%
	store.Update(now.Add(1*time.Second), map[string]CounterSnapshot{
		"f-ehealth-id-wireguard": {Segments: 20, Retrans: 1},
	})
	snap = store.Snapshot()
	if snap[0].InstantPercent != 5.0 {
		t.Fatalf("instant = %f, want 5", snap[0].InstantPercent)
	}

	// Window: 30 seg / 3 ret = 10%
	store.Update(now.Add(2*time.Second), map[string]CounterSnapshot{
		"f-ehealth-id-wireguard": {Segments: 30, Retrans: 3},
	})
	snap = store.Snapshot()
	if snap[0].InstantPercent != 10.0 {
		t.Fatalf("instant = %f, want 10", snap[0].InstantPercent)
	}

	// Evict first sample (10/1); window: 10/0 + 10/2 + 10/0 = 30 seg / 2 ret
	store.Update(now.Add(3*time.Second), map[string]CounterSnapshot{
		"f-ehealth-id-wireguard": {Segments: 40, Retrans: 3},
	})
	snap = store.Snapshot()
	want := 100.0 * 2.0 / 30.0
	if snap[0].InstantPercent != want {
		t.Fatalf("instant = %f, want %f", snap[0].InstantPercent, want)
	}
}
