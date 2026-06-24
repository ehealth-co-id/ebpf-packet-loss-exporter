package metrics

import (
	"testing"
	"time"

	"github.com/ehealth-id/ebpf-packet-loss-exporter/internal/config"
)

func zoneByDst(states []ZoneState, dstZone string) (ZoneState, bool) {
	for _, st := range states {
		if st.DstZone == dstZone {
			return st, true
		}
	}
	return ZoneState{}, false
}

func testZones() []config.ResolvedZone {
	return []config.ResolvedZone{{
		DstZone:    "f",
		ZoneID:     4,
		SourceZone: "e",
	}}
}

func TestEMAUpdateAndHold(t *testing.T) {
	cfg := &config.Config{
		PollInterval: 15 * time.Second,
		EMAHalfLife: 5 * time.Minute,
	}
	store := NewEMAStore(cfg, testZones())
	now := time.Now()

	store.Update(now, map[string]CounterSnapshot{
		"f": {Segments: 100, Retrans: 10},
	})
	snap := store.Snapshot()
	if len(snap) != 1 {
		t.Fatalf("expected 1 snapshot, got %d", len(snap))
	}
	st, ok := zoneByDst(snap, "f")
	if !ok {
		t.Fatal("zone f not found")
	}
	if st.InstantPercent != 10.0 {
		t.Fatalf("instant = %f, want 10", st.InstantPercent)
	}
	if st.EMAPercent != 10.0 {
		t.Fatalf("ema = %f, want 10 on first sample", st.EMAPercent)
	}

	// No new segments: hold EMA.
	store.Update(now.Add(15*time.Second), map[string]CounterSnapshot{
		"f": {Segments: 0, Retrans: 0},
	})
	snap = store.Snapshot()
	st, _ = zoneByDst(snap, "f")
	if st.EMAPercent != 10.0 {
		t.Fatalf("ema should hold at 10, got %f", st.EMAPercent)
	}

	// More traffic with 20% loss.
	store.Update(now.Add(30*time.Second), map[string]CounterSnapshot{
		"f": {Segments: 100, Retrans: 20},
	})
	snap = store.Snapshot()
	st, _ = zoneByDst(snap, "f")
	if st.InstantPercent != 20.0 {
		t.Fatalf("instant = %f, want 20", st.InstantPercent)
	}
	if st.EMAPercent <= 10.0 || st.EMAPercent >= 20.0 {
		t.Fatalf("ema should be between 10 and 20, got %f", st.EMAPercent)
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
		EMAHalfLife: 5 * time.Minute,
	}
	store := NewEMAStore(cfg, testZones())
	now := time.Now()

	store.Update(now, map[string]CounterSnapshot{
		"f": {Segments: 10, Retrans: 1},
	})
	snap := store.Snapshot()
	st, _ := zoneByDst(snap, "f")
	if st.InstantPercent != 10.0 {
		t.Fatalf("instant = %f, want 10", st.InstantPercent)
	}

	store.Update(now.Add(1*time.Second), map[string]CounterSnapshot{
		"f": {Segments: 10, Retrans: 0},
	})
	snap = store.Snapshot()
	st, _ = zoneByDst(snap, "f")
	if st.InstantPercent != 5.0 {
		t.Fatalf("instant = %f, want 5", st.InstantPercent)
	}

	store.Update(now.Add(2*time.Second), map[string]CounterSnapshot{
		"f": {Segments: 10, Retrans: 2},
	})
	snap = store.Snapshot()
	st, _ = zoneByDst(snap, "f")
	if st.InstantPercent != 10.0 {
		t.Fatalf("instant = %f, want 10", st.InstantPercent)
	}

	// Evict first sample (10/1); window: 10/0 + 10/2 + 10/0 = 30 seg / 2 ret
	store.Update(now.Add(3*time.Second), map[string]CounterSnapshot{
		"f": {Segments: 10, Retrans: 0},
	})
	snap = store.Snapshot()
	st, _ = zoneByDst(snap, "f")
	want := 100.0 * 2.0 / 30.0
	if st.InstantPercent != want {
		t.Fatalf("instant = %f, want %f", st.InstantPercent, want)
	}
}
