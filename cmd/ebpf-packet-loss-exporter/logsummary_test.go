package main

import (
	"log"
	"os"
	"strings"
	"testing"
)

func sampleTick(tick uint64) tickCounters {
	return tickCounters{
		Tick: tick,
		Zones: []zoneTick{
			{Zone: "f", Segments: 5818, Retrans: 71, Loss: 0.66, EMA: 0.5},
			{Zone: "c"},
		},
		TCP: 5818, Zoned: 5818,
	}
}

func TestFormatTickSummary(t *testing.T) {
	body, vol := formatTickSummary(sampleTick(1))
	for _, want := range []string{"c=idle", "f=loss0.7%/ema0.5%"} {
		if !strings.Contains(body, want) {
			t.Errorf("body missing %q: %q", want, body)
		}
	}
	if vol != "c:0/0 f:5818/71" {
		t.Errorf("volume = %q", vol)
	}
	if strings.Contains(body, "warn") {
		t.Errorf("unexpected warn: %q", body)
	}

	c := sampleTick(2)
	c.TCP, c.Zoned = 10, 0
	if b, _ := formatTickSummary(c); !strings.Contains(b, "warn=unzoned") {
		t.Errorf("want unzoned warn: %q", b)
	}
	c.TCP = 0
	c.Unknown = 3
	b, _ := formatTickSummary(c)
	if !strings.Contains(b, "warn=no-tcp") || !strings.Contains(b, "unknown_zone_drops=3") {
		t.Errorf("want no-tcp + drops: %q", b)
	}
}

func TestVolumeDoesNotChangeBody(t *testing.T) {
	a := sampleTick(1)
	b := sampleTick(2)
	b.Zones[0].Segments, b.Zones[0].Retrans = 4000, 1
	ba, _ := formatTickSummary(a)
	bb, _ := formatTickSummary(b)
	if ba != bb {
		t.Errorf("bodies differ: %q vs %q", ba, bb)
	}
}

func TestEmitTickSummary_ChangeOnlyWithHeartbeat(t *testing.T) {
	var buf strings.Builder
	log.SetOutput(&buf)
	log.SetFlags(0)
	defer log.SetOutput(os.Stderr)

	var prev string
	var last uint64
	emitTickSummary(&prev, &last, sampleTick(1)) // first: emits
	emitTickSummary(&prev, &last, sampleTick(2)) // same body: silent
	emitTickSummary(&prev, &last, sampleTick(3)) // same body: silent
	if n := strings.Count(buf.String(), "\n"); n != 1 {
		t.Fatalf("want 1 line, got %d: %q", n, buf.String())
	}
	emitTickSummary(&prev, &last, sampleTick(1+summaryHeartbeatTicks)) // heartbeat
	c := sampleTick(40)
	c.Zones[0].Loss = 3.0 // body changed
	emitTickSummary(&prev, &last, c)
	if n := strings.Count(buf.String(), "\n"); n != 3 {
		t.Fatalf("want 3 lines, got %d: %q", n, buf.String())
	}
}
