package metrics

import (
	"testing"
	"time"

	"github.com/ehealth-id/ebpf-packet-loss-exporter/internal/config"
)

// BenchmarkExporterPublish measures the Publish method.
func BenchmarkExporterPublish(b *testing.B) {
	zones := []config.ResolvedZone{
		{DstZone: "zone-a", ZoneID: 1, SourceZone: "src"},
		{DstZone: "zone-b", ZoneID: 2, SourceZone: "src"},
		{DstZone: "zone-c", ZoneID: 3, SourceZone: "src"},
		{DstZone: "zone-d", ZoneID: 4, SourceZone: "src"},
		{DstZone: "zone-e", ZoneID: 5, SourceZone: "src"},
		{DstZone: "zone-f", ZoneID: 6, SourceZone: "src"},
		{DstZone: "zone-g", ZoneID: 7, SourceZone: "src"},
		{DstZone: "zone-h", ZoneID: 8, SourceZone: "src"},
		{DstZone: "zone-i", ZoneID: 9, SourceZone: "src"},
		{DstZone: "zone-j", ZoneID: 10, SourceZone: "src"},
	}

	cfg := &config.Config{
		PollInterval:  1 * time.Second,
		InstantWindow: 10 * time.Second,
		EMAHalfLife:   5 * time.Minute,
	}
	store := NewEMAStore(cfg, zones)
	prom := NewExporter()

	// Seed the store with some data so Publish has real work to do.
	now := time.Now()
	for i := 0; i < 5; i++ {
		counters := make(map[string]CounterSnapshot, len(zones))
		for _, z := range zones {
			counters[z.DstZone] = CounterSnapshot{Segments: 1000, Retrans: uint64(i * 10)}
		}
		store.Update(now.Add(time.Duration(i)*cfg.PollInterval), counters)
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		prom.Publish(store.Snapshot())
	}
}
