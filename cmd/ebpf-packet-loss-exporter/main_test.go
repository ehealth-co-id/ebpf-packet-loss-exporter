package main

import (
	"encoding/binary"
	"fmt"
	"math/rand"
	"testing"

	"github.com/ehealth-id/ebpf-packet-loss-exporter/internal/config"
)

// BenchmarkParseStatsEvent measures the direct binary read approach (Step 2).
// Compare against the old bytes.Reader approach by running before the change.
func BenchmarkParseStatsEvent(b *testing.B) {
	raw := make([]byte, 8)
	binary.NativeEndian.PutUint32(raw[0:4], 42)
	raw[4] = 7
	raw[5] = 1
	raw[6] = 0
	raw[7] = 0

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		evt, err := parseStatsEvent(raw)
		if err != nil {
			b.Fatal(err)
		}
		if evt.IfIndex != 42 || evt.DstZoneID != 7 || evt.IsRetrans != 1 {
			b.Fatal("unexpected values")
		}
	}
}

// BenchmarkAccumulatorRecord measures the atomic-based record (Step 3).
func BenchmarkAccumulatorRecord(b *testing.B) {
	nZones := 10
	zones := make([]config.ResolvedZone, nZones)
	for i := range zones {
		zones[i] = config.ResolvedZone{
			DstZone:    fmt.Sprintf("zone-%d", i),
			ZoneID:     uint8(i + 1),
			SourceZone: "src",
		}
	}

	acc := newAccumulator(zones)

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		acc.record(i%nZones, i%3 == 0)
	}
}

// BenchmarkAccumulatorSnapshotAndReset measures the atomic-swap snapshot (Step 3).
func BenchmarkAccumulatorSnapshotAndReset(b *testing.B) {
	nZones := 10
	zones := make([]config.ResolvedZone, nZones)
	for i := range zones {
		zones[i] = config.ResolvedZone{
			DstZone:    fmt.Sprintf("zone-%d", i),
			ZoneID:     uint8(i + 1),
			SourceZone: "src",
		}
	}

	acc := newAccumulator(zones)

	b.ResetTimer()
	b.StopTimer()

	for i := 0; i < b.N; i++ {
		// Pre-fill some counters to make it realistic.
		for j := range zones {
			acc.segs[j] = uint64(rand.Int63() % 1000)
			acc.rets[j] = uint64(rand.Int63() % 100)
		}
		b.StartTimer()
		_ = acc.snapshotAndReset(zones)
		b.StopTimer()
	}
}