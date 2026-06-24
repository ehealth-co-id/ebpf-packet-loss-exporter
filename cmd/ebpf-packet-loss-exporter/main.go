package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/cilium/ebpf/ringbuf"
	"github.com/ehealth-id/ebpf-packet-loss-exporter/internal/bpf"
	"github.com/ehealth-id/ebpf-packet-loss-exporter/internal/config"
	"github.com/ehealth-id/ebpf-packet-loss-exporter/internal/metrics"
	"github.com/ehealth-id/ebpf-packet-loss-exporter/internal/tcattach"
)

type accumulator struct {
	mu   sync.Mutex
	segs map[string]uint64
	rets map[string]uint64
}

func newAccumulator(zones []config.ResolvedZone) *accumulator {
	acc := &accumulator{
		segs: make(map[string]uint64, len(zones)),
		rets: make(map[string]uint64, len(zones)),
	}
	for _, z := range zones {
		acc.segs[z.DstZone] = 0
		acc.rets[z.DstZone] = 0
	}
	return acc
}

func (acc *accumulator) record(dstZone string, isRetrans bool) {
	acc.mu.Lock()
	defer acc.mu.Unlock()
	acc.segs[dstZone]++
	if isRetrans {
		acc.rets[dstZone]++
	}
}

func (acc *accumulator) snapshotAndReset(zones []config.ResolvedZone) map[string]metrics.CounterSnapshot {
	acc.mu.Lock()
	defer acc.mu.Unlock()

	counters := make(map[string]metrics.CounterSnapshot, len(zones))
	for _, z := range zones {
		counters[z.DstZone] = metrics.CounterSnapshot{
			Segments: acc.segs[z.DstZone],
			Retrans:  acc.rets[z.DstZone],
		}
		acc.segs[z.DstZone] = 0
		acc.rets[z.DstZone] = 0
	}
	return counters
}

func buildZoneIndex(zones []config.ResolvedZone) map[uint8]string {
	out := make(map[uint8]string, len(zones))
	for _, z := range zones {
		out[z.ZoneID] = z.DstZone
	}
	return out
}

func parseStatsEvent(raw []byte) (bpf.StatsEvent, error) {
	var evt bpf.StatsEvent
	if len(raw) < binary.Size(&evt) {
		return evt, fmt.Errorf("short ringbuf sample: %d bytes", len(raw))
	}
	if err := binary.Read(bytes.NewReader(raw), binary.NativeEndian, &evt); err != nil {
		return evt, err
	}
	return evt, nil
}

func startRingbufReader(ctx context.Context, rd *ringbuf.Reader, zoneByID map[uint8]string, acc *accumulator) {
	go func() {
		for {
			rec, err := rd.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) || ctx.Err() != nil {
					return
				}
				log.Printf("ringbuf read: %v", err)
				continue
			}

			evt, err := parseStatsEvent(rec.RawSample)
			if err != nil {
				log.Printf("ringbuf parse: %v", err)
				continue
			}

			dstZone, ok := zoneByID[evt.DstZoneID]
			if !ok {
				continue
			}
			acc.record(dstZone, evt.IsRetrans != 0)
		}
	}()
}

func main() {
	configPath := flag.String("config", "/etc/ebpf_packet_loss_exporter/config.yml", "path to config file")
	listen := flag.String("listen", "", "listen address (overrides config)")
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	addr := cfg.Listen
	if *listen != "" {
		addr = *listen
	}

	zoneEntries, err := cfg.ZoneLPMEntries()
	if err != nil {
		log.Fatalf("zone entries: %v", err)
	}

	srcZoneEntries, err := cfg.SourceZoneLPMEntries()
	if err != nil {
		log.Fatalf("source zone entries: %v", err)
	}

	coll, err := bpf.Load(zoneEntries, srcZoneEntries)
	if err != nil {
		log.Fatalf("bpf load: %v", err)
	}
	defer coll.Close()

	ifaceNames, err := config.DiscoverTransitInterfaces(cfg.Interfaces.Ignore)
	if err != nil {
		log.Fatalf("interfaces: %v", err)
	}

	zones := cfg.RemoteZones()

	attachments, err := tcattach.AttachAll(ifaceNames, coll.Program(), coll)
	if err != nil {
		log.Fatalf("tc attach: %v", err)
	}
	defer func() {
		for _, a := range attachments {
			_ = a.Close()
		}
	}()

	log.Printf("attached TC egress on %v (auto-discovered)", ifaceNames)
	log.Printf("metrics reflect transit TCP from source_zone=%q to remote zones", cfg.SourceZone)
	for _, z := range zones {
		log.Printf("zone %s: zone_id=%d", z.DstZone, z.ZoneID)
	}

	rd, err := coll.NewRingbufReader()
	if err != nil {
		log.Fatalf("ringbuf reader: %v", err)
	}

	ema := metrics.NewEMAStore(cfg, zones)
	prom := metrics.NewExporter()
	acc := newAccumulator(zones)
	zoneByID := buildZoneIndex(zones)

	mux := http.NewServeMux()
	mux.Handle("/metrics", prom.Handler())
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	srv := &http.Server{Addr: addr, Handler: mux}
	go func() {
		log.Printf("listening on %s", addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("http: %v", err)
		}
	}()

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	startRingbufReader(ctx, rd, zoneByID, acc)

	ticker := time.NewTicker(cfg.PollInterval)
	defer ticker.Stop()

	publish := func() {
		counters := acc.snapshotAndReset(zones)
		ema.Update(time.Now(), counters)
		prom.Publish(ema.Snapshot())
	}

	publish()

	for {
		select {
		case <-ctx.Done():
			_ = rd.Close()
			shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer shutdownCancel()
			_ = srv.Shutdown(shutdownCtx)
			return
		case <-ticker.C:
			publish()
		}
	}
}
