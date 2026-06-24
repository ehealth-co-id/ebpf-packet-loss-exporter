package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
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

type targetKey struct {
	ifIndex int
	zoneID  uint8
}

type accumulator struct {
	mu   sync.Mutex
	segs map[string]uint64
	rets map[string]uint64
}

func newAccumulator(targets []config.ResolvedTarget) *accumulator {
	acc := &accumulator{
		segs: make(map[string]uint64, len(targets)),
		rets: make(map[string]uint64, len(targets)),
	}
	for _, t := range targets {
		acc.segs[t.Name] = 0
		acc.rets[t.Name] = 0
	}
	return acc
}

func (acc *accumulator) record(name string, isRetrans bool) {
	acc.mu.Lock()
	defer acc.mu.Unlock()
	acc.segs[name]++
	if isRetrans {
		acc.rets[name]++
	}
}

func (acc *accumulator) snapshotAndReset(targets []config.ResolvedTarget) map[string]metrics.CounterSnapshot {
	acc.mu.Lock()
	defer acc.mu.Unlock()

	counters := make(map[string]metrics.CounterSnapshot, len(targets))
	for _, t := range targets {
		counters[t.Name] = metrics.CounterSnapshot{
			Segments: acc.segs[t.Name],
			Retrans:  acc.rets[t.Name],
		}
		acc.segs[t.Name] = 0
		acc.rets[t.Name] = 0
	}
	return counters
}

func buildTargetIndex(targets []config.ResolvedTarget) map[targetKey]string {
	out := make(map[targetKey]string, len(targets))
	for _, t := range targets {
		out[targetKey{ifIndex: t.IfIndex, zoneID: t.ZoneID}] = t.Name
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

func startRingbufReader(ctx context.Context, rd *ringbuf.Reader, targetByKey map[targetKey]string, acc *accumulator) {
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

			name, ok := targetByKey[targetKey{ifIndex: int(evt.IfIndex), zoneID: evt.DstZoneID}]
			if !ok {
				continue
			}
			acc.record(name, evt.IsRetrans != 0)
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

	ifIndexByName, err := resolveInterfaces(cfg)
	if err != nil {
		log.Fatalf("interfaces: %v", err)
	}

	targets, err := cfg.ResolveTargets(ifIndexByName)
	if err != nil {
		log.Fatalf("targets: %v", err)
	}

	ifaceNames := cfg.InterfaceNames()
	attachments, err := tcattach.AttachAll(ifaceNames, coll.Program(), coll)
	if err != nil {
		log.Fatalf("tc attach: %v", err)
	}
	defer func() {
		for _, a := range attachments {
			_ = a.Close()
		}
	}()

	log.Printf("attached TC egress on %v", ifaceNames)
	log.Printf("metrics reflect transit TCP from source_zone=%q to remote zones; attach only on listed path interfaces", cfg.SourceZone)
	for _, t := range targets {
		log.Printf("target %s: ifindex=%d zone_id=%d path=%s dst_zone=%s",
			t.Name, t.IfIndex, t.ZoneID, t.Path, t.DstZone)
	}

	rd, err := coll.NewRingbufReader()
	if err != nil {
		log.Fatalf("ringbuf reader: %v", err)
	}

	ema := metrics.NewEMAStore(cfg, targets)
	prom := metrics.NewExporter()
	acc := newAccumulator(targets)
	targetByKey := buildTargetIndex(targets)

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

	startRingbufReader(ctx, rd, targetByKey, acc)

	ticker := time.NewTicker(cfg.PollInterval)
	defer ticker.Stop()

	publish := func() {
		counters := acc.snapshotAndReset(targets)
		ema.Update(time.Now(), counters)
		prom.Publish(ema.Snapshot())
		if dbg, err := coll.ReadDebugCounters(); err == nil {
			prom.PublishDebug(dbg.TCPPackets, dbg.TCPZoned)
		}
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

func resolveInterfaces(cfg *config.Config) (map[string]int, error) {
	out := make(map[string]int)
	for _, name := range cfg.InterfaceNames() {
		if cfg.ShouldIgnore(name) {
			return nil, fmt.Errorf("interface %q is configured for monitoring and listed in ignore", name)
		}
		iface, err := net.InterfaceByName(name)
		if err != nil {
			return nil, fmt.Errorf("lookup %q: %w", name, err)
		}
		out[name] = iface.Index
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no transit interfaces configured")
	}
	return out, nil
}
