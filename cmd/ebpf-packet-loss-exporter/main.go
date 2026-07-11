package main

import (
	"context"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/cilium/ebpf/ringbuf"
	"github.com/ehealth-id/ebpf-packet-loss-exporter/internal/bpf"
	"github.com/ehealth-id/ebpf-packet-loss-exporter/internal/config"
	"github.com/ehealth-id/ebpf-packet-loss-exporter/internal/metrics"
	"github.com/ehealth-id/ebpf-packet-loss-exporter/internal/tcattach"
)

const statsEventSize = 8 // mirrors struct stats_event in bpf/packet_loss.bpf.c

type accumulator struct {
	segs      []uint64
	rets      []uint64
	zoneNames []string
}

func newAccumulator(zones []config.ResolvedZone) *accumulator {
	n := len(zones)
	acc := &accumulator{
		segs:      make([]uint64, n),
		rets:      make([]uint64, n),
		zoneNames: make([]string, n),
	}
	for i, z := range zones {
		acc.zoneNames[i] = z.DstZone
	}
	return acc
}

func (acc *accumulator) record(idx int, isRetrans bool) {
	atomic.AddUint64(&acc.segs[idx], 1)
	if isRetrans {
		atomic.AddUint64(&acc.rets[idx], 1)
	}
}

func (acc *accumulator) snapshotAndReset(_ []config.ResolvedZone) map[string]metrics.CounterSnapshot {
	counters := make(map[string]metrics.CounterSnapshot, len(acc.zoneNames))
	for i, name := range acc.zoneNames {
		segs := atomic.SwapUint64(&acc.segs[i], 0)
		rets := atomic.SwapUint64(&acc.rets[i], 0)
		counters[name] = metrics.CounterSnapshot{
			Segments: segs,
			Retrans:  rets,
		}
	}
	return counters
}

func buildZoneIndex(zones []config.ResolvedZone) map[uint8]int {
	out := make(map[uint8]int, len(zones))
	for i, z := range zones {
		out[z.ZoneID] = i
	}
	return out
}

func parseStatsEvent(raw []byte) (bpf.StatsEvent, error) {
	if len(raw) < statsEventSize {
		return bpf.StatsEvent{}, fmt.Errorf("short ringbuf sample: %d bytes", len(raw))
	}
	return bpf.StatsEvent{
		IfIndex:   binary.NativeEndian.Uint32(raw[0:4]),
		DstZoneID: raw[4],
		IsRetrans: raw[5],
		// Pad intentionally ignored
	}, nil
}

func startRingbufReader(ctx context.Context, rd *ringbuf.Reader, zoneByID map[uint8]int, acc *accumulator) {
	go func() {
		var unknownZone uint64
		var rec ringbuf.Record
		for {
			err := rd.ReadInto(&rec)
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) || ctx.Err() != nil {
					return
				}
				log.Printf("ringbuf read: %v", err)
				continue
			}
			// Process the first record from the blocking read, then drain all
			// remaining records without additional syscall round-trips.
			for {
				evt, evtErr := parseStatsEvent(rec.RawSample)
				if evtErr != nil {
					log.Printf("ringbuf parse: %v", evtErr)
				} else {
					idx, ok := zoneByID[evt.DstZoneID]
					if !ok {
						unknownZone++
						if unknownZone == 1 || unknownZone%1000 == 0 {
							log.Printf("ringbuf: unknown dst_zone_id=%d (ifindex=%d), dropped %d events so far",
								evt.DstZoneID, evt.IfIndex, unknownZone)
						}
					} else {
						acc.record(idx, evt.IsRetrans != 0)
					}
				}

				// Try to drain the next record without blocking.
				rd.SetDeadline(time.Now())
				err = rd.ReadInto(&rec)
				if err != nil {
					if errors.Is(err, os.ErrDeadlineExceeded) {
						// All buffered records consumed; prepare to block on the
						// next iteration.
						rd.SetDeadline(time.Time{})
						break
					}
					if errors.Is(err, ringbuf.ErrClosed) || ctx.Err() != nil {
						return
					}
					log.Printf("ringbuf read: %v", err)
					rd.SetDeadline(time.Time{})
					break
				}
				// rec has been populated; loop to process it.
			}
		}
	}()
}

func main() {
	configPath := flag.String("config", "/etc/ebpf_packet_loss_exporter/config.yml", "path to config file")
	listen := flag.String("listen", "", "listen address (overrides config)")
	pprofAddr := flag.String("pprof", "", "pprof listen address (e.g. localhost:6060)")
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

	ifaceNames, err := cfg.TransitInterfaceNames()
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

	log.Printf("attached TC egress on %v", ifaceNames)
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

	if *pprofAddr != "" {
		go func() {
			log.Printf("pprof listening on %s", *pprofAddr)
			if err := http.ListenAndServe(*pprofAddr, nil); err != nil {
				log.Printf("pprof server: %v", err)
			}
		}()
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	startRingbufReader(ctx, rd, zoneByID, acc)

	ticker := time.NewTicker(cfg.PollInterval)
	defer ticker.Stop()

	var zeroPolls int
	publish := func() {
		counters := acc.snapshotAndReset(zones)
		var userSegs uint64
		for dst, c := range counters {
			userSegs += c.Segments
			if c.Segments > 0 {
				log.Printf("poll: zone %s segments=%d retrans=%d", dst, c.Segments, c.Retrans)
			}
		}
		if dbg, err := coll.ReadDebugCounters(); err == nil {
			if userSegs == 0 && dbg.TCPPackets == 0 {
				zeroPolls++
				if zeroPolls == 1 || zeroPolls%60 == 0 {
					log.Printf("poll: no TCP segments yet (bpf tcp=%d zoned=%d); check interfaces, subnets, and inter-zone traffic",
						dbg.TCPPackets, dbg.TCPZoned)
				}
			} else if userSegs == 0 && dbg.TCPZoned > 0 {
				log.Printf("poll: bpf zoned=%d but userspace=0; check zone_id mapping (bpf zoned tcp=%d)",
					dbg.TCPZoned, dbg.TCPPackets)
			} else if dbg.TCPPackets > 0 && dbg.TCPZoned == 0 {
				log.Printf("poll: bpf tcp=%d but zoned=0; check source_zone and dst_zone subnets",
					dbg.TCPPackets)
			} else {
				zeroPolls = 0
			}
		}

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
