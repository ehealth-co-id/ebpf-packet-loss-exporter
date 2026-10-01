// ebpf-packet-loss-exporter: TC egress eBPF TCP retransmit counter exported as
// per-zone loss percent. Logging contract (kept deliberately dense, same shape
// as pathprofiler):
//
//   - ONE summary line per tick body ("tick N: f=loss0.7%/ema0.5% c=idle
//     seg/ret=c:0/0 f:5818/71") is emitted only when its body changed, plus a
//     30-tick heartbeat. Per-tick seg/retrans volume rides along on emitted
//     lines but never triggers one.
//   - Conditions (no TCP seen, unzoned traffic, unknown-zone drops) live in the
//     body, so they log when they start or change, never once per poll.
//   - Per-zone per-poll counters are behind --verbose.
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
	unknown   atomic.Uint64 // events dropped for unknown zone_id; surfaced in the tick summary
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
						acc.unknown.Add(1)
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
	verbose := flag.Bool("verbose", false, "log per-zone per-poll counters")
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

	for _, name := range ifaceNames {
		if err := tcattach.CleanupEgress(name, coll.Program()); err != nil {
			log.Printf("cleanup stale filters on %q: %v", name, err)
		}
	}

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

	var (
		tick, lastSummaryTick uint64
		prevSummaryBody       string
		prevTCP, prevZoned    uint64
		zeroPolls             int
	)
	publish := func() {
		now := time.Now()
		tick++
		counters := acc.snapshotAndReset(zones)
		if *verbose {
			for dst, c := range counters {
				if c.Segments > 0 {
					log.Printf("[verbose] poll: zone %s segments=%d retrans=%d", dst, c.Segments, c.Retrans)
				}
			}
		}

		ema.Update(now, counters)
		snap := ema.Snapshot()
		prom.Publish(snap)

		tc := tickCounters{Tick: tick, Unknown: acc.unknown.Load()}
		var userSegs uint64
		for _, st := range snap {
			c := counters[st.DstZone]
			userSegs += c.Segments
			tc.Zones = append(tc.Zones, zoneTick{
				Zone: st.DstZone, Segments: c.Segments, Retrans: c.Retrans,
				Loss: st.InstantPercent, EMA: st.EMAPercent,
			})
		}
		if dbg, err := coll.ReadDebugCounters(); err == nil {
			tc.TCP, tc.Zoned = dbg.TCPPackets-prevTCP, dbg.TCPZoned-prevZoned
			prevTCP, prevZoned = dbg.TCPPackets, dbg.TCPZoned
			// The summary body flags "no-tcp"; this adds the bpf drop-reason
			// breakdown once on entry and every 60 ticks while it persists.
			if userSegs == 0 && tc.TCP == 0 {
				zeroPolls++
				if zeroPolls == 1 || zeroPolls%60 == 0 {
					log.Printf("no TCP segments; seen=%d not_ipv4=%d not_tcp=%d tcp_short=%d pure_ack=%d tcp=%d no_src_zone=%d no_dst_zone=%d zoned=%d",
						dbg.Seen, dbg.NotIPv4, dbg.NotTCP, dbg.TCPShort, dbg.TCPPureAck,
						dbg.TCPPackets, dbg.NoSrcZone, dbg.NoDstZone, dbg.TCPZoned)
				}
			} else {
				zeroPolls = 0
			}
		}
		emitTickSummary(&prevSummaryBody, &lastSummaryTick, tc)
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
