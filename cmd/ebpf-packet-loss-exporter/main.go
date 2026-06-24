package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os/signal"
	"syscall"
	"time"

	"github.com/ehealth-id/ebpf-packet-loss-exporter/internal/bpf"
	"github.com/ehealth-id/ebpf-packet-loss-exporter/internal/config"
	"github.com/ehealth-id/ebpf-packet-loss-exporter/internal/metrics"
	"github.com/ehealth-id/ebpf-packet-loss-exporter/internal/tcattach"
)

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

	coll, err := bpf.Load(zoneEntries)
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

	ema := metrics.NewEMAStore(cfg, targets)
	prom := metrics.NewExporter()

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

	ticker := time.NewTicker(cfg.PollInterval)
	defer ticker.Stop()

	poll := func() {
		counters := make(map[string]metrics.CounterSnapshot, len(targets))
		for _, t := range targets {
			seg, ret, err := coll.ReadCounters(t)
			if err != nil {
				log.Printf("read counters for %s: %v", t.Name, err)
				continue
			}
			counters[t.Name] = metrics.CounterSnapshot{
				Segments: seg,
				Retrans:  ret,
			}
		}
		ema.Update(time.Now(), counters)
		prom.Publish(ema.Snapshot())
	}

	poll()

	for {
		select {
		case <-ctx.Done():
			shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer shutdownCancel()
			_ = srv.Shutdown(shutdownCtx)
			return
		case <-ticker.C:
			poll()
		}
	}
}

func resolveInterfaces(cfg *config.Config) (map[string]int, error) {
	out := make(map[string]int)
	for _, name := range cfg.InterfaceNames() {
		if cfg.ShouldIgnore(name) {
			continue
		}
		iface, err := net.InterfaceByName(name)
		if err != nil {
			return nil, fmt.Errorf("lookup %q: %w", name, err)
		}
		out[name] = iface.Index
	}
	return out, nil
}
