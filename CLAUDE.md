# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A Prometheus exporter that runs on a **transit gateway** (not application hosts) and passively
estimates TCP retransmit loss between "zones" (subnet groups) by attaching an eBPF program to TC
egress on transit interfaces (WireGuard, Ethernet). It complements
[network_exporter](https://github.com/syepes/network_exporter): this exporter covers inter-zone
transit loss (`:9435`), network_exporter covers per-host ICMP detail (`:9427`). See README.md for
config format, metrics, and PromQL usage.

## Build / test commands

Building requires **clang**, **llvm-strip**, and Linux BPF headers (see `.github/workflows/ci.yml`
for the exact `apt-get` package list and the `/usr/include/$(uname -m)-linux-gnu/asm` symlink
needed for the vmlinux/libbpf headers to resolve).

```bash
make generate   # regenerate internal/bpf/packetloss_bpf{el,eb}.go and .o from bpf/packet_loss.bpf.c
make build      # generate + go build -> ./ebpf_packet_loss_exporter
make test       # go test ./...
make clean      # remove binary and generated bpf2go output
GOOS=linux GOARCH=arm64 make cross   # cross-compile (also used for amd64 in CI/release)
```

Run a single test: `go test ./internal/metrics/ -run TestEMAUpdateAndHold -v`.

`make generate` must be re-run after any edit to `bpf/packet_loss.bpf.c` — the generated
`internal/bpf/packetloss_bpfel.go` / `packetloss_bpfeb.go` / `.o` files are committed but derived;
don't hand-edit them.

Most Go code (config parsing, EMA math, LPM key encoding) is portable and testable on any host.
Actually loading/attaching the eBPF program (`internal/bpf/load.go`, `internal/tcattach/`) requires
a Linux kernel with BPF support and typically root/CAP_BPF/CAP_NET_ADMIN — this only really runs at
runtime on the target gateway, not in most sandboxes.

## Architecture

**Data path (kernel side — `bpf/packet_loss.bpf.c`):** a single TC egress program (`path_egress`,
`SEC("tc")`) parses IPv4/TCP headers off every outgoing packet on the attached interfaces. It:

1. Skips non-IPv4, non-TCP, and pure-ACK packets (no payload, no SYN/FIN/RST).
2. Looks up `iph->saddr` in `src_zone_lpm` and `iph->daddr` in `zone_lpm` (both `BPF_MAP_TYPE_LPM_TRIE`,
   populated from config at startup). A packet only counts if both the source is in the configured
   `source_zone` and the destination matches some other configured zone.
3. Estimates retransmits with a custom 3-hash Bloom filter over `(saddr, daddr, sport, dport, seq)`,
   keyed on `seq >> 4` for data packets or raw `seq` for bare SYNs. The filter uses a double-buffered
   "generation" scheme (`bloom_epoch`, rolled every 1.5s) so old entries age out without ever clearing
   the whole table — this trades precision for O(1) eviction, so retransmit counts are approximate.
4. Emits one `stats_event{ifindex, dst_zone_id, is_retrans}` per classified packet into a `BPF_RINGBUF`
   (`stats_rb`), plus increments several `PERCPU_ARRAY` debug counters (`debug_seen`, `debug_not_ipv4`,
   `debug_tcp_zoned`, etc.) used for the "why are metrics zero" diagnostics logged by `main.go`.

**Data path (userspace — `cmd/ebpf-packet-loss-exporter/main.go`):** a single goroutine
(`startRingbufReader`) drains `stats_rb`, resolves `dst_zone_id` to an array index via
`buildZoneIndex`, and does lock-free atomic increments into an `accumulator` (one segment/retrans
counter pair per remote zone). The main loop, on a `poll_interval` ticker, atomically swaps and
resets those counters (`snapshotAndReset`), feeds the delta into `metrics.EMAStore.Update`, and
publishes to the Prometheus registry. If segment/retrans counts stay at zero, it logs the BPF debug
counters (via `Collection.ReadDebugCounters`) to narrow down which pipeline stage is dropping packets
(not IPv4 → not TCP → too short → pure ACK → no src/dst zone match).

**Zone model (`internal/config/config.go`):** `zones:` in config maps a zone name to a list of
CIDRs. Zone names are sorted and assigned deterministic `uint8` IDs (1..N) at load time
(`assignZoneIDs`) — this ordering must stay consistent between the LPM trie values written into the
BPF maps and the `dst_zone_id` byte read back out of ring buffer events, since it's how the kernel
and userspace agree on zone identity without exchanging strings. `source_zone` must be one of the
configured zones; every other zone is a "remote" zone that gets its own metric label pair.

**Metrics smoothing (`internal/metrics/ema.go`):** two numbers are tracked per remote zone: an
"instant" loss % computed over a fixed-size ring buffer of the last `instant_window / poll_interval`
poll deltas, and an EMA (`ebpf_packet_loss_percent_ema`, the primary dashboard series) with
`alpha = 1 - e^(-dt/half_life)` so smoothing self-adjusts to variable poll intervals. When a zone
sees zero segments in a poll, both values are deliberately held rather than decayed toward zero or
reset, so a quiet zone doesn't create a false "loss dropped to 0%" signal — see the `NOTE` in
`internal/metrics/exporter.go` about why `Publish` never calls `Reset()` on the gauge vectors either
(same reasoning: avoids metric flapping/disappearing for silent zone pairs).

**TC attachment (`internal/tcattach/attach.go`):** attaches via clsact + a direct-action BPF filter
(`attachClsActEgress`) rather than the newer TCX API — see the `use clsact` commit; `attachTCXEgress`
exists but is currently unused/dead code from that migration. Before attaching, `CleanupEgress` scans
for and removes filters/links left behind by a crashed or SIGKILLed previous instance, matching by
program name prefix (`path_egress` / `transit_egress`, truncated to 15 chars by the kernel) since
stale attachments would otherwise double-count packets or hold a stale program FD.

**Interface selection (`internal/config/interfaces.go`):** if `interfaces:` is omitted, transit
interfaces are auto-discovered as "up" interfaces that are WireGuard (has a
`/sys/class/net/<name>/wireguard` dir) or Ethernet (`ARPHRD_ETHER` type), excluding a built-in
denylist of virtual interface name patterns (`lo`, `docker0`, `veth*`, `cni*`, `calico*`, etc.) in
`defaultIgnorePatterns`.

## Release / install

`scripts/install.sh` downloads a prebuilt binary from GitHub Releases (arch-matched
`ebpf_packet_loss_exporter-linux-{amd64,arm64}`, built by `.github/workflows/release.yml` on `v*`
tags) and installs a systemd unit granting `CAP_BPF CAP_NET_ADMIN CAP_SYS_ADMIN`. It never touches
network_exporter and refuses to start the service if `/etc/ebpf_packet_loss_exporter/config.yml` is
missing.
