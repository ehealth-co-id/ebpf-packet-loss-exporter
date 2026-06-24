# ebpf-packet-loss-exporter

Passive eBPF TCP retransmit monitoring for **wireguard** and **l2** inter-zone paths. Complements [network_exporter](https://github.com/syepes/network_exporter) — active ICMP `direct` probes stay on network_exporter (`:9427`).

## Scope

| Path | Tool | Method | Port |
|---|---|---|---|
| `wireguard` | ebpf-packet-loss-exporter | Passive TCP retransmit ratio | `:9435` |
| `l2` | ebpf-packet-loss-exporter | Passive TCP retransmit ratio | `:9435` |
| `direct` | network_exporter (unchanged) | Active ICMP | `:9427` |

TC egress attaches only on configured wireguard and l2 interfaces on the **transit gateway**. No WAN attachment, no ICMP parsing.

## Gateway deployment

This exporter runs on the **transit gateway** that forwards inter-zone traffic (WireGuard mesh, L2 links). It does **not** run on application hosts.

- **Hook**: TC egress on configured path interfaces (`wg0`, `ens21`, …). Kernel `tcp_retransmit_skb` tracepoints are not used because they only fire for sockets owned by the local TCP stack, not forwarded transit traffic.
- **Signal**: approximate transit-path TCP retransmit ratio from `source_zone` to each `dst_zone`, keyed by egress `ifindex` (separates `wireguard` vs `l2` targets).
- **Classification**: both `saddr ∈ source_zone` subnets and `daddr ∈ remote zone` subnets must match before a packet is counted.
- **Retransmit detection**: epoch Bloom filter (5-minute window, ~32 KB/CPU fixed memory). Duplicate `(4-tuple, seq)` within an epoch is treated as a probable retransmit. Segment counting stays exact.

Metrics are only meaningful when TC attaches exclusively to transit path interfaces listed in config. The exporter cannot verify routing policy beyond subnet filters.

## Build

Requires **clang**, **llvm-strip**, and vendored BPF headers under `bpf/headers/`.

```bash
make generate   # bpf2go via clang
make build
make test
```

Cross-compile:

```bash
GOOS=linux GOARCH=arm64 make cross
```

## Configuration

Production config: `/etc/ebpf_packet_loss_exporter/config.yml`

```yaml
source_zone: e
listen: :9435
poll_interval: 1s
instant_window: 10s

interfaces:
  wireguard: [wg0]
  l2: [ens21]
  ignore: [lo, docker0, br-*]

zones:
  c:
    id: 1
    subnets: [192.168.0.0/24]
  d:
    id: 2
    subnets: [192.168.1.0/24]
  e:
    id: 3
    subnets: [192.168.3.0/24, 192.168.4.0/24]
  f:
    id: 4
    subnets: [192.168.5.0/24, 192.168.6.0/24]

targets:
  - name: c-ehealth-id-wireguard
    dst_zone: c
    path: wireguard
  - name: f-ehealth-id-l2
    dst_zone: f
    path: l2

ema:
  half_life: 5m
```

When deploying, **trim** wg/l2 targets from `network_exporter.yml`; keep `*-direct` ICMP targets.

## Metrics

| Metric | Type | Description |
|---|---|---|
| `ebpf_packet_loss_percent` | Gauge | Rolling short-window loss ratio (default 10s) |
| `ebpf_packet_loss_percent_ema` | Gauge | EMA-smoothed approximate loss (primary for dashboards) |
| `ebpf_packet_loss_segments_total` | Counter | Raw BPF segments, exact (debug) |
| `ebpf_packet_loss_retrans_total` | Counter | Raw BPF retransmits, approximate (debug) |
| `ebpf_packet_loss_ema_last_update_timestamp` | Gauge | Unix time of last EMA update |

Labels: `name`, `source_zone`, `path`, `dst_zone`

### PromQL

Primary series (partition-resilient — no `rate()` needed):

```promql
ebpf_packet_loss_percent_ema{instance="e.ehealth.id:9435"}
```

Combine with network_exporter direct paths in Grafana:

```promql
# wireguard + l2 (ebpf)
ebpf_packet_loss_percent_ema{instance="e.ehealth.id:9435"}

# direct (network_exporter, unchanged)
ping_loss_percent{instance="e.ehealth.id:9427",name=~".*-direct"}
```

Staleness alert:

```promql
time() - ebpf_packet_loss_ema_last_update_timestamp > 300
```

### Troubleshooting zero metrics

This exporter is **passive** — it only observes real TCP traffic on monitored interfaces. Adding `tc netem loss` alone does not create metrics; you need active TCP flows between zone subnets (e.g. `iperf3`, `ssh`, Ceph/PG traffic).

**WireGuard (`wg0`) uses L3 skbs** (no Ethernet header). The BPF program handles both L2 and L3 packet layouts.

Check debug gauges after generating traffic:

```promql
ebpf_packet_loss_debug_tcp_payload_total   # TCP on monitored interfaces (before zone filter)?
ebpf_packet_loss_debug_tcp_zoned_total     # matched source_zone + remote dst_zone?
```

| debug_tcp_payload | debug_tcp_zoned | Likely cause |
|---|---|---|
| 0 | 0 | No TCP traffic on monitored egress, or hook not firing |
| >0 | 0 | Source or destination IPs don't match configured zone subnets |
| >0 | >0 | Counters should increment; check `ebpf_packet_loss_segments_total` |

Zone subnets must match **source and destination IPs** seen on the wire (e.g. `192.168.3.0/24` for zone `e`), not WireGuard peer endpoint addresses.

EMA updates on an internal poll loop (`poll_interval`, default 1s) independent of Prometheus scrapes. `ebpf_packet_loss_percent` aggregates the last `instant_window` (default 10s) of per-poll deltas. During scrape gaps the exporter keeps observing traffic; when scrapes resume the EMA gauge reflects the outage window.

## Install

From a tagged release (recommended):

```bash
curl -fsSL https://raw.githubusercontent.com/ehealth-id/ebpf-packet-loss-exporter/main/scripts/install.sh | sudo bash
```

`install.sh` downloads the latest release binary for your architecture, installs it to `/opt/ebpf_packet_loss_exporter/`, writes the systemd unit, and does **not** stop `network_exporter`. Place config at `/etc/ebpf_packet_loss_exporter/config.yml` before starting.

## Verification

```bash
systemctl status network_exporter
systemctl status ebpf_packet_loss_exporter

curl -s localhost:9427/metrics | grep 'ping_loss_percent.*direct'
curl -s localhost:9435/metrics | grep ebpf_packet_loss_percent_ema
```

## Limitations

- Gateway transit paths only (wireguard + l2); direct stays on network_exporter
- Passive TCP — requires real production traffic between configured zones
- **Approximate retransmits**: global Bloom filter (~1 MB fixed) with ~1% false-positive bias at typical load (conservative — over-counts retrans slightly); not suitable for audit-grade per-flow counts
- Bloom epoch rolls every 1.5 seconds; seq reuse across epochs on long-lived flows can cause spurious duplicates
- Global Bloom bitmap shared across CPUs; cross-core atomic contention at very high PPS — hash-to-slot sharding is the scale-up path if profiling shows a bottleneck
- Fixed ~1 MB global Bloom bitmap regardless of flow count
- Quiet paths: EMA holds last value; instant may read 0 when the rolling window has no segments
- TCP IPv4 only
- TCX egress on kernel 6.6+; clsact TC egress fallback on older kernels
- Egress TC may observe pre-GSO skbs; `seq >> 4` bucketing tolerates minor segmentation variance
- Path congestion proxy, not a byte-for-byte wire duplicate counter
