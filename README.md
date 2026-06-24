# ebpf-packet-loss-exporter

Passive eBPF TCP retransmit monitoring for **wireguard** and **l2** inter-zone paths. Complements [network_exporter](https://github.com/syepes/network_exporter) — active ICMP `direct` probes stay on network_exporter (`:9427`).

## Scope

| Path | Tool | Method | Port |
|---|---|---|---|
| `wireguard` | ebpf-packet-loss-exporter | Passive TCP retransmit ratio | `:9435` |
| `l2` | ebpf-packet-loss-exporter | Passive TCP retransmit ratio | `:9435` |
| `direct` | network_exporter (unchanged) | Active ICMP | `:9427` |

TC egress attaches only on configured wireguard and l2 interfaces. No WAN attachment, no ICMP parsing.

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
poll_interval: 15s

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
| `ebpf_packet_loss_percent` | Gauge | Instant loss from last poll window |
| `ebpf_packet_loss_percent_ema` | Gauge | EMA-smoothed loss (primary for dashboards) |
| `ebpf_packet_loss_segments_total` | Counter | Raw BPF segments (debug) |
| `ebpf_packet_loss_retrans_total` | Counter | Raw BPF retrans (debug) |
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

EMA updates on an internal poll loop (`poll_interval`, default 15s) independent of Prometheus scrapes. During scrape gaps the exporter keeps observing traffic; when scrapes resume the EMA gauge reflects the outage window.

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

- wireguard + l2 only; direct stays on network_exporter
- Passive TCP — requires real production traffic
- Quiet paths: EMA holds last value; instant may be 0
- TCP IPv4 only
- TCX egress on kernel 6.6+; clsact TC egress fallback on older kernels
