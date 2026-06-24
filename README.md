# ebpf-packet-loss-exporter

Passive zone-to-zone TCP retransmit monitoring on transit gateways. Complements [network_exporter](https://github.com/syepes/network_exporter) — use this for inter-zone transit loss (`:9435`), keep network_exporter for per-host ICMP detail (`:9427`).

Runs on the **transit gateway** that forwards traffic between zones (WireGuard, L2). Not on application hosts.

## How it works

- Attaches TC egress on configured transit interfaces (or auto-discovers WireGuard + Ethernet when `interfaces` is omitted).
- Counts TCP segments between `source_zone` subnets and each remote zone's subnets.
- Estimates retransmits via a Bloom filter on `(4-tuple, seq)`.
- Exposes one smoothed loss % per `source_zone` → `dst_zone` pair.

Requires real TCP traffic between zones (Ceph, SSH, app traffic). Passive — no probes of its own.

## Configuration

Path: `/etc/ebpf_packet_loss_exporter/config.yml`

```yaml
source_zone: e
interfaces: [wg0, ens21]
zones:
  c: [192.168.0.0/24]
  d: [192.168.1.0/24]
  e: [192.168.3.0/24, 192.168.4.0/24]
  f: [192.168.5.0/24, 192.168.6.0/24]
```

All fields below are optional (defaults shown):

| Field | Default | Description |
|---|---|---|
| `listen` | `:9435` | Metrics HTTP listen address |
| `poll_interval` | `1s` | Internal counter poll interval |
| `instant_window` | `10s` | Rolling window for `ebpf_packet_loss_percent` |
| `ema_half_life` | `5m` | EMA smoothing half-life |
| `interfaces` | auto-discover | TC egress attach list (`wg0`, `ens21`, …) |

Subnet IPs must match what is seen on the wire (zone internal addresses), not WireGuard peer endpoints.

## Metrics

| Metric | Description |
|---|---|
| `ebpf_packet_loss_percent_ema` | Primary — EMA-smoothed loss % |
| `ebpf_packet_loss_percent` | Short-window instant loss % |
| `ebpf_packet_loss_ema_last_update_timestamp` | Last EMA update (staleness checks) |

Labels: `source_zone`, `dst_zone`

```promql
# headline
ebpf_packet_loss_percent_ema{instance="e.ehealth.id:9435"}

# staleness
time() - ebpf_packet_loss_ema_last_update_timestamp > 300
```

Combine with network_exporter in Grafana:

```promql
ebpf_packet_loss_percent_ema{instance="e.ehealth.id:9435"}
ping_loss_percent{instance="e.ehealth.id:9427", name=~".*-direct"}
```

## Build

Requires **clang**, **llvm-strip**, and BPF headers under `bpf/headers/`.

```bash
make generate
make build
make test
```

```bash
GOOS=linux GOARCH=arm64 make cross
```

## Install

```bash
curl -fsSL https://raw.githubusercontent.com/ehealth-co-id/ebpf-packet-loss-exporter/master/scripts/install.sh | sudo bash
```

Installs to `/opt/ebpf_packet_loss_exporter/`, writes a systemd unit, does not touch network_exporter. Place config before starting.

## Verify

```bash
systemctl status ebpf_packet_loss_exporter
curl -s localhost:9435/metrics | grep ebpf_packet_loss_percent_ema
```

Startup logs list auto-discovered interfaces. If metrics stay at zero, confirm TCP flows exist between zones and that subnets match on-wire addresses.

## Limitations

- IPv4 TCP only; approximate retransmits (Bloom filter), not audit-grade
- TCX egress on kernel 6.6+, clsact fallback on older kernels
- Quiet zones: EMA holds last value until traffic resumes
