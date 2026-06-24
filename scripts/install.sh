#!/usr/bin/env bash
set -euo pipefail

# Configuration
REPO="ehealth-co-id/ebpf-packet-loss-exporter"
SERVICE_NAME="ebpf_packet_loss_exporter"
INSTALL_DIR="/opt/ebpf_packet_loss_exporter"
CONFIG_DIR="/etc/ebpf_packet_loss_exporter"
BINARY="ebpf_packet_loss_exporter"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"

echo "[*] Installing ${SERVICE_NAME} from latest release..."

# 1. Pre-flight checks
if [[ $EUID -ne 0 ]]; then
  echo "ERROR: This script must be run as root"
  exit 1
fi

case "$(uname -m)" in
  x86_64) GOARCH="amd64" ;;
  aarch64|arm64) GOARCH="arm64" ;;
  *)
    echo "ERROR: Unsupported architecture: $(uname -m)"
    exit 1
    ;;
esac

ASSET_NAME="${BINARY}-linux-${GOARCH}"

# 2. Fetch latest release asset URL
echo "[*] Fetching latest release information..."
RELEASE_JSON=$(curl -fsSL \
  -H "Accept: application/vnd.github+json" \
  -H "User-Agent: ebpf-packet-loss-exporter-install" \
  "https://api.github.com/repos/${REPO}/releases/latest")

ASSET_URL=$(echo "$RELEASE_JSON" | grep -oE "https://[^\"]+/${ASSET_NAME}\"" | head -1 | tr -d '"')

if [[ -z "$ASSET_URL" ]]; then
  echo "ERROR: Could not find release asset ${ASSET_NAME}"
  exit 1
fi

echo "[*] Downloading release from: $ASSET_URL"

# Stop service if it exists to allow file overwrite
systemctl stop "${SERVICE_NAME}" 2>/dev/null || true

# 3. Install binary
echo "[*] Installing to ${INSTALL_DIR}/${BINARY}..."
install -d "${INSTALL_DIR}"
curl -fsSL -o "${INSTALL_DIR}/${BINARY}" "$ASSET_URL"
chmod 755 "${INSTALL_DIR}/${BINARY}"

install -d "${CONFIG_DIR}"
if [[ ! -f "${CONFIG_DIR}/config.yml" ]]; then
  echo "WARNING: ${CONFIG_DIR}/config.yml not found — create it before the service can start"
fi

# 4. Systemd setup
echo "[*] Configuring systemd service..."

cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=eBPF packet loss exporter (wireguard + l2)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=${INSTALL_DIR}/${BINARY} \\
  --config=${CONFIG_DIR}/config.yml \\
  --listen=:9435
WorkingDirectory=${INSTALL_DIR}

# Reliability
Restart=always
RestartSec=2
TimeoutStartSec=10

# eBPF / TC attach requires elevated capabilities
AmbientCapabilities=CAP_BPF CAP_NET_ADMIN CAP_SYS_ADMIN
CapabilityBoundingSet=CAP_BPF CAP_NET_ADMIN CAP_SYS_ADMIN

# Hardening (compatible with ambient capabilities)
PrivateTmp=true

# Logging
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

echo "[*] Reloading systemd"
systemctl daemon-reload

echo "[*] Enabling service"
systemctl enable "${SERVICE_NAME}"

if [[ -f "${CONFIG_DIR}/config.yml" ]]; then
  echo "[*] Starting service"
  systemctl restart "${SERVICE_NAME}"
else
  echo "[*] Skipping start — create ${CONFIG_DIR}/config.yml first, then run:"
  echo "    systemctl start ${SERVICE_NAME}"
fi

echo "[✓] Done"
echo "    status:  systemctl status ${SERVICE_NAME}"
echo "    logs:    journalctl -u ${SERVICE_NAME} -f"
echo ""
echo "Ensure ${CONFIG_DIR}/config.yml exists before relying on metrics."
