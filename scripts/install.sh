#!/usr/bin/env bash
# Install gmesh locally without a .deb. Requires root.
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "Run as root." >&2
    exit 1
fi

cd "$(dirname "$0")/.."

make build
make install

if [[ ! -f /etc/gmesh/config.yaml ]]; then
    mkdir -p /etc/gmesh
    cat > /etc/gmesh/config.yaml <<'YAML'
socket:  {path: /run/gmesh.sock, mode: 0o660}
log:     {format: text, level: info}
wireguard:
  interface: wg-gritiva
  listen_port: 51820
  mtu: 1420
  keepalive_seconds: 25
  prefer_kernel: true
  network_cidr: 10.200.0.0/16
YAML
fi

systemctl daemon-reload
echo
echo "Installed. Start with: systemctl enable --now gmeshd"
echo "Check status:          gmeshctl status"
