# Deployment

## Install

### From a built `.deb`

```bash
sudo dpkg -i gmeshd_0.1.0-1_amd64.deb
sudo systemctl enable --now gmeshd
gmeshctl status
```

### From source (development)

```bash
git clone https://github.com/mohammad2000/Gmesh.git
cd Gmesh
make build
sudo make install
sudo systemctl enable --now gmeshd
```

## Configuration

Default config is written to `/etc/gmesh/config.yaml` on first install. Key
sections — see `internal/config/config.go` for the full schema.

```yaml
socket:
  path: /run/gmesh.sock
  mode: 0o660

wireguard:
  interface: wg-gritiva
  listen_port: 51820
  mtu: 1420
  keepalive_seconds: 25
  prefer_kernel: true
  network_cidr: 10.200.0.0/16

nat:
  stun_servers:
    - stun.l.google.com:19302
    - stun1.l.google.com:19302
    - stun.cloudflare.com:3478
    - stun.ekiga.net:3478
  cache_ttl_seconds: 300
  udp_responder_port: 51822

firewall:
  table: gmesh
  chain: mesh
  use_nftables: true
```

Reload after editing: `sudo systemctl restart gmeshd`.

## Upgrade

```bash
sudo apt install ./gmeshd_<newver>.deb
# postinst runs daemon-reload; systemd restarts the unit automatically
gmeshctl version
```

State at `/var/lib/gmesh/state.json` is forward-compatible within a major
version.

## Rollback

```bash
sudo apt install ./gmeshd_<oldver>.deb --allow-downgrades
sudo systemctl restart gmeshd
```

Or rebuild from a Git tag:

```bash
git checkout v0.1.0
make deb
sudo dpkg -i dist/gmeshd_0.1.0-1_amd64.deb
```

## Observability

### Logs

```bash
journalctl -u gmeshd -f              # follow
journalctl -u gmeshd --since "1h ago"
```

Log format is controlled by `log.format` in config (`text` or `json`). JSON
is recommended in production (machine-parseable by Loki, Elasticsearch, etc.).

### CLI

```bash
gmeshctl status            # lifecycle + peer count
gmeshctl peers list        # all peers (Phase 1+)
gmeshctl peer show NN      # single peer detail (Phase 1+)
gmeshctl nat discover      # force NAT re-discovery (Phase 2+)
gmeshctl firewall list     # active rules (Phase 5+)
gmeshctl events tail       # live event stream (Phase 7+)
```

### Metrics (Phase 9+)

Prometheus scrape endpoint exposed on the Unix socket (HTTP over UDS):

```
curl --unix-socket /run/gmesh.sock http://localhost/metrics
```

## Troubleshooting

| Symptom                             | Check                                              |
|-------------------------------------|----------------------------------------------------|
| `gmeshctl status` → `connection refused` | `systemctl status gmeshd`; `journalctl -u gmeshd` |
| Kernel WG unavailable               | `lsmod | grep wireguard`; enable via wg-go in cfg  |
| Socket permission denied            | Check `socket.owner/group/mode`; client must be root (default) |
| NAT discovery timeout               | Check STUN server reachability: `nc -zvu stun.l.google.com 19302` |
| Firewall apply fails                | `nft list table inet gmesh`; verify nftables installed |
