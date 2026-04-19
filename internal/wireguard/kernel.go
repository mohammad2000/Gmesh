package wireguard

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// kernelManager uses wgctrl to talk to the in-kernel WireGuard module.
// Interface creation (the `ip link add type wireguard` step) is handled by
// the iface.go helpers so wgctrl only does configuration.
type kernelManager struct {
	cli *wgctrl.Client
	log *slog.Logger
}

func newKernelManager(cli *wgctrl.Client, log *slog.Logger) *kernelManager {
	return &kernelManager{cli: cli, log: log}
}

func (k *kernelManager) Backend() Backend { return BackendKernel }

func (k *kernelManager) Close() error { return k.cli.Close() }

func (k *kernelManager) CreateInterface(ctx context.Context, name, addrCIDR string, mtu int, listenPort uint16) error {
	if err := ifaceEnsure(ctx, name, addrCIDR, mtu); err != nil {
		return fmt.Errorf("ensure interface: %w", err)
	}
	port := int(listenPort)
	cfg := wgtypes.Config{ListenPort: &port, ReplacePeers: false}
	if err := k.cli.ConfigureDevice(name, cfg); err != nil {
		return fmt.Errorf("configure %s: %w", name, err)
	}
	return nil
}

func (k *kernelManager) DeleteInterface(_ context.Context, name string) error {
	return ifaceDelete(name)
}

func (k *kernelManager) SetPrivateKey(_ context.Context, iface, privB64 string) error {
	priv, err := wgtypes.ParseKey(privB64)
	if err != nil {
		return fmt.Errorf("parse private key: %w", err)
	}
	cfg := wgtypes.Config{PrivateKey: &priv}
	return k.cli.ConfigureDevice(iface, cfg)
}

func (k *kernelManager) AddPeer(_ context.Context, iface string, p PeerConfig) error {
	pub, err := wgtypes.ParseKey(p.PublicKey)
	if err != nil {
		return fmt.Errorf("parse peer public key: %w", err)
	}

	var endpoint *net.UDPAddr
	if p.Endpoint != "" {
		ep, err := net.ResolveUDPAddr("udp", p.Endpoint)
		if err != nil {
			return fmt.Errorf("resolve endpoint %s: %w", p.Endpoint, err)
		}
		endpoint = ep
	}

	allowed, err := parseAllowedIPs(p.AllowedIPs)
	if err != nil {
		return err
	}

	var keepalive *time.Duration
	if p.PersistentKeepaliveInterval > 0 {
		ka := p.PersistentKeepaliveInterval
		keepalive = &ka
	}

	peer := wgtypes.PeerConfig{
		PublicKey:                   pub,
		Endpoint:                    endpoint,
		AllowedIPs:                  allowed,
		PersistentKeepaliveInterval: keepalive,
		ReplaceAllowedIPs:           true,
		UpdateOnly:                  false,
	}
	if p.PresharedKey != "" {
		psk, err := wgtypes.ParseKey(p.PresharedKey)
		if err != nil {
			return fmt.Errorf("parse preshared key: %w", err)
		}
		peer.PresharedKey = &psk
	}

	return k.cli.ConfigureDevice(iface, wgtypes.Config{Peers: []wgtypes.PeerConfig{peer}})
}

func (k *kernelManager) RemovePeer(_ context.Context, iface, publicKey string) error {
	pub, err := wgtypes.ParseKey(publicKey)
	if err != nil {
		return fmt.Errorf("parse peer public key: %w", err)
	}
	peer := wgtypes.PeerConfig{PublicKey: pub, Remove: true}
	return k.cli.ConfigureDevice(iface, wgtypes.Config{Peers: []wgtypes.PeerConfig{peer}})
}

func (k *kernelManager) ListPeers(_ context.Context, iface string) ([]PeerDump, error) {
	dev, err := k.cli.Device(iface)
	if err != nil {
		if errors.Is(err, errNotExist{}) {
			return nil, ErrInterfaceNotFound
		}
		return nil, fmt.Errorf("read device %s: %w", iface, err)
	}
	out := make([]PeerDump, 0, len(dev.Peers))
	for _, p := range dev.Peers {
		allowed := make([]string, 0, len(p.AllowedIPs))
		for _, a := range p.AllowedIPs {
			allowed = append(allowed, a.String())
		}
		ep := ""
		if p.Endpoint != nil {
			ep = p.Endpoint.String()
		}
		out = append(out, PeerDump{
			PublicKey:     p.PublicKey.String(),
			Endpoint:      ep,
			AllowedIPs:    allowed,
			LastHandshake: p.LastHandshakeTime,
			RxBytes:       p.ReceiveBytes,
			TxBytes:       p.TransmitBytes,
		})
	}
	return out, nil
}

// parseAllowedIPs parses CIDR strings; bare IPs get /32 or /128 appended.
func parseAllowedIPs(ips []string) ([]net.IPNet, error) {
	out := make([]net.IPNet, 0, len(ips))
	for _, raw := range ips {
		if raw == "" {
			continue
		}
		// Accept bare IPs by appending /32 or /128.
		if _, _, err := net.ParseCIDR(raw); err != nil {
			if ip := net.ParseIP(raw); ip != nil {
				if ip.To4() != nil {
					raw += "/32"
				} else {
					raw += "/128"
				}
			}
		}
		_, n, err := net.ParseCIDR(raw)
		if err != nil {
			return nil, fmt.Errorf("parse allowed ip %q: %w", raw, err)
		}
		out = append(out, *n)
	}
	return out, nil
}

// errNotExist is a placeholder so kernel.go compiles on platforms where
// wgctrl uses a different "not found" sentinel. We compare by type.
type errNotExist struct{}

func (errNotExist) Error() string { return "does not exist" }
