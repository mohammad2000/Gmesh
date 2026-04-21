package wireguard

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/ipc"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// userspaceManager runs a pure-Go WireGuard device via wireguard-go +
// wgctrl. It targets hosts without the in-kernel WG module (macOS,
// stock FreeBSD, Alpine without wireguard-tools). On Linux it's
// available as a fallback when PreferKernel=false.
//
// # Scope
//
//   - Creates a TUN device (utun on macOS, wg-gmesh on Linux if not
//     pre-existing) via golang.zx2c4.com/wireguard/tun.
//   - Runs a wireguard-go device goroutine against it.
//   - Exposes the UAPI socket so wgctrl can read/set config the same
//     way it does kernel WG.
//   - Assigns the mesh IP to the TUN via `ifconfig` / `ip addr` (the
//     correct platform command).
//
// # What it does NOT do
//
//   - Cross-platform kernel routing beyond basic add — egress policy
//     still lives in internal/egress/linux.go which is Linux-only. On
//     macOS, egress profiles return NotImplemented from the stub
//     manager; that's fine because the Mac client is a pure endpoint,
//     not an exit node.
type userspaceManager struct {
	log *slog.Logger

	mu      sync.Mutex
	devices map[string]*usDevice
}

type usDevice struct {
	name   string
	dev    *device.Device
	uapi   net.Listener
	tunDev tun.Device
}

// newUserspaceManager returns a ready userspace backend.
func newUserspaceManager(log *slog.Logger) (*userspaceManager, error) {
	if log == nil {
		log = slog.Default()
	}
	return &userspaceManager{log: log, devices: map[string]*usDevice{}}, nil
}

// Backend identifies the implementation.
func (u *userspaceManager) Backend() Backend { return BackendUserspace }

// Close tears down every device and UAPI socket. Safe to call twice.
func (u *userspaceManager) Close() error {
	u.mu.Lock()
	defer u.mu.Unlock()
	for _, d := range u.devices {
		d.close()
	}
	u.devices = map[string]*usDevice{}
	return nil
}

// CreateInterface spins up a wireguard-go device under `name`. The
// mesh IP is assigned via platform-native tooling so other userland
// services (ping, ssh) see the interface normally.
//
// On macOS, TUN device names are opaque "utunN" — wireguard-go picks
// one. We record the canonical name via tunDev.Name() after creation
// and symlink/alias internally so callers who pass "wg-gmesh" can
// still reach the device. (wgctrl looks up by UAPI socket, not by
// OS interface name, so this is purely cosmetic.)
func (u *userspaceManager) CreateInterface(
	ctx context.Context, name, addrCIDR string, mtu int, listenPort uint16,
) error {
	u.mu.Lock()
	defer u.mu.Unlock()
	if _, exists := u.devices[name]; exists {
		// Idempotent: re-creating an existing device is a no-op if the
		// params line up. We conservatively Close + recreate when we
		// see the name again, so repeated Join calls converge.
		u.devices[name].close()
		delete(u.devices, name)
	}

	if mtu <= 0 {
		mtu = device.DefaultMTU
	}

	// macOS rejects any TUN name that isn't "utun[0-9]*". Callers
	// (backends, admin scripts) pass logical names like "wg-gritiva"
	// that make sense on Linux. On Darwin we translate to the bare
	// sentinel "utun", which wireguard-go's tun_darwin.go treats as
	// "pick the next free utunN". The logical name is preserved as
	// the map key in u.devices so wgctrl lookups by callers work.
	createName := name
	if runtime.GOOS == "darwin" && !isUtunName(name) {
		createName = "utun"
	}
	tunDev, err := tun.CreateTUN(createName, mtu)
	if err != nil {
		return fmt.Errorf("userspace wg: create tun %q: %w", name, err)
	}
	realName, err := tunDev.Name()
	if err != nil {
		_ = tunDev.Close()
		return fmt.Errorf("userspace wg: tun name: %w", err)
	}
	u.log.Info("userspace wg tun created", "requested", name, "real", realName, "mtu", mtu)

	// Create the wireguard-go device.
	dlog := &device.Logger{
		Verbosef: func(format string, args ...any) { u.log.Debug(fmt.Sprintf(format, args...)) },
		Errorf:   func(format string, args ...any) { u.log.Warn(fmt.Sprintf(format, args...)) },
	}
	wgDev := device.NewDevice(tunDev, conn.NewDefaultBind(), dlog)

	// UAPI socket so wgctrl can configure it. On Linux + macOS this
	// ends up as a unix socket under /var/run/wireguard/<name>.sock.
	uapiFile, err := ipc.UAPIOpen(realName)
	if err != nil {
		wgDev.Close()
		_ = tunDev.Close()
		return fmt.Errorf("userspace wg: uapi open: %w", err)
	}
	uapi, err := ipc.UAPIListen(realName, uapiFile)
	if err != nil {
		uapiFile.Close()
		wgDev.Close()
		_ = tunDev.Close()
		return fmt.Errorf("userspace wg: uapi listen: %w", err)
	}
	// Accept loop — wgctrl connects to UAPI and sends one command.
	go func() {
		for {
			c, err := uapi.Accept()
			if err != nil {
				return
			}
			go wgDev.IpcHandle(c)
		}
	}()

	// Listen port via UAPI. The private key is set later via
	// SetPrivateKey (the Engine.Join flow generates the keypair after
	// CreateInterface). Passing an empty key here avoids a base64
	// parse error in ConfigureDevice.
	if err := u.applyInitialConfig(realName, "", listenPort); err != nil {
		uapi.Close()
		wgDev.Close()
		_ = tunDev.Close()
		return fmt.Errorf("userspace wg: apply initial config: %w", err)
	}

	// Bring interface up + assign the mesh address with platform
	// tooling. Linux uses `ip addr add`; Darwin uses `ifconfig X inet
	// Y/prefix Y` (the second Y is the peer/destination, required by
	// utun).
	if err := ifaceUp(ctx, realName, mtu); err != nil {
		u.log.Warn("userspace wg: ifconfig up failed; continuing anyway", "error", err)
	}
	if addrCIDR != "" {
		if err := ifaceAddAddr(ctx, realName, addrCIDR); err != nil {
			u.log.Warn("userspace wg: address assign failed; continuing anyway",
				"iface", realName, "addr", addrCIDR, "error", err)
		}
	}

	u.devices[name] = &usDevice{
		name: realName, dev: wgDev, uapi: uapi, tunDev: tunDev,
	}
	return nil
}

// DeleteInterface tears down a previously created device. Idempotent.
func (u *userspaceManager) DeleteInterface(ctx context.Context, name string) error {
	u.mu.Lock()
	d, ok := u.devices[name]
	delete(u.devices, name)
	u.mu.Unlock()
	if !ok {
		return nil
	}
	d.close()
	return nil
}

// SetPrivateKey updates the key on a running device via wgctrl.
func (u *userspaceManager) SetPrivateKey(_ context.Context, name, privateKey string) error {
	u.mu.Lock()
	d, ok := u.devices[name]
	u.mu.Unlock()
	if !ok {
		return fmt.Errorf("userspace wg: no such device %q", name)
	}
	k, err := wgtypes.ParseKey(privateKey)
	if err != nil {
		return fmt.Errorf("userspace wg: parse key: %w", err)
	}
	client, err := wgctrl.New()
	if err != nil {
		return fmt.Errorf("userspace wg: wgctrl open: %w", err)
	}
	defer client.Close()
	return client.ConfigureDevice(d.name, wgtypes.Config{PrivateKey: &k})
}

// AddPeer adds or replaces a peer. Replacement is via wgctrl's
// ReplacePeers=false: the same peer public key is updated in place,
// a new one is appended.
func (u *userspaceManager) AddPeer(_ context.Context, name string, p PeerConfig) error {
	u.mu.Lock()
	d, ok := u.devices[name]
	u.mu.Unlock()
	if !ok {
		return fmt.Errorf("userspace wg: no such device %q", name)
	}
	pub, err := wgtypes.ParseKey(p.PublicKey)
	if err != nil {
		return fmt.Errorf("userspace wg: parse peer key: %w", err)
	}
	var endpoint *net.UDPAddr
	if p.Endpoint != "" {
		ua, err := net.ResolveUDPAddr("udp", p.Endpoint)
		if err != nil {
			return fmt.Errorf("userspace wg: resolve endpoint %q: %w", p.Endpoint, err)
		}
		endpoint = ua
	}
	allowed := make([]net.IPNet, 0, len(p.AllowedIPs))
	for _, a := range p.AllowedIPs {
		_, ipn, err := net.ParseCIDR(a)
		if err != nil {
			return fmt.Errorf("userspace wg: parse allowed_ip %q: %w", a, err)
		}
		allowed = append(allowed, *ipn)
	}
	var keepalive *time.Duration
	if p.PersistentKeepaliveInterval > 0 {
		d := p.PersistentKeepaliveInterval
		keepalive = &d
	}
	client, err := wgctrl.New()
	if err != nil {
		return fmt.Errorf("userspace wg: wgctrl open: %w", err)
	}
	defer client.Close()
	return client.ConfigureDevice(d.name, wgtypes.Config{
		Peers: []wgtypes.PeerConfig{{
			PublicKey:                   pub,
			Endpoint:                    endpoint,
			AllowedIPs:                  allowed,
			PersistentKeepaliveInterval: keepalive,
			ReplaceAllowedIPs:           true,
		}},
	})
}

// RemovePeer drops a peer by public key. Idempotent.
func (u *userspaceManager) RemovePeer(_ context.Context, name, publicKey string) error {
	u.mu.Lock()
	d, ok := u.devices[name]
	u.mu.Unlock()
	if !ok {
		return nil
	}
	pub, err := wgtypes.ParseKey(publicKey)
	if err != nil {
		return fmt.Errorf("userspace wg: parse peer key: %w", err)
	}
	client, err := wgctrl.New()
	if err != nil {
		return fmt.Errorf("userspace wg: wgctrl open: %w", err)
	}
	defer client.Close()
	return client.ConfigureDevice(d.name, wgtypes.Config{
		Peers: []wgtypes.PeerConfig{{PublicKey: pub, Remove: true}},
	})
}

// ListPeers returns the live peer table for the given device.
func (u *userspaceManager) ListPeers(_ context.Context, name string) ([]PeerDump, error) {
	u.mu.Lock()
	d, ok := u.devices[name]
	u.mu.Unlock()
	if !ok {
		return nil, fmt.Errorf("userspace wg: no such device %q", name)
	}
	client, err := wgctrl.New()
	if err != nil {
		return nil, fmt.Errorf("userspace wg: wgctrl open: %w", err)
	}
	defer client.Close()
	dev, err := client.Device(d.name)
	if err != nil {
		return nil, fmt.Errorf("userspace wg: get device %q: %w", d.name, err)
	}
	out := make([]PeerDump, 0, len(dev.Peers))
	for _, p := range dev.Peers {
		allowed := make([]string, 0, len(p.AllowedIPs))
		for _, ipn := range p.AllowedIPs {
			allowed = append(allowed, ipn.String())
		}
		endpoint := ""
		if p.Endpoint != nil {
			endpoint = p.Endpoint.String()
		}
		out = append(out, PeerDump{
			PublicKey:     p.PublicKey.String(),
			Endpoint:      endpoint,
			AllowedIPs:    allowed,
			RxBytes:       p.ReceiveBytes,
			TxBytes:       p.TransmitBytes,
			LastHandshake: p.LastHandshakeTime,
		})
	}
	return out, nil
}

// ── helpers ──────────────────────────────────────────────────────────

// applyInitialConfig sets private key + listen port on a fresh device.
func (u *userspaceManager) applyInitialConfig(iface, privateKey string, listenPort uint16) error {
	client, err := wgctrl.New()
	if err != nil {
		return err
	}
	defer client.Close()
	cfg := wgtypes.Config{}
	if privateKey != "" {
		k, err := wgtypes.ParseKey(privateKey)
		if err != nil {
			return fmt.Errorf("parse private key: %w", err)
		}
		cfg.PrivateKey = &k
	}
	if listenPort != 0 {
		p := int(listenPort)
		cfg.ListenPort = &p
	}
	return client.ConfigureDevice(iface, cfg)
}

func (d *usDevice) close() {
	if d == nil {
		return
	}
	if d.uapi != nil {
		_ = d.uapi.Close()
	}
	if d.dev != nil {
		d.dev.Close()
	}
	// tunDev is closed internally by device.Close().
	// Best-effort cleanup of the UAPI socket file on disk.
	_ = os.Remove(filepath.Join("/var/run/wireguard", d.name+".sock"))
}

// ifaceUp is a tiny platform-command abstraction so this file compiles
// cleanly everywhere. On Linux we call `ip link set ... up` + `ip link
// set ... mtu ...`; on macOS (darwin) we call `ifconfig`.
func ifaceUp(ctx context.Context, name string, mtu int) error {
	switch runtime.GOOS {
	case "linux":
		if err := runCmd(ctx, "ip", "link", "set", name, "up"); err != nil {
			return err
		}
		if mtu > 0 {
			return runCmd(ctx, "ip", "link", "set", name, "mtu", fmt.Sprintf("%d", mtu))
		}
		return nil
	case "darwin":
		if err := runCmd(ctx, "ifconfig", name, "up"); err != nil {
			return err
		}
		if mtu > 0 {
			return runCmd(ctx, "ifconfig", name, "mtu", fmt.Sprintf("%d", mtu))
		}
		return nil
	default:
		return errors.New("userspace wg: interface up unsupported on " + runtime.GOOS)
	}
}

// ifaceAddAddr assigns a CIDR address to the TUN/utun interface using
// platform-native tooling. On Linux: `ip addr add`. On Darwin: utun is
// a point-to-point interface, and `ifconfig utunN inet addr peer addr`
// is the shape BSD expects (we use the same address on both sides so
// the kernel routes traffic through WireGuard-allowed IPs to the
// device). A raw prefix-less `ifconfig utunN inet X.Y.Z.W` works too
// but doesn't set the route, so peers can't reach you.
func ifaceAddAddr(ctx context.Context, name, addrCIDR string) error {
	switch runtime.GOOS {
	case "linux":
		return runCmd(ctx, "ip", "addr", "add", addrCIDR, "dev", name)
	case "darwin":
		ip := addrCIDR
		if i := strings.Index(addrCIDR, "/"); i > 0 {
			ip = addrCIDR[:i]
		}
		// utun is point-to-point. Set local = peer = our mesh IP so
		// BSD doesn't complain; the actual routing is done by the
		// explicit `route add` below.
		if err := runCmd(ctx, "ifconfig", name, "inet", ip, ip); err != nil {
			return err
		}
		// Route the mesh CIDR (if provided) via this utun, so traffic
		// to any other peer's mesh IP flows through WireGuard. Normalize
		// to the network address (10.200.0.3/16 → 10.200.0.0/16) —
		// macOS's `route add -net` rejects CIDRs whose host bits are
		// non-zero. First best-effort delete any prior route for this
		// network so we win a restart race with stale utunN routes left
		// by a previous gmeshd run.
		if strings.Contains(addrCIDR, "/") {
			netCIDR := normalizeNetworkCIDR(addrCIDR)
			_ = runCmd(ctx, "route", "-q", "-n", "delete", "-net", netCIDR)
			if err := runCmd(ctx, "route", "-q", "-n", "add", "-net", netCIDR, "-interface", name); err != nil {
				return err
			}
		}
		return nil
	default:
		return errors.New("userspace wg: address assign unsupported on " + runtime.GOOS)
	}
}

// normalizeNetworkCIDR takes "host/prefix" like "10.200.0.3/16" and
// returns the network base "10.200.0.0/16". Needed for macOS's
// `route add -net` which refuses CIDRs with non-zero host bits.
func normalizeNetworkCIDR(addrCIDR string) string {
	_, n, err := net.ParseCIDR(addrCIDR)
	if err != nil || n == nil {
		return addrCIDR
	}
	return n.String()
}

// isUtunName reports whether name matches macOS's "utun" + N format.
// We use it to decide whether to rewrite the requested TUN name on
// Darwin (the kernel rejects anything else).
func isUtunName(name string) bool {
	if !strings.HasPrefix(name, "utun") {
		return false
	}
	suffix := name[len("utun"):]
	if suffix == "" {
		return false
	}
	for _, c := range suffix {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func runCmd(ctx context.Context, name string, args ...string) error {
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %w (%s)", name, strings.Join(args, " "),
			err, strings.TrimSpace(string(out)))
	}
	return nil
}
