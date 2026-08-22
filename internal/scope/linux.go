//go:build linux

package scope

import (
	"context"
	"fmt"
	"log/slog"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/mohammad2000/Gmesh/internal/crypto"
)

// LinuxManager creates real network namespaces, veth pairs, a dedicated
// WireGuard interface inside each netns, and a matching DNAT rule on the
// host so remote peers can reach the scope's WG port.
//
// Commands issued (all via exec.Command, so `ip`, `wg`, and `iptables`
// must be on PATH and the daemon must run as root):
//
//	ip netns add scope-N
//	ip link add vh-sN type veth peer name vs-sN
//	ip link set vs-sN netns scope-N
//	ip addr add <VMVethIP>/30 dev vh-sN
//	ip -n scope-N addr add <ScopeVethIP>/30 dev vs-sN
//	ip link set vh-sN up
//	ip -n scope-N link set vs-sN up
//	ip -n scope-N link set lo up
//	ip -n scope-N route add default via <VMVethIP>
//	ip -n scope-N link add wg-scope type wireguard
//	ip -n scope-N addr add <MeshIP>/16 dev wg-scope
//	wg set wg-scope … (inside netns via nsenter)  # key + listen port
//	ip -n scope-N link set wg-scope up
//	iptables -t nat -A PREROUTING -p udp --dport <ListenPort>
//	        -j DNAT --to-destination <ScopeVethIP>:<ListenPort>
//	iptables -A FORWARD -d <ScopeVethIP> -p udp --dport <ListenPort> -j ACCEPT
//	sysctl -w net.ipv4.ip_forward=1   (one-time)
type LinuxManager struct {
	Log *slog.Logger

	mu    sync.Mutex
	peers map[int64]*Peer
}

// NewLinux returns the real Linux scope manager.
func NewLinux(log *slog.Logger) *LinuxManager {
	if log == nil {
		log = slog.Default()
	}
	return &LinuxManager{Log: log, peers: make(map[int64]*Peer)}
}

// Name returns "linux".
func (m *LinuxManager) Name() string { return "linux" }

// Connect builds the full per-scope networking stack.
func (m *LinuxManager) Connect(ctx context.Context, s Spec) (*Peer, error) {
	m.mu.Lock()
	if _, ok := m.peers[s.ScopeID]; ok {
		m.mu.Unlock()
		return nil, ErrAlreadyConnected
	}
	m.mu.Unlock()

	netns := s.Netns
	if netns == "" {
		netns = fmt.Sprintf("scope-%d", s.ScopeID)
	}
	mtu := s.MTU
	if mtu == 0 {
		mtu = 1420
	}

	p := &Peer{
		ID:            s.ScopeID,
		Netns:         netns,
		MeshIP:        s.MeshIP,
		VethHost:      fmt.Sprintf("vh-s%d", s.ScopeID),
		VethScope:     fmt.Sprintf("vs-s%d", s.ScopeID),
		VethCIDR:      s.VethCIDR,
		VMVethIP:      s.VMVethIP,
		ScopeVethIP:   s.ScopeVethIP,
		GatewayMeshIP: s.GatewayMeshIP,
		ListenPort:    s.ListenPort,
		CreatedAt:     time.Now(),
	}

	kp, err := crypto.GenerateKeypair()
	if err != nil {
		return nil, fmt.Errorf("generate keypair: %w", err)
	}
	p.PublicKey = kp.Public
	p.PrivateKey = kp.Private

	// Roll-forward with a best-effort teardown on any failure.
	success := false
	defer func() {
		if !success {
			_ = m.tearDown(context.Background(), p) //nolint:errcheck
		}
	}()

	if err := m.enableForwarding(ctx); err != nil {
		return nil, err
	}
	if err := m.createNetns(ctx, p); err != nil {
		return nil, err
	}
	if err := m.createVeth(ctx, p, mtu); err != nil {
		return nil, err
	}
	if err := m.setupAddrs(ctx, p); err != nil {
		return nil, err
	}
	if err := m.setupWGInNetns(ctx, p, mtu); err != nil {
		return nil, err
	}
	if err := m.setupDNAT(ctx, p); err != nil {
		return nil, err
	}

	m.mu.Lock()
	m.peers[s.ScopeID] = p
	m.mu.Unlock()

	success = true
	m.Log.Info("scope connected",
		"id", s.ScopeID, "mesh_ip", s.MeshIP, "netns", netns,
		"listen_port", s.ListenPort)
	return p, nil
}

// Disconnect tears down everything Connect installed. Idempotent.
func (m *LinuxManager) Disconnect(ctx context.Context, scopeID int64) error {
	m.mu.Lock()
	p, ok := m.peers[scopeID]
	delete(m.peers, scopeID)
	m.mu.Unlock()
	if !ok {
		return ErrNotConnected
	}
	if err := m.tearDown(ctx, p); err != nil {
		m.Log.Warn("scope teardown reported errors", "id", scopeID, "error", err)
	}
	m.Log.Info("scope disconnected", "id", scopeID)
	return nil
}

// List returns a snapshot.
func (m *LinuxManager) List() []*Peer {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]*Peer, 0, len(m.peers))
	for _, p := range m.peers {
		out = append(out, p)
	}
	return out
}

// ── Setup steps ────────────────────────────────────────────────────────

func (m *LinuxManager) enableForwarding(ctx context.Context) error {
	// Ignore failure — on managed hosts this may be set via sysctl.conf.
	_ = run(ctx, "sysctl", "-qw", "net.ipv4.ip_forward=1")
	return nil
}

func (m *LinuxManager) createNetns(ctx context.Context, p *Peer) error {
	// `ip netns add` errors if the namespace exists — detect + skip.
	//
	// Whether we created it decides whether we may ever delete it. On a
	// GritivaCore host the agent builds scope-{id} first and the running
	// service lives inside; we are a guest there, adding a veth and a
	// WireGuard interface alongside. Deleting someone else's namespace on
	// rollback would take the service down with it.
	out, _ := exec.CommandContext(ctx, "ip", "netns", "list").Output()
	if strings.Contains(string(out), p.Netns) {
		p.ownsNetns = false
		return nil
	}
	if err := run(ctx, "ip", "netns", "add", p.Netns); err != nil {
		return err
	}
	p.ownsNetns = true
	return nil
}

func (m *LinuxManager) createVeth(ctx context.Context, p *Peer, mtu int) error {
	// A veth left behind by an earlier attempt used to make every retry
	// fail forever: `ip link add` reports "File exists" and there was no
	// tolerance for it, so a half-built scope could never be repaired —
	// only observed, stuck in CONNECTING.
	if linkExists(ctx, p.VethHost) {
		m.Log.Info("scope veth already present, adopting", "veth", p.VethHost, "id", p.ID)
	} else {
		if err := run(ctx, "ip", "link", "add", p.VethHost, "type", "veth", "peer", "name", p.VethScope); err != nil {
			return fmt.Errorf("veth add: %w", err)
		}
		p.ownsVeth = true
	}
	// The scope end may already have been moved by the earlier attempt.
	if linkExists(ctx, p.VethScope) {
		if err := run(ctx, "ip", "link", "set", p.VethScope, "netns", p.Netns); err != nil {
			return fmt.Errorf("move veth to netns: %w", err)
		}
	}
	if err := run(ctx, "ip", "link", "set", p.VethHost, "mtu", itoa(mtu)); err != nil {
		return fmt.Errorf("set host veth mtu: %w", err)
	}
	return nil
}

func (m *LinuxManager) setupAddrs(ctx context.Context, p *Peer) error {
	// Defensive: gmeshd panicked here when VethCIDR was empty
	// (strings.Split("", "/")[1:][0] -> index out of range).
	vethParts := strings.Split(p.VethCIDR, "/")
	hostMask := ""
	if len(vethParts) >= 2 {
		hostMask = vethParts[1]
	}
	if hostMask == "" {
		hostMask = "30"
	}
	if err := run(ctx, "ip", "addr", "add", p.VMVethIP+"/"+hostMask, "dev", p.VethHost); err != nil && !alreadyExists(err) {
		return fmt.Errorf("host addr: %w", err)
	}
	if err := runNetns(ctx, p.Netns, "ip", "addr", "add", p.ScopeVethIP+"/"+hostMask, "dev", p.VethScope); err != nil && !alreadyExists(err) {
		return fmt.Errorf("scope addr: %w", err)
	}
	if err := run(ctx, "ip", "link", "set", p.VethHost, "up"); err != nil {
		return fmt.Errorf("host up: %w", err)
	}
	if err := runNetns(ctx, p.Netns, "ip", "link", "set", p.VethScope, "up"); err != nil {
		return fmt.Errorf("scope up: %w", err)
	}
	if err := runNetns(ctx, p.Netns, "ip", "link", "set", "lo", "up"); err != nil {
		return fmt.Errorf("scope lo up: %w", err)
	}
	if err := runNetns(ctx, p.Netns, "ip", "route", "add", "default", "via", p.VMVethIP); err != nil && !strings.Contains(err.Error(), "File exists") {
		return fmt.Errorf("scope default route: %w", err)
	}
	return nil
}

func (m *LinuxManager) setupWGInNetns(ctx context.Context, p *Peer, mtu int) error {
	iface := "wg-scope"
	// Re-running against an existing interface is the repair path, not an
	// error: `wg set` below reconfigures key and port either way.
	if err := runNetnsIdempotent(ctx, p.Netns, "ip", "link", "add", iface, "type", "wireguard"); err != nil {
		return fmt.Errorf("add wg-scope: %w", err)
	}
	if err := runNetns(ctx, p.Netns, "ip", "addr", "replace", p.MeshIP+"/16", "dev", iface); err != nil {
		return fmt.Errorf("wg-scope addr: %w", err)
	}
	if err := runNetns(ctx, p.Netns, "ip", "link", "set", "mtu", itoa(mtu), "dev", iface); err != nil {
		return fmt.Errorf("wg-scope mtu: %w", err)
	}

	// Set private key + listen port via `wg set` inside the netns. We use
	// a temp file for the key since `wg set private-key` reads from a path.
	tmp := fmt.Sprintf("/tmp/gmesh-scope-%d.key", p.ID)
	if err := writeFile(tmp, p.PrivateKey, 0o600); err != nil {
		return fmt.Errorf("write key tmp: %w", err)
	}
	defer removeFile(tmp) //nolint:errcheck
	if err := runNetns(ctx, p.Netns, "wg", "set", iface,
		"private-key", tmp,
		"listen-port", itoa(int(p.ListenPort))); err != nil {
		return fmt.Errorf("wg set: %w", err)
	}
	if err := runNetns(ctx, p.Netns, "ip", "link", "set", iface, "up"); err != nil {
		return fmt.Errorf("wg-scope up: %w", err)
	}
	return nil
}

func (m *LinuxManager) setupDNAT(ctx context.Context, p *Peer) error {
	port := itoa(int(p.ListenPort))
	// -C first: a retry must not stack a second identical rule. Duplicate
	// FORWARD/PREROUTING entries are how a chain quietly grows to dozens
	// of copies of the same line over a host's lifetime.
	dnat := []string{"-t", "nat", "PREROUTING",
		"-p", "udp", "--dport", port,
		"-j", "DNAT", "--to-destination", p.ScopeVethIP + ":" + port}
	if err := ensureRule(ctx, dnat); err != nil {
		return fmt.Errorf("iptables DNAT: %w", err)
	}
	fwd := []string{"FORWARD",
		"-d", p.ScopeVethIP, "-p", "udp", "--dport", port, "-j", "ACCEPT"}
	if err := ensureRule(ctx, fwd); err != nil {
		return fmt.Errorf("iptables FORWARD: %w", err)
	}
	return nil
}

// tearDown reverses Connect. Every sub-step is best-effort; we keep going
// on failures and report the last error.
func (m *LinuxManager) tearDown(ctx context.Context, p *Peer) error {
	var lastErr error
	port := itoa(int(p.ListenPort))

	// DNAT rule + forward rule (use `-D` to delete by spec).
	if err := run(ctx, "iptables", "-t", "nat", "-D", "PREROUTING",
		"-p", "udp", "--dport", port,
		"-j", "DNAT", "--to-destination", p.ScopeVethIP+":"+port); err != nil {
		lastErr = err
	}
	if err := run(ctx, "iptables", "-D", "FORWARD",
		"-d", p.ScopeVethIP, "-p", "udp", "--dport", port, "-j", "ACCEPT"); err != nil {
		lastErr = err
	}

	// Delete veth (also removes scope end inside netns) — but only if this
	// daemon created it. Adopting a veth an earlier attempt left behind
	// does not make it ours to destroy on a later failure.
	if p.ownsVeth {
		if err := run(ctx, "ip", "link", "del", p.VethHost); err != nil && !strings.Contains(err.Error(), "Cannot find") {
			lastErr = err
		}
	}
	// The namespace is only ever ours when we created it. On a GritivaCore
	// host the agent builds scope-{id} and the running service lives
	// inside; deleting it because a later step failed would take the
	// service's networking down as collateral for a rollback.
	if p.ownsNetns {
		if err := run(ctx, "ip", "netns", "del", p.Netns); err != nil && !strings.Contains(err.Error(), "No such file") {
			lastErr = err
		}
	}
	return lastErr
}

// ── Small helpers ──────────────────────────────────────────────────────

// linkExists reports whether a network interface is present on the host.
func linkExists(ctx context.Context, name string) bool {
	return exec.CommandContext(ctx, "ip", "link", "show", name).Run() == nil
}

// ensureRule appends an iptables rule unless an identical one is already
// there. `spec` is the rule without the leading -A/-C verb.
func ensureRule(ctx context.Context, spec []string) error {
	if exec.CommandContext(ctx, "iptables", spliceVerb(spec, "-C")...).Run() == nil {
		return nil // already present
	}
	return run(ctx, "iptables", spliceVerb(spec, "-A")...)
}

func run(ctx context.Context, name string, args ...string) error {
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %w (%s)", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

// runNetns prefixes the command with `ip netns exec <ns>`.
func runNetns(ctx context.Context, ns, name string, args ...string) error {
	full := append([]string{"netns", "exec", ns, name}, args...)
	return run(ctx, "ip", full...)
}

// runNetnsIdempotent is a wrapper around runNetns that treats kernel
// EEXIST ('File exists') as success. Used for ip link add operations
// where the interface may have been created by a prior successful run
// that gmeshd has lost track of (init respawn destroyed the netns, but
// the wg-scope interface persisted; OR a partial cleanup left it
// behind). Without this the scope_connect RPC bubbles up an INTERNAL
// error to the panel, the agent's client-side recovery has to disconnect
// + retry, and the cascade spreads. 2026-05-21.
func runNetnsIdempotent(ctx context.Context, ns, name string, args ...string) error {
	err := runNetns(ctx, ns, name, args...)
	if err != nil && strings.Contains(err.Error(), "File exists") {
		return nil
	}
	return err
}

func itoa(n int) string { return fmt.Sprintf("%d", n) }

// writeFile is a tiny helper that avoids pulling os package into the file
// just for WriteFile.
func writeFile(path, content string, mode uint32) error {
	return writeFileImpl(path, content, mode)
}

func removeFile(path string) error {
	return removeFileImpl(path)
}
