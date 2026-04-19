//go:build linux

package circuit

import (
	"context"
	"fmt"
	"log/slog"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// LinuxManager installs per-circuit nftables + iproute2 state and
// reacts to the node's role in the circuit.
//
// Ruleset layout (inside table `inet gmesh-circuit`):
//
//   chain circuit_source_out  hook output    priority mangle
//   chain circuit_transit_fwd hook forward   priority mangle
//   chain circuit_exit_post   hook postrouting priority srcnat
//   chain circuit_exit_fwd    hook forward   priority filter
//
// Rules are per-circuit, tagged with `comment "circuit-<id>"` so the
// delete path flushes them by comment (same pattern as egress).
type LinuxManager struct {
	Log      *slog.Logger
	NftTable string

	mu       sync.Mutex
	circuits map[int64]*Circuit
	roles    map[int64]Role // per-circuit role this node plays
	ensured  bool
}

// NewLinux returns a ready LinuxManager.
func NewLinux(log *slog.Logger) *LinuxManager {
	if log == nil {
		log = slog.Default()
	}
	return &LinuxManager{
		Log: log, NftTable: "gmesh-circuit",
		circuits: map[int64]*Circuit{},
		roles:    map[int64]Role{},
	}
}

// Name returns "linux".
func (m *LinuxManager) Name() string { return "linux" }

// Create installs this node's share of the circuit. nextHopMeshIP is
// the mesh IP of the peer this node must send traffic to — resolved by
// the engine before the call.
func (m *LinuxManager) Create(ctx context.Context, c *Circuit, nextHopMeshIP, wgIface string, localPeerID int64) (*Circuit, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	if wgIface == "" {
		return nil, fmt.Errorf("circuit linux: wg_iface required")
	}
	role := c.RoleFor(localPeerID)
	if role == RoleNone {
		// Nothing to install here — node is not in the circuit. Still
		// record the circuit so operators see a consistent list across
		// nodes; Delete is then a no-op.
		m.mu.Lock()
		defer m.mu.Unlock()
		if _, ok := m.circuits[c.ID]; ok {
			return nil, ErrExists
		}
		now := time.Now()
		c.CreatedAt = now
		c.UpdatedAt = now
		m.circuits[c.ID] = c
		m.roles[c.ID] = RoleNone
		m.Log.Info("circuit recorded (no-op for this node)",
			"id", c.ID, "name", c.Name,
			"path", FormatHops(c.Source, c.Hops))
		return c, nil
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.circuits[c.ID]; ok {
		return nil, ErrExists
	}
	if err := m.ensureNftTable(ctx); err != nil {
		return nil, err
	}

	switch role {
	case RoleSource:
		if nextHopMeshIP == "" {
			return nil, fmt.Errorf("circuit linux: source role needs next_hop_mesh_ip")
		}
		if err := m.installSource(ctx, c, nextHopMeshIP, wgIface); err != nil {
			return nil, fmt.Errorf("install source: %w", err)
		}
	case RoleTransit:
		if nextHopMeshIP == "" {
			return nil, fmt.Errorf("circuit linux: transit role needs next_hop_mesh_ip")
		}
		if err := m.installTransit(ctx, c, nextHopMeshIP, wgIface); err != nil {
			return nil, fmt.Errorf("install transit: %w", err)
		}
	case RoleExit:
		if err := m.installExit(ctx, c, wgIface); err != nil {
			return nil, fmt.Errorf("install exit: %w", err)
		}
	}

	now := time.Now()
	c.CreatedAt = now
	c.UpdatedAt = now
	m.circuits[c.ID] = c
	m.roles[c.ID] = role
	m.Log.Info("circuit installed",
		"id", c.ID, "name", c.Name, "role", role,
		"path", FormatHops(c.Source, c.Hops),
		"next_hop_ip", nextHopMeshIP)
	return c, nil
}

// Update re-installs a circuit atomically.
func (m *LinuxManager) Update(ctx context.Context, c *Circuit, nextHopMeshIP, wgIface string, localPeerID int64) (*Circuit, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	m.mu.Lock()
	old, ok := m.circuits[c.ID]
	m.mu.Unlock()
	if !ok {
		return nil, ErrNotFound
	}
	if err := m.Delete(ctx, c.ID); err != nil {
		return nil, fmt.Errorf("update (delete step): %w", err)
	}
	c.CreatedAt = old.CreatedAt
	return m.Create(ctx, c, nextHopMeshIP, wgIface, localPeerID)
}

// Delete tears down this node's share. Idempotent.
func (m *LinuxManager) Delete(ctx context.Context, circuitID int64) error {
	m.mu.Lock()
	c, ok := m.circuits[circuitID]
	role := m.roles[circuitID]
	delete(m.circuits, circuitID)
	delete(m.roles, circuitID)
	m.mu.Unlock()
	if !ok {
		return nil
	}

	// Best-effort rebuild via flush-and-reinsert for the relevant chains.
	_ = m.runNftInput(ctx, m.nftReflush())
	// Route table + ip rule cleanup for source / transit.
	switch role {
	case RoleSource, RoleTransit:
		table := TableID(circuitID)
		mark := FwMark(circuitID)
		_ = run(ctx, "ip", "rule", "del", "fwmark", fmt.Sprintf("0x%x", mark),
			"lookup", itoa(table))
		_ = run(ctx, "ip", "route", "flush", "table", itoa(table))
	}
	m.Log.Info("circuit removed", "id", circuitID, "role", role, "name", c.Name)
	return nil
}

// List returns a snapshot.
func (m *LinuxManager) List() []*Circuit {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]*Circuit, 0, len(m.circuits))
	for _, c := range m.circuits {
		cp := *c
		out = append(out, &cp)
	}
	return out
}

// ── install helpers ──────────────────────────────────────────────────

func (m *LinuxManager) installSource(ctx context.Context, c *Circuit, nextHopIP, wgIface string) error {
	table := TableID(c.ID)
	mark := FwMark(c.ID)
	prio := RulePriority(c.Priority)
	// 1) route default for this circuit's table to hops[0].
	if err := run(ctx, "ip", "route", "replace", "default", "via", nextHopIP,
		"dev", wgIface, "table", itoa(table)); err != nil {
		return fmt.Errorf("source route: %w", err)
	}
	// 2) ip rule to steer by fwmark. Pre-delete for restart idempotency.
	for i := 0; i < 8; i++ {
		if err := run(ctx, "ip", "rule", "del", "fwmark", fmt.Sprintf("0x%x", mark),
			"lookup", itoa(table)); err != nil {
			break
		}
	}
	if err := run(ctx, "ip", "rule", "add", "fwmark", fmt.Sprintf("0x%x", mark),
		"lookup", itoa(table), "priority", itoa(prio)); err != nil {
		return fmt.Errorf("source ip rule: %w", err)
	}
	// 3) nft mark rule in the output chain.
	return m.runNftInput(ctx, m.nftSourceRule(c, mark))
}

func (m *LinuxManager) installTransit(ctx context.Context, c *Circuit, nextHopIP, wgIface string) error {
	_ = run(ctx, "sysctl", "-qw", "net.ipv4.ip_forward=1")

	table := TableID(c.ID)
	mark := FwMark(c.ID)
	prio := RulePriority(c.Priority)

	// Transit needs a route to push traffic onwards.
	if err := run(ctx, "ip", "route", "replace", "default", "via", nextHopIP,
		"dev", wgIface, "table", itoa(table)); err != nil {
		return fmt.Errorf("transit route: %w", err)
	}
	for i := 0; i < 8; i++ {
		if err := run(ctx, "ip", "rule", "del", "fwmark", fmt.Sprintf("0x%x", mark),
			"lookup", itoa(table)); err != nil {
			break
		}
	}
	if err := run(ctx, "ip", "rule", "add", "fwmark", fmt.Sprintf("0x%x", mark),
		"lookup", itoa(table), "priority", itoa(prio)); err != nil {
		return fmt.Errorf("transit ip rule: %w", err)
	}
	// nft: mark packets arriving from the PREV hop destined for the
	// circuit filter and matching the source meshIP; set circuit fwmark
	// so they route through the table above.
	return m.runNftInput(ctx, m.nftTransitRule(c, mark))
}

func (m *LinuxManager) installExit(ctx context.Context, c *Circuit, wgIface string) error {
	_ = run(ctx, "sysctl", "-qw", "net.ipv4.ip_forward=1")
	return m.runNftInput(ctx, m.nftExitRule(c, wgIface))
}

// ── nft helpers ──────────────────────────────────────────────────────

func (m *LinuxManager) ensureNftTable(ctx context.Context) error {
	if m.ensured {
		return nil
	}
	_ = m.runNftInput(ctx, fmt.Sprintf("delete table inet %s\n", m.NftTable))
	script := fmt.Sprintf(`
add table inet %[1]s
add chain inet %[1]s circuit_source_out { type route hook output priority mangle; }
add chain inet %[1]s circuit_transit_fwd { type filter hook forward priority mangle; }
add chain inet %[1]s circuit_exit_post { type nat hook postrouting priority srcnat; }
add chain inet %[1]s circuit_exit_fwd { type filter hook forward priority filter; }
`, m.NftTable)
	if err := m.runNftInput(ctx, script); err != nil {
		return fmt.Errorf("ensure nft circuit table: %w", err)
	}
	m.ensured = true
	return nil
}

// matchBody builds the per-circuit filter (protocol, dest CIDR, ports)
// — the shared prefix of source/transit rules.
func (m *LinuxManager) matchBody(c *Circuit) []string {
	body := []string{}
	switch c.Protocol {
	case "tcp":
		body = append(body, "ip protocol tcp")
	case "udp":
		body = append(body, "ip protocol udp")
	}
	if c.DestCIDR != "" && c.DestCIDR != "0.0.0.0/0" {
		body = append(body, "ip daddr "+c.DestCIDR)
	}
	if c.DestPorts != "" {
		proto := c.Protocol
		if proto == "" || proto == "any" {
			proto = "tcp"
		}
		body = append(body, fmt.Sprintf("%s dport %s", proto, c.DestPorts))
	}
	return body
}

func (m *LinuxManager) nftSourceRule(c *Circuit, mark uint32) string {
	body := m.matchBody(c)
	body = append(body, "counter",
		fmt.Sprintf(`meta mark set 0x%x`, mark),
		fmt.Sprintf(`ct mark set 0x%x`, mark),
		fmt.Sprintf(`comment "circuit-%d"`, c.ID))
	return fmt.Sprintf("add rule inet %s circuit_source_out %s\n",
		m.NftTable, strings.Join(body, " "))
}

func (m *LinuxManager) nftTransitRule(c *Circuit, mark uint32) string {
	body := m.matchBody(c)
	// Only mark packets that arrived via the wg interface (the outer
	// tunnel) — otherwise an unrelated LAN flow could get marked.
	body = append([]string{`iifname "wg-gmesh"`}, body...)
	body = append(body, "counter",
		fmt.Sprintf(`meta mark set 0x%x`, mark),
		fmt.Sprintf(`comment "circuit-%d"`, c.ID))
	return fmt.Sprintf("add rule inet %s circuit_transit_fwd %s\n",
		m.NftTable, strings.Join(body, " "))
}

func (m *LinuxManager) nftExitRule(c *Circuit, wgIface string) string {
	var b strings.Builder
	// Accept forwarded packets from the wg-gmesh interface to the
	// outside; accept return traffic as long as the flow is established.
	fmt.Fprintf(&b,
		"add rule inet %s circuit_exit_fwd iifname \"%s\" oifname != \"%s\" counter accept comment \"circuit-%d\"\n",
		m.NftTable, wgIface, wgIface, c.ID)
	fmt.Fprintf(&b,
		"add rule inet %s circuit_exit_fwd iifname != \"%s\" oifname \"%s\" ct state established,related counter accept comment \"circuit-%d\"\n",
		m.NftTable, wgIface, wgIface, c.ID)
	// MASQUERADE packets leaving the exit to the internet. We scope by
	// iifname to avoid MASQUERADing every outgoing flow on the host.
	fmt.Fprintf(&b,
		"add rule inet %s circuit_exit_post iifname \"%s\" oifname != \"%s\" masquerade comment \"circuit-%d\"\n",
		m.NftTable, wgIface, wgIface, c.ID)
	return b.String()
}

// nftReflush rebuilds the table from scratch based on the in-memory
// circuit set. Same flush-and-reinsert pattern as egress; simpler than
// rule-handle bookkeeping and costs one kernel transaction per delete.
func (m *LinuxManager) nftReflush() string {
	var b strings.Builder
	fmt.Fprintf(&b, "flush chain inet %s circuit_source_out\n", m.NftTable)
	fmt.Fprintf(&b, "flush chain inet %s circuit_transit_fwd\n", m.NftTable)
	fmt.Fprintf(&b, "flush chain inet %s circuit_exit_fwd\n", m.NftTable)
	fmt.Fprintf(&b, "flush chain inet %s circuit_exit_post\n", m.NftTable)
	// Re-add the remaining circuits' rules.
	for id, c := range m.circuits {
		switch m.roles[id] {
		case RoleSource:
			b.WriteString(m.nftSourceRule(c, FwMark(c.ID)))
		case RoleTransit:
			b.WriteString(m.nftTransitRule(c, FwMark(c.ID)))
		case RoleExit:
			b.WriteString(m.nftExitRule(c, "wg-gmesh"))
		}
	}
	return b.String()
}

// ── shell-outs ───────────────────────────────────────────────────────

func (m *LinuxManager) runNftInput(ctx context.Context, script string) error {
	cmd := exec.CommandContext(ctx, "nft", "-f", "-")
	cmd.Stdin = strings.NewReader(script)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("nft: %w (%s)", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func run(ctx context.Context, name string, args ...string) error {
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %w (%s)",
			name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

func itoa(n int) string { return fmt.Sprintf("%d", n) }
