//go:build linux

package egress

import (
	"context"
	"fmt"
	"log/slog"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// LinuxManager installs real `ip rule` + routing table + nftables mark
// rules via shell-out to the iproute2 + nftables suites.
//
// Layout:
//
//   - One routing table per profile (num = 100 + profile.id mod 1000).
//   - One nftables table `inet gmesh-egress` shared by all profiles; chain
//     `mark` applies marks pre-routing.
//   - One `ip rule` per profile: `from fwmark X lookup T`.
type LinuxManager struct {
	Log       *slog.Logger
	NftTable  string // default "gmesh-egress"

	mu       sync.Mutex
	profiles map[int64]*Profile
	ensured  bool // nft table/chain created?
}

// NewLinux returns the real Linux manager.
func NewLinux(log *slog.Logger) *LinuxManager {
	if log == nil {
		log = slog.Default()
	}
	return &LinuxManager{
		Log:      log,
		NftTable: "gmesh-egress",
		profiles: make(map[int64]*Profile),
	}
}

// Name returns "linux".
func (m *LinuxManager) Name() string { return "linux" }

// Create installs the kernel state for p.
func (m *LinuxManager) Create(ctx context.Context, p *Profile, exitPeerMeshIP, wgIface string) (*Profile, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	if exitPeerMeshIP == "" || wgIface == "" {
		return nil, fmt.Errorf("egress linux: exit_peer_mesh_ip and wg_iface required")
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, ok := m.profiles[p.ID]; ok {
		return nil, ErrExists
	}
	if err := m.ensureNftTable(ctx); err != nil {
		return nil, err
	}

	table := TableID(p.ID)
	mark := FwMark(p.ID)
	prio := RulePriority(p.Priority)

	// 1. Install default route in per-profile table.
	if err := run(ctx, "ip", "route", "replace", "default", "via", exitPeerMeshIP, "dev", wgIface, "table", itoa(table)); err != nil {
		return nil, fmt.Errorf("install route: %w", err)
	}

	// 2. Install `ip rule from fwmark X lookup T`.
	if err := run(ctx, "ip", "rule", "add", "fwmark", fmt.Sprintf("0x%x", mark),
		"lookup", itoa(table), "priority", itoa(prio)); err != nil {
		// Rollback route.
		_ = run(ctx, "ip", "route", "del", "default", "table", itoa(table))
		return nil, fmt.Errorf("install rule: %w", err)
	}

	// 3. Install nftables mark rule with a comment so we can find & remove later.
	script := m.nftMarkRule(p, mark)
	if err := m.runNftInput(ctx, script); err != nil {
		// Rollback ip rule + route.
		_ = run(ctx, "ip", "rule", "del", "fwmark", fmt.Sprintf("0x%x", mark), "lookup", itoa(table))
		_ = run(ctx, "ip", "route", "del", "default", "table", itoa(table))
		return nil, fmt.Errorf("install nft mark: %w", err)
	}

	now := time.Now()
	p.CreatedAt = now
	p.UpdatedAt = now
	m.profiles[p.ID] = p

	m.Log.Info("egress profile installed",
		"id", p.ID, "name", p.Name, "source", p.Source(),
		"exit_ip", exitPeerMeshIP, "table", table, "mark", fmt.Sprintf("0x%x", mark))
	return p, nil
}

// Update reinstalls the profile atomically (delete + create).
func (m *LinuxManager) Update(ctx context.Context, p *Profile, exitPeerMeshIP, wgIface string) (*Profile, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	m.mu.Lock()
	old, ok := m.profiles[p.ID]
	m.mu.Unlock()
	if !ok {
		return nil, ErrNotFound
	}
	if err := m.Delete(ctx, p.ID); err != nil {
		return nil, fmt.Errorf("update (delete step): %w", err)
	}
	p.CreatedAt = old.CreatedAt
	return m.Create(ctx, p, exitPeerMeshIP, wgIface)
}

// Delete tears down kernel state. Idempotent.
func (m *LinuxManager) Delete(ctx context.Context, profileID int64) error {
	m.mu.Lock()
	p, ok := m.profiles[profileID]
	delete(m.profiles, profileID)
	m.mu.Unlock()
	if !ok {
		return nil
	}

	table := TableID(profileID)
	mark := FwMark(profileID)

	// Teardown in reverse order; best-effort.
	_ = m.runNftInput(ctx, m.nftDeleteByComment(p.ID))
	_ = run(ctx, "ip", "rule", "del", "fwmark", fmt.Sprintf("0x%x", mark), "lookup", itoa(table))
	_ = run(ctx, "ip", "route", "flush", "table", itoa(table))
	m.Log.Info("egress profile removed", "id", profileID)
	return nil
}

// List returns a snapshot.
func (m *LinuxManager) List() []*Profile {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]*Profile, 0, len(m.profiles))
	for _, p := range m.profiles {
		cp := *p
		out = append(out, &cp)
	}
	return out
}

// ── Helpers ─────────────────────────────────────────────────────────

// ensureNftTable creates the table + chain if missing. Idempotent.
func (m *LinuxManager) ensureNftTable(ctx context.Context) error {
	if m.ensured {
		return nil
	}
	// Use `add table` (idempotent) rather than delete-and-recreate to avoid
	// wiping other profiles' rules on first use.
	// Two chains hook the mark rule set into both packet paths:
	//   - prerouting: traffic arriving at the host from a scope / local veth
	//                 (forwarded, not locally-originated)
	//   - output:    traffic originating on this host that needs to egress
	// Without the output chain, `curl` from the host itself wouldn't be
	// subject to egress policy — only scope-originated flows would.
	// Named sets scoped to the egress table:
	//   - protected_oif: interface names whose traffic must NEVER be marked
	//     (would either loop or break unrelated overlays).
	//   - protected_daddr: destination CIDRs that must NEVER be routed
	//     through an exit (local LAN, CGNAT/Tailscale, link-local,
	//     multicast, and the mesh range itself).
	//
	// Every per-profile mark rule is prefixed with
	//     oifname != @protected_oif ip daddr != @protected_daddr
	// so no matter how broad the user's filter is, management traffic and
	// LAN access keep working.
	script := fmt.Sprintf(`
add table inet %[1]s
add set inet %[1]s protected_oif { type ifname; }
add element inet %[1]s protected_oif { "wg-gmesh", "tailscale0" }
add set inet %[1]s protected_daddr { type ipv4_addr; flags interval; }
add element inet %[1]s protected_daddr { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 100.64.0.0/10, 169.254.0.0/16, 224.0.0.0/4 }
add chain inet %[1]s egress_mark_pre { type filter hook prerouting priority mangle; }
add chain inet %[1]s egress_mark_out { type route hook output priority mangle; }
add rule inet %[1]s egress_mark_out oifname @protected_oif meta mark set 0x0
add rule inet %[1]s egress_mark_out ip daddr @protected_daddr meta mark set 0x0
`, m.NftTable)
	if err := m.runNftInput(ctx, script); err != nil {
		return fmt.Errorf("ensure nft table: %w", err)
	}
	m.ensured = true
	return nil
}

// nftMarkRule builds the `add rule` line that stamps matching packets
// with fwmark = mark. Comment = `egress-<id>` for later removal.
//
// The rule body always begins with two guard matches:
//   - oifname != @protected_oif  — skip WG + Tailscale interfaces
//   - ip daddr != @protected_daddr — skip LAN, CGNAT, multicast, mesh
// These stop "egress everything" profiles from breaking management
// connectivity or creating routing loops.
func (m *LinuxManager) nftMarkRule(p *Profile, mark uint32) string {
	body := []string{
		`oifname != @protected_oif`,
		`ip daddr != @protected_daddr`,
	}
	if p.SourceCIDR != "" {
		body = append(body, "ip saddr "+p.SourceCIDR)
	}
	switch p.Protocol {
	case "tcp":
		body = append(body, "ip protocol tcp")
	case "udp":
		body = append(body, "ip protocol udp")
	}
	if p.DestCIDR != "" && p.DestCIDR != "0.0.0.0/0" {
		body = append(body, "ip daddr "+p.DestCIDR)
	}
	if p.DestPorts != "" {
		proto := p.Protocol
		if proto == "" || proto == "any" {
			proto = "tcp"
		}
		body = append(body, fmt.Sprintf("%s dport %s", proto, nftPortSet(p.DestPorts)))
	}
	body = append(body, fmt.Sprintf(`meta mark set 0x%x`, mark))
	body = append(body, fmt.Sprintf(`comment "egress-%d"`, p.ID))

	line := strings.Join(body, " ")
	return fmt.Sprintf("add rule inet %[1]s egress_mark_pre %[2]s\nadd rule inet %[1]s egress_mark_out %[2]s\n",
		m.NftTable, line)
}

// nftDeleteByComment deletes every rule in chain `mark` with our profile
// comment. We use a flush-and-reinsert pattern keyed by comment via
// `nft -j list` — simpler approach: flush the whole chain and reinstall
// every still-active profile's rule. For Phase 11 we favour the simpler
// approach at the small cost of a kernel transaction per delete.
func (m *LinuxManager) nftDeleteByComment(profileID int64) string {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("flush chain inet %s egress_mark_pre\n", m.NftTable))
	b.WriteString(fmt.Sprintf("flush chain inet %s egress_mark_out\n", m.NftTable))
	// Re-add the per-chain clear-mark guards that ensureNftTable installed.
	// Flushing the chain wipes them along with profile rules, so restore
	// them here before re-adding profile rules.
	b.WriteString(fmt.Sprintf("add rule inet %s egress_mark_out oifname @protected_oif meta mark set 0x0\n", m.NftTable))
	b.WriteString(fmt.Sprintf("add rule inet %s egress_mark_out ip daddr @protected_daddr meta mark set 0x0\n", m.NftTable))
	// Reinstall remaining profiles (m.profiles already has the deleted one
	// removed before this call).
	for _, p := range m.profiles {
		b.WriteString(m.nftMarkRule(p, FwMark(p.ID)))
	}
	_ = profileID // kept for potential future per-rule deletion via handle
	return b.String()
}

// nftPortSet converts "80" / "80-443" / "22,80,443" into nft syntax.
func nftPortSet(s string) string {
	s = strings.TrimSpace(s)
	if strings.Contains(s, ",") {
		return "{ " + s + " }"
	}
	return s
}

// runNftInput pipes `script` to `nft -f -`.
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
