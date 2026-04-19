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
	if wgIface == "" {
		return nil, fmt.Errorf("egress linux: wg_iface required")
	}
	// Single-exit profiles must provide the exit peer's mesh IP. Pool
	// profiles use p.ExitPoolMeshIPs (populated by the engine) instead
	// and ignore exitPeerMeshIP.
	if len(p.ExitPool) == 0 && exitPeerMeshIP == "" {
		return nil, fmt.Errorf("egress linux: exit_peer_mesh_ip required for single-exit profiles")
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, ok := m.profiles[p.ID]; ok {
		return nil, ErrExists
	}
	if err := m.ensureNftTable(ctx); err != nil {
		return nil, err
	}
	if err := m.ensureGeoIPSet(ctx, p); err != nil {
		return nil, fmt.Errorf("install geoip set: %w", err)
	}

	prio := RulePriority(p.Priority)

	if len(p.ExitPool) > 0 {
		if err := m.installPool(ctx, p, wgIface, prio); err != nil {
			return nil, err
		}
	} else {
		table := TableID(p.ID)
		mark := FwMark(p.ID)

		// 1. Install default route in per-profile table.
		if err := run(ctx, "ip", "route", "replace", "default", "via", exitPeerMeshIP, "dev", wgIface, "table", itoa(table)); err != nil {
			return nil, fmt.Errorf("install route: %w", err)
		}

		// 2. Install `ip rule from fwmark X lookup T`. Pre-delete so
		//    `ip rule add` is idempotent across daemon restarts — without
		//    this a stale rule from the previous process trips
		//    "File exists". We delete ALL rules matching the mark and
		//    table combo, not just one, because operators may have
		//    accidentally duplicated a rule in the past.
		for i := 0; i < 8; i++ {
			if err := run(ctx, "ip", "rule", "del", "fwmark", fmt.Sprintf("0x%x", mark),
				"lookup", itoa(table)); err != nil {
				break
			}
		}
		if err := run(ctx, "ip", "rule", "add", "fwmark", fmt.Sprintf("0x%x", mark),
			"lookup", itoa(table), "priority", itoa(prio)); err != nil {
			_ = run(ctx, "ip", "route", "del", "default", "table", itoa(table))
			return nil, fmt.Errorf("install rule: %w", err)
		}

		// 3. Install nftables mark rule with a comment so we can find & remove later.
		script := m.nftMarkRule(p, mark)
		if err := m.runNftInput(ctx, script); err != nil {
			_ = run(ctx, "ip", "rule", "del", "fwmark", fmt.Sprintf("0x%x", mark), "lookup", itoa(table))
			_ = run(ctx, "ip", "route", "del", "default", "table", itoa(table))
			return nil, fmt.Errorf("install nft mark: %w", err)
		}
		m.Log.Info("egress profile installed",
			"id", p.ID, "name", p.Name, "source", p.Source(),
			"exit_ip", exitPeerMeshIP, "table", table, "mark", fmt.Sprintf("0x%x", mark))
	}

	now := time.Now()
	p.CreatedAt = now
	p.UpdatedAt = now
	m.profiles[p.ID] = p
	return p, nil
}

// installPool wires up a weighted exit pool. One routing table per pool
// entry, one `ip rule` per mark, and a single numgen-based nft rule that
// stamps the right mark on each new flow. Weights need not normalise —
// we sum them and map [0..sum) into the vmap.
func (m *LinuxManager) installPool(ctx context.Context, p *Profile, wgIface string, prio int) error {
	if len(p.ExitPool) != len(p.ExitPoolMeshIPs) {
		return fmt.Errorf("egress: pool/mesh_ips length mismatch (%d vs %d)",
			len(p.ExitPool), len(p.ExitPoolMeshIPs))
	}
	var total int32
	for _, w := range p.ExitWeights {
		total += w
	}
	// 1. Per-entry route + ip rule.
	for i := range p.ExitPool {
		tbl := PoolTableID(p.ID, i)
		mk := PoolFwMark(p.ID, i)
		if err := run(ctx, "ip", "route", "replace", "default", "via", p.ExitPoolMeshIPs[i],
			"dev", wgIface, "table", itoa(tbl)); err != nil {
			return fmt.Errorf("pool route[%d]: %w", i, err)
		}
		// Pre-delete stale rules for this (mark, table) pair — idempotent
		// restart. See the single-exit path above for the rationale.
		for j := 0; j < 8; j++ {
			if err := run(ctx, "ip", "rule", "del", "fwmark", fmt.Sprintf("0x%x", mk),
				"lookup", itoa(tbl)); err != nil {
				break
			}
		}
		if err := run(ctx, "ip", "rule", "add", "fwmark", fmt.Sprintf("0x%x", mk),
			"lookup", itoa(tbl), "priority", itoa(prio+i)); err != nil {
			return fmt.Errorf("pool rule[%d]: %w", i, err)
		}
	}
	// 2. Build the numgen vmap body.
	var b strings.Builder
	var cursor int32
	for i, w := range p.ExitWeights {
		if w == 0 {
			continue
		}
		if b.Len() > 0 {
			b.WriteString(", ")
		}
		end := cursor + w - 1
		fmt.Fprintf(&b, "%d-%d : 0x%x", cursor, end, PoolFwMark(p.ID, i))
		cursor += w
	}
	// 3. Pool nft rule. Uses `numgen inc mod <total>` → deterministic
	// round-robin scaled by weight; for random (non-deterministic) use
	// switch to `numgen random`.
	body := m.nftMarkRulePool(p, total, b.String())
	if err := m.runNftInput(ctx, body); err != nil {
		return fmt.Errorf("install pool nft: %w", err)
	}
	m.Log.Info("egress pool installed",
		"id", p.ID, "name", p.Name, "pool_size", len(p.ExitPool), "total_weight", total)
	return nil
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

	// Teardown in reverse order; best-effort.
	_ = m.runNftInput(ctx, m.nftDeleteByComment(p.ID))
	// Clean up per-profile geoip set if it exists. Ignore errors — the
	// set may never have been created.
	_ = m.runNftInput(ctx,
		fmt.Sprintf("delete set inet %s geoip_%d\n", m.NftTable, profileID))
	if len(p.ExitPool) > 0 {
		for i := range p.ExitPool {
			tbl := PoolTableID(profileID, i)
			mk := PoolFwMark(profileID, i)
			_ = run(ctx, "ip", "rule", "del", "fwmark", fmt.Sprintf("0x%x", mk),
				"lookup", itoa(tbl))
			_ = run(ctx, "ip", "route", "flush", "table", itoa(tbl))
		}
	} else {
		table := TableID(profileID)
		mark := FwMark(profileID)
		_ = run(ctx, "ip", "rule", "del", "fwmark", fmt.Sprintf("0x%x", mark), "lookup", itoa(table))
		_ = run(ctx, "ip", "route", "flush", "table", itoa(table))
	}
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

// ensureNftTable creates the table + chain if missing. Idempotent within
// a single daemon run, and idempotent ACROSS daemon restarts by wiping
// the table on first call — the previous daemon's rules are orphaned
// (the in-memory profile map was lost at restart anyway), so the new
// daemon owns the kernel state cleanly. The caller holds m.mu, and
// ensured flips to true only after a successful rebuild, so concurrent
// Create calls serialize on the mutex instead of racing the table.
func (m *LinuxManager) ensureNftTable(ctx context.Context) error {
	if m.ensured {
		return nil
	}
	// First-call rebuild: delete-then-add. Silently ignore the delete if
	// the table doesn't exist yet. This replaces the earlier `add table`
	// approach, which left guard rules doubled after a daemon restart.
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
	// Conntrack-aware marking strategy:
	//
	//   1. First packet of a new flow is evaluated by the profile rule
	//      and marked with fwmark if it matches.
	//   2. `ct mark set meta mark` saves that mark onto the conntrack
	//      entry. Every subsequent packet of this flow inherits from ct.
	//   3. WireGuard encapsulates the inner packet → generates an OUTER
	//      UDP packet to the peer's underlay endpoint. That outer packet
	//      is a brand-new flow: distinct 5-tuple, distinct ct entry, no
	//      inherited mark. It only gets marked if its OWN 5-tuple matches
	//      the profile — which it won't, because the guard excludes
	//      @protected_daddr (Tailscale CGNAT) and @protected_oif
	//      (wg-gmesh / tailscale0).
	//   4. To be safe, we also add an early "skip marking for packets
	//      that already carry the gmesh mark OR come from a ct entry
	//      with a gmesh mark" rule — this stops a re-queued packet from
	//      re-triggering routing + encap.
	// Best-effort delete — ignore the error; the table may not exist.
	_ = m.runNftInput(ctx, fmt.Sprintf("delete table inet %s\n", m.NftTable))
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
add rule inet %[1]s egress_mark_out meta mark and 0xF0000000 == 0x10000000 return
add rule inet %[1]s egress_mark_out ct mark and 0xF0000000 == 0x10000000 meta mark set ct mark return
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
	// GeoIP match layers on top of DestCIDR: both filters must pass. The
	// per-profile nft set is named `geoip_<id>` and populated by
	// ensureGeoIPSet from p.GeoIPCIDRs at Create time.
	if len(p.GeoIPCIDRs) > 0 {
		body = append(body, fmt.Sprintf("ip daddr @geoip_%d", p.ID))
	}
	if p.DestPorts != "" {
		proto := p.Protocol
		if proto == "" || proto == "any" {
			proto = "tcp"
		}
		body = append(body, fmt.Sprintf("%s dport %s", proto, nftPortSet(p.DestPorts)))
	}
	// `counter` attaches a packet+byte counter that Phase 13's Quota
	// Manager polls via `nft -j list table`. Without it, used_bytes
	// stays 0 forever.
	body = append(body, "counter")
	body = append(body, fmt.Sprintf(`meta mark set 0x%x`, mark))
	// Save the mark onto conntrack so subsequent packets of the same flow
	// inherit it via the early `ct mark` return rule in egress_mark_out.
	// This makes fwmark evaluation happen once per flow instead of per
	// packet and decouples it from the packet payload.
	body = append(body, fmt.Sprintf(`ct mark set 0x%x`, mark))
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
	// them here before re-adding profile rules. Keep this list in sync with
	// ensureNftTable's initial rule set.
	b.WriteString(fmt.Sprintf("add rule inet %s egress_mark_out oifname @protected_oif meta mark set 0x0\n", m.NftTable))
	b.WriteString(fmt.Sprintf("add rule inet %s egress_mark_out ip daddr @protected_daddr meta mark set 0x0\n", m.NftTable))
	b.WriteString(fmt.Sprintf("add rule inet %s egress_mark_out meta mark and 0xF0000000 == 0x10000000 return\n", m.NftTable))
	b.WriteString(fmt.Sprintf("add rule inet %s egress_mark_out ct mark and 0xF0000000 == 0x10000000 meta mark set ct mark return\n", m.NftTable))
	// Reinstall remaining profiles (m.profiles already has the deleted one
	// removed before this call).
	for _, p := range m.profiles {
		b.WriteString(m.nftMarkRule(p, FwMark(p.ID)))
	}
	_ = profileID // kept for potential future per-rule deletion via handle
	return b.String()
}

// nftMarkRulePool builds the nft rule used when a profile has a
// weighted exit pool. Same match prefix as nftMarkRule but the mark is
// stamped via `meta mark set numgen inc mod <total> map { … }` so each
// new flow lands in a different routing table keyed by fwmark. Still
// installed in both egress_mark_pre and egress_mark_out to cover
// forwarded + locally-originated traffic.
func (m *LinuxManager) nftMarkRulePool(p *Profile, total int32, vmap string) string {
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
	if len(p.GeoIPCIDRs) > 0 {
		body = append(body, fmt.Sprintf("ip daddr @geoip_%d", p.ID))
	}
	if p.DestPorts != "" {
		proto := p.Protocol
		if proto == "" || proto == "any" {
			proto = "tcp"
		}
		body = append(body, fmt.Sprintf("%s dport %s", proto, nftPortSet(p.DestPorts)))
	}
	body = append(body, "counter")
	body = append(body,
		fmt.Sprintf(`meta mark set numgen inc mod %d map { %s }`, total, vmap))
	body = append(body, fmt.Sprintf(`ct mark set meta mark`))
	body = append(body, fmt.Sprintf(`comment "egress-%d"`, p.ID))

	line := strings.Join(body, " ")
	return fmt.Sprintf("add rule inet %[1]s egress_mark_pre %[2]s\nadd rule inet %[1]s egress_mark_out %[2]s\n",
		m.NftTable, line)
}

// ensureGeoIPSet installs/refreshes the per-profile `geoip_<id>` named
// set in the egress table. No-op when p.GeoIPCIDRs is empty. Delete
// takes care of removing the set via table-level flush on update.
func (m *LinuxManager) ensureGeoIPSet(ctx context.Context, p *Profile) error {
	if len(p.GeoIPCIDRs) == 0 {
		return nil
	}
	setName := fmt.Sprintf("geoip_%d", p.ID)
	// Drop any stale version so re-create picks up a refreshed CIDR list.
	_ = m.runNftInput(ctx, fmt.Sprintf("delete set inet %s %s\n", m.NftTable, setName))
	script := fmt.Sprintf(
		"add set inet %[1]s %[2]s { type ipv4_addr; flags interval; }\n"+
			"add element inet %[1]s %[2]s { %[3]s }\n",
		m.NftTable, setName, strings.Join(p.GeoIPCIDRs, ", "))
	return m.runNftInput(ctx, script)
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
