//go:build linux

package ingress

import (
	"context"
	"fmt"
	"log/slog"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// LinuxManager installs real nftables DNAT rules via shell-out to `nft`.
//
// Table `inet gmesh-ingress` layout:
//
//	chain prerouting  { type nat    hook prerouting  priority dstnat; }
//	chain forward     { type filter hook forward     priority filter; }
//	chain postrouting { type nat    hook postrouting priority srcnat; }
//
// Each profile adds three rules (one per chain), all annotated with
// comment "ingress-<id>" for later removal via flush+rebuild.
type LinuxManager struct {
	Log      *slog.Logger
	NftTable string // default "gmesh-ingress"

	mu       sync.Mutex
	profiles map[int64]*Profile
	ensured  bool
}

// NewLinux returns the real Linux manager.
func NewLinux(log *slog.Logger) *LinuxManager {
	if log == nil {
		log = slog.Default()
	}
	return &LinuxManager{Log: log, NftTable: "gmesh-ingress", profiles: make(map[int64]*Profile)}
}

// Name returns "linux".
func (m *LinuxManager) Name() string { return "linux" }

// Create installs kernel state for p.
func (m *LinuxManager) Create(ctx context.Context, p *Profile) (*Profile, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.profiles[p.ID]; ok {
		return nil, ErrExists
	}
	if err := m.ensureTable(ctx); err != nil {
		return nil, err
	}

	// Best-effort ensure net.ipv4.ip_forward — ingress means we'll forward
	// from the public interface into the mesh, which needs forwarding on.
	_ = runNft(ctx, "", "sysctl", "-qw", "net.ipv4.ip_forward=1")

	now := time.Now()
	p.CreatedAt = now
	p.UpdatedAt = now
	m.profiles[p.ID] = p

	if err := m.reapply(ctx); err != nil {
		delete(m.profiles, p.ID)
		return nil, fmt.Errorf("ingress create: %w", err)
	}
	m.Log.Info("ingress profile installed",
		"id", p.ID, "name", p.Name,
		"edge_port", p.EdgePort, "backend", fmt.Sprintf("%s:%d", p.BackendIP, p.BackendPort))
	return p, nil
}

// Update re-installs a profile.
func (m *LinuxManager) Update(ctx context.Context, p *Profile) (*Profile, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	old, ok := m.profiles[p.ID]
	if !ok {
		return nil, ErrNotFound
	}
	p.CreatedAt = old.CreatedAt
	p.UpdatedAt = time.Now()
	m.profiles[p.ID] = p
	if err := m.reapply(ctx); err != nil {
		m.profiles[p.ID] = old
		_ = m.reapply(ctx)
		return nil, fmt.Errorf("ingress update: %w", err)
	}
	return p, nil
}

// Delete removes kernel state. Idempotent.
func (m *LinuxManager) Delete(ctx context.Context, profileID int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.profiles[profileID]; !ok {
		return nil
	}
	delete(m.profiles, profileID)
	return m.reapply(ctx)
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

// ── Internals ────────────────────────────────────────────────────────

// ensureTable installs the empty table + three chains. Idempotent.
func (m *LinuxManager) ensureTable(ctx context.Context) error {
	if m.ensured {
		return nil
	}
	script := fmt.Sprintf(`
add table inet %[1]s
add chain inet %[1]s prerouting  { type nat    hook prerouting  priority dstnat; }
add chain inet %[1]s forward     { type filter hook forward     priority filter; }
add chain inet %[1]s postrouting { type nat    hook postrouting priority srcnat; }
`, m.NftTable)
	if err := runNft(ctx, script); err != nil {
		return fmt.Errorf("ensure ingress table: %w", err)
	}
	m.ensured = true
	return nil
}

// reapply flushes all three chains and re-installs rules for every
// active profile. Called from Create/Update/Delete under m.mu.
func (m *LinuxManager) reapply(ctx context.Context) error {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("flush chain inet %s prerouting\n", m.NftTable))
	b.WriteString(fmt.Sprintf("flush chain inet %s forward\n", m.NftTable))
	b.WriteString(fmt.Sprintf("flush chain inet %s postrouting\n", m.NftTable))
	for _, p := range m.profiles {
		if !p.Enabled {
			continue
		}
		b.WriteString(m.ruleFor(p))
	}
	return runNft(ctx, b.String())
}

// ruleFor produces the three-line nft script for one profile.
func (m *LinuxManager) ruleFor(p *Profile) string {
	proto := p.Protocol
	if proto == "" {
		proto = "tcp"
	}

	// Optional source-CIDR filter.
	srcFilter := ""
	if len(p.AllowedSources) > 0 {
		srcFilter = fmt.Sprintf("ip saddr { %s } ", strings.Join(p.AllowedSources, ", "))
	}

	// prerouting DNAT: inbound edge_port → backend_ip:backend_port.
	pre := fmt.Sprintf(
		"add rule inet %s prerouting %s%s dport %d dnat ip to %s:%d comment \"ingress-%d\"\n",
		m.NftTable, srcFilter, proto, p.EdgePort, p.BackendIP, p.BackendPort, p.ID,
	)
	// forward: allow both directions of the DNATed flow.
	fwd := fmt.Sprintf(
		"add rule inet %s forward %sip daddr %s %s dport %d ct state new,established,related accept comment \"ingress-%d\"\n",
		m.NftTable, srcFilter, p.BackendIP, proto, p.BackendPort, p.ID,
	)
	// postrouting MASQUERADE: rewrite source so the backend's reply comes
	// back to the edge (which holds conntrack state).
	post := fmt.Sprintf(
		"add rule inet %s postrouting ip daddr %s %s dport %d masquerade comment \"ingress-%d\"\n",
		m.NftTable, p.BackendIP, proto, p.BackendPort, p.ID,
	)
	return pre + fwd + post
}

// runNft executes `nft -f -` with the given script as stdin. If script
// is empty, it runs the remaining args directly (used for sysctl above).
func runNft(ctx context.Context, script string, cmdArgs ...string) error {
	if script != "" {
		cmd := exec.CommandContext(ctx, "nft", "-f", "-")
		cmd.Stdin = strings.NewReader(script)
		out, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("nft: %w (%s)", err, strings.TrimSpace(string(out)))
		}
		return nil
	}
	if len(cmdArgs) == 0 {
		return fmt.Errorf("runNft: empty args")
	}
	cmd := exec.CommandContext(ctx, cmdArgs[0], cmdArgs[1:]...)
	_, _ = cmd.CombinedOutput()
	return nil // best-effort
}
