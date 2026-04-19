//go:build linux

package quota

import (
	"context"
	"fmt"
	"log/slog"
	"os/exec"
	"strings"
	"sync"

	"github.com/mohammad2000/Gmesh/internal/metrics"
)

// LinuxEnforcer installs nftables DROP rules keyed by the egress
// profile's fwmark (0x1_______). The table is separate from
// `gmesh-egress` so toggling hard-stop on/off never touches the
// mark chain and can't race with ordinary profile edits.
//
// Ruleset:
//
//   table inet gmesh-quota {
//       chain quota_drop_out { type filter hook output priority filter; }
//       chain quota_drop_fwd { type filter hook forward priority filter; }
//   }
//
// Per blocked profile we insert:
//
//   meta mark 0x1000000a counter drop comment "quota-drop-10"
//
// into both chains — `output` catches traffic originated on the host,
// `forward` catches traffic arriving from a scope / veth / peer.
//
// Unblock flushes both chains and reinserts every still-blocked profile
// to avoid relying on nft rule handles.
type LinuxEnforcer struct {
	Log   *slog.Logger
	Table string

	mu      sync.Mutex
	blocked map[int64]uint32 // profile id → mark
	ensured bool
}

// NewLinuxEnforcer returns a real Linux enforcer.
func NewLinuxEnforcer(log *slog.Logger) *LinuxEnforcer {
	if log == nil {
		log = slog.Default()
	}
	return &LinuxEnforcer{
		Log: log, Table: "gmesh-quota",
		blocked: map[int64]uint32{},
	}
}

// Name returns "linux".
func (e *LinuxEnforcer) Name() string { return "linux" }

func (e *LinuxEnforcer) ensure(ctx context.Context) error {
	if e.ensured {
		return nil
	}
	// Idempotent across daemon restarts: wipe-then-rebuild so stale DROP
	// rules from a previous run don't silently outlive the process.
	_ = e.runNft(ctx, fmt.Sprintf("delete table inet %s\n", e.Table))
	script := fmt.Sprintf(`
add table inet %[1]s
add chain inet %[1]s quota_drop_out { type filter hook output priority filter; }
add chain inet %[1]s quota_drop_fwd { type filter hook forward priority filter; }
`, e.Table)
	if err := e.runNft(ctx, script); err != nil {
		return fmt.Errorf("enforcer ensure: %w", err)
	}
	e.ensured = true
	return nil
}

// Block installs DROP rules for mark.
func (e *LinuxEnforcer) Block(ctx context.Context, egressProfileID int64, mark uint32) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if err := e.ensure(ctx); err != nil {
		return err
	}
	if _, ok := e.blocked[egressProfileID]; ok {
		return nil
	}
	script := fmt.Sprintf(`add rule inet %[1]s quota_drop_out meta mark 0x%[2]x counter drop comment "quota-drop-%[3]d"
add rule inet %[1]s quota_drop_fwd meta mark 0x%[2]x counter drop comment "quota-drop-%[3]d"
`, e.Table, mark, egressProfileID)
	if err := e.runNft(ctx, script); err != nil {
		return fmt.Errorf("block: %w", err)
	}
	e.blocked[egressProfileID] = mark
	e.Log.Info("quota hard-stop DROP installed",
		"profile", egressProfileID, "mark", fmt.Sprintf("0x%x", mark))
	metrics.QuotaBlocks.WithLabelValues("block").Inc()
	return nil
}

// Unblock removes DROP rules. Idempotent.
func (e *LinuxEnforcer) Unblock(ctx context.Context, egressProfileID int64) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if _, ok := e.blocked[egressProfileID]; !ok {
		return nil
	}
	delete(e.blocked, egressProfileID)
	if !e.ensured {
		return nil
	}
	var b strings.Builder
	b.WriteString(fmt.Sprintf("flush chain inet %s quota_drop_out\n", e.Table))
	b.WriteString(fmt.Sprintf("flush chain inet %s quota_drop_fwd\n", e.Table))
	for pid, mark := range e.blocked {
		b.WriteString(fmt.Sprintf(
			`add rule inet %[1]s quota_drop_out meta mark 0x%[2]x counter drop comment "quota-drop-%[3]d"`+"\n",
			e.Table, mark, pid))
		b.WriteString(fmt.Sprintf(
			`add rule inet %[1]s quota_drop_fwd meta mark 0x%[2]x counter drop comment "quota-drop-%[3]d"`+"\n",
			e.Table, mark, pid))
	}
	if err := e.runNft(ctx, b.String()); err != nil {
		return fmt.Errorf("unblock: %w", err)
	}
	e.Log.Info("quota hard-stop DROP removed", "profile", egressProfileID)
	metrics.QuotaBlocks.WithLabelValues("unblock").Inc()
	return nil
}

func (e *LinuxEnforcer) runNft(ctx context.Context, script string) error {
	cmd := exec.CommandContext(ctx, "nft", "-f", "-")
	cmd.Stdin = strings.NewReader(script)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("nft: %w (%s)", err, strings.TrimSpace(string(out)))
	}
	return nil
}

var _ Enforcer = (*LinuxEnforcer)(nil)
