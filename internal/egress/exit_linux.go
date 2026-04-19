//go:build linux

package egress

import (
	"context"
	"fmt"
	"log/slog"
	"os/exec"
	"strings"
	"sync"
)

// LinuxExitManager installs MASQUERADE + FORWARD rules on a node that is
// serving as an exit for other mesh peers.
//
// Ruleset (nftables table `inet gmesh-exit`):
//
//   table inet gmesh-exit {
//       chain forward {
//           type filter hook forward priority filter;
//           iifname wg-gmesh oifname != wg-gmesh accept;
//           iifname != wg-gmesh oifname wg-gmesh ct state established,related accept;
//       }
//       chain postrouting {
//           type nat hook postrouting priority srcnat;
//           iifname wg-gmesh oifname != wg-gmesh masquerade;
//       }
//   }
//
// Also enables net.ipv4.ip_forward.
type LinuxExitManager struct {
	Log      *slog.Logger
	NftTable string

	mu      sync.Mutex
	enabled bool
	iface   string
	allowed []int64
}

// NewLinuxExit returns a real Linux exit manager.
func NewLinuxExit(log *slog.Logger) *LinuxExitManager {
	if log == nil {
		log = slog.Default()
	}
	return &LinuxExitManager{Log: log, NftTable: "gmesh-exit"}
}

// Name returns "linux".
func (m *LinuxExitManager) Name() string { return "linux" }

// IsEnabled reports whether Enable has been called.
func (m *LinuxExitManager) IsEnabled() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.enabled
}

// Enable installs the exit ruleset + enables ip_forward.
func (m *LinuxExitManager) Enable(ctx context.Context, wgIface string, allowed []int64) error {
	if wgIface == "" {
		return fmt.Errorf("exit: wgIface required")
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	// Enable forwarding (best-effort — may be set via sysctl.conf).
	_ = run(ctx, "sysctl", "-qw", "net.ipv4.ip_forward=1")

	// Atomic replace via add+delete+add.
	script := fmt.Sprintf(`
add table inet %[1]s
delete table inet %[1]s
add table inet %[1]s
add chain inet %[1]s forward { type filter hook forward priority filter; }
add rule inet %[1]s forward iifname "%[2]s" oifname != "%[2]s" accept
add rule inet %[1]s forward iifname != "%[2]s" oifname "%[2]s" ct state established,related accept
add chain inet %[1]s postrouting { type nat hook postrouting priority srcnat; }
add rule inet %[1]s postrouting iifname "%[2]s" oifname != "%[2]s" masquerade
`, m.NftTable, wgIface)
	if err := m.runNftInput(ctx, script); err != nil {
		return fmt.Errorf("enable exit: %w", err)
	}

	m.enabled = true
	m.iface = wgIface
	m.allowed = append([]int64(nil), allowed...)
	m.Log.Info("exit enabled", "iface", wgIface, "allowed", allowed)
	return nil
}

// Disable tears the exit ruleset down. Idempotent.
func (m *LinuxExitManager) Disable(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.enabled {
		return nil
	}
	script := fmt.Sprintf("delete table inet %s\n", m.NftTable)
	if err := m.runNftInput(ctx, script); err != nil {
		// Ignore "no such file" — means it never existed.
		if !strings.Contains(err.Error(), "No such file") &&
			!strings.Contains(err.Error(), "does not exist") {
			m.Log.Warn("exit disable reported error", "error", err)
		}
	}
	m.enabled = false
	m.Log.Info("exit disabled")
	return nil
}

func (m *LinuxExitManager) runNftInput(ctx context.Context, script string) error {
	cmd := exec.CommandContext(ctx, "nft", "-f", "-")
	cmd.Stdin = strings.NewReader(script)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("nft: %w (%s)", err, strings.TrimSpace(string(out)))
	}
	return nil
}
