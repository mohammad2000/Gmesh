package firewall

import (
	"context"
	"errors"
	"log/slog"
	"os/exec"
	"time"
)

// Detect picks the best available backend for the current host, preferring
// nftables, then iptables, then an in-memory backend (for non-Linux dev).
//
// preferNftables mirrors cfg.Firewall.UseNftables: if false and iptables is
// present, iptables wins.
func Detect(preferNftables bool, table, chain string, log *slog.Logger) Backend {
	if log == nil {
		log = slog.Default()
	}
	if b := platformBackend(log); b != nil {
		log.Info("firewall backend", "kind", b.Name())
		return b
	}

	nftAvail := binaryAvailable("nft")
	iptAvail := iptablesAvailable()

	switch {
	case preferNftables && nftAvail:
		log.Info("firewall backend", "kind", "nftables")
		return NewNft(table, "inet", log)
	case iptAvail:
		log.Info("firewall backend", "kind", "iptables")
		return NewIptables(chain, log)
	case nftAvail:
		// preferNftables=false but no iptables — fall back to nft anyway.
		log.Info("firewall backend", "kind", "nftables-fallback")
		return NewNft(table, "inet", log)
	default:
		log.Warn("no firewall backend on this host; mesh firewall rules will be refused")
		return Unavailable{}
	}
}

func binaryAvailable(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

// Unavailable is the backend of a host with no firewall engine gmeshd can
// drive (e.g. macOS). It refuses every rule, so the control plane reports
// the machine as not enforcing them instead of believing a no-op.
type Unavailable struct{}

// Name returns "none".
func (Unavailable) Name() string { return "none" }

// Ensure succeeds; Apply is where the refusal is reported.
func (Unavailable) Ensure(context.Context) error { return nil }

// Apply refuses the live rules.
func (Unavailable) Apply(_ context.Context, rules []Rule, _ string) (int, int, []error) {
	live := FilterLive(rules, time.Now())
	if len(live) == 0 {
		return 0, 0, nil
	}
	return 0, len(live), []error{errors.New("no firewall engine on this host; mesh firewall rules are not enforced here")}
}

// Reset has nothing to remove.
func (Unavailable) Reset(context.Context) error { return nil }

// List: nothing is enforced.
func (Unavailable) List(context.Context) ([]Rule, error) { return nil, nil }

// HitCounts: no counters.
func (Unavailable) HitCounts(context.Context) (map[int64]int64, error) { return map[int64]int64{}, nil }
