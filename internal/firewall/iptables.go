package firewall

import (
	"context"
	"fmt"
	"log/slog"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// IptablesBackend is the legacy-kernel fallback backend.
//
// Differences from NftBackend:
//   - Not atomic. We approximate atomicity by flushing our chain then
//     reinstalling rule-by-rule. A partial failure mid-apply leaves the
//     chain in an inconsistent state; we log the failed count.
//   - Hit counts require `iptables -vnxL` parsing which we don't
//     implement yet. Returns an empty map.
//
// Chain naming: GMESH_INPUT, GMESH_OUTPUT, GMESH_FORWARD. We jump into
// them from the standard INPUT/OUTPUT/FORWARD chains.
type IptablesBackend struct {
	Chain string // base name ("GMESH") — suffixed with _INPUT etc.
	Log   *slog.Logger

	mu          sync.Mutex
	lastApplied []Rule
}

// NewIptables returns a backend.
func NewIptables(chain string, log *slog.Logger) *IptablesBackend {
	if chain == "" {
		chain = "GMESH"
	}
	if log == nil {
		log = slog.Default()
	}
	return &IptablesBackend{Chain: chain, Log: log}
}

// Name returns "iptables".
func (b *IptablesBackend) Name() string { return "iptables" }

// Ensure creates the GMESH_* chains if missing.
func (b *IptablesBackend) Ensure(ctx context.Context) error {
	for _, direction := range []string{"INPUT", "OUTPUT", "FORWARD"} {
		chain := b.Chain + "_" + direction
		// -N creates only if absent; the "Chain already exists" error we ignore.
		if _, err := runCmd(ctx, "iptables", "-N", chain); err != nil && !strings.Contains(err.Error(), "exists") {
			return fmt.Errorf("iptables -N %s: %w", chain, err)
		}
		// Install the jump from the built-in chain.
		jumpArgs := []string{"-C", direction, "-j", chain}
		if _, err := runCmd(ctx, "iptables", jumpArgs...); err != nil {
			// Not there — install.
			addArgs := []string{"-I", direction, "-j", chain}
			if _, err := runCmd(ctx, "iptables", addArgs...); err != nil {
				return fmt.Errorf("iptables -I %s -j %s: %w", direction, chain, err)
			}
		}
	}
	return nil
}

// Apply flushes our chains and reinstalls every live rule.
func (b *IptablesBackend) Apply(ctx context.Context, rules []Rule, _ string) (int, int, []error) {
	live := FilterLive(rules, time.Now())

	for _, direction := range []string{"INPUT", "OUTPUT", "FORWARD"} {
		if _, err := runCmd(ctx, "iptables", "-F", b.Chain+"_"+direction); err != nil {
			return 0, len(live), []error{fmt.Errorf("flush %s: %w", b.Chain+"_"+direction, err)}
		}
	}

	applied, failed := 0, 0
	var errs []error
	for _, r := range live {
		for _, chain := range iptablesChainsForDirection(b.Chain, r.Direction) {
			args := ruleToIptablesArgs(chain, r)
			if len(args) == 0 {
				continue
			}
			if _, err := runCmd(ctx, "iptables", args...); err != nil {
				failed++
				errs = append(errs, fmt.Errorf("rule %d: %w", r.ID, err))
			} else {
				applied++
			}
		}
	}

	b.mu.Lock()
	b.lastApplied = append(b.lastApplied[:0], live...)
	b.mu.Unlock()
	return applied, failed, errs
}

// Reset flushes the GMESH_* chains.
func (b *IptablesBackend) Reset(ctx context.Context) error {
	for _, direction := range []string{"INPUT", "OUTPUT", "FORWARD"} {
		chain := b.Chain + "_" + direction
		_, _ = runCmd(ctx, "iptables", "-F", chain)
	}
	b.mu.Lock()
	b.lastApplied = nil
	b.mu.Unlock()
	return nil
}

// List returns the last-applied rules (cached).
func (b *IptablesBackend) List(_ context.Context) ([]Rule, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]Rule, len(b.lastApplied))
	copy(out, b.lastApplied)
	return out, nil
}

// HitCounts: iptables counter parsing is TODO; returns empty for now.
func (b *IptablesBackend) HitCounts(_ context.Context) (map[int64]int64, error) {
	return map[int64]int64{}, nil
}

func iptablesChainsForDirection(base string, d Direction) []string {
	switch d {
	case DirectionInbound:
		return []string{base + "_INPUT"}
	case DirectionOutbound:
		return []string{base + "_OUTPUT"}
	default:
		return []string{base + "_INPUT", base + "_OUTPUT"}
	}
}

// ruleToIptablesArgs renders a rule to iptables -A ... args.
func ruleToIptablesArgs(chain string, r Rule) []string {
	var a []string
	a = append(a, "-A", chain)

	if proto := r.Protocol; proto == ProtoTCP || proto == ProtoUDP {
		a = append(a, "-p", proto.String())
		if r.PortRange != "" {
			a = append(a, "--dport", iptablesPort(r.PortRange))
		}
	} else if proto == ProtoICMP {
		a = append(a, "-p", "icmp")
	}

	if s := r.Source; s != "" && s != "any" {
		a = append(a, "-s", s)
	}
	if d := r.Destination; d != "" && d != "any" {
		a = append(a, "-d", d)
	}
	if r.ConnState != "" {
		a = append(a, "-m", "conntrack", "--ctstate", r.ConnState)
	}
	// Skip RateLimit / TCPFlags for v1 to keep translation safe.

	// Action.
	switch r.Action {
	case ActionAllow:
		a = append(a, "-j", "ACCEPT")
	case ActionDeny:
		a = append(a, "-j", "DROP")
	case ActionLog:
		a = append(a, "-j", "LOG", "--log-prefix", "gmesh: ")
	default:
		return nil
	}
	return a
}

// iptablesPort converts our port range to iptables format (hyphen → colon).
func iptablesPort(p string) string {
	return strings.ReplaceAll(p, "-", ":")
}

// iptablesAvailable reports whether the `iptables` binary is on PATH.
func iptablesAvailable() bool {
	_, err := exec.LookPath("iptables")
	return err == nil
}
