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
	Iface string // mesh interface; jumps and rules only match traffic on it

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

// iptables is xtables-lock-based: any concurrent invocation (e.g.
// docker, fail2ban, ufw, another gmeshd unit during reload) makes our
// call fail with "Another app is currently holding the xtables lock".
// Pass -w 10 so iptables waits up to 10s for the lock instead of
// failing fast — this is the single biggest cause of transient Apply
// failures in production and the kernel itself queues the wait.
//
// Helper prepends -w 10 to the user args. Goes through runCmd so the
// nft path (which doesn't need -w) is unchanged.
func iptablesRunWithLock(ctx context.Context, args ...string) (string, error) {
	full := make([]string, 0, len(args)+2)
	full = append(full, "-w", "10")
	full = append(full, args...)
	return runCmd(ctx, "iptables", full...)
}

// iptablesRetryRunWithLock wraps iptablesRunWithLock with a small
// exponential-backoff retry. -w handles xtables-lock contention; this
// retry covers the rarer transient failures (kernel module just
// loaded, iptables binary upgrade race, etc.). Three attempts with
// 100ms / 500ms / 2.5s waits — bounded so a genuinely-broken iptables
// install fails fast.
func iptablesRetryRunWithLock(ctx context.Context, args ...string) (string, error) { //nolint:unparam // output kept for parity with iptablesRunWithLock
	var lastErr error
	delays := []time.Duration{100 * time.Millisecond, 500 * time.Millisecond, 2500 * time.Millisecond}
	for i := 0; i < 3; i++ {
		out, err := iptablesRunWithLock(ctx, args...)
		if err == nil {
			return out, nil
		}
		lastErr = err
		// Don't burn budget on errors that won't change with retry —
		// "no such chain", missing required arg, etc. xtables-lock and
		// EAGAIN-style errors mention "lock" or "Resource temporarily
		// unavailable" and benefit from waiting.
		msg := err.Error()
		if !strings.Contains(msg, "lock") &&
			!strings.Contains(msg, "Resource temporarily") &&
			!strings.Contains(msg, "Try again") {
			return out, err
		}
		select {
		case <-ctx.Done():
			return out, ctx.Err()
		case <-time.After(delays[i]):
		}
	}
	return "", lastErr
}

// Name returns "iptables".
func (b *IptablesBackend) Name() string { return "iptables" }

// SetInterface confines the chains to the mesh interface.
func (b *IptablesBackend) SetInterface(name string) { b.Iface = name }

// meshJumps are the built-in → GMESH_* jumps, matched on the mesh
// interface only. The old unconditional `-I INPUT -j GMESH_INPUT` sent
// every packet on the host through mesh rules.
func (b *IptablesBackend) meshJumps() [][]string {
	return [][]string{
		{"INPUT", "-i", b.Iface, "-j", b.Chain + "_INPUT"},
		{"OUTPUT", "-o", b.Iface, "-j", b.Chain + "_OUTPUT"},
		{"FORWARD", "-i", b.Iface, "-j", b.Chain + "_FORWARD"},
		{"FORWARD", "-o", b.Iface, "-j", b.Chain + "_FORWARD"},
	}
}

// Ensure creates the GMESH_* chains if missing and installs the jumps.
func (b *IptablesBackend) Ensure(ctx context.Context) error {
	if b.Iface == "" {
		return fmt.Errorf("iptables: mesh interface unknown; refusing to hook the whole host")
	}
	for _, direction := range []string{"INPUT", "OUTPUT", "FORWARD"} {
		chain := b.Chain + "_" + direction
		// -N creates only if absent; the "Chain already exists" error we ignore.
		if _, err := iptablesRetryRunWithLock(ctx, "-N", chain); err != nil && !strings.Contains(err.Error(), "exists") {
			return fmt.Errorf("iptables -N %s: %w", chain, err)
		}
		// Drop a legacy host-wide jump left by older versions.
		for {
			if _, err := iptablesRunWithLock(ctx, "-D", direction, "-j", chain); err != nil {
				break
			}
		}
	}
	for _, j := range b.meshJumps() {
		check := append([]string{"-C"}, j...)
		if _, err := iptablesRunWithLock(ctx, check...); err != nil {
			add := append([]string{"-I"}, j...)
			if _, err := iptablesRetryRunWithLock(ctx, add...); err != nil {
				return fmt.Errorf("iptables -I %v: %w", j, err)
			}
		}
	}
	return nil
}

// Apply flushes our chains and reinstalls every live rule.
func (b *IptablesBackend) Apply(ctx context.Context, rules []Rule, defaultPolicy string) (int, int, []error) {
	live := FilterLive(rules, time.Now())
	if b.Iface == "" {
		return 0, len(live), []error{fmt.Errorf("iptables: mesh interface unknown; nothing applied")}
	}

	for _, direction := range []string{"INPUT", "OUTPUT", "FORWARD"} {
		if _, err := iptablesRetryRunWithLock(ctx, "-F", b.Chain+"_"+direction); err != nil {
			return 0, len(live), []error{fmt.Errorf("flush %s: %w", b.Chain+"_"+direction, err)}
		}
	}

	applied, failed := 0, 0
	var errs []error
	for _, direction := range []string{"INPUT", "OUTPUT", "FORWARD"} {
		_, _ = iptablesRetryRunWithLock(ctx, "-A", b.Chain+"_"+direction,
			"-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT")
	}
	for _, r := range live {
		if p := RuleProblem(r); p != "" {
			failed++
			errs = append(errs, fmt.Errorf("rule %d skipped: invalid %s", r.ID, p))
			continue
		}
		for _, target := range iptablesTargets(b.Chain, b.Iface, r.Direction) {
			args := ruleToIptablesArgs(target.chain, r)
			if len(args) == 0 {
				continue
			}
			args = append(args[:2:2], append(target.match, args[2:]...)...)
			if _, err := iptablesRetryRunWithLock(ctx, args...); err != nil {
				failed++
				errs = append(errs, fmt.Errorf("rule %d: %w", r.ID, err))
			} else {
				applied++
			}
		}
	}

	if nftPolicy(defaultPolicy) == "drop" {
		// Only mesh traffic ever reaches these chains (see meshJumps).
		for _, direction := range []string{"INPUT", "OUTPUT", "FORWARD"} {
			_, _ = iptablesRetryRunWithLock(ctx, "-A", b.Chain+"_"+direction, "-j", "DROP")
		}
	}

	b.mu.Lock()
	b.lastApplied = append(b.lastApplied[:0], live...)
	b.mu.Unlock()
	return applied, failed, errs
}

type iptTarget struct {
	chain string
	match []string // extra interface match (FORWARD carries both directions)
}

// iptablesTargets: inbound rules filter INPUT and traffic routed in from
// the mesh; outbound rules OUTPUT and traffic routed out to it.
func iptablesTargets(base, iface string, d Direction) []iptTarget {
	var out []iptTarget
	if d != DirectionOutbound {
		out = append(out, iptTarget{base + "_INPUT", nil}, iptTarget{base + "_FORWARD", []string{"-i", iface}})
	}
	if d != DirectionInbound {
		out = append(out, iptTarget{base + "_OUTPUT", nil}, iptTarget{base + "_FORWARD", []string{"-o", iface}})
	}
	return out
}

// Reset flushes the GMESH_* chains.
func (b *IptablesBackend) Reset(ctx context.Context) error {
	for _, direction := range []string{"INPUT", "OUTPUT", "FORWARD"} {
		chain := b.Chain + "_" + direction
		_, _ = iptablesRunWithLock(ctx, "-F", chain)
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
