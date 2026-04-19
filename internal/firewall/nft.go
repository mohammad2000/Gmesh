package firewall

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// NftBackend drives the nftables engine via the `nft` CLI.
//
// Every Apply renders a single nft script, pipes it through `nft -f -`
// (stdin). nftables executes the whole script in one transaction —
// failure rolls back, success replaces atomically. That's why we don't
// need to track diffs between applies: each Apply is a full replace.
type NftBackend struct {
	Table  string
	Family string
	Log    *slog.Logger

	mu          sync.Mutex
	lastApplied []Rule // snapshot returned by List as a fallback
}

// NewNft returns a backend. Pass empty strings to accept defaults
// ("gmesh", "inet").
func NewNft(table, family string, log *slog.Logger) *NftBackend {
	if table == "" {
		table = "gmesh"
	}
	if family == "" {
		family = "inet"
	}
	if log == nil {
		log = slog.Default()
	}
	return &NftBackend{Table: table, Family: family, Log: log}
}

// Name returns "nftables".
func (b *NftBackend) Name() string { return "nftables" }

// Ensure verifies `nft` is runnable and the table can be created.
func (b *NftBackend) Ensure(ctx context.Context) error {
	script := fmt.Sprintf("add table %s %s\n", b.Family, b.Table)
	_, err := b.runNft(ctx, script)
	return err
}

// Apply renders the full nft script and pushes it atomically.
func (b *NftBackend) Apply(ctx context.Context, rules []Rule, defaultPolicy string) (int, int, []error) {
	// Defensive copy + live filter.
	live := FilterLive(rules, time.Now())
	script := BuildNftScript(b.Table, b.Family, live, defaultPolicy)

	if _, err := b.runNft(ctx, script.String()); err != nil {
		return 0, len(live), []error{fmt.Errorf("nft apply: %w", err)}
	}
	b.mu.Lock()
	b.lastApplied = append(b.lastApplied[:0], live...)
	b.mu.Unlock()
	return len(live), 0, nil
}

// Reset deletes the gmesh table.
func (b *NftBackend) Reset(ctx context.Context) error {
	script := fmt.Sprintf("add table %s %s\ndelete table %s %s\n", b.Family, b.Table, b.Family, b.Table)
	_, err := b.runNft(ctx, script)
	if err != nil {
		return fmt.Errorf("nft reset: %w", err)
	}
	b.mu.Lock()
	b.lastApplied = nil
	b.mu.Unlock()
	return nil
}

// List returns the last-applied ruleset. (The authoritative source of truth
// is the backend DB; this is for diagnostics and Status RPC responses.)
func (b *NftBackend) List(_ context.Context) ([]Rule, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]Rule, len(b.lastApplied))
	copy(out, b.lastApplied)
	return out, nil
}

// HitCounts parses `nft -j list table …` and returns per-rule counters.
// Rule IDs are matched via the comment: we write each rule's `comment "r{id}"`
// marker so we can map counters back.
func (b *NftBackend) HitCounts(ctx context.Context) (map[int64]int64, error) {
	out, err := b.runNft(ctx, fmt.Sprintf("list table %s %s\n", b.Family, b.Table))
	// Fall back to JSON listing for structured parsing.
	if err == nil && !strings.Contains(out, "{") {
		jsonOut, jerr := runCmd(ctx, "nft", "-j", "list", "table", b.Family, b.Table)
		if jerr == nil {
			return parseNftHitCounts(jsonOut)
		}
	}
	return map[int64]int64{}, nil
}

// runNft feeds the given script to `nft -f -`.
func (b *NftBackend) runNft(ctx context.Context, script string) (string, error) {
	cmd := exec.CommandContext(ctx, "nft", "-f", "-")
	cmd.Stdin = bytes.NewReader([]byte(script))
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("nft exit: %w — %s", err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}

// runCmd is a tiny helper for plain-arg invocations.
func runCmd(ctx context.Context, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("%s %s: %w — %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}

// parseNftHitCounts extracts per-rule counter values from `nft -j list`.
// The JSON blob is an object {"nftables": [...]} of heterogeneous entries.
// We only look at entries of type {"rule": {...}}, pull out comment + counter.
func parseNftHitCounts(jsonBlob string) (map[int64]int64, error) {
	var top struct {
		Nftables []map[string]json.RawMessage `json:"nftables"`
	}
	if err := json.Unmarshal([]byte(jsonBlob), &top); err != nil {
		return nil, fmt.Errorf("parse nft json: %w", err)
	}
	counts := make(map[int64]int64, len(top.Nftables))
	for _, entry := range top.Nftables {
		raw, ok := entry["rule"]
		if !ok {
			continue
		}
		var rule struct {
			Comment string          `json:"comment"`
			Expr    json.RawMessage `json:"expr"`
		}
		if err := json.Unmarshal(raw, &rule); err != nil {
			continue
		}
		id := extractRuleID(rule.Comment)
		if id == 0 {
			continue
		}
		if c := extractCounter(rule.Expr); c >= 0 {
			counts[id] = c
		}
	}
	return counts, nil
}

// extractRuleID looks for "r{id}" inside the comment string.
// We encode the rule ID into the comment during ruleBody(); this is the
// reverse map.
func extractRuleID(comment string) int64 {
	if !strings.HasPrefix(comment, "r") {
		return 0
	}
	var id int64
	_, err := fmt.Sscanf(comment, "r%d", &id)
	if err != nil {
		return 0
	}
	return id
}

// extractCounter walks the rule expression list and returns the first
// counter's packet count. Returns -1 if no counter found.
func extractCounter(exprRaw json.RawMessage) int64 {
	if len(exprRaw) == 0 {
		return -1
	}
	var exprs []map[string]json.RawMessage
	if err := json.Unmarshal(exprRaw, &exprs); err != nil {
		return -1
	}
	for _, e := range exprs {
		cRaw, ok := e["counter"]
		if !ok {
			continue
		}
		var ctr struct {
			Packets int64 `json:"packets"`
		}
		if err := json.Unmarshal(cRaw, &ctr); err != nil {
			continue
		}
		return ctr.Packets
	}
	return -1
}
