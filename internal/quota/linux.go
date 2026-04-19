//go:build linux

package quota

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// LinuxManager embeds coreManager with a nftables-backed CounterReader.
// It parses `nft -j list table inet gmesh-egress` and extracts the
// counter attached to each profile's mark rule.
//
// Rule shape (from internal/egress/linux.go):
//   add rule inet gmesh-egress egress_mark_out ... meta mark set 0x1... comment "egress-<N>"
//
// nftables attaches a counter element automatically when `counter`
// appears in the rule body. Our egress translator doesn't emit a
// counter today; we add it via a rebuild when a Quota attaches.
type LinuxManager struct {
	*coreManager
}

// NewLinux wires a LinuxManager.
func NewLinux(log *slog.Logger, pub Publisher, sw Switcher) *LinuxManager {
	r := &nftReader{log: log, table: "gmesh-egress"}
	c := newCore("linux", log, r, sw, pub)
	return &LinuxManager{coreManager: c}
}

// ── nft counter reader ───────────────────────────────────────────────

type nftReader struct {
	mu    sync.Mutex
	log   *slog.Logger
	table string
}

func (r *nftReader) ReadProfileBytes(ctx context.Context, profileID int64) (int64, time.Time, error) {
	out, err := runNft(ctx, "-j", "list", "table", "inet", r.table)
	if err != nil {
		return 0, time.Time{}, err
	}
	bytes, err := parseEgressCounter(out, profileID)
	return bytes, time.Now(), err
}

// Reset zeroes the per-rule counter by rewriting the egress table's
// counters. In practice Quota Manager can either (a) call the egress
// Manager to reinstall the profile (which flushes chains and rebuilds
// rules with fresh counters) — preferred — or (b) call `nft reset
// counters table inet gmesh-egress` which clears ALL counters but is
// atomic. We do the latter — simpler; safe even if multiple profiles
// share the table.
func (r *nftReader) Reset(ctx context.Context, profileID int64) error {
	_ = profileID
	_, err := runNft(ctx, "reset", "counters", "table", "inet", r.table)
	return err
}

// parseEgressCounter walks the JSON blob and finds the rule whose comment
// matches "egress-<id>", returning its (packets+bytes) counter. If the
// rule doesn't carry a counter yet, returns 0 with no error (quota will
// simply see no usage until the next egress rebuild adds a counter).
func parseEgressCounter(jsonBlob string, profileID int64) (int64, error) {
	var top struct {
		Nftables []map[string]json.RawMessage `json:"nftables"`
	}
	if err := json.Unmarshal([]byte(jsonBlob), &top); err != nil {
		return 0, fmt.Errorf("parse nft json: %w", err)
	}
	wantComment := fmt.Sprintf("egress-%d", profileID)
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
		if rule.Comment != wantComment {
			continue
		}
		if bytes := extractBytes(rule.Expr); bytes >= 0 {
			return bytes, nil
		}
	}
	return 0, nil
}

func extractBytes(exprRaw json.RawMessage) int64 {
	if len(exprRaw) == 0 {
		return -1
	}
	var exprs []map[string]json.RawMessage
	if err := json.Unmarshal(exprRaw, &exprs); err != nil {
		return -1
	}
	for _, e := range exprs {
		c, ok := e["counter"]
		if !ok {
			continue
		}
		var ctr struct {
			Packets int64 `json:"packets"`
			Bytes   int64 `json:"bytes"`
		}
		if err := json.Unmarshal(c, &ctr); err != nil {
			continue
		}
		return ctr.Bytes
	}
	return -1
}

// runNft is a tiny wrapper so we don't pull internal/firewall in.
func runNft(ctx context.Context, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "nft", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("nft %s: %w — %s",
			strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}

var _ Manager = (*LinuxManager)(nil)
var _ CounterReader = (*nftReader)(nil)
