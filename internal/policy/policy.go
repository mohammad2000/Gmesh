// Package policy is a minimal event-driven rule engine. It subscribes
// to the engine's event bus, matches incoming events against operator-
// defined Policies from YAML files, and invokes Actions (egress swap,
// enable/disable profile, quota reset) when triggers fire.
//
// # Scope
//
// This is explicitly a **skeleton** for Phase 17 — not the full
// declarative DSL the roadmap sketches. It covers the one use case
// operators have asked for in production:
//
//     "When path_loss(peer=3) > 10% for 30s, shift profile 10 to peer 5."
//
// The full DSL (boolean composition, time-windowed predicates beyond a
// single debounce, sub-queries) is a follow-up. The surface here is
// chosen so the follow-up can extend it without breaking existing
// YAML: the file format is versioned and keyed, and unknown fields
// fail loudly at load time instead of being silently dropped.
//
// # File format (v1)
//
//   version: 1
//   name: failover_on_high_loss
//   when:
//     event: path_down      # path_up | path_down | quota_shift | quota_stop | quota_warning
//     peer_id: 3            # optional — restricts event matching
//     profile_id: 10        # optional — for quota_* events
//     debounce_seconds: 30  # optional — fire only if matching events arrive within this window
//     min_count: 1          # optional (default 1)
//   do:
//     action: swap_exit_peer     # swap_exit_peer | enable_profile | disable_profile | reset_quota
//     profile_id: 10
//     to_peer_id: 5
//
// # Why YAML not Starlark / Rego / CEL
//
// Rego/CEL are great for stateless predicates but this engine needs to
// debounce across events. Operators already read YAML for Kubernetes;
// we stay on their tooling. When pathmon.loss / quota_shift evolve, we
// grow the schema, not the language.
package policy

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

// Policy is a single rule loaded from a YAML file.
type Policy struct {
	Version int    `yaml:"version"`
	Name    string `yaml:"name"`
	When    When   `yaml:"when"`
	Do      Do     `yaml:"do"`

	// Source path — filled in by the loader so error messages and
	// reloads can refer back to the file.
	source string
}

// When is the trigger condition.
type When struct {
	Event           string `yaml:"event"`
	PeerID          int64  `yaml:"peer_id"`
	ProfileID       int64  `yaml:"profile_id"`
	DebounceSeconds int    `yaml:"debounce_seconds"`
	MinCount        int    `yaml:"min_count"`
}

// Do is the action to take.
type Do struct {
	Action    string `yaml:"action"`
	ProfileID int64  `yaml:"profile_id"`
	ToPeerID  int64  `yaml:"to_peer_id"`
	QuotaID   int64  `yaml:"quota_id"`
}

// Event is what the engine feeds into Policy.Match. Kept minimal so the
// package has zero dependency on internal/events.
type Event struct {
	Type      string
	PeerID    int64
	ProfileID int64
	Timestamp time.Time
}

// Actor is the narrow interface the policy engine uses to reach back
// into the engine. Implementations live in internal/engine.
type Actor interface {
	SwapExitPeer(ctx context.Context, profileID, newExitPeerID int64) error
	SetProfileEnabled(ctx context.Context, profileID int64, enabled bool) error
	ResetQuota(ctx context.Context, quotaID int64) error
}

// Validate ensures the policy is well-formed.
func (p *Policy) Validate() error {
	if p.Version != 1 {
		return fmt.Errorf("policy: unsupported version %d (want 1)", p.Version)
	}
	if strings.TrimSpace(p.Name) == "" {
		return errors.New("policy: name required")
	}
	switch p.When.Event {
	case "path_up", "path_down", "quota_warning", "quota_shift", "quota_stop":
	case "":
		return errors.New("policy: when.event required")
	default:
		return fmt.Errorf("policy: unsupported when.event %q", p.When.Event)
	}
	if p.When.DebounceSeconds < 0 {
		return errors.New("policy: debounce_seconds must be >= 0")
	}
	if p.When.MinCount < 0 {
		return errors.New("policy: min_count must be >= 0")
	}
	switch p.Do.Action {
	case "swap_exit_peer":
		if p.Do.ProfileID == 0 || p.Do.ToPeerID == 0 {
			return errors.New("policy: swap_exit_peer requires profile_id and to_peer_id")
		}
	case "enable_profile", "disable_profile":
		if p.Do.ProfileID == 0 {
			return fmt.Errorf("policy: %s requires profile_id", p.Do.Action)
		}
	case "reset_quota":
		if p.Do.QuotaID == 0 {
			return errors.New("policy: reset_quota requires quota_id")
		}
	case "":
		return errors.New("policy: do.action required")
	default:
		return fmt.Errorf("policy: unsupported do.action %q", p.Do.Action)
	}
	return nil
}

// LoadFile parses one YAML policy file.
func LoadFile(path string) (*Policy, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var p Policy
	dec := yaml.NewDecoder(strings.NewReader(string(raw)))
	dec.KnownFields(true) // reject typos in operator files at load time
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("decode %s: %w", path, err)
	}
	if p.When.MinCount == 0 {
		p.When.MinCount = 1
	}
	p.source = path
	if err := p.Validate(); err != nil {
		return nil, fmt.Errorf("validate %s: %w", path, err)
	}
	return &p, nil
}

// LoadDir parses every *.yaml / *.yml file in dir. Files that fail to
// parse are returned in the error list but do not abort the load —
// operators want partial load-success during iteration. A zero-dir
// (empty string or missing) returns (nil, nil).
func LoadDir(dir string) ([]*Policy, []error) {
	if dir == "" {
		return nil, nil
	}
	if _, err := os.Stat(dir); errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, []error{fmt.Errorf("policy: read dir %s: %w", dir, err)}
	}
	var policies []*Policy
	var errs []error
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(name, ".yaml") && !strings.HasSuffix(name, ".yml") {
			continue
		}
		p, err := LoadFile(filepath.Join(dir, name))
		if err != nil {
			errs = append(errs, err)
			continue
		}
		policies = append(policies, p)
	}
	return policies, errs
}

// Engine is the runtime: holds live policies + per-policy state for
// debounce, accepts events, dispatches actions via an Actor.
type Engine struct {
	mu           sync.Mutex
	policies     []*Policy
	counts       map[string]int       // policy name -> match count in current window
	windows      map[string]time.Time // policy name -> window start
	cooldownUntil map[string]time.Time // policy name -> earliest next-fire time
	Actor        Actor
	Log          Logger
}

// Logger is a tiny shim so we don't depend on log/slog here. The engine
// passes a slog.Logger wrapped to Debug/Info/Warn.
type Logger interface {
	Debug(msg string, args ...any)
	Info(msg string, args ...any)
	Warn(msg string, args ...any)
}

// New builds an empty engine.
func New(actor Actor, log Logger) *Engine {
	return &Engine{
		Actor:         actor,
		Log:           log,
		counts:        map[string]int{},
		windows:       map[string]time.Time{},
		cooldownUntil: map[string]time.Time{},
	}
}

// Replace atomically swaps the active policy set. Typical flow: load
// from disk, call Replace. Matches tests' use too — they build policies
// in-memory.
func (e *Engine) Replace(ps []*Policy) {
	e.mu.Lock()
	e.policies = append([]*Policy(nil), ps...)
	e.counts = map[string]int{}
	e.windows = map[string]time.Time{}
	e.cooldownUntil = map[string]time.Time{}
	e.mu.Unlock()
}

// List returns a copy of the active policies.
func (e *Engine) List() []*Policy {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]*Policy, len(e.policies))
	copy(out, e.policies)
	return out
}

// OnEvent feeds one event through every policy. Fires actions on match.
func (e *Engine) OnEvent(ctx context.Context, ev Event) {
	e.mu.Lock()
	policies := make([]*Policy, len(e.policies))
	copy(policies, e.policies)
	e.mu.Unlock()

	for _, p := range policies {
		if !matches(p.When, ev) {
			continue
		}
		if !e.debounceFires(p, ev.Timestamp) {
			continue
		}
		e.fire(ctx, p)
	}
}

// matches is a pure predicate.
func matches(w When, ev Event) bool {
	if w.Event != ev.Type {
		return false
	}
	if w.PeerID != 0 && w.PeerID != ev.PeerID {
		return false
	}
	if w.ProfileID != 0 && w.ProfileID != ev.ProfileID {
		return false
	}
	return true
}

// debounceFires returns true iff the policy has now received the
// required number of matches within its debounce window. Callers must
// already know the event matched.
//
// After a fire, the policy enters a cooldown for `debounce_seconds` so
// additional matches within that window do not retrigger the action —
// otherwise a sustained burst (e.g. many path_down per second) would
// reset + re-fire on every min_count hit. Cooldown expires silently.
func (e *Engine) debounceFires(p *Policy, now time.Time) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	if p.When.DebounceSeconds <= 0 {
		// No debounce — every match fires, independent of min_count.
		return true
	}
	if until, ok := e.cooldownUntil[p.Name]; ok && now.Before(until) {
		return false
	}
	start, ok := e.windows[p.Name]
	if !ok || now.Sub(start) > time.Duration(p.When.DebounceSeconds)*time.Second {
		e.windows[p.Name] = now
		e.counts[p.Name] = 1
	} else {
		e.counts[p.Name]++
	}
	if e.counts[p.Name] >= p.When.MinCount {
		delete(e.windows, p.Name)
		delete(e.counts, p.Name)
		e.cooldownUntil[p.Name] = now.Add(time.Duration(p.When.DebounceSeconds) * time.Second)
		return true
	}
	return false
}

func (e *Engine) fire(ctx context.Context, p *Policy) {
	if e.Actor == nil {
		if e.Log != nil {
			e.Log.Warn("policy fired without Actor", "policy", p.Name, "action", p.Do.Action)
		}
		return
	}
	var err error
	switch p.Do.Action {
	case "swap_exit_peer":
		err = e.Actor.SwapExitPeer(ctx, p.Do.ProfileID, p.Do.ToPeerID)
	case "enable_profile":
		err = e.Actor.SetProfileEnabled(ctx, p.Do.ProfileID, true)
	case "disable_profile":
		err = e.Actor.SetProfileEnabled(ctx, p.Do.ProfileID, false)
	case "reset_quota":
		err = e.Actor.ResetQuota(ctx, p.Do.QuotaID)
	}
	if err != nil {
		if e.Log != nil {
			e.Log.Warn("policy action failed", "policy", p.Name, "action", p.Do.Action, "error", err)
		}
		return
	}
	if e.Log != nil {
		e.Log.Info("policy fired", "policy", p.Name, "action", p.Do.Action)
	}
}

// Source returns the file a policy was loaded from (empty for in-memory).
func (p *Policy) Source() string { return p.source }
