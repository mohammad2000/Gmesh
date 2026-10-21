//go:build windows

package firewall

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/tailscale/wf"
	"golang.org/x/sys/windows"
)

// WFPBackend enforces the mesh firewall with the Windows Filtering Platform,
// the layer Windows Firewall itself is built on. It mirrors the nftables
// backend's semantics on the mesh interface only:
//
//   - rules are tried in order and the first match decides: each becomes a
//     filter in gmesh's own sublayer with a weight that falls with its
//     position, and the default-deny filter has the lowest weight;
//   - filters sit at the ALE connect / receive-accept layers, which decide
//     once per connection, so replies to allowed connections stay open (the
//     "ct established,related accept" of the nft chains);
//   - every filter carries the mesh interface's LUID, so nothing else on
//     the host (internet, LAN, RDP) is touched.
//
// Like a separate nft table, an "allow" here cannot open what Windows
// Firewall itself blocks: every sublayer must permit a connection.
//
// What WFP can't express (rate limits, TCP flags, connection states other
// than new connections, log/limit actions, IPv6 addresses — the mesh is
// IPv4) is reported back as failed rather than dropped silently.
type WFPBackend struct {
	log   *slog.Logger
	mu    sync.Mutex
	iface string
	last  []Rule
}

var (
	wfpProvider = wf.ProviderID(mustGUID("{6f1d3a52-5c1e-4a52-9a4e-6b0f2b1c7a01}"))
	wfpSublayer = wf.SublayerID(mustGUID("{6f1d3a52-5c1e-4a52-9a4e-6b0f2b1c7a02}"))
)

func mustGUID(s string) windows.GUID {
	g, err := windows.GUIDFromString(s)
	if err != nil {
		panic(err)
	}
	return g
}

// NewWFP returns the Windows Filtering Platform backend.
func NewWFP(log *slog.Logger) *WFPBackend {
	if log == nil {
		log = slog.Default()
	}
	return &WFPBackend{log: log}
}

// Name returns "wfp".
func (b *WFPBackend) Name() string { return "wfp" }

// SetInterface confines the filters to the mesh interface.
func (b *WFPBackend) SetInterface(name string) {
	b.mu.Lock()
	b.iface = name
	b.mu.Unlock()
}

func (b *WFPBackend) session() (*wf.Session, error) {
	return wf.New(&wf.Options{Name: "gmeshd", Description: "Gritiva mesh firewall", Dynamic: false})
}

// Ensure registers gmesh's provider and sublayer. Idempotent.
func (b *WFPBackend) Ensure(_ context.Context) error {
	s, err := b.session()
	if err != nil {
		return fmt.Errorf("wfp: open: %w", err)
	}
	defer s.Close()
	return ensureWFP(s)
}

func ensureWFP(s *wf.Session) error {
	provs, err := s.Providers()
	if err != nil {
		return fmt.Errorf("wfp: providers: %w", err)
	}
	have := false
	for _, p := range provs {
		if p.ID == wfpProvider {
			have = true
		}
	}
	if !have {
		if err := s.AddProvider(&wf.Provider{ID: wfpProvider, Name: "Gritiva mesh", Description: "gmeshd: mesh firewall rules from the Gritiva panel"}); err != nil {
			return fmt.Errorf("wfp: add provider: %w", err)
		}
	}
	subs, err := s.Sublayers(wfpProvider)
	if err != nil {
		return fmt.Errorf("wfp: sublayers: %w", err)
	}
	for _, sl := range subs {
		if sl.ID == wfpSublayer {
			return nil
		}
	}
	if err := s.AddSublayer(&wf.Sublayer{ID: wfpSublayer, Name: "Gritiva mesh firewall", Provider: wfpProvider, Weight: 0x8000}); err != nil {
		return fmt.Errorf("wfp: add sublayer: %w", err)
	}
	return nil
}

// meshLUID is the mesh adapter's NET_LUID.
func meshLUID(name string) (uint64, error) {
	ifc, err := net.InterfaceByName(name)
	if err != nil {
		return 0, fmt.Errorf("wfp: mesh interface %q: %w", name, err)
	}
	row := windows.MibIfRow2{InterfaceIndex: uint32(ifc.Index)}
	if err := windows.GetIfEntry2Ex(windows.MibIfEntryNormal, &row); err != nil {
		return 0, fmt.Errorf("wfp: interface %q LUID: %w", name, err)
	}
	return row.InterfaceLuid, nil
}

// Apply replaces gmesh's filters with the live ruleset. The new filters go
// in before the old ones are removed, so there is no moment without rules.
func (b *WFPBackend) Apply(_ context.Context, rules []Rule, defaultPolicy string) (int, int, []error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	live := FilterLive(rules, time.Now())
	if b.iface == "" {
		return 0, len(live), []error{errors.New("wfp: no mesh interface")}
	}
	luid, err := meshLUID(b.iface)
	if err != nil {
		return 0, len(live), []error{err}
	}
	s, err := b.session()
	if err != nil {
		return 0, len(live), []error{fmt.Errorf("wfp: open: %w", err)}
	}
	defer s.Close()
	if err := ensureWFP(s); err != nil {
		return 0, len(live), []error{err}
	}
	old, err := ourFilters(s)
	if err != nil {
		return 0, len(live), []error{err}
	}

	filters, applied, errs := buildWFPFilters(live, luid, defaultPolicy)
	failed := len(live) - applied
	added := make([]wf.RuleID, 0, len(filters))
	for _, f := range filters {
		if err := s.AddRule(f); err != nil {
			// leave the old set in force rather than a half-built one
			for _, id := range added {
				_ = s.DeleteRule(id)
			}
			return 0, len(live), append(errs, fmt.Errorf("wfp: add %q: %w", f.Name, err))
		}
		added = append(added, f.ID)
	}
	for _, id := range old {
		if err := s.DeleteRule(id); err != nil {
			errs = append(errs, fmt.Errorf("wfp: remove an old filter: %w", err))
		}
	}
	b.last = append(b.last[:0], live...)
	b.log.Info("wfp: mesh firewall applied", "rules", applied, "failed", failed, "filters", len(filters), "default", defaultPolicy, "iface", b.iface)
	return applied, failed, errs
}

func ourFilters(s *wf.Session) ([]wf.RuleID, error) {
	all, err := s.Rules()
	if err != nil {
		return nil, fmt.Errorf("wfp: list filters: %w", err)
	}
	var out []wf.RuleID
	for _, r := range all {
		if r.Provider == wfpProvider {
			out = append(out, r.ID)
		}
	}
	return out, nil
}

// Reset removes every gmesh filter.
func (b *WFPBackend) Reset(_ context.Context) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	s, err := b.session()
	if err != nil {
		return fmt.Errorf("wfp: open: %w", err)
	}
	defer s.Close()
	ids, err := ourFilters(s)
	if err != nil {
		return err
	}
	for _, id := range ids {
		if err := s.DeleteRule(id); err != nil {
			return fmt.Errorf("wfp: remove a filter: %w", err)
		}
	}
	b.last = nil
	return nil
}

// List returns the last applied live rules.
func (b *WFPBackend) List(_ context.Context) ([]Rule, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]Rule(nil), b.last...), nil
}

// HitCounts: WFP keeps no per-filter counters; zeros, like the memory backend.
func (b *WFPBackend) HitCounts(_ context.Context) (map[int64]int64, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make(map[int64]int64, len(b.last))
	for _, r := range b.last {
		out[r.ID] = 0
	}
	return out, nil
}

// wfpUnsupported says why a rule can't become WFP filters, or "".
func wfpUnsupported(r Rule) string {
	if p := RuleProblem(r); p != "" {
		return p
	}
	switch r.Action {
	case ActionAllow, ActionDeny:
	default:
		return fmt.Sprintf("action %s is not supported on Windows", r.Action)
	}
	if r.TCPFlags != "" {
		return "TCP flag matches are not supported on Windows"
	}
	if r.RateLimit != "" {
		return "rate limits are not supported on Windows"
	}
	if cs := strings.ToLower(strings.ReplaceAll(r.ConnState, " ", "")); cs != "" && !strings.Contains(cs, "new") {
		return fmt.Sprintf("connection state %q is not supported on Windows (rules apply to new connections)", r.ConnState)
	}
	for _, a := range []string{r.Source, r.Destination} {
		if p, ok := wfpPrefix(a); ok && !p.Addr().Is4() {
			return "IPv6 addresses are not supported (the mesh is IPv4)"
		}
	}
	return ""
}

// wfpPrefix parses a rule address ("" / "any" = no match on it).
func wfpPrefix(a string) (netip.Prefix, bool) {
	a = strings.TrimSpace(a)
	if a == "" || a == "any" {
		return netip.Prefix{}, false
	}
	if strings.Contains(a, "/") {
		p, err := netip.ParsePrefix(a)
		return p.Masked(), err == nil
	}
	ip, err := netip.ParseAddr(a)
	if err != nil {
		return netip.Prefix{}, false
	}
	return netip.PrefixFrom(ip, ip.BitLen()), true
}

// wfpPorts turns "80" / "80-443" / "22,80,443" into port matches; several
// matches on the same field are OR'ed by WFP.
func wfpPorts(field wf.FieldID, spec string) []*wf.Match {
	var out []*wf.Match
	for _, part := range strings.Split(strings.ReplaceAll(spec, " ", ""), ",") {
		if part == "" {
			continue
		}
		lo, hi, isRange := strings.Cut(part, "-")
		a, _ := strconv.ParseUint(lo, 10, 16)
		if isRange {
			z, _ := strconv.ParseUint(hi, 10, 16)
			out = append(out, &wf.Match{Field: field, Op: wf.MatchTypeRange, Value: wf.Range{From: uint16(a), To: uint16(z)}})
		} else {
			out = append(out, &wf.Match{Field: field, Op: wf.MatchTypeEqual, Value: uint16(a)})
		}
	}
	return out
}

// buildWFPFilters renders the ruleset as WFP filters, highest weight first.
// It returns the filters, how many rules made it in, and why the others
// didn't.
func buildWFPFilters(rules []Rule, luid uint64, defaultPolicy string) ([]*wf.Rule, int, []error) {
	var (
		out     []*wf.Rule
		errs    []error
		applied int
	)
	const top = uint64(1) << 60
	n := uint64(0)
	add := func(name string, layer wf.LayerID, action wf.Action, conds []*wf.Match) {
		n++
		id, _ := windows.GenerateGUID()
		out = append(out, &wf.Rule{
			ID: wf.RuleID(id), Name: name, Layer: layer, Sublayer: wfpSublayer, Provider: wfpProvider,
			Weight: top - n*16, Action: action,
			Conditions: append([]*wf.Match{{Field: wf.FieldIPLocalInterface, Op: wf.MatchTypeEqual, Value: luid}}, conds...),
		})
	}
	for _, r := range rules {
		if why := wfpUnsupported(r); why != "" {
			errs = append(errs, fmt.Errorf("rule %d (%s): %s", r.ID, r.Name, why))
			continue
		}
		action := wf.ActionPermit
		if r.Action == ActionDeny {
			action = wf.ActionBlock
		}
		var proto []*wf.Match
		switch r.Protocol {
		case ProtoTCP:
			proto = []*wf.Match{{Field: wf.FieldIPProtocol, Op: wf.MatchTypeEqual, Value: wf.IPProtoTCP}}
		case ProtoUDP:
			proto = []*wf.Match{{Field: wf.FieldIPProtocol, Op: wf.MatchTypeEqual, Value: wf.IPProtoUDP}}
		case ProtoICMP:
			proto = []*wf.Match{{Field: wf.FieldIPProtocol, Op: wf.MatchTypeEqual, Value: wf.IPProtoICMP}}
		}
		ports := r.PortRange != "" && (r.Protocol == ProtoTCP || r.Protocol == ProtoUDP)
		name := fmt.Sprintf("gmesh rule %d %s", r.ID, r.Name)
		// inbound: the peer is the remote side, this host the local one
		if r.Direction != DirectionOutbound {
			c := append([]*wf.Match(nil), proto...)
			if p, ok := wfpPrefix(r.Source); ok {
				c = append(c, &wf.Match{Field: wf.FieldIPRemoteAddress, Op: wf.MatchTypeEqual, Value: p})
			}
			if p, ok := wfpPrefix(r.Destination); ok {
				c = append(c, &wf.Match{Field: wf.FieldIPLocalAddress, Op: wf.MatchTypeEqual, Value: p})
			}
			if ports {
				c = append(c, wfpPorts(wf.FieldIPLocalPort, r.PortRange)...)
			}
			add(name+" in", wf.LayerALEAuthRecvAcceptV4, action, c)
		}
		if r.Direction != DirectionInbound {
			c := append([]*wf.Match(nil), proto...)
			if p, ok := wfpPrefix(r.Source); ok {
				c = append(c, &wf.Match{Field: wf.FieldIPLocalAddress, Op: wf.MatchTypeEqual, Value: p})
			}
			if p, ok := wfpPrefix(r.Destination); ok {
				c = append(c, &wf.Match{Field: wf.FieldIPRemoteAddress, Op: wf.MatchTypeEqual, Value: p})
			}
			if ports {
				c = append(c, wfpPorts(wf.FieldIPRemotePort, r.PortRange)...)
			}
			add(name+" out", wf.LayerALEAuthConnectV4, action, c)
		}
		applied++
	}
	if nftPolicy(defaultPolicy) == "drop" {
		for _, l := range []wf.LayerID{wf.LayerALEAuthRecvAcceptV4, wf.LayerALEAuthConnectV4} {
			id, _ := windows.GenerateGUID()
			out = append(out, &wf.Rule{
				ID: wf.RuleID(id), Name: "gmesh default deny", Layer: l, Sublayer: wfpSublayer, Provider: wfpProvider,
				Weight: 1, Action: wf.ActionBlock,
				Conditions: []*wf.Match{{Field: wf.FieldIPLocalInterface, Op: wf.MatchTypeEqual, Value: luid}},
			})
		}
	}
	return out, applied, errs
}
