package firewall

import (
	"fmt"
	"strconv"
	"strings"
)

// NftScript holds the full `nft` script that will be piped to `nft -f -`.
// We always replace atomically: delete the table (if present) then
// redefine it with every live rule.
type NftScript struct {
	Family string // "inet"
	Table  string // "gmesh"
	Lines  []string
}

// String returns the script as a single newline-joined blob ready for
// `nft -f -`.
func (s *NftScript) String() string { return strings.Join(s.Lines, "\n") + "\n" }

// BuildNftScript renders a full atomic-replace script for the given live
// ruleset plus the default policy.
//
// Layout:
//
//	flush ruleset                   # no — dangerous, affects non-gmesh
//	# Instead: drop and recreate gmesh table only
//	table inet gmesh { ... }        # if exists
//	delete table inet gmesh
//	table inet gmesh {
//	    chain mesh_input { type filter hook input priority filter; policy <p>; ... }
//	    chain mesh_output { type filter hook output priority filter; policy <p>; ... }
//	    chain mesh_forward { type filter hook forward priority filter; policy <p>; ... }
//	}
func BuildNftScript(table, family string, rules []Rule, defaultPolicy string) *NftScript {
	if table == "" {
		table = "gmesh"
	}
	if family == "" {
		family = "inet"
	}
	s := &NftScript{Family: family, Table: table}

	policy := nftPolicy(defaultPolicy)

	// Idempotent teardown: `delete table` errors if missing, so prefix with
	// `add table` + `delete table` — nft treats the pair as a no-op when
	// the table didn't exist and a clean teardown when it did.
	s.push(fmt.Sprintf("add table %s %s", family, table))
	s.push(fmt.Sprintf("delete table %s %s", family, table))

	// Recreate.
	s.push(fmt.Sprintf("add table %s %s", family, table))
	s.push(fmt.Sprintf("add chain %s %s mesh_input  { type filter hook input  priority filter; policy %s; }", family, table, policy))
	s.push(fmt.Sprintf("add chain %s %s mesh_output { type filter hook output priority filter; policy %s; }", family, table, policy))
	s.push(fmt.Sprintf("add chain %s %s mesh_forward { type filter hook forward priority filter; policy %s; }", family, table, policy))

	// Rules (priority-sorted by caller; we emit in given order).
	for _, r := range rules {
		for _, line := range ruleToNftLines(family, table, r) {
			s.push(line)
		}
	}
	return s
}

func (s *NftScript) push(l string) { s.Lines = append(s.Lines, l) }

// nftPolicy maps our "allow"|"deny" → nft policy keyword.
func nftPolicy(p string) string {
	switch strings.ToLower(p) {
	case "deny", "drop":
		return "drop"
	case "", "allow", "accept":
		return "accept"
	default:
		return "accept"
	}
}

// ruleToNftLines renders one Rule to one or more `add rule` statements,
// possibly across multiple chains (for Direction=Both).
func ruleToNftLines(family, table string, r Rule) []string {
	var out []string
	chains := chainsForDirection(r.Direction)

	body := ruleBody(r)
	if body == "" {
		return out
	}

	for _, chain := range chains {
		out = append(out, fmt.Sprintf("add rule %s %s %s %s", family, table, chain, body))
	}
	return out
}

// chainsForDirection returns the chain names a rule applies to.
func chainsForDirection(d Direction) []string {
	switch d {
	case DirectionInbound:
		return []string{"mesh_input"}
	case DirectionOutbound:
		return []string{"mesh_output"}
	default:
		return []string{"mesh_input", "mesh_output"}
	}
}

// ruleBody builds the "match ... action" portion of an `add rule` line.
func ruleBody(r Rule) string {
	var parts []string

	// Protocol + port constraints.
	if proto := r.Protocol; proto == ProtoTCP || proto == ProtoUDP {
		if r.PortRange != "" {
			parts = append(parts, fmt.Sprintf("%s dport %s", proto.String(), nftPortSet(r.PortRange)))
		} else {
			parts = append(parts, fmt.Sprintf("meta l4proto %s", proto.String()))
		}
	} else if proto == ProtoICMP {
		parts = append(parts, "icmp type echo-request")
	} else if proto == ProtoICMPv6 {
		parts = append(parts, "icmpv6 type echo-request")
	}

	// Source / destination addresses.
	if addr := nftAddr(r.Source); addr != "" {
		parts = append(parts, "ip saddr "+addr)
	}
	if addr := nftAddr(r.Destination); addr != "" {
		parts = append(parts, "ip daddr "+addr)
	}

	// TCP flags.
	if r.TCPFlags != "" {
		parts = append(parts, fmt.Sprintf("tcp flags & (fin|syn|rst|psh|ack|urg) == %s", strings.ToLower(r.TCPFlags)))
	}

	// Connection tracking.
	if r.ConnState != "" {
		parts = append(parts, "ct state "+nftCTSet(r.ConnState))
	}

	// Rate limit.
	if r.RateLimit != "" {
		limit := "limit rate " + nftRate(r.RateLimit)
		if r.RateBurst > 0 {
			limit += fmt.Sprintf(" burst %d packets", r.RateBurst)
		}
		parts = append(parts, limit)
	}

	// Counter (for HitCounts).
	parts = append(parts, "counter")

	// Action.
	parts = append(parts, actionVerb(r.Action))

	// Comment for traceability.
	if r.Name != "" {
		parts = append(parts, fmt.Sprintf("comment \"%s\"", safeComment(r.Name)))
	}

	return strings.Join(parts, " ")
}

// nftPortSet accepts "80" | "80-443" | "22,80,443" and returns a valid nft set.
func nftPortSet(s string) string {
	s = strings.TrimSpace(s)
	if strings.Contains(s, ",") {
		return "{ " + s + " }"
	}
	if strings.Contains(s, "-") {
		// nft uses hyphen for ranges natively.
		return s
	}
	return s
}

// nftAddr turns "any" | "" | CIDR into a match expression or "" for no match.
// "peer:NN" is intentionally not resolved here — the caller should substitute
// the peer's mesh_ip before building the script.
func nftAddr(s string) string {
	s = strings.TrimSpace(s)
	if s == "" || s == "any" {
		return ""
	}
	// Bare IPs become /32 / /128.
	if !strings.ContainsAny(s, "/") && !strings.Contains(s, ":") {
		return s // IPv4 — nft accepts bare IPs
	}
	return s
}

// nftCTSet converts "NEW,ESTABLISHED,RELATED" → "{ new, established, related }".
func nftCTSet(s string) string {
	parts := strings.Split(s, ",")
	for i := range parts {
		parts[i] = strings.ToLower(strings.TrimSpace(parts[i]))
	}
	return "{ " + strings.Join(parts, ", ") + " }"
}

// nftRate turns "100/s" | "1000/m" | "10000/h" into nft's "N/second" etc.
func nftRate(s string) string {
	parts := strings.SplitN(strings.TrimSpace(s), "/", 2)
	if len(parts) != 2 {
		return s
	}
	n, err := strconv.Atoi(parts[0])
	if err != nil {
		return s
	}
	unit := "second"
	switch strings.ToLower(parts[1]) {
	case "s", "second", "sec":
		unit = "second"
	case "m", "minute", "min":
		unit = "minute"
	case "h", "hour":
		unit = "hour"
	case "d", "day":
		unit = "day"
	}
	return fmt.Sprintf("%d/%s", n, unit)
}

// actionVerb maps our Action to nft's action verb.
func actionVerb(a Action) string {
	switch a {
	case ActionAllow:
		return "accept"
	case ActionDeny:
		return "drop"
	case ActionLimit:
		// `limit rate ... accept` is handled via RateLimit in ruleBody;
		// here we just need the fallback accept.
		return "accept"
	case ActionLog:
		return `log prefix "gmesh: " accept`
	default:
		return "accept"
	}
}

// safeComment strips embedded quotes so nft's lexer stays happy.
func safeComment(s string) string {
	s = strings.ReplaceAll(s, `"`, `'`)
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) > 128 {
		s = s[:128]
	}
	return s
}
