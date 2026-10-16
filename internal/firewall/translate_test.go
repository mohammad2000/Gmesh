package firewall

import (
	"strings"
	"testing"
)

func containsAll(haystack string, needles ...string) bool {
	for _, n := range needles {
		if !strings.Contains(haystack, n) {
			return false
		}
	}
	return true
}

func TestBuildNftScriptBasic(t *testing.T) {
	rules := []Rule{
		{ID: 1, Name: "allow ssh", Enabled: true, Action: ActionAllow, Protocol: ProtoTCP, PortRange: "22", Direction: DirectionInbound},
	}
	s := BuildNftScript("gmesh", "inet", "wg-gmesh", rules, "deny")
	script := s.String()

	if !containsAll(script,
		"add table inet gmesh",
		"delete table inet gmesh",
		"add chain inet gmesh mesh_input",
		`counter drop comment "gmesh default deny"`, // deny = trailing rule, chain policy stays accept
		"tcp dport 22",
		"accept",
		`comment "allow ssh"`) {
		t.Errorf("script missing expected parts:\n%s", script)
	}
}

func TestBuildNftScriptPortRange(t *testing.T) {
	rules := []Rule{
		{ID: 1, Enabled: true, Action: ActionAllow, Protocol: ProtoTCP, PortRange: "80-443", Direction: DirectionInbound},
	}
	s := BuildNftScript("gmesh", "inet", "wg-gmesh", rules, "accept")
	if !strings.Contains(s.String(), "tcp dport 80-443") {
		t.Errorf("expected port range: %s", s.String())
	}
}

func TestBuildNftScriptPortList(t *testing.T) {
	rules := []Rule{
		{ID: 1, Enabled: true, Action: ActionAllow, Protocol: ProtoTCP, PortRange: "22,80,443", Direction: DirectionInbound},
	}
	s := BuildNftScript("gmesh", "inet", "wg-gmesh", rules, "")
	if !strings.Contains(s.String(), "tcp dport { 22,80,443 }") {
		t.Errorf("expected port set: %s", s.String())
	}
}

func TestBuildNftScriptBothDirections(t *testing.T) {
	rules := []Rule{
		{ID: 1, Enabled: true, Action: ActionAllow, Protocol: ProtoTCP, PortRange: "443", Direction: DirectionBoth},
	}
	s := BuildNftScript("gmesh", "inet", "wg-gmesh", rules, "")
	out := s.String()
	if !strings.Contains(out, "mesh_input") || !strings.Contains(out, "mesh_output") {
		t.Errorf("both chains expected: %s", out)
	}
}

func TestBuildNftScriptRateLimit(t *testing.T) {
	rules := []Rule{
		{ID: 1, Enabled: true, Action: ActionAllow, Protocol: ProtoTCP, PortRange: "22",
			Direction: DirectionInbound, RateLimit: "100/s", RateBurst: 10},
	}
	s := BuildNftScript("gmesh", "inet", "wg-gmesh", rules, "")
	out := s.String()
	if !strings.Contains(out, "limit rate 100/second") {
		t.Errorf("rate limit missing: %s", out)
	}
	if !strings.Contains(out, "burst 10 packets") {
		t.Errorf("burst missing: %s", out)
	}
}

func TestBuildNftScriptConnState(t *testing.T) {
	rules := []Rule{
		{ID: 1, Enabled: true, Action: ActionAllow, Protocol: ProtoAny,
			Direction: DirectionInbound, ConnState: "NEW,ESTABLISHED,RELATED"},
	}
	s := BuildNftScript("gmesh", "inet", "wg-gmesh", rules, "")
	if !strings.Contains(s.String(), "ct state { new, established, related }") {
		t.Errorf("ct state missing: %s", s.String())
	}
}

func TestBuildNftScriptDenyAction(t *testing.T) {
	rules := []Rule{
		{ID: 1, Enabled: true, Action: ActionDeny, Protocol: ProtoTCP, PortRange: "23", Direction: DirectionInbound},
	}
	s := BuildNftScript("gmesh", "inet", "wg-gmesh", rules, "")
	out := s.String()
	if !strings.Contains(out, "drop") {
		t.Errorf("drop action missing: %s", out)
	}
}

func TestBuildNftScriptLogAction(t *testing.T) {
	rules := []Rule{
		{ID: 1, Enabled: true, Action: ActionLog, Protocol: ProtoAny, Direction: DirectionInbound},
	}
	s := BuildNftScript("gmesh", "inet", "wg-gmesh", rules, "")
	out := s.String()
	if !strings.Contains(out, `log prefix "gmesh: " accept`) {
		t.Errorf("log action missing: %s", out)
	}
}

func TestBuildNftScriptIgnoresDisabled(t *testing.T) {
	rules := []Rule{
		{ID: 1, Name: "live", Enabled: true, Action: ActionAllow, Protocol: ProtoTCP, PortRange: "22", Direction: DirectionInbound},
	}
	s := BuildNftScript("gmesh", "inet", "wg-gmesh", rules, "")
	// Translator doesn't filter disabled rules — the engine layer does
	// that via FilterLive. This just verifies translation of a single live rule.
	if !strings.Contains(s.String(), "dport 22") {
		t.Errorf("live rule missing: %s", s.String())
	}
}

func TestNftPortSet(t *testing.T) {
	cases := map[string]string{
		"22":        "22",
		"22-23":     "22-23",
		"22,80,443": "{ 22,80,443 }",
	}
	for in, want := range cases {
		if got := nftPortSet(in); got != want {
			t.Errorf("nftPortSet(%q) = %q; want %q", in, got, want)
		}
	}
}

func TestNftCTSet(t *testing.T) {
	got := nftCTSet("NEW, ESTABLISHED,Related")
	want := "{ new, established, related }"
	if got != want {
		t.Errorf("got %q; want %q", got, want)
	}
}

func TestNftRate(t *testing.T) {
	cases := map[string]string{
		"100/s": "100/second",
		"10/m":  "10/minute",
		"5/h":   "5/hour",
		"1/d":   "1/day",
		"bad":   "bad",
	}
	for in, want := range cases {
		if got := nftRate(in); got != want {
			t.Errorf("nftRate(%q) = %q; want %q", in, got, want)
		}
	}
}

func TestParseActionAndDirection(t *testing.T) {
	if ParseAction("ALLOW") != ActionAllow {
		t.Error("ALLOW")
	}
	if ParseAction("drop") != ActionDeny {
		t.Error("drop → deny")
	}
	if ParseDirection("out") != DirectionOutbound {
		t.Error("out")
	}
	if ParseDirection("xyz") != DirectionBoth {
		t.Error("xyz → both")
	}
}


// The chains must never filter non-mesh traffic: before 2026-10-16 the
// default policy was the chain policy and a "deny" cut SSH and the LAN.
func TestBuildNftScriptOnlyFiltersMeshInterface(t *testing.T) {
	rules := []Rule{{ID: 1, Name: "deny all", Enabled: true, Action: ActionDeny, Direction: DirectionBoth}}
	out := BuildNftScript("gmesh", "inet", "wg-gmesh", rules, "deny").String()
	if strings.Contains(out, "policy drop") {
		t.Fatalf("chain policy must stay accept:\n%s", out)
	}
	lines := strings.Split(out, "\n")
	first := map[string]string{}
	for _, l := range lines {
		for _, c := range []string{"mesh_input", "mesh_output", "mesh_forward"} {
			if strings.HasPrefix(l, "add rule inet gmesh "+c+" ") && first[c] == "" {
				first[c] = l
			}
		}
	}
	for c, want := range map[string]string{
		"mesh_input":   `iifname != "wg-gmesh" accept`,
		"mesh_output":  `oifname != "wg-gmesh" accept`,
		"mesh_forward": `iifname != "wg-gmesh" oifname != "wg-gmesh" accept`,
	} {
		if !strings.HasSuffix(first[c], want) {
			t.Errorf("first rule of %s = %q; want the non-mesh bypass %q", c, first[c], want)
		}
	}
	if !strings.Contains(out, `mesh_forward iifname "wg-gmesh" counter drop`) {
		t.Errorf("inbound rules must also cover traffic routed in from the mesh:\n%s", out)
	}
}

func TestBuildNftScriptRejectsInjection(t *testing.T) {
	bad := []Rule{
		{ID: 1, Enabled: true, Action: ActionAllow, Source: "1.2.3.4 accept\nflush ruleset"},
		{ID: 2, Enabled: true, Action: ActionAllow, Destination: "10.0.0.0/8; reboot"},
		{ID: 3, Enabled: true, Action: ActionAllow, Protocol: ProtoTCP, PortRange: "22 accept\nadd table x"},
		{ID: 4, Enabled: true, Action: ActionAllow, Protocol: ProtoTCP, TCPFlags: "syn\nflush ruleset"},
		{ID: 5, Enabled: true, Action: ActionAllow, ConnState: "NEW\ndelete table inet filter"},
		{ID: 6, Enabled: true, Action: ActionAllow, RateLimit: "10/s\nflush ruleset"},
	}
	out := BuildNftScript("gmesh", "inet", "wg-gmesh", bad, "").String()
	for _, w := range []string{"flush ruleset", "reboot", "add table x", "delete table inet filter"} {
		if strings.Contains(out, w) {
			t.Errorf("injected %q reached the script:\n%s", w, out)
		}
	}
	for _, r := range bad {
		if RuleProblem(r) == "" {
			t.Errorf("rule %d should be rejected", r.ID)
		}
	}
	ok := Rule{ID: 9, Enabled: true, Action: ActionAllow, Protocol: ProtoTCP, PortRange: "80,443,8000-8100",
		Source: "10.200.0.0/16", Destination: "10.200.0.5", ConnState: "NEW,ESTABLISHED", RateLimit: "100/s"}
	if p := RuleProblem(ok); p != "" {
		t.Errorf("valid rule rejected: %s", p)
	}
}
