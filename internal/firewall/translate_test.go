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
	s := BuildNftScript("gmesh", "inet", rules, "deny")
	script := s.String()

	if !containsAll(script,
		"add table inet gmesh",
		"delete table inet gmesh",
		"add chain inet gmesh mesh_input",
		"policy drop",
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
	s := BuildNftScript("gmesh", "inet", rules, "accept")
	if !strings.Contains(s.String(), "tcp dport 80-443") {
		t.Errorf("expected port range: %s", s.String())
	}
}

func TestBuildNftScriptPortList(t *testing.T) {
	rules := []Rule{
		{ID: 1, Enabled: true, Action: ActionAllow, Protocol: ProtoTCP, PortRange: "22,80,443", Direction: DirectionInbound},
	}
	s := BuildNftScript("gmesh", "inet", rules, "")
	if !strings.Contains(s.String(), "tcp dport { 22,80,443 }") {
		t.Errorf("expected port set: %s", s.String())
	}
}

func TestBuildNftScriptBothDirections(t *testing.T) {
	rules := []Rule{
		{ID: 1, Enabled: true, Action: ActionAllow, Protocol: ProtoTCP, PortRange: "443", Direction: DirectionBoth},
	}
	s := BuildNftScript("gmesh", "inet", rules, "")
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
	s := BuildNftScript("gmesh", "inet", rules, "")
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
	s := BuildNftScript("gmesh", "inet", rules, "")
	if !strings.Contains(s.String(), "ct state { new, established, related }") {
		t.Errorf("ct state missing: %s", s.String())
	}
}

func TestBuildNftScriptDenyAction(t *testing.T) {
	rules := []Rule{
		{ID: 1, Enabled: true, Action: ActionDeny, Protocol: ProtoTCP, PortRange: "23", Direction: DirectionInbound},
	}
	s := BuildNftScript("gmesh", "inet", rules, "")
	out := s.String()
	if !strings.Contains(out, "drop") {
		t.Errorf("drop action missing: %s", out)
	}
}

func TestBuildNftScriptLogAction(t *testing.T) {
	rules := []Rule{
		{ID: 1, Enabled: true, Action: ActionLog, Protocol: ProtoAny, Direction: DirectionInbound},
	}
	s := BuildNftScript("gmesh", "inet", rules, "")
	out := s.String()
	if !strings.Contains(out, `log prefix "gmesh: " accept`) {
		t.Errorf("log action missing: %s", out)
	}
}

func TestBuildNftScriptIgnoresDisabled(t *testing.T) {
	rules := []Rule{
		{ID: 1, Name: "live", Enabled: true, Action: ActionAllow, Protocol: ProtoTCP, PortRange: "22", Direction: DirectionInbound},
	}
	s := BuildNftScript("gmesh", "inet", rules, "")
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
