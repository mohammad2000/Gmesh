//go:build linux

package l7

import "testing"

func TestParseConntrackLine(t *testing.T) {
	line := "ipv4     2 tcp      6 431999 ESTABLISHED src=10.250.0.1 dst=10.250.0.20 sport=52060 dport=443 packets=42 bytes=8432 src=10.250.0.20 dst=10.250.0.1 sport=443 dport=52060 packets=40 bytes=14600 [ASSURED] mark=0 use=1"
	f, ok := parseConntrackLine(line)
	if !ok {
		t.Fatal("failed to parse conntrack line")
	}
	if f.L4Proto != "tcp" {
		t.Errorf("l4=%q", f.L4Proto)
	}
	if f.SrcIP != "10.250.0.1" || f.DstIP != "10.250.0.20" {
		t.Errorf("src/dst mismatch: %s → %s", f.SrcIP, f.DstIP)
	}
	if f.SrcPort != 52060 || f.DstPort != 443 {
		t.Errorf("ports = %d → %d", f.SrcPort, f.DstPort)
	}
	if f.TxBytes != 8432 || f.RxBytes != 14600 {
		t.Errorf("bytes tx=%d rx=%d", f.TxBytes, f.RxBytes)
	}
}

func TestParseConntrackLineSkipsICMP(t *testing.T) {
	line := "ipv4     2 icmp     1 29 src=10.0.0.1 dst=10.0.0.2 type=8 code=0 id=1"
	if _, ok := parseConntrackLine(line); ok {
		t.Error("icmp line should be skipped")
	}
}
