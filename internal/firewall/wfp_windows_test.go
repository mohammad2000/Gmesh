//go:build windows

package firewall

import (
	"strings"
	"testing"

	"github.com/tailscale/wf"
)

func TestBuildWFPFilters(t *testing.T) {
	rules := []Rule{
		{ID: 1, Name: "ssh from ops", Enabled: true, Action: ActionAllow, Protocol: ProtoTCP, Source: "10.200.0.4", PortRange: "22", Direction: DirectionInbound},
		{ID: 2, Name: "web", Enabled: true, Action: ActionAllow, Protocol: ProtoTCP, PortRange: "80,443,8000-8100", Direction: DirectionBoth},
		{ID: 3, Name: "rate", Enabled: true, Action: ActionAllow, Protocol: ProtoTCP, RateLimit: "10/s"},
		{ID: 4, Name: "v6", Enabled: true, Action: ActionDeny, Source: "fd00::/8"},
		{ID: 5, Name: "log", Enabled: true, Action: ActionLog},
		{ID: 6, Name: "block icmp", Enabled: true, Action: ActionDeny, Protocol: ProtoICMP, Direction: DirectionInbound},
	}
	fs, applied, errs := buildWFPFilters(rules, 42, "deny")
	if applied != 3 || len(errs) != 3 {
		t.Fatalf("applied %d, errs %v", applied, errs)
	}
	// 1 in, 2 in+out, 6 in, + 2 default deny
	if len(fs) != 6 {
		t.Fatalf("%d filters", len(fs))
	}
	for i := 1; i < len(fs); i++ {
		if fs[i].Name == "gmesh default deny" && fs[i-1].Name == "gmesh default deny" {
			continue // one per layer, both the lowest
		}
		if fs[i].Weight >= fs[i-1].Weight {
			t.Fatalf("filter %d weight %d not below %d (first match must win)", i, fs[i].Weight, fs[i-1].Weight)
		}
	}
	for _, f := range fs {
		if f.Sublayer != wfpSublayer || f.Provider != wfpProvider {
			t.Fatalf("%s outside gmesh's sublayer", f.Name)
		}
		if c := f.Conditions[0]; c.Field != wf.FieldIPLocalInterface || c.Value != uint64(42) {
			t.Fatalf("%s not confined to the mesh interface", f.Name)
		}
	}
	ssh := fs[0]
	if ssh.Layer != wf.LayerALEAuthRecvAcceptV4 || ssh.Action != wf.ActionPermit || len(ssh.Conditions) != 4 {
		t.Fatalf("ssh filter: %+v", ssh)
	}
	ports := 0
	for _, c := range fs[2].Conditions { // web, outbound
		if c.Field == wf.FieldIPRemotePort {
			ports++
		}
	}
	if fs[2].Layer != wf.LayerALEAuthConnectV4 || ports != 3 {
		t.Fatalf("web out: layer %v, %d port matches", fs[2].Layer, ports)
	}
	last := fs[len(fs)-1]
	if last.Name != "gmesh default deny" || last.Action != wf.ActionBlock || last.Weight != 1 {
		t.Fatalf("default deny: %+v", last)
	}
	if !strings.Contains(errs[0].Error(), "rate limits") {
		t.Fatalf("errs[0] = %v", errs[0])
	}
	if fs2, _, _ := buildWFPFilters(rules[:1], 42, "allow"); len(fs2) != 1 {
		t.Fatalf("allow policy: %d filters", len(fs2))
	}
}
