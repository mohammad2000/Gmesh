package traversal

import (
	"testing"

	"github.com/mohammad2000/Gmesh/internal/nat"
)

func TestSelectLadder(t *testing.T) {
	cases := []struct {
		name string
		c    Classification
		want []Method
	}{
		{
			"both open",
			Classification{Local: nat.Open, Remote: nat.Open},
			[]Method{MethodDirect},
		},
		{
			"one open",
			Classification{Local: nat.Open, Remote: nat.PortRestrictedCone},
			[]Method{MethodDirect, MethodUPnPPortMap, MethodSTUNHolePunch},
		},
		{
			"both cone",
			Classification{Local: nat.PortRestrictedCone, Remote: nat.PortRestrictedCone},
			[]Method{MethodUPnPPortMap, MethodSTUNHolePunch, MethodSimultaneousOpen, MethodBirthdayPunch, MethodRelay},
		},
		{
			"one symmetric",
			Classification{Local: nat.Symmetric, Remote: nat.PortRestrictedCone},
			[]Method{MethodUPnPPortMap, MethodSTUNHolePunch, MethodSimultaneousOpen, MethodBirthdayPunch, MethodRelay, MethodWSTunnel},
		},
		{
			"both symmetric",
			Classification{Local: nat.Symmetric, Remote: nat.Symmetric},
			[]Method{MethodUPnPPortMap, MethodSTUNHolePunch, MethodSimultaneousOpen, MethodBirthdayPunch, MethodRelay, MethodWSTunnel},
		},
		{
			"both unknown",
			Classification{Local: nat.Unknown, Remote: nat.Unknown},
			[]Method{MethodDirect, MethodUPnPPortMap, MethodSTUNHolePunch, MethodSimultaneousOpen, MethodBirthdayPunch, MethodRelay, MethodWSTunnel},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := SelectLadder(tc.c)
			if len(got) != len(tc.want) {
				t.Fatalf("ladder len = %d; want %d (got %v)", len(got), len(tc.want), got)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Errorf("ladder[%d] = %v; want %v", i, got[i], tc.want[i])
				}
			}
		})
	}
}
