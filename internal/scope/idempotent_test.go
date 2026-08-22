package scope

import (
	"errors"
	"testing"
)

// The repair path exists because a half-built scope used to be
// unrecoverable: `ip link add` reports "File exists", nothing tolerated
// it, and the scope stayed in CONNECTING forever while every retry died
// on the same line.
func TestAlreadyExistsRecognisesTheBenignFailure(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"plain file exists", errors.New("ip link add: exit status 2 (File exists)"), true},
		{"rtnetlink form", errors.New("RTNETLINK answers: File exists"), true},
		{"a real failure", errors.New("Cannot find device \"vh-s9\""), false},
		{"permission", errors.New("Operation not permitted"), false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := alreadyExists(c.err); got != c.want {
				t.Fatalf("alreadyExists(%v) = %v, want %v", c.err, got, c.want)
			}
		})
	}
}

// ensureRule splices the verb in front of the chain, which is not the
// same position for a plain rule and a `-t nat` rule. Getting this wrong
// silently produces an iptables syntax error at the exact moment a scope
// is being repaired.
func TestEnsureRuleVerbPlacement(t *testing.T) {
	tests := []struct {
		name      string
		spec      []string
		wantCheck []string
	}{
		{
			name:      "filter table rule",
			spec:      []string{"FORWARD", "-d", "10.50.9.2", "-j", "ACCEPT"},
			wantCheck: []string{"-C", "FORWARD", "-d", "10.50.9.2", "-j", "ACCEPT"},
		},
		{
			name:      "nat table rule keeps -t nat leading",
			spec:      []string{"-t", "nat", "PREROUTING", "-p", "udp", "-j", "DNAT"},
			wantCheck: []string{"-t", "nat", "-C", "PREROUTING", "-p", "udp", "-j", "DNAT"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := spliceVerb(tc.spec, "-C")
			if len(got) != len(tc.wantCheck) {
				t.Fatalf("got %v, want %v", got, tc.wantCheck)
			}
			for i := range got {
				if got[i] != tc.wantCheck[i] {
					t.Fatalf("got %v, want %v", got, tc.wantCheck)
				}
			}
		})
	}
}

// A namespace the daemon did not create must survive a rollback. On a
// GritivaCore host the agent builds scope-{id} with the running service's
// interfaces inside it; deleting that because a later Connect step failed
// would take the service's networking down as collateral.
func TestTearDownLeavesAForeignNamespaceAlone(t *testing.T) {
	borrowed := &Peer{ID: 239, Netns: "scope-239", VethHost: "vh-s239"}
	if borrowed.ownsNetns {
		t.Fatal("a Peer must not claim a namespace it never created")
	}
	if borrowed.ownsVeth {
		t.Fatal("a Peer must not claim a veth it never created")
	}

	ours := &Peer{ID: 900, Netns: "scope-900", VethHost: "vh-s900"}
	ours.ownsNetns = true
	ours.ownsVeth = true
	if !ours.ownsNetns || !ours.ownsVeth {
		t.Fatal("ownership flags must round-trip")
	}
}

// `ip` reports "already configured" with different wording depending on
// what is being added. Matching only the link-layer phrase left the repair
// path dying on address assignment — found in production while retrying a
// scope whose wg-scope had outlived a teardown.
func TestAlreadyExistsCoversAddressAssignment(t *testing.T) {
	err := errors.New(
		"ip netns exec scope-239 ip addr add 10.200.0.7/16 dev wg-scope: " +
			"exit status 2 (Error: ipv4: Address already assigned.)")
	if !alreadyExists(err) {
		t.Fatal("address-already-assigned must be treated as benign on the repair path")
	}
}
