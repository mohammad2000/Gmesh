package traversal

import "github.com/mohammad2000/Gmesh/internal/nat"

// Classification is the pair of NAT types for local + remote, used to pick
// a traversal ladder.
type Classification struct {
	Local  nat.Type
	Remote nat.Type
}

// SelectLadder returns the ordered list of ConnectionMethods to attempt,
// from most to least preferred, given the local and remote NAT types.
//
// Rules (mirrors the Python implementation for continuity):
//
//	both Open                  → [DIRECT]
//	one Open  + one non-symmetric → [DIRECT, UPNP, STUN_HOLE_PUNCH]
//	both non-symmetric         → [UPNP, STUN_HOLE_PUNCH, SIMOPEN, BIRTHDAY, RELAY]
//	any Symmetric              → [UPNP, STUN_HOLE_PUNCH, SIMOPEN, BIRTHDAY, RELAY, WS_TUNNEL]
//	both Unknown               → [DIRECT, UPNP, STUN_HOLE_PUNCH, SIMOPEN, BIRTHDAY, RELAY, WS_TUNNEL]
//
// The engine tries methods in order until one succeeds or the ladder is
// exhausted.
func SelectLadder(c Classification) []Method {
	if c.Local == nat.Open && c.Remote == nat.Open {
		return []Method{MethodDirect}
	}

	// Either side symmetric? Need relay + WS tunnel fallbacks.
	if c.Local.IsSymmetric() || c.Remote.IsSymmetric() {
		return []Method{
			MethodUPnPPortMap,
			MethodSTUNHolePunch,
			MethodSimultaneousOpen,
			MethodBirthdayPunch,
			MethodRelay,
			MethodWSTunnel,
		}
	}

	// At least one Open, the other non-symmetric — direct should work.
	if c.Local == nat.Open || c.Remote == nat.Open {
		return []Method{MethodDirect, MethodUPnPPortMap, MethodSTUNHolePunch}
	}

	// Both classified & non-symmetric (cone/restricted/etc).
	if c.Local != nat.Unknown && c.Remote != nat.Unknown {
		return []Method{
			MethodUPnPPortMap,
			MethodSTUNHolePunch,
			MethodSimultaneousOpen,
			MethodBirthdayPunch,
			MethodRelay,
		}
	}

	// At least one Unknown — try everything, cheap first.
	return []Method{
		MethodDirect,
		MethodUPnPPortMap,
		MethodSTUNHolePunch,
		MethodSimultaneousOpen,
		MethodBirthdayPunch,
		MethodRelay,
		MethodWSTunnel,
	}
}
