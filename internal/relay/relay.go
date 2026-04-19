// Package relay provides the two fallback transports used when direct P2P
// traversal fails:
//
//   - a UDP relay via the `gmesh-relay` server (DERP-style), implemented
//     in client.go
//   - a WebSocket tunnel through the GritivaCore backend's
//     /ws/relay/{session}/{peer} endpoint, implemented in ws_tunnel.go
//
// Both share a small header/frame format defined in protocol.go plus the
// Stats snapshot type below.
package relay

// Stats is a per-session counter snapshot used by both the UDP client and
// the WS tunnel client.
type Stats struct {
	TxFrames, RxFrames uint64
	BytesTx, BytesRx   uint64
	ConnectedS         int64
}
