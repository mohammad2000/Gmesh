// Package relay provides the two fallback transports used when direct P2P
// traversal fails: a UDP relay via gmesh-relay (DERP-style), and a WebSocket
// tunnel over the GritivaCore backend's /ws/relay/{session}/{peer} endpoint.
package relay

import (
	"context"
	"errors"
)

// Client is a relay transport.
type Client interface {
	// Dial opens a relay session for (peerID, sessionID). Must be idempotent.
	Dial(ctx context.Context, peerID int64, sessionID string) error

	// Close tears the session down.
	Close(peerID int64) error

	// Stats returns current relay statistics for the peer.
	Stats(peerID int64) Stats
}

// Stats is a per-peer relay counter snapshot.
type Stats struct {
	BytesRx    int64
	BytesTx    int64
	PacketsRx  int64
	PacketsTx  int64
	ConnectedS int64
}

// ErrNoTransport is returned when neither UDP relay nor WS tunnel succeeded.
var ErrNoTransport = errors.New("relay: no available transport")
