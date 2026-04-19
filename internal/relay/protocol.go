// Package relay defines the wire protocol between gmeshd clients and the
// gmesh-relay server, plus the client + tunnel forwarders that plug the
// encoded stream into a local UDP socket WireGuard can talk to.
//
// # Protocol
//
// Each UDP datagram carries exactly one frame. Byte layout:
//
//	+------+-----------------+
//	| type |     payload     |
//	| u8   |      ...        |
//	+------+-----------------+
//
// Frame types:
//
//	0x01 AUTH         client → server. payload = auth token (session || nonce || hmac)
//	0x02 AUTH_OK      server → client. empty payload
//	0x03 AUTH_FAIL    server → client. payload = ASCII error
//	0x04 DATA         either direction. payload = opaque (WireGuard packet)
//	0x05 PEER_OFFLINE server → client. empty. sent when the paired peer drops
//	0x06 PING         client → server. empty. keepalive
//	0x07 PONG         server → client. empty
//
// The AUTH token structure is:
//
//	 0      16        24                   56
//	+--------+--------+----------------------+
//	|session |  peer  |   hmac_sha256        |
//	|  id    |   id   |   of (session||peer) |
//	| 16B    |  8B    |        32B           |
//	+--------+--------+----------------------+
//
// HMAC is keyed with a shared secret the backend and the relay server
// agree on. Replay protection: the relay drops duplicate (session, peer,
// hmac) triples seen within the last 5 minutes (future work).
package relay

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
)

// FrameType is the 1-byte type tag.
type FrameType byte

const (
	FrameAUTH        FrameType = 0x01
	FrameAUTHOK      FrameType = 0x02
	FrameAUTHFail    FrameType = 0x03
	FrameDATA        FrameType = 0x04
	FramePeerOffline FrameType = 0x05
	FramePING        FrameType = 0x06
	FramePONG        FrameType = 0x07
)

// String returns a debug name for the frame type.
func (t FrameType) String() string {
	switch t {
	case FrameAUTH:
		return "AUTH"
	case FrameAUTHOK:
		return "AUTH_OK"
	case FrameAUTHFail:
		return "AUTH_FAIL"
	case FrameDATA:
		return "DATA"
	case FramePeerOffline:
		return "PEER_OFFLINE"
	case FramePING:
		return "PING"
	case FramePONG:
		return "PONG"
	default:
		return fmt.Sprintf("UNKNOWN(0x%02x)", byte(t))
	}
}

// AuthToken is the structured form of a relay auth token.
type AuthToken struct {
	SessionID [16]byte
	PeerID    uint64
	HMAC      [32]byte
}

// TokenSize is the wire size of an AuthToken.
const TokenSize = 16 + 8 + 32 // 56 bytes

// SignToken computes the HMAC-SHA256 over (sessionID || peerID) with the
// given shared secret, and returns a full AuthToken.
func SignToken(secret []byte, sessionID [16]byte, peerID uint64) AuthToken {
	t := AuthToken{SessionID: sessionID, PeerID: peerID}
	mac := hmac.New(sha256.New, secret)
	mac.Write(sessionID[:])
	var peerBytes [8]byte
	binary.BigEndian.PutUint64(peerBytes[:], peerID)
	mac.Write(peerBytes[:])
	copy(t.HMAC[:], mac.Sum(nil))
	return t
}

// Verify returns nil iff the HMAC is valid for the given secret.
func (t *AuthToken) Verify(secret []byte) error {
	expected := SignToken(secret, t.SessionID, t.PeerID)
	if !hmac.Equal(t.HMAC[:], expected.HMAC[:]) {
		return ErrAuthFail
	}
	return nil
}

// Encode serialises the token to wire format.
func (t *AuthToken) Encode() []byte {
	out := make([]byte, TokenSize)
	copy(out[0:16], t.SessionID[:])
	binary.BigEndian.PutUint64(out[16:24], t.PeerID)
	copy(out[24:56], t.HMAC[:])
	return out
}

// DecodeAuthToken parses a wire-format token.
func DecodeAuthToken(b []byte) (*AuthToken, error) {
	if len(b) != TokenSize {
		return nil, fmt.Errorf("auth token: want %d bytes, got %d", TokenSize, len(b))
	}
	t := &AuthToken{PeerID: binary.BigEndian.Uint64(b[16:24])}
	copy(t.SessionID[:], b[0:16])
	copy(t.HMAC[:], b[24:56])
	return t, nil
}

// EncodeFrame builds one relay frame (type + payload).
func EncodeFrame(t FrameType, payload []byte) []byte {
	buf := make([]byte, 1+len(payload))
	buf[0] = byte(t)
	copy(buf[1:], payload)
	return buf
}

// DecodeFrame splits a datagram into (type, payload) or returns an error.
func DecodeFrame(b []byte) (FrameType, []byte, error) {
	if len(b) < 1 {
		return 0, nil, errors.New("empty frame")
	}
	return FrameType(b[0]), b[1:], nil
}

// ErrAuthFail is returned for any HMAC mismatch.
var ErrAuthFail = errors.New("relay: auth failed")

// MaxFrameSize is the largest accepted datagram. WireGuard packets are
// typically ≤ 1500 bytes; we allow 2048 to cover framing overhead.
const MaxFrameSize = 2048
