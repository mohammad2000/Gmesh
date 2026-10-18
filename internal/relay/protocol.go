// Package relay defines the wire protocol between gmeshd clients and the
// gmesh-relay server, plus the client that plugs the relayed stream into a
// local UDP socket WireGuard can talk to.
//
// # Protocol (v2)
//
// Each UDP datagram carries exactly one frame: a 1-byte type and a payload.
//
//	0x01 AUTH         client → server. payload = Auth (below)
//	0x02 AUTH_OK      server → client. empty
//	0x03 AUTH_FAIL    server → client. payload = ASCII reason
//	0x04 DATA         either direction. payload = opaque WireGuard packet
//	0x05 PEER_OFFLINE server → client. reserved
//	0x06 PING         client → server. empty
//	0x07 PONG         server → client. empty
//
// # Who may use the relay
//
// The control plane gives every node a Credential: an HMAC, keyed with the
// relay's secret, over the node's own WireGuard public key and an expiry.
// Nodes never hold the secret. A node authenticates for one peer at a time:
//
//	 0     1        33        65       73          105
//	+-----+--------+---------+--------+-----------+
//	| 0x02| self   | peer    | expiry | cred mac  |
//	|  v  | pubkey | pubkey  | u64 BE | 32 bytes  |
//	+-----+--------+---------+--------+-----------+
//
// The relay checks the credential against `self`, then pairs the client into
// the session named by the two public keys (PairSessionID), in the slot
// belonging to `self`. A node can therefore only ever stand in for its own
// key, and only in sessions that include it. The relay sees WireGuard
// ciphertext only.
package relay

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"time"
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

// Key is a WireGuard public key (Curve25519, 32 bytes).
type Key [32]byte

// ParseKey decodes a base64 WireGuard key.
func ParseKey(s string) (Key, error) {
	var k Key
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil || len(b) != 32 {
		return k, fmt.Errorf("relay: bad public key")
	}
	copy(k[:], b)
	return k, nil
}

func (k Key) String() string { return base64.StdEncoding.EncodeToString(k[:]) }

const credLabel = "gmesh-relay-cred-v2"

// Credential lets the holder of one WireGuard key use the relay until Expiry.
type Credential struct {
	PublicKey Key
	Expiry    int64 // unix seconds
	MAC       [32]byte
}

func credMAC(secret []byte, pub Key, expiry int64) [32]byte {
	m := hmac.New(sha256.New, secret)
	m.Write([]byte(credLabel))
	m.Write(pub[:])
	var e [8]byte
	binary.BigEndian.PutUint64(e[:], uint64(expiry))
	m.Write(e[:])
	var out [32]byte
	copy(out[:], m.Sum(nil))
	return out
}

// IssueCredential is what the control plane (and tests) run; nodes don't
// have the secret.
func IssueCredential(secret []byte, pub Key, expiry time.Time) Credential {
	return Credential{PublicKey: pub, Expiry: expiry.Unix(), MAC: credMAC(secret, pub, expiry.Unix())}
}

// Verify checks the MAC and the expiry.
func (c Credential) Verify(secret []byte, now time.Time) error {
	want := credMAC(secret, c.PublicKey, c.Expiry)
	if !hmac.Equal(want[:], c.MAC[:]) {
		return ErrAuthFail
	}
	if now.Unix() > c.Expiry {
		return ErrExpired
	}
	return nil
}

// PairSessionID names the relay session of two keys; it is the same from
// both sides.
func PairSessionID(a, b Key) [16]byte {
	lo, hi := a, b
	if bytes.Compare(a[:], b[:]) > 0 {
		lo, hi = b, a
	}
	h := sha256.New()
	h.Write([]byte("gmesh-relay-pair-v2"))
	h.Write(lo[:])
	h.Write(hi[:])
	var out [16]byte
	copy(out[:], h.Sum(nil))
	return out
}

// Auth is the AUTH frame payload.
type Auth struct {
	Cred Credential // Cred.PublicKey is "self"
	Peer Key
}

// AuthSize is the wire size of an Auth payload.
const AuthSize = 1 + 32 + 32 + 8 + 32

const authVersion = 0x02

// Encode serialises the payload.
func (a Auth) Encode() []byte {
	out := make([]byte, AuthSize)
	out[0] = authVersion
	copy(out[1:33], a.Cred.PublicKey[:])
	copy(out[33:65], a.Peer[:])
	binary.BigEndian.PutUint64(out[65:73], uint64(a.Cred.Expiry))
	copy(out[73:105], a.Cred.MAC[:])
	return out
}

// DecodeAuth parses an AUTH payload.
func DecodeAuth(b []byte) (Auth, error) {
	var a Auth
	if len(b) != AuthSize || b[0] != authVersion {
		return a, fmt.Errorf("auth: want v2, %d bytes", AuthSize)
	}
	copy(a.Cred.PublicKey[:], b[1:33])
	copy(a.Peer[:], b[33:65])
	a.Cred.Expiry = int64(binary.BigEndian.Uint64(b[65:73]))
	copy(a.Cred.MAC[:], b[73:105])
	if a.Cred.PublicKey == a.Peer {
		return a, errors.New("auth: self and peer are the same key")
	}
	return a, nil
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

var (
	// ErrAuthFail is returned for a MAC mismatch.
	ErrAuthFail = errors.New("relay: auth failed")
	// ErrExpired is returned for a credential past its expiry.
	ErrExpired = errors.New("relay: credential expired")
)

// MaxFrameSize is the largest accepted datagram. WireGuard packets are
// ≤ 1500 bytes on a normal path; 2048 covers framing.
const MaxFrameSize = 2048
