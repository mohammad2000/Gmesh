package relay

import (
	"bytes"
	"testing"
)

func TestFrameTypeString(t *testing.T) {
	if FrameAUTH.String() != "AUTH" {
		t.Errorf("AUTH string = %q", FrameAUTH.String())
	}
	if FrameType(0xFF).String() != "UNKNOWN(0xff)" {
		t.Errorf("unknown string = %q", FrameType(0xFF).String())
	}
}

func TestTokenRoundtrip(t *testing.T) {
	secret := []byte("shared-secret-example")
	sid := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	tok := SignToken(secret, sid, 42)

	wire := tok.Encode()
	if len(wire) != TokenSize {
		t.Fatalf("encoded size = %d; want %d", len(wire), TokenSize)
	}

	got, err := DecodeAuthToken(wire)
	if err != nil {
		t.Fatalf("DecodeAuthToken: %v", err)
	}
	if got.SessionID != tok.SessionID {
		t.Errorf("session mismatch")
	}
	if got.PeerID != 42 {
		t.Errorf("peer = %d; want 42", got.PeerID)
	}
	if got.HMAC != tok.HMAC {
		t.Errorf("hmac mismatch")
	}
	if err := got.Verify(secret); err != nil {
		t.Errorf("Verify: %v", err)
	}
}

func TestTokenVerifyWrongSecret(t *testing.T) {
	tok := SignToken([]byte("right"), [16]byte{}, 1)
	if err := tok.Verify([]byte("wrong")); err != ErrAuthFail {
		t.Errorf("err = %v; want ErrAuthFail", err)
	}
}

func TestTokenVerifyTampered(t *testing.T) {
	tok := SignToken([]byte("s"), [16]byte{1}, 1)
	tok.PeerID = 99 // tamper without re-signing
	if err := tok.Verify([]byte("s")); err != ErrAuthFail {
		t.Errorf("tampered → %v; want ErrAuthFail", err)
	}
}

func TestDecodeAuthTokenBadSize(t *testing.T) {
	cases := [][]byte{nil, {1, 2, 3}, make([]byte, TokenSize+1)}
	for _, c := range cases {
		if _, err := DecodeAuthToken(c); err == nil {
			t.Errorf("expected error for %d bytes", len(c))
		}
	}
}

func TestEncodeDecodeFrame(t *testing.T) {
	payload := []byte("hello world")
	f := EncodeFrame(FrameDATA, payload)
	if f[0] != byte(FrameDATA) {
		t.Errorf("type byte wrong")
	}
	typ, p, err := DecodeFrame(f)
	if err != nil {
		t.Fatalf("DecodeFrame: %v", err)
	}
	if typ != FrameDATA {
		t.Errorf("type = %v", typ)
	}
	if !bytes.Equal(p, payload) {
		t.Errorf("payload roundtrip failed")
	}
}

func TestDecodeFrameEmpty(t *testing.T) {
	if _, _, err := DecodeFrame(nil); err == nil {
		t.Error("expected error for empty")
	}
}

func TestEncodeFrameZeroPayload(t *testing.T) {
	f := EncodeFrame(FramePING, nil)
	if len(f) != 1 || f[0] != byte(FramePING) {
		t.Errorf("PING frame wrong: %v", f)
	}
}
