package relay

import (
	"encoding/base64"
	"errors"
	"testing"
	"time"
)

func key(b byte) Key {
	var k Key
	for i := range k {
		k[i] = b
	}
	return k
}

func TestFrameTypeString(t *testing.T) {
	if FrameAUTH.String() != "AUTH" {
		t.Errorf("AUTH string = %q", FrameAUTH.String())
	}
	if FrameType(0xFF).String() != "UNKNOWN(0xff)" {
		t.Errorf("unknown string = %q", FrameType(0xFF).String())
	}
}

func TestCredential(t *testing.T) {
	secret := []byte("s3cret")
	now := time.Unix(1_800_000_000, 0)
	c := IssueCredential(secret, key(1), now.Add(time.Hour))
	if err := c.Verify(secret, now); err != nil {
		t.Fatalf("valid credential: %v", err)
	}
	if err := c.Verify([]byte("other"), now); !errors.Is(err, ErrAuthFail) {
		t.Errorf("wrong secret → %v", err)
	}
	if err := c.Verify(secret, now.Add(2*time.Hour)); !errors.Is(err, ErrExpired) {
		t.Errorf("expired → %v", err)
	}
	stolen := c
	stolen.PublicKey = key(2) // someone else's key with my MAC
	if err := stolen.Verify(secret, now); !errors.Is(err, ErrAuthFail) {
		t.Errorf("key swap → %v", err)
	}
	longer := c
	longer.Expiry += 3600
	if err := longer.Verify(secret, now); !errors.Is(err, ErrAuthFail) {
		t.Errorf("extended expiry → %v", err)
	}
}

func TestPairSessionIDSymmetric(t *testing.T) {
	if PairSessionID(key(1), key(2)) != PairSessionID(key(2), key(1)) {
		t.Fatal("session id depends on the side")
	}
	if PairSessionID(key(1), key(2)) == PairSessionID(key(1), key(3)) {
		t.Fatal("different pairs share a session")
	}
}

func TestAuthRoundtrip(t *testing.T) {
	a := Auth{Cred: IssueCredential([]byte("x"), key(1), time.Unix(1_900_000_000, 0)), Peer: key(2)}
	w := a.Encode()
	if len(w) != AuthSize {
		t.Fatalf("size %d", len(w))
	}
	got, err := DecodeAuth(w)
	if err != nil || got != a {
		t.Fatalf("roundtrip: %v %+v", err, got)
	}
	if _, err := DecodeAuth(w[:50]); err == nil {
		t.Error("short payload accepted")
	}
	self := Auth{Cred: IssueCredential([]byte("x"), key(1), time.Now()), Peer: key(1)}
	if _, err := DecodeAuth(self.Encode()); err == nil {
		t.Error("self-pair accepted")
	}
}

func TestParseKey(t *testing.T) {
	k := key(7)
	got, err := ParseKey(k.String())
	if err != nil || got != k {
		t.Fatalf("ParseKey: %v", err)
	}
	if _, err := ParseKey("short"); err == nil {
		t.Error("bad key accepted")
	}
}

// The control plane (GritivaCore app/services/mesh_relay.py) computes the
// same MAC; this vector is checked on both sides.
func TestCredentialVector(t *testing.T) {
	c := IssueCredential([]byte("s"), key(1), time.Unix(1800000000, 0))
	if got := base64.StdEncoding.EncodeToString(c.MAC[:]); got != "NAa7foav70R7gPpRSYpRjqappG4/IMYXL0k2aBBWtnU=" {
		t.Fatalf("mac %s", got)
	}
}
