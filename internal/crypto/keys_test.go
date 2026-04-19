package crypto

import (
	"strings"
	"testing"
)

func TestGenerateKeypair(t *testing.T) {
	kp, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}
	if kp.Private == "" || kp.Public == "" {
		t.Fatal("empty keys")
	}
	if kp.Private == kp.Public {
		t.Fatal("private and public keys are identical")
	}
	// WireGuard base64 keys are always 44 chars (32 bytes → 44 base64 chars).
	if len(kp.Private) != 44 {
		t.Errorf("private len = %d, want 44", len(kp.Private))
	}
	if len(kp.Public) != 44 {
		t.Errorf("public len = %d, want 44", len(kp.Public))
	}
	if !strings.HasSuffix(kp.Private, "=") {
		t.Errorf("private key should end with '=' (base64 padding)")
	}
}

func TestParsePrivateKey(t *testing.T) {
	kp, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	priv, pub, err := ParsePrivateKey(kp.Private)
	if err != nil {
		t.Fatalf("ParsePrivateKey: %v", err)
	}
	if priv != kp.Private {
		t.Errorf("private roundtrip mismatch")
	}
	if pub != kp.Public {
		t.Errorf("public derived mismatch: got %s, want %s", pub, kp.Public)
	}
}

func TestParsePrivateKeyInvalid(t *testing.T) {
	cases := []string{"", "not-base64", "YWJj", strings.Repeat("A", 50)}
	for _, c := range cases {
		if _, _, err := ParsePrivateKey(c); err == nil {
			t.Errorf("expected error for %q", c)
		}
	}
}

func TestParsePublicKey(t *testing.T) {
	kp, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	if err := ParsePublicKey(kp.Public); err != nil {
		t.Errorf("ParsePublicKey: %v", err)
	}
}

func TestParsePresharedKeyEmpty(t *testing.T) {
	if err := ParsePresharedKey(""); err != nil {
		t.Errorf("empty PSK should be valid: %v", err)
	}
}
