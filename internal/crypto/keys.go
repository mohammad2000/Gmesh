// Package crypto handles WireGuard keypair generation and the at-rest
// encryption of private keys on disk.
//
// WireGuard uses curve25519 for key agreement. The base64 wire format
// matches the `wg genkey` / `wg pubkey` tools.
package crypto

import (
	"fmt"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// Keypair is a WireGuard private/public keypair, both base64-encoded.
type Keypair struct {
	Private string
	Public  string
}

// GenerateKeypair returns a fresh curve25519 keypair.
func GenerateKeypair() (*Keypair, error) {
	priv, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return nil, fmt.Errorf("generate private key: %w", err)
	}
	return &Keypair{
		Private: priv.String(),
		Public:  priv.PublicKey().String(),
	}, nil
}

// ParsePrivateKey decodes a base64 private key and returns the corresponding
// public key.
func ParsePrivateKey(privB64 string) (priv, pub string, err error) {
	k, err := wgtypes.ParseKey(privB64)
	if err != nil {
		return "", "", fmt.Errorf("parse private key: %w", err)
	}
	return k.String(), k.PublicKey().String(), nil
}

// ParsePublicKey validates a public key string.
func ParsePublicKey(pubB64 string) error {
	_, err := wgtypes.ParseKey(pubB64)
	return err
}

// ParsePresharedKey validates a preshared key string. Empty string is valid
// (no preshared key).
func ParsePresharedKey(psk string) error {
	if psk == "" {
		return nil
	}
	_, err := wgtypes.ParseKey(psk)
	return err
}
