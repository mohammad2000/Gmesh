// Package mtls implements a small, self-hosted certificate authority
// for gmesh peers. Each peer that joins the mesh can request a short-
// lived client/server certificate signed by the mesh CA; the cert's
// SAN carries a SPIFFE-style identity (spiffe://<trust_domain>/peer/<id>)
// so higher-layer services (ingress profiles, per-peer gRPC auth) can
// authenticate callers without depending on WireGuard keys directly.
//
// # Scope for Phase 20
//
// This package provides:
//
//   - CA bootstrap (self-signed root, stored on disk)
//   - Peer cert issuance with SPIFFE ID + DNS SAN
//   - In-memory + on-disk cert store
//   - Revocation list (CRL-style, plain JSON on disk)
//   - Trust-bundle export (CA cert PEM) for peers
//
// What it does NOT do yet:
//
//   - OCSP responder (revocation is polled from the JSON CRL)
//   - Automatic rotation (callers must call IssueCert to refresh)
//   - Intermediate CAs (one root per mesh, for now)
//   - HSM/KMS-backed root (root key lives on disk, protected by file
//     mode 0600; bootstrap your root on a well-secured control node)
//
// The CA lives in config.MTLS.CADir — a directory with:
//
//   ca.crt        PEM-encoded root certificate
//   ca.key        PEM-encoded root private key (mode 0600)
//   issued/       One file per issued cert, named <peer_id>-<serial>.json
//   revoked.json  List of revoked serials
//
// Callers access the package through the Manager interface; the Linux
// implementation is the only one today, but the split keeps tests stub-
// friendly.
package mtls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"time"
)

// TrustDomain is the SPIFFE trust-domain used when constructing SANs.
// Operators can override per-instance via config.MTLS.TrustDomain; the
// default matches the mesh's typical scope.
const DefaultTrustDomain = "gmesh.local"

// CertRequest is what callers hand to IssueCert. The Manager fills
// NotBefore / NotAfter if zero.
type CertRequest struct {
	PeerID     int64
	CommonName string // usually "peer-<id>" — rendered as CN if empty
	DNSNames   []string
	IPAddrs    []net.IP
	// SpiffeID override. Zero → generated as spiffe://<trust_domain>/peer/<id>.
	SpiffeID string
	// Validity window. Zero → 90 days starting now.
	NotBefore time.Time
	NotAfter  time.Time
}

// Cert is the issued material returned to the caller.
type Cert struct {
	Serial     string    // hex-encoded big int
	PeerID     int64
	SpiffeID   string
	CommonName string
	CertPEM    string
	KeyPEM     string // PEM of the peer's private key
	CAPEM      string // PEM of the root cert (trust anchor)
	NotBefore  time.Time
	NotAfter   time.Time
	CreatedAt  time.Time
}

// Summary is the read-only projection for List/Get RPCs — no private key.
type Summary struct {
	Serial     string
	PeerID     int64
	SpiffeID   string
	CommonName string
	NotBefore  time.Time
	NotAfter   time.Time
	Revoked    bool
	RevokedAt  time.Time
	Reason     string
}

// Manager is the full lifecycle surface. Implementations must be safe
// for concurrent use — the gRPC server may call InitCA + IssueCert
// from different goroutines.
type Manager interface {
	// InitCA creates a fresh CA in the configured directory. Errors if
	// a CA already exists unless force is true. Returns the root cert
	// PEM so callers can hand it to newly-joining peers without a
	// follow-up RPC.
	InitCA(trustDomain string, force bool) (caPEM string, err error)

	// Loaded reports whether an existing CA is present + loaded. Useful
	// for gmeshd startup to distinguish "never initialised" from "error".
	Loaded() bool

	// TrustDomain returns the domain the loaded CA uses.
	TrustDomain() string

	// CACert returns the root cert PEM, or "" if not loaded.
	CACert() string

	// IssueCert signs a new peer certificate.
	IssueCert(req CertRequest) (*Cert, error)

	// ListCerts returns summaries of every certificate issued (live +
	// revoked). Optionally filter by peer_id (0 → all).
	ListCerts(peerID int64) []Summary

	// GetCert returns one cert by serial. Found=false if missing.
	GetCert(serial string) (Summary, bool)

	// RevokeCert marks a serial revoked with a reason. Idempotent on
	// already-revoked serials.
	RevokeCert(serial, reason string) error

	// IsRevoked is a cheap synchronous check used by verifiers.
	IsRevoked(serial string) bool

	// Name identifies the backend in logs: "linux" | "stub".
	Name() string
}

// Errors.
var (
	ErrAlreadyInitialised = errors.New("mtls: CA already initialised")
	ErrNotInitialised     = errors.New("mtls: CA not initialised")
	ErrNotFound           = errors.New("mtls: cert not found")
)

// ── PEM helpers ───────────────────────────────────────────────────────

// generateECKey returns an ECDSA P-256 key — same curve WebPKI expects
// and fast enough that peer issuance is < 1 ms.
func generateECKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

func pemEncodeCert(der []byte) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func pemEncodeECKey(key *ecdsa.PrivateKey) (string, error) {
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return "", fmt.Errorf("marshal ec key: %w", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})), nil
}

// spiffeURIFor builds the canonical URL for a peer. Keep in lock-step
// with the issued cert's URI SAN so verifiers can match on string
// equality.
func spiffeURIFor(trustDomain string, peerID int64) string {
	if trustDomain == "" {
		trustDomain = DefaultTrustDomain
	}
	return fmt.Sprintf("spiffe://%s/peer/%d", trustDomain, peerID)
}

// randSerial returns a 16-byte random serial as a big.Int. x509 requires
// a unique non-zero serial; the default reader has more than enough
// entropy that collisions are not a concern.
func randSerial() (*big.Int, error) {
	max := new(big.Int).Lsh(big.NewInt(1), 128)
	return rand.Int(rand.Reader, max)
}

// buildCATemplate returns a fresh self-signed CA template.
func buildCATemplate(trustDomain string) (*x509.Certificate, error) {
	serial, err := randSerial()
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	return &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "gmesh Root CA",
			Organization: []string{"gmesh"},
		},
		NotBefore:             now,
		NotAfter:              now.AddDate(10, 0, 0), // 10 years
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true, // no intermediates for now
		DNSNames:              []string{trustDomain},
	}, nil
}

// defaultValidity returns the 90-day window used when NotBefore/NotAfter
// are zero on a request. Operators who need longer or shorter lifetimes
// set them explicitly.
func defaultValidity() (time.Time, time.Time) {
	now := time.Now().UTC()
	return now, now.AddDate(0, 0, 90)
}

// ParseCertPEM is exposed so verifiers (e.g. ingress TLS termination)
// can reuse it.
func ParseCertPEM(p string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(p))
	if block == nil {
		return nil, errors.New("mtls: no PEM block in input")
	}
	return x509.ParseCertificate(block.Bytes)
}
