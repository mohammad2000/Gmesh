package mtls

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/mohammad2000/Gmesh/internal/metrics"
)

func randReader() io.Reader { return rand.Reader }

// LinuxManager is the filesystem-backed CA implementation. It is not
// actually Linux-specific — the name matches the package-layout pattern
// used elsewhere (egress, quota) and keeps room for a future KMS-backed
// sibling that only works on specific hosts.
type LinuxManager struct {
	Log *slog.Logger
	Dir string

	mu       sync.RWMutex
	loaded   bool
	trust    string
	caCert   *x509.Certificate
	caKey    any // *ecdsa.PrivateKey
	caPEM    string
	issued   map[string]*issuedRec // serial hex → record
	revoked  map[string]revokeRec  // serial hex → record
}

type issuedRec struct {
	Summary Summary `json:"summary"`
	CertPEM string  `json:"cert_pem"`
}

type revokeRec struct {
	Serial    string    `json:"serial"`
	Reason    string    `json:"reason"`
	RevokedAt time.Time `json:"revoked_at"`
}

// NewLinux returns an unopened manager. Call Open() or InitCA() next.
func NewLinux(log *slog.Logger, dir string) *LinuxManager {
	if log == nil {
		log = slog.Default()
	}
	return &LinuxManager{
		Log: log, Dir: dir,
		issued:  map[string]*issuedRec{},
		revoked: map[string]revokeRec{},
	}
}

// Name implements Manager.
func (m *LinuxManager) Name() string { return "linux" }

// Loaded reports whether Open / InitCA has established a usable root.
func (m *LinuxManager) Loaded() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.loaded
}

// TrustDomain returns the domain the loaded CA uses.
func (m *LinuxManager) TrustDomain() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.trust
}

// CACert returns the PEM of the root cert, or "" if not loaded.
func (m *LinuxManager) CACert() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.caPEM
}

// Open loads an existing CA from disk. Returns ErrNotInitialised if the
// directory has no ca.crt. Idempotent — calling Open on an already-open
// manager is a no-op.
func (m *LinuxManager) Open() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.loaded {
		return nil
	}
	return m.openLocked()
}

func (m *LinuxManager) openLocked() error {
	caCrtPath := filepath.Join(m.Dir, "ca.crt")
	caKeyPath := filepath.Join(m.Dir, "ca.key")
	caPEMBytes, err := os.ReadFile(caCrtPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return ErrNotInitialised
		}
		return fmt.Errorf("read ca.crt: %w", err)
	}
	cert, err := ParseCertPEM(string(caPEMBytes))
	if err != nil {
		return fmt.Errorf("parse ca.crt: %w", err)
	}
	keyPEMBytes, err := os.ReadFile(caKeyPath)
	if err != nil {
		return fmt.Errorf("read ca.key: %w", err)
	}
	block, _ := pem.Decode(keyPEMBytes)
	if block == nil {
		return errors.New("mtls: ca.key has no PEM block")
	}
	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("parse ca.key: %w", err)
	}
	m.caCert = cert
	m.caKey = key
	m.caPEM = string(caPEMBytes)
	// The trust domain is baked into the CA's DNSNames — the first entry
	// is our canonical domain (buildCATemplate writes it that way).
	if len(cert.DNSNames) > 0 {
		m.trust = cert.DNSNames[0]
	} else {
		m.trust = DefaultTrustDomain
	}

	// Load issued certs + revoked list.
	if err := m.loadIssued(); err != nil {
		return err
	}
	if err := m.loadRevoked(); err != nil {
		return err
	}

	m.loaded = true
	m.Log.Info("mtls CA loaded",
		"trust_domain", m.trust,
		"issued", len(m.issued),
		"revoked", len(m.revoked))
	return nil
}

// InitCA creates a new CA at Dir. Returns ErrAlreadyInitialised unless
// force=true. After a successful InitCA, the manager is "loaded".
func (m *LinuxManager) InitCA(trustDomain string, force bool) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.loaded && !force {
		return m.caPEM, ErrAlreadyInitialised
	}
	if trustDomain == "" {
		trustDomain = DefaultTrustDomain
	}
	if err := os.MkdirAll(m.Dir, 0o700); err != nil {
		return "", fmt.Errorf("mkdir %s: %w", m.Dir, err)
	}
	if err := os.MkdirAll(filepath.Join(m.Dir, "issued"), 0o700); err != nil {
		return "", fmt.Errorf("mkdir issued: %w", err)
	}

	// Generate key + self-signed cert.
	key, err := generateECKey()
	if err != nil {
		return "", fmt.Errorf("gen ca key: %w", err)
	}
	tmpl, err := buildCATemplate(trustDomain)
	if err != nil {
		return "", err
	}
	der, err := x509.CreateCertificate(randReader(), tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return "", fmt.Errorf("self-sign ca: %w", err)
	}
	certPEM := pemEncodeCert(der)
	keyPEM, err := pemEncodeECKey(key)
	if err != nil {
		return "", err
	}

	if err := writeFileSecure(filepath.Join(m.Dir, "ca.crt"), []byte(certPEM), 0o644); err != nil {
		return "", err
	}
	if err := writeFileSecure(filepath.Join(m.Dir, "ca.key"), []byte(keyPEM), 0o600); err != nil {
		return "", err
	}

	// Reset in-memory caches — force=true may be wiping an old CA.
	m.caCert, _ = x509.ParseCertificate(der)
	m.caKey = key
	m.caPEM = certPEM
	m.trust = trustDomain
	m.issued = map[string]*issuedRec{}
	m.revoked = map[string]revokeRec{}
	m.loaded = true

	m.Log.Info("mtls CA initialised", "trust_domain", trustDomain, "dir", m.Dir, "force", force)
	return certPEM, nil
}

// IssueCert implements Manager.
func (m *LinuxManager) IssueCert(req CertRequest) (*Cert, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.loaded {
		return nil, ErrNotInitialised
	}

	// Fill defaults.
	if req.NotBefore.IsZero() || req.NotAfter.IsZero() {
		req.NotBefore, req.NotAfter = defaultValidity()
	}
	if req.NotAfter.Before(req.NotBefore) {
		return nil, errors.New("mtls: not_after must be after not_before")
	}
	if req.SpiffeID == "" {
		req.SpiffeID = spiffeURIFor(m.trust, req.PeerID)
	}
	if req.CommonName == "" {
		req.CommonName = fmt.Sprintf("peer-%d", req.PeerID)
	}

	spiffeURL, err := url.Parse(req.SpiffeID)
	if err != nil {
		return nil, fmt.Errorf("mtls: bad spiffe id: %w", err)
	}

	// Peer key.
	key, err := generateECKey()
	if err != nil {
		return nil, fmt.Errorf("gen peer key: %w", err)
	}

	serial, err := randSerial()
	if err != nil {
		return nil, fmt.Errorf("gen serial: %w", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   req.CommonName,
			Organization: []string{"gmesh peer"},
		},
		NotBefore:   req.NotBefore,
		NotAfter:    req.NotAfter,
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		DNSNames:    req.DNSNames,
		IPAddresses: req.IPAddrs,
		URIs:        []*url.URL{spiffeURL},
	}

	caKey, _ := m.caKey.(interface {
		Public() any
	})
	_ = caKey // pacify linter if unused

	der, err := x509.CreateCertificate(randReader(), tmpl, m.caCert, &key.PublicKey, m.caKey)
	if err != nil {
		return nil, fmt.Errorf("sign peer cert: %w", err)
	}

	certPEM := pemEncodeCert(der)
	keyPEM, err := pemEncodeECKey(key)
	if err != nil {
		return nil, err
	}

	serialHex := fmt.Sprintf("%x", serial)
	now := time.Now().UTC()
	summary := Summary{
		Serial: serialHex, PeerID: req.PeerID, SpiffeID: req.SpiffeID,
		CommonName: req.CommonName,
		NotBefore:  req.NotBefore, NotAfter: req.NotAfter,
	}
	m.issued[serialHex] = &issuedRec{Summary: summary, CertPEM: certPEM}
	if err := m.saveIssued(req.PeerID, serialHex, summary, certPEM); err != nil {
		m.Log.Warn("persist issued cert", "serial", serialHex, "error", err)
	}

	m.Log.Info("mtls cert issued",
		"peer_id", req.PeerID, "serial", serialHex,
		"cn", req.CommonName, "spiffe", req.SpiffeID,
		"not_after", req.NotAfter)
	metrics.MTLSCertsIssued.Inc()

	return &Cert{
		Serial:     serialHex,
		PeerID:     req.PeerID,
		SpiffeID:   req.SpiffeID,
		CommonName: req.CommonName,
		CertPEM:    certPEM,
		KeyPEM:     keyPEM,
		CAPEM:      m.caPEM,
		NotBefore:  req.NotBefore,
		NotAfter:   req.NotAfter,
		CreatedAt:  now,
	}, nil
}

// ListCerts implements Manager.
func (m *LinuxManager) ListCerts(peerID int64) []Summary {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]Summary, 0, len(m.issued))
	for _, r := range m.issued {
		s := r.Summary
		if peerID != 0 && s.PeerID != peerID {
			continue
		}
		if rv, ok := m.revoked[s.Serial]; ok {
			s.Revoked = true
			s.RevokedAt = rv.RevokedAt
			s.Reason = rv.Reason
		}
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].PeerID != out[j].PeerID {
			return out[i].PeerID < out[j].PeerID
		}
		return out[i].NotBefore.Before(out[j].NotBefore)
	})
	return out
}

// GetCert implements Manager.
func (m *LinuxManager) GetCert(serial string) (Summary, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	r, ok := m.issued[serial]
	if !ok {
		return Summary{}, false
	}
	s := r.Summary
	if rv, ok := m.revoked[serial]; ok {
		s.Revoked = true
		s.RevokedAt = rv.RevokedAt
		s.Reason = rv.Reason
	}
	return s, true
}

// RevokeCert implements Manager.
func (m *LinuxManager) RevokeCert(serial, reason string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.loaded {
		return ErrNotInitialised
	}
	if _, ok := m.issued[serial]; !ok {
		return ErrNotFound
	}
	if _, ok := m.revoked[serial]; ok {
		return nil // idempotent
	}
	m.revoked[serial] = revokeRec{
		Serial: serial, Reason: reason, RevokedAt: time.Now().UTC(),
	}
	if err := m.saveRevoked(); err != nil {
		return fmt.Errorf("persist revocation: %w", err)
	}
	m.Log.Info("mtls cert revoked", "serial", serial, "reason", reason)
	metrics.MTLSCertsRevoked.Inc()
	return nil
}

// IsRevoked implements Manager.
func (m *LinuxManager) IsRevoked(serial string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	_, ok := m.revoked[strings.ToLower(serial)]
	return ok
}

// ── persistence helpers ──────────────────────────────────────────────

func (m *LinuxManager) loadIssued() error {
	dir := filepath.Join(m.Dir, "issued")
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		var rec issuedRec
		if err := json.Unmarshal(raw, &rec); err != nil {
			continue
		}
		m.issued[rec.Summary.Serial] = &rec
	}
	return nil
}

func (m *LinuxManager) saveIssued(peerID int64, serial string, s Summary, certPEM string) error {
	path := filepath.Join(m.Dir, "issued", fmt.Sprintf("peer-%d-%s.json", peerID, serial))
	rec := issuedRec{Summary: s, CertPEM: certPEM}
	raw, err := json.MarshalIndent(&rec, "", "  ")
	if err != nil {
		return err
	}
	return writeFileSecure(path, raw, 0o640)
}

func (m *LinuxManager) loadRevoked() error {
	path := filepath.Join(m.Dir, "revoked.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	var list []revokeRec
	if err := json.Unmarshal(raw, &list); err != nil {
		return fmt.Errorf("parse revoked.json: %w", err)
	}
	for _, r := range list {
		m.revoked[r.Serial] = r
	}
	return nil
}

func (m *LinuxManager) saveRevoked() error {
	list := make([]revokeRec, 0, len(m.revoked))
	for _, r := range m.revoked {
		list = append(list, r)
	}
	sort.Slice(list, func(i, j int) bool {
		return list[i].RevokedAt.Before(list[j].RevokedAt)
	})
	raw, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}
	return writeFileSecure(filepath.Join(m.Dir, "revoked.json"), raw, 0o640)
}

// writeFileSecure writes atomically (temp + rename) with the requested
// mode. The rename is atomic on POSIX so a crashed write never leaves a
// half-written file visible to readers.
func writeFileSecure(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

var _ Manager = (*LinuxManager)(nil)
