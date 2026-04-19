package mtls

import (
	"crypto/x509"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func silent() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func newLinuxT(t *testing.T) *LinuxManager {
	t.Helper()
	return NewLinux(silent(), t.TempDir())
}

func TestInitCAAndLoad(t *testing.T) {
	m := newLinuxT(t)
	if m.Loaded() {
		t.Fatal("manager should not be loaded before InitCA")
	}
	caPEM, err := m.InitCA("example.test", false)
	if err != nil {
		t.Fatalf("InitCA: %v", err)
	}
	if !m.Loaded() {
		t.Error("manager not loaded after InitCA")
	}
	if m.TrustDomain() != "example.test" {
		t.Errorf("trust domain = %q", m.TrustDomain())
	}
	if !strings.Contains(caPEM, "BEGIN CERTIFICATE") {
		t.Error("CA PEM missing cert header")
	}

	// Reopen from disk.
	m2 := NewLinux(silent(), m.Dir)
	if err := m2.Open(); err != nil {
		t.Fatalf("Open: %v", err)
	}
	if m2.TrustDomain() != "example.test" {
		t.Errorf("reopened trust = %q", m2.TrustDomain())
	}
}

func TestInitCAAlreadyInitialised(t *testing.T) {
	m := newLinuxT(t)
	if _, err := m.InitCA("", false); err != nil {
		t.Fatal(err)
	}
	if _, err := m.InitCA("", false); err != ErrAlreadyInitialised {
		t.Errorf("second init without force: got %v; want ErrAlreadyInitialised", err)
	}
	if _, err := m.InitCA("", true); err != nil {
		t.Errorf("force init failed: %v", err)
	}
}

func TestIssueCertAndVerify(t *testing.T) {
	m := newLinuxT(t)
	_, _ = m.InitCA("", false)
	c, err := m.IssueCert(CertRequest{PeerID: 42, CommonName: "core-peer"})
	if err != nil {
		t.Fatalf("IssueCert: %v", err)
	}
	if c.SpiffeID != "spiffe://gmesh.local/peer/42" {
		t.Errorf("spiffe id = %q", c.SpiffeID)
	}
	if c.Serial == "" {
		t.Error("empty serial")
	}

	// Verify the issued cert chains back to the CA.
	caCert, err := ParseCertPEM(c.CAPEM)
	if err != nil {
		t.Fatalf("parse CA: %v", err)
	}
	peerCert, err := ParseCertPEM(c.CertPEM)
	if err != nil {
		t.Fatalf("parse peer cert: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	if _, err := peerCert.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
		t.Errorf("peer cert does not verify against CA: %v", err)
	}
	if len(peerCert.URIs) != 1 || peerCert.URIs[0].String() != c.SpiffeID {
		t.Errorf("peer cert URI SAN mismatch: %v", peerCert.URIs)
	}
}

func TestIssueCertNotInitialised(t *testing.T) {
	m := newLinuxT(t)
	if _, err := m.IssueCert(CertRequest{PeerID: 1}); err != ErrNotInitialised {
		t.Errorf("got %v; want ErrNotInitialised", err)
	}
}

func TestListCertsFilter(t *testing.T) {
	m := newLinuxT(t)
	_, _ = m.InitCA("", false)
	_, _ = m.IssueCert(CertRequest{PeerID: 1})
	_, _ = m.IssueCert(CertRequest{PeerID: 1})
	_, _ = m.IssueCert(CertRequest{PeerID: 2})
	if n := len(m.ListCerts(0)); n != 3 {
		t.Errorf("ListCerts(0) = %d; want 3", n)
	}
	if n := len(m.ListCerts(1)); n != 2 {
		t.Errorf("ListCerts(1) = %d; want 2", n)
	}
	if n := len(m.ListCerts(99)); n != 0 {
		t.Errorf("ListCerts(99) = %d; want 0", n)
	}
}

func TestRevokeCert(t *testing.T) {
	m := newLinuxT(t)
	_, _ = m.InitCA("", false)
	c, _ := m.IssueCert(CertRequest{PeerID: 1})
	if m.IsRevoked(c.Serial) {
		t.Fatal("pre-revoke should be false")
	}
	if err := m.RevokeCert(c.Serial, "compromised"); err != nil {
		t.Fatal(err)
	}
	if !m.IsRevoked(c.Serial) {
		t.Error("revoked but IsRevoked false")
	}
	// Idempotent.
	if err := m.RevokeCert(c.Serial, "any"); err != nil {
		t.Errorf("idempotent revoke failed: %v", err)
	}
	// ListCerts reports revoked=true.
	summary, ok := m.GetCert(c.Serial)
	if !ok || !summary.Revoked || summary.Reason != "compromised" {
		t.Errorf("GetCert revocation fields = %+v", summary)
	}

	// Reopen — revocation persists.
	m2 := NewLinux(silent(), m.Dir)
	_ = m2.Open()
	if !m2.IsRevoked(c.Serial) {
		t.Error("revocation did not persist")
	}
}

func TestRevokeMissing(t *testing.T) {
	m := newLinuxT(t)
	_, _ = m.InitCA("", false)
	if err := m.RevokeCert("deadbeef", "x"); err != ErrNotFound {
		t.Errorf("got %v; want ErrNotFound", err)
	}
}

func TestCustomValidityWindow(t *testing.T) {
	m := newLinuxT(t)
	_, _ = m.InitCA("", false)
	before := time.Now().Add(-time.Hour).UTC()
	after := time.Now().Add(time.Hour).UTC()
	c, err := m.IssueCert(CertRequest{PeerID: 9, NotBefore: before, NotAfter: after})
	if err != nil {
		t.Fatal(err)
	}
	if !c.NotBefore.Equal(before) || !c.NotAfter.Equal(after) {
		t.Errorf("validity mismatch: got %v .. %v; want %v .. %v",
			c.NotBefore, c.NotAfter, before, after)
	}
}

func TestOpenMissingCA(t *testing.T) {
	m := NewLinux(silent(), filepath.Join(t.TempDir(), "nope"))
	if err := m.Open(); err != ErrNotInitialised {
		t.Errorf("got %v; want ErrNotInitialised", err)
	}
}

func TestSpiffeOverride(t *testing.T) {
	m := newLinuxT(t)
	_, _ = m.InitCA("", false)
	c, err := m.IssueCert(CertRequest{PeerID: 1, SpiffeID: "spiffe://custom/svc/web"})
	if err != nil {
		t.Fatal(err)
	}
	if c.SpiffeID != "spiffe://custom/svc/web" {
		t.Errorf("override not honoured: %s", c.SpiffeID)
	}
}
