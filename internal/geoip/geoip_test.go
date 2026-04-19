package geoip

import (
	"os"
	"path/filepath"
	"testing"
)

func TestStubAddAndCountry(t *testing.T) {
	r := NewStub()
	r.Add("de", "5.0.0.0/8")
	r.Add("DE", "78.0.0.0/8")
	r.Add("us", "8.8.8.0/24")
	got := r.CountryCIDRs("de")
	if len(got) != 2 {
		t.Errorf("DE CIDRs = %v; want 2 entries", got)
	}
	if len(r.CountryCIDRs("ZZ")) != 0 {
		t.Error("unknown country should return empty slice")
	}
}

func TestStubDedup(t *testing.T) {
	r := NewStub()
	r.Add("DE", "5.0.0.0/8")
	r.Add("DE", "5.0.0.0/8")
	if got := r.CountryCIDRs("DE"); len(got) != 1 {
		t.Errorf("dedup failed: %v", got)
	}
}

func TestCSVLoad(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "geoip.csv")
	if err := os.WriteFile(path, []byte(`
# sample
DE,5.0.0.0/8
DE,78.0.0.0/8
US,8.8.8.0/24
  us , 1.1.1.0/24

`), 0644); err != nil {
		t.Fatal(err)
	}
	r := NewCSV(path)
	if err := r.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
	if n := len(r.CountryCIDRs("DE")); n != 2 {
		t.Errorf("DE = %d; want 2", n)
	}
	if n := len(r.CountryCIDRs("US")); n != 2 {
		t.Errorf("US = %d; want 2", n)
	}
}

func TestCSVBadCIDR(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.csv")
	_ = os.WriteFile(path, []byte("DE,not-a-cidr\n"), 0644)
	r := NewCSV(path)
	if err := r.Load(); err == nil {
		t.Error("expected error for invalid CIDR")
	}
}

func TestValidateAndCollect(t *testing.T) {
	r := NewStub()
	r.Add("DE", "5.0.0.0/8")
	r.Add("FR", "80.0.0.0/8")
	if err := Validate(r, []string{"DE", "FR"}); err != nil {
		t.Errorf("Validate: %v", err)
	}
	if err := Validate(r, []string{"DE", "ZZ"}); err == nil {
		t.Error("expected Validate to fail for unknown country")
	}
	cidrs := CollectCIDRs(r, []string{"DE", "FR", "DE"})
	if len(cidrs) != 2 {
		t.Errorf("CollectCIDRs = %v; want 2 (dedup)", cidrs)
	}
}
