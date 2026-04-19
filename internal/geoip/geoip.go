// Package geoip maps ISO-3166 country codes to the IPv4 CIDRs that
// announce from that country. It is used by egress profiles with
// `geoip_countries` set — the engine asks the Resolver for each
// country's CIDR list, installs a nftables named set, and narrows the
// profile's match to `ip daddr @geoip_<country>`.
//
// # Why a file, not a bundled DB
//
// Bundling MaxMind GeoLite2 inside gmesh would pin the data to build
// time and carry licence baggage. Instead, gmesh expects an operator
// to drop a CSV at `/etc/gmesh/geoip/cidrs.csv` — one `country,cidr`
// line per entry. Common sources:
//
//   - DB-IP lite (CC-BY)          — https://db-ip.com/db/download/ip-to-country-lite
//   - ip2location LITE            — (needs processing into CIDRs)
//   - MaxMind GeoLite2 Country    — licence-gated; operator's choice
//
// The CSV format is deliberately permissive: blank lines and lines
// starting with `#` are ignored; fields are trimmed; country codes are
// upper-cased; CIDRs are parsed with net.ParseCIDR, so IPv6 is supported
// even though the nft set today is IPv4-only (future extension).
//
// # Performance
//
// Resolver.Load reads the whole file into memory. A full DB-IP lite
// CSV is ~3 MB / ~300k lines, which fits comfortably even on small
// VMs. Lookup is O(1) per country — CIDR lists are sliced pre-grouped
// at load time.
package geoip

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
)

// Resolver returns CIDR lists per country.
type Resolver interface {
	// CountryCIDRs returns the IPv4 CIDRs announced from ISO-3166
	// `country`. Returns a nil slice (not error) if the country is
	// unknown or the resolver is empty.
	CountryCIDRs(country string) []string

	// Countries returns every country code known to the resolver.
	Countries() []string

	// Name is used in logs / health pages.
	Name() string
}

// StubResolver is an in-memory map. Convenient for tests and for
// operators who want a tiny curated list.
type StubResolver struct {
	mu   sync.RWMutex
	data map[string][]string
}

// NewStub returns an empty stub resolver.
func NewStub() *StubResolver {
	return &StubResolver{data: map[string][]string{}}
}

// Add inserts a CIDR under the given country code. Idempotent per pair.
func (s *StubResolver) Add(country, cidr string) {
	country = strings.ToUpper(strings.TrimSpace(country))
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, existing := range s.data[country] {
		if existing == cidr {
			return
		}
	}
	s.data[country] = append(s.data[country], cidr)
}

// CountryCIDRs implements Resolver.
func (s *StubResolver) CountryCIDRs(country string) []string {
	country = strings.ToUpper(strings.TrimSpace(country))
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]string, len(s.data[country]))
	copy(out, s.data[country])
	return out
}

// Countries implements Resolver.
func (s *StubResolver) Countries() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]string, 0, len(s.data))
	for c := range s.data {
		out = append(out, c)
	}
	return out
}

// Name implements Resolver.
func (s *StubResolver) Name() string { return "stub" }

// CSVResolver loads country,cidr pairs from a file. Load is not cheap
// (O(N) on the CSV size) so it's called once at engine startup and the
// result is kept in memory.
type CSVResolver struct {
	path string
	StubResolver
}

// NewCSV returns an unloaded CSV resolver. Call Load before first use.
func NewCSV(path string) *CSVResolver {
	return &CSVResolver{
		path:         path,
		StubResolver: StubResolver{data: map[string][]string{}},
	}
}

// Name implements Resolver.
func (c *CSVResolver) Name() string { return "csv:" + c.path }

// Load reads the CSV file into memory. Safe to call multiple times —
// the existing data is replaced atomically.
func (c *CSVResolver) Load() error {
	f, err := os.Open(c.path)
	if err != nil {
		return fmt.Errorf("geoip: open %q: %w", c.path, err)
	}
	defer f.Close()

	fresh := map[string][]string{}
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	var line int
	for scanner.Scan() {
		line++
		raw := strings.TrimSpace(scanner.Text())
		if raw == "" || strings.HasPrefix(raw, "#") {
			continue
		}
		parts := strings.SplitN(raw, ",", 2)
		if len(parts) != 2 {
			return fmt.Errorf("geoip: line %d: expected `country,cidr`", line)
		}
		country := strings.ToUpper(strings.TrimSpace(parts[0]))
		cidr := strings.TrimSpace(parts[1])
		if _, _, err := net.ParseCIDR(cidr); err != nil {
			return fmt.Errorf("geoip: line %d: bad CIDR %q: %w", line, cidr, err)
		}
		fresh[country] = append(fresh[country], cidr)
	}
	if err := scanner.Err(); err != nil && !errors.Is(err, io.EOF) {
		return fmt.Errorf("geoip: scan: %w", err)
	}
	c.mu.Lock()
	c.data = fresh
	c.mu.Unlock()
	return nil
}

// Validate returns an error if any of `countries` has no CIDRs known to
// the resolver. Useful for rejecting egress profiles with a bad country
// code at create time.
func Validate(r Resolver, countries []string) error {
	for _, c := range countries {
		cc := strings.ToUpper(strings.TrimSpace(c))
		if len(r.CountryCIDRs(cc)) == 0 {
			return fmt.Errorf("geoip: no CIDRs known for country %q", cc)
		}
	}
	return nil
}

// CollectCIDRs returns the union of CIDRs across all requested countries,
// de-duplicated. Callers get a ready-to-install nft set payload.
func CollectCIDRs(r Resolver, countries []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, c := range countries {
		for _, cidr := range r.CountryCIDRs(c) {
			if !seen[cidr] {
				seen[cidr] = true
				out = append(out, cidr)
			}
		}
	}
	return out
}
