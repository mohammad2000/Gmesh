// Package config loads gmeshd configuration from a YAML file with sensible
// defaults. Most fields can be overridden via the GMESH_* env vars.
package config

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// Config is the full gmeshd configuration.
type Config struct {
	Socket    SocketConfig    `yaml:"socket"`
	Log       LogConfig       `yaml:"log"`
	WireGuard WireGuardConfig `yaml:"wireguard"`
	NAT       NATConfig       `yaml:"nat"`
	Health    HealthConfig    `yaml:"health"`
	Firewall  FirewallConfig  `yaml:"firewall"`
	Relay     RelayConfig     `yaml:"relay"`
	State     StateConfig     `yaml:"state"`
	Metrics   MetricsConfig   `yaml:"metrics"`
	Audit     AuditConfig     `yaml:"audit"`
	GeoIP     GeoIPConfig     `yaml:"geoip"`
	Policies  PoliciesConfig  `yaml:"policies"`
}

// GeoIPConfig controls the GeoIP resolver used by egress profiles with
// a `geoip_countries` field (Phase 15).
type GeoIPConfig struct {
	// CIDRFile is a CSV of `country_code,cidr` lines. Leave empty to
	// disable; GeoIP profiles will be rejected at create time.
	CIDRFile string `yaml:"cidr_file"`
}

// PoliciesConfig controls the Phase-17 policy loader.
type PoliciesConfig struct {
	// Dir is scanned for *.yaml policy files at engine start and after
	// explicit reloads. Leave empty to disable policy evaluation.
	Dir string `yaml:"dir"`
}

// MetricsConfig controls the Prometheus HTTP endpoint.
type MetricsConfig struct {
	Enabled    bool   `yaml:"enabled"`     // default true
	SocketPath string `yaml:"socket_path"` // default /run/gmesh-metrics.sock
}

// AuditConfig controls the audit log.
type AuditConfig struct {
	Enabled   bool   `yaml:"enabled"`    // default true
	Path      string `yaml:"path"`       // default /var/log/gmesh/audit.log
	MaxBytes  int64  `yaml:"max_bytes"`  // default 10 MB
}

// SocketConfig controls the Unix socket exposed for gRPC.
type SocketConfig struct {
	Path  string `yaml:"path"`
	Owner string `yaml:"owner"`
	Group string `yaml:"group"`
	Mode  uint32 `yaml:"mode"`
}

// LogConfig controls logging output.
type LogConfig struct {
	Format string `yaml:"format"` // "text" | "json"
	Level  string `yaml:"level"`  // "debug" | "info" | "warn" | "error"
}

// WireGuardConfig controls the WG interface lifecycle.
type WireGuardConfig struct {
	Interface        string `yaml:"interface"`         // "wg-gritiva"
	ListenPort       uint16 `yaml:"listen_port"`       // 51820
	MTU              uint16 `yaml:"mtu"`               // 1420
	KeepaliveSeconds uint16 `yaml:"keepalive_seconds"` // 25
	PreferKernel     bool   `yaml:"prefer_kernel"`     // fall back to wireguard-go if unavailable
	NetworkCIDR      string `yaml:"network_cidr"`      // "10.200.0.0/16"
}

// NATConfig controls STUN + discovery behavior.
type NATConfig struct {
	STUNServers       []string `yaml:"stun_servers"`
	CacheTTLSeconds   int      `yaml:"cache_ttl_seconds"`
	DiscoveryTimeoutS int      `yaml:"discovery_timeout_seconds"`
	UDPResponderPort  uint16   `yaml:"udp_responder_port"` // 51822
}

// HealthConfig controls health monitoring loops.
type HealthConfig struct {
	CheckIntervalSeconds         int `yaml:"check_interval_seconds"`          // 30
	DegradedCheckIntervalSeconds int `yaml:"degraded_check_interval_seconds"` // 15
	MaxConcurrentPings           int `yaml:"max_concurrent_pings"`            // 5
	ReconnectFailingThreshold    int `yaml:"reconnect_failing_threshold"`     // 3
}

// FirewallConfig controls nftables behavior.
type FirewallConfig struct {
	Table       string `yaml:"table"`         // "gmesh"
	Chain       string `yaml:"chain"`         // "mesh"
	UseNftables bool   `yaml:"use_nftables"`  // true → nft, false → iptables legacy
}

// RelayConfig controls relay fallback.
type RelayConfig struct {
	DefaultRelayURL string `yaml:"default_relay_url"` // gmesh-relay endpoint
	WSTunnelBuffer  int    `yaml:"ws_tunnel_buffer"`  // 2048
}

// StateConfig controls on-disk state persistence.
type StateConfig struct {
	Dir  string `yaml:"dir"`  // /var/lib/gmesh
	File string `yaml:"file"` // state.json
}

// Default returns the baseline configuration.
func Default() *Config {
	return &Config{
		Socket: SocketConfig{
			Path: "/run/gmesh.sock",
			Mode: 0o660,
		},
		Log: LogConfig{Format: "text", Level: "info"},
		WireGuard: WireGuardConfig{
			Interface:        "wg-gritiva",
			ListenPort:       51820,
			MTU:              1420,
			KeepaliveSeconds: 25,
			PreferKernel:     true,
			NetworkCIDR:      "10.200.0.0/16",
		},
		NAT: NATConfig{
			STUNServers: []string{
				"stun.l.google.com:19302",
				"stun1.l.google.com:19302",
				"stun.cloudflare.com:3478",
				"stun.ekiga.net:3478",
			},
			CacheTTLSeconds:   300,
			DiscoveryTimeoutS: 10,
			UDPResponderPort:  51822,
		},
		Health: HealthConfig{
			CheckIntervalSeconds:         30,
			DegradedCheckIntervalSeconds: 15,
			MaxConcurrentPings:           5,
			ReconnectFailingThreshold:    3,
		},
		Firewall: FirewallConfig{Table: "gmesh", Chain: "mesh", UseNftables: true},
		Relay:    RelayConfig{WSTunnelBuffer: 2048},
		State:    StateConfig{Dir: "/var/lib/gmesh", File: "state.json"},
		Metrics:  MetricsConfig{Enabled: true, SocketPath: "/run/gmesh-metrics.sock"},
		Audit:    AuditConfig{Enabled: true, Path: "/var/log/gmesh/audit.log", MaxBytes: 10 * 1024 * 1024},
	}
}

// Load reads config from path, overlaying onto defaults. Missing file = defaults.
func Load(path string) (*Config, error) {
	cfg := Default()
	if path == "" {
		return cfg, nil
	}

	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil
		}
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}
	return cfg, nil
}
