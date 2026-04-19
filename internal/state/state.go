// Package state persists gmeshd's durable state to a single JSON file
// with atomic writes (write-to-temp + rename). The file is readable only
// by root (mode 0600) because it contains the WireGuard private key.
package state

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// State is the top-level schema written to disk.
type State struct {
	Version   int        `json:"version"`
	UpdatedAt time.Time  `json:"updated_at"`
	Node      NodeState  `json:"node"`
	Peers     []PeerEntry `json:"peers"`
}

// NodeState is this gmeshd's own identity.
type NodeState struct {
	MeshIP     string `json:"mesh_ip"`
	Interface  string `json:"interface"`
	ListenPort uint16 `json:"listen_port"`
	PrivateKey string `json:"private_key"` // base64; file is 0600
	PublicKey  string `json:"public_key"`
	NodeID     string `json:"node_id"`
	Joined     bool   `json:"joined"`
}

// PeerEntry is one remote peer stored on disk.
type PeerEntry struct {
	ID         int64    `json:"id"`
	Type       string   `json:"type"` // "vm" | "scope"
	MeshIP     string   `json:"mesh_ip"`
	PublicKey  string   `json:"public_key"`
	Endpoint   string   `json:"endpoint"`
	AllowedIPs []string `json:"allowed_ips"`
	ScopeID    int64    `json:"scope_id,omitempty"`
}

// Store is a thread-safe state file manager.
type Store struct {
	mu   sync.Mutex
	path string
}

// NewStore returns a Store bound to dir/file. Creates dir if missing.
func NewStore(dir, file string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, fmt.Errorf("mkdir %s: %w", dir, err)
	}
	return &Store{path: filepath.Join(dir, file)}, nil
}

// Path returns the backing file path.
func (s *Store) Path() string { return s.path }

// Load reads state from disk. If the file does not exist, returns an empty
// State with Version=currentVersion and no error.
func (s *Store) Load() (*State, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := os.ReadFile(s.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return &State{Version: currentVersion}, nil
		}
		return nil, fmt.Errorf("read %s: %w", s.path, err)
	}

	var st State
	if err := json.Unmarshal(data, &st); err != nil {
		return nil, fmt.Errorf("unmarshal %s: %w", s.path, err)
	}
	if st.Version == 0 {
		st.Version = currentVersion
	}
	return &st, nil
}

// Save writes state to disk atomically: write to a temp file in the same
// directory, fsync, then rename. The final file has mode 0600.
func (s *Store) Save(st *State) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	st.Version = currentVersion
	st.UpdatedAt = time.Now().UTC()

	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}

	dir := filepath.Dir(s.path)
	tmp, err := os.CreateTemp(dir, ".state-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp: %w", err)
	}
	tmpPath := tmp.Name()
	// Best-effort cleanup on failure paths below.
	defer func() { _ = os.Remove(tmpPath) }()

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write temp: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("fsync temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp: %w", err)
	}
	if err := os.Chmod(tmpPath, 0o600); err != nil {
		return fmt.Errorf("chmod temp: %w", err)
	}
	if err := os.Rename(tmpPath, s.path); err != nil {
		return fmt.Errorf("rename %s → %s: %w", tmpPath, s.path, err)
	}
	return nil
}

const currentVersion = 1
