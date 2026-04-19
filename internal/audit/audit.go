// Package audit writes one JSON record per security-relevant event to an
// append-only log file. Rotation is automatic: when the file exceeds
// MaxBytes (default 10 MB), it's renamed with a timestamp and a fresh
// file is opened.
//
// Records are flushed on every Write. Failures are logged (to slog) but
// never propagated — audit is best-effort from the daemon's point of view.
//
// Schema:
//
//	{"ts":"2026-04-19T10:14:02Z","actor":"unix-peer","method":"Join",
//	 "code":"OK","latency_ms":14,"peer_id":0,
//	 "params":{"mesh_ip":"10.200.0.7","interface":"wg-gritiva"}}
package audit

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Record is one audit entry. Param values are allowed to be any JSON-
// serializable value; sensitive fields (private keys, tokens) must be
// redacted by the caller.
type Record struct {
	Timestamp string                 `json:"ts"`
	Actor     string                 `json:"actor"`
	Method    string                 `json:"method"`
	Code      string                 `json:"code"`
	LatencyMS int64                  `json:"latency_ms"`
	PeerID    int64                  `json:"peer_id,omitempty"`
	ScopeID   int64                  `json:"scope_id,omitempty"`
	Params    map[string]interface{} `json:"params,omitempty"`
	Error     string                 `json:"error,omitempty"`
}

// Logger writes audit records.
type Logger struct {
	Path     string // file path; parent dir auto-created
	MaxBytes int64  // rotate threshold; default 10 MB
	Log      *slog.Logger

	mu sync.Mutex
	f  *os.File
}

// New returns an audit logger. If path is empty, the logger is a no-op.
func New(path string, maxBytes int64, log *slog.Logger) *Logger {
	if maxBytes == 0 {
		maxBytes = 10 * 1024 * 1024
	}
	if log == nil {
		log = slog.Default()
	}
	return &Logger{Path: path, MaxBytes: maxBytes, Log: log}
}

// Open ensures the file is opened for append. Safe to call multiple times.
func (l *Logger) Open() error {
	if l.Path == "" {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.f != nil {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(l.Path), 0o750); err != nil {
		return fmt.Errorf("mkdir audit dir: %w", err)
	}
	f, err := os.OpenFile(l.Path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o640)
	if err != nil {
		return fmt.Errorf("open audit: %w", err)
	}
	l.f = f
	return nil
}

// Close flushes + closes the file. Idempotent.
func (l *Logger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.f == nil {
		return nil
	}
	err := l.f.Close()
	l.f = nil
	return err
}

// Write appends one record. Auto-opens + rotates as needed. Never blocks
// the caller on errors — failures are logged and swallowed.
func (l *Logger) Write(r Record) {
	if l == nil || l.Path == "" {
		return
	}
	if r.Timestamp == "" {
		r.Timestamp = time.Now().UTC().Format(time.RFC3339Nano)
	}
	if err := l.Open(); err != nil {
		l.Log.Warn("audit open failed", "error", err)
		return
	}

	data, err := json.Marshal(r)
	if err != nil {
		l.Log.Warn("audit marshal failed", "error", err, "method", r.Method)
		return
	}
	data = append(data, '\n')

	l.mu.Lock()
	defer l.mu.Unlock()
	if l.f == nil {
		return
	}
	if _, err := l.f.Write(data); err != nil {
		l.Log.Warn("audit write failed", "error", err)
		return
	}

	if fi, err := l.f.Stat(); err == nil && fi.Size() > l.MaxBytes {
		l.rotateLocked()
	}
}

// rotateLocked assumes l.mu is held. Renames the current file with a
// timestamp suffix and opens a fresh one.
func (l *Logger) rotateLocked() {
	if l.f == nil {
		return
	}
	_ = l.f.Close()
	l.f = nil

	rotated := fmt.Sprintf("%s.%s", l.Path, time.Now().UTC().Format("20060102-150405"))
	if err := os.Rename(l.Path, rotated); err != nil {
		l.Log.Warn("audit rotate failed", "error", err)
		return
	}
	// Reopen fresh file.
	f, err := os.OpenFile(l.Path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o640)
	if err != nil {
		l.Log.Warn("audit reopen failed", "error", err)
		return
	}
	l.f = f
	l.Log.Info("audit log rotated", "from", rotated, "to", l.Path)
}
