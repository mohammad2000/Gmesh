package audit

import (
	"bufio"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func silent() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func TestLoggerAppendsJSONLine(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "audit.log")
	l := New(p, 1<<20, silent())
	defer l.Close()

	l.Write(Record{Method: "AddPeer", Code: "OK", PeerID: 42, LatencyMS: 3})
	l.Write(Record{Method: "RemovePeer", Code: "NotFound", PeerID: 99, Error: "peer not found"})

	f, err := os.Open(p)
	if err != nil {
		t.Fatalf("open audit: %v", err)
	}
	defer f.Close()

	lines := 0
	s := bufio.NewScanner(f)
	for s.Scan() {
		var r Record
		if err := json.Unmarshal(s.Bytes(), &r); err != nil {
			t.Errorf("malformed line: %v (%s)", err, s.Text())
		}
		if r.Timestamp == "" || r.Method == "" {
			t.Errorf("missing required fields: %+v", r)
		}
		lines++
	}
	if lines != 2 {
		t.Errorf("lines = %d; want 2", lines)
	}
}

func TestLoggerRotates(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "audit.log")
	l := New(p, 100 /* 100 bytes ≈ 1-2 records */, silent())
	defer l.Close()

	for i := 0; i < 20; i++ {
		l.Write(Record{Method: "X", Code: "OK", PeerID: int64(i)})
	}
	l.Close()

	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	var rotated int
	var hasCurrent bool
	for _, e := range ents {
		if e.Name() == "audit.log" {
			hasCurrent = true
		}
		if strings.HasPrefix(e.Name(), "audit.log.") {
			rotated++
		}
	}
	if !hasCurrent {
		t.Error("current audit.log missing")
	}
	if rotated == 0 {
		t.Errorf("no rotated files; entries = %v", ents)
	}
}

func TestLoggerEmptyPathIsNoOp(t *testing.T) {
	l := New("", 0, silent())
	// Must not panic and must not create any file.
	l.Write(Record{Method: "X"})
	if l.f != nil {
		t.Error("empty path should not open a file")
	}
}

func TestLoggerOpenIdempotent(t *testing.T) {
	dir := t.TempDir()
	l := New(filepath.Join(dir, "a.log"), 0, silent())
	if err := l.Open(); err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := l.Open(); err != nil {
		t.Fatalf("Open 2: %v", err)
	}
	_ = l.Close()
}
