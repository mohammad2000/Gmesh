package policy

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

type fakeActor struct {
	mu    sync.Mutex
	calls []string
	err   error
}

func (a *fakeActor) SwapExitPeer(_ context.Context, profile, peer int64) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.calls = append(a.calls, "swap")
	return a.err
}
func (a *fakeActor) SetProfileEnabled(_ context.Context, _ int64, enabled bool) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if enabled {
		a.calls = append(a.calls, "enable")
	} else {
		a.calls = append(a.calls, "disable")
	}
	return a.err
}
func (a *fakeActor) ResetQuota(_ context.Context, _ int64) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.calls = append(a.calls, "reset")
	return a.err
}
func (a *fakeActor) count() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.calls)
}

type silentLogger struct{}

func (silentLogger) Debug(string, ...any) {}
func (silentLogger) Info(string, ...any)  {}
func (silentLogger) Warn(string, ...any)  {}

func TestPolicyValidate(t *testing.T) {
	cases := []struct {
		name    string
		p       Policy
		wantErr bool
	}{
		{"ok swap",
			Policy{Version: 1, Name: "x",
				When: When{Event: "path_down"},
				Do:   Do{Action: "swap_exit_peer", ProfileID: 1, ToPeerID: 2}},
			false},
		{"missing version",
			Policy{Name: "x", When: When{Event: "path_down"}, Do: Do{Action: "reset_quota", QuotaID: 1}},
			true},
		{"missing event",
			Policy{Version: 1, Name: "x", Do: Do{Action: "reset_quota", QuotaID: 1}},
			true},
		{"bad event",
			Policy{Version: 1, Name: "x", When: When{Event: "bogus"}, Do: Do{Action: "reset_quota", QuotaID: 1}},
			true},
		{"swap without to_peer",
			Policy{Version: 1, Name: "x", When: When{Event: "path_down"},
				Do: Do{Action: "swap_exit_peer", ProfileID: 1}},
			true},
		{"bad action",
			Policy{Version: 1, Name: "x", When: When{Event: "path_down"}, Do: Do{Action: "launch_missiles"}},
			true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := c.p.Validate()
			if (err != nil) != c.wantErr {
				t.Errorf("err=%v want=%v", err, c.wantErr)
			}
		})
	}
}

func TestOnEventFires(t *testing.T) {
	a := &fakeActor{}
	e := New(a, silentLogger{})
	e.Replace([]*Policy{{
		Version: 1, Name: "failover", When: When{Event: "path_down", PeerID: 3},
		Do: Do{Action: "swap_exit_peer", ProfileID: 10, ToPeerID: 5},
	}})
	e.OnEvent(context.Background(), Event{Type: "path_down", PeerID: 3, Timestamp: time.Now()})
	if a.count() != 1 {
		t.Errorf("calls = %d; want 1", a.count())
	}
}

func TestOnEventFilters(t *testing.T) {
	a := &fakeActor{}
	e := New(a, silentLogger{})
	e.Replace([]*Policy{{
		Version: 1, Name: "peer3only", When: When{Event: "path_down", PeerID: 3},
		Do: Do{Action: "reset_quota", QuotaID: 1},
	}})
	e.OnEvent(context.Background(), Event{Type: "path_down", PeerID: 4, Timestamp: time.Now()})
	e.OnEvent(context.Background(), Event{Type: "path_up", PeerID: 3, Timestamp: time.Now()})
	if a.count() != 0 {
		t.Errorf("wrong-peer / wrong-event still fired: %d", a.count())
	}
}

func TestDebounceMinCount(t *testing.T) {
	a := &fakeActor{}
	e := New(a, silentLogger{})
	e.Replace([]*Policy{{
		Version: 1, Name: "triple", When: When{Event: "path_down", DebounceSeconds: 5, MinCount: 3},
		Do: Do{Action: "reset_quota", QuotaID: 1},
	}})
	base := time.Now()
	for i := 0; i < 2; i++ {
		e.OnEvent(context.Background(), Event{Type: "path_down", Timestamp: base.Add(time.Duration(i) * time.Second)})
	}
	if a.count() != 0 {
		t.Errorf("fired before min_count: %d", a.count())
	}
	e.OnEvent(context.Background(), Event{Type: "path_down", Timestamp: base.Add(3 * time.Second)})
	if a.count() != 1 {
		t.Errorf("min_count crossing did not fire: %d", a.count())
	}
	// More matches in the same window should NOT re-fire until a fresh
	// window begins.
	for i := 0; i < 5; i++ {
		e.OnEvent(context.Background(), Event{Type: "path_down", Timestamp: base.Add(4 * time.Second)})
	}
	if a.count() != 1 {
		t.Errorf("unexpected re-fire within window: %d", a.count())
	}
}

func TestLoadFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "failover.yaml")
	_ = os.WriteFile(path, []byte(`version: 1
name: failover
when:
  event: path_down
  peer_id: 3
do:
  action: swap_exit_peer
  profile_id: 10
  to_peer_id: 5
`), 0644)
	p, err := LoadFile(path)
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}
	if p.Name != "failover" || p.Do.ToPeerID != 5 {
		t.Errorf("bad parse: %+v", p)
	}
}

func TestLoadFileRejectsUnknownFields(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.yaml")
	_ = os.WriteFile(path, []byte(`version: 1
name: x
mystery_field: oops
when:
  event: path_down
do:
  action: reset_quota
  quota_id: 1
`), 0644)
	if _, err := LoadFile(path); err == nil {
		t.Error("expected unknown-field rejection")
	}
}

func TestLoadDir(t *testing.T) {
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "a.yaml"), []byte(`version: 1
name: a
when: {event: path_down}
do: {action: reset_quota, quota_id: 1}
`), 0644)
	_ = os.WriteFile(filepath.Join(dir, "b.yml"), []byte(`version: 1
name: b
when: {event: path_up}
do: {action: reset_quota, quota_id: 2}
`), 0644)
	_ = os.WriteFile(filepath.Join(dir, "c.txt"), []byte("not a yaml"), 0644)
	ps, errs := LoadDir(dir)
	if len(errs) != 0 {
		t.Errorf("unexpected errs: %v", errs)
	}
	if len(ps) != 2 {
		t.Errorf("loaded %d; want 2", len(ps))
	}
}

func TestActionFailureIsLogged(t *testing.T) {
	a := &fakeActor{err: context.DeadlineExceeded}
	e := New(a, silentLogger{})
	e.Replace([]*Policy{{
		Version: 1, Name: "x", When: When{Event: "path_down"},
		Do: Do{Action: "reset_quota", QuotaID: 1},
	}})
	e.OnEvent(context.Background(), Event{Type: "path_down", Timestamp: time.Now()})
	if a.count() != 1 {
		t.Errorf("actor should still have been called once: %d", a.count())
	}
}
