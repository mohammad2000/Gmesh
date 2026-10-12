package rpc

import (
	"context"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/mohammad2000/Gmesh/internal/config"
)

func silentLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func TestCredPolicy(t *testing.T) {
	p, err := newCredPolicy(config.SocketConfig{AllowedUIDs: []int{501}})
	if err != nil {
		t.Fatal(err)
	}
	p.gids[20] = true
	cases := []struct {
		name string
		cred peerCred
		want bool
	}{
		{"root", peerCred{UID: 0}, true},
		{"daemon user", peerCred{UID: os.Geteuid()}, true},
		{"allowed uid", peerCred{UID: 501}, true},
		{"group member", peerCred{UID: 4242, GIDs: []int{7, 20}}, true},
		{"stranger", peerCred{UID: 4242, GIDs: []int{7}}, false},
	}
	for _, c := range cases {
		if os.Geteuid() == 4242 {
			t.Skip("test uid collides with the fixture")
		}
		if got := p.allows(c.cred); got != c.want {
			t.Errorf("%s: allows = %v; want %v", c.name, got, c.want)
		}
	}
}

func TestCheckLoopback(t *testing.T) {
	for addr, ok := range map[string]bool{
		"127.0.0.1:51821": true,
		"[::1]:51821":     true,
		"localhost:51821": true,
		"0.0.0.0:51821":   false,
		":51821":          false,
		"10.0.0.5:51821":  false,
		"nonsense":        false,
	} {
		if err := checkLoopback(addr); (err == nil) != ok {
			t.Errorf("checkLoopback(%q) err = %v; want ok=%v", addr, err, ok)
		}
	}
}

func TestLoadOrCreateToken(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "control.token")
	tok, err := loadOrCreateToken(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(tok) != 64 {
		t.Errorf("token length = %d; want 64 hex chars", len(tok))
	}
	if runtime.GOOS != "windows" {
		fi, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != 0o600 {
			t.Errorf("token mode = %v; want 0600", fi.Mode().Perm())
		}
	}
	again, err := loadOrCreateToken(path)
	if err != nil || again != tok {
		t.Errorf("second load = %q, %v; want the same token", again, err)
	}
}

func TestTokenInterceptor(t *testing.T) {
	const tok = "0123456789abcdef0123456789abcdef"
	ic := newTokenUnaryInterceptor(tok)
	call := func(ctx context.Context) error {
		_, err := ic(ctx, nil, nil, func(context.Context, any) (any, error) { return "ok", nil })
		return err
	}
	if err := call(context.Background()); status.Code(err) != codes.Unauthenticated {
		t.Errorf("no token: %v; want Unauthenticated", err)
	}
	bad := metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", "Bearer nope"))
	if err := call(bad); status.Code(err) != codes.Unauthenticated {
		t.Errorf("wrong token: %v; want Unauthenticated", err)
	}
	good := metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", "Bearer "+tok))
	if err := call(good); err != nil {
		t.Errorf("right token: %v", err)
	}
}

// End to end over a real unix socket: the kernel-reported credentials of
// this test process must be accepted by a policy that names it and
// dropped by one that does not.
func TestCredListenerRealSocket(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skip("peer credentials only on linux/darwin")
	}
	dir, err := os.MkdirTemp("", "gm") // short path: sun_path is ~104 bytes on macOS
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)

	try := func(policy *credPolicy) bool {
		path := filepath.Join(dir, "s.sock")
		_ = os.Remove(path)
		raw, err := net.Listen("unix", path)
		if err != nil {
			t.Fatal(err)
		}
		ln := &credListener{Listener: raw, policy: policy, log: silentLog()}
		defer ln.Close()
		accepted := make(chan bool, 1)
		go func() {
			c, err := ln.Accept()
			if err == nil {
				_ = c.Close()
			}
			accepted <- err == nil
		}()
		c, err := net.Dial("unix", path)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		select {
		case ok := <-accepted:
			return ok
		case <-time.After(300 * time.Millisecond):
			return false // dropped: Accept is still waiting for an allowed caller
		}
	}

	if !try(&credPolicy{uids: map[int]bool{os.Geteuid(): true}, gids: map[int]bool{}}) {
		t.Error("own uid was rejected")
	}
	if try(&credPolicy{uids: map[int]bool{}, gids: map[int]bool{}}) {
		t.Error("caller outside the policy was accepted")
	}
}
