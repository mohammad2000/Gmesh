package rpc

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/mohammad2000/Gmesh/internal/config"
)

// The control socket drives a root daemon: whoever can call it can add
// peers, rewrite firewall rules, turn the node into an exit or issue
// certificates. File mode alone is not enough (installers have shipped
// 0666 sockets), so every connection is also checked here.
//
//   - unix: the kernel tells us the caller's uid/gids (SO_PEERCRED on
//     Linux, LOCAL_PEERCRED on macOS). Allowed callers are root, the
//     daemon's own user, socket.allowed_uids, socket.allowed_users and
//     members of socket.group.
//   - tcp: the listener must be loopback. A TCP peer has no kernel
//     credentials, so any local user can connect unless
//     socket.token_file is set; the daemon warns at startup when it
//     is not (kept optional so existing Windows installs keep working).
//   - socket.token_file (any transport): every RPC must carry
//     "authorization: Bearer <token>".

// peerCred is what the kernel reports about the process on the other
// end of a unix socket.
type peerCred struct {
	UID  int
	GIDs []int
	PID  int // 0 when the platform does not report it
}

// credPolicy decides which local users may use the socket.
type credPolicy struct {
	uids map[int]bool
	gids map[int]bool
}

func newCredPolicy(cfg config.SocketConfig) (*credPolicy, error) {
	p := &credPolicy{uids: map[int]bool{0: true, os.Geteuid(): true}, gids: map[int]bool{}}
	for _, uid := range cfg.AllowedUIDs {
		p.uids[uid] = true
	}
	for _, name := range cfg.AllowedUsers {
		u, err := user.Lookup(name)
		if err != nil {
			return nil, fmt.Errorf("socket.allowed_users: %w", err)
		}
		uid, err := strconv.Atoi(u.Uid)
		if err != nil {
			return nil, fmt.Errorf("socket.allowed_users %q: uid %q is not numeric", name, u.Uid)
		}
		p.uids[uid] = true
	}
	if cfg.Group != "" {
		gid, err := lookupGID(cfg.Group)
		if err != nil {
			return nil, err
		}
		p.gids[gid] = true
	}
	return p, nil
}

func (p *credPolicy) allows(c peerCred) bool {
	if p.uids[c.UID] {
		return true
	}
	for _, g := range c.GIDs {
		if p.gids[g] {
			return true
		}
	}
	return false
}

// credListener drops unix connections from callers the policy rejects
// before gRPC ever sees them.
type credListener struct {
	net.Listener
	policy *credPolicy
	log    *slog.Logger
}

func (l *credListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		uc, ok := conn.(*net.UnixConn)
		if !ok {
			_ = conn.Close()
			continue
		}
		cred, err := getPeerCred(uc)
		if err != nil {
			l.log.Warn("rejected control connection: cannot read peer credentials", "error", err)
			_ = conn.Close()
			continue
		}
		if !l.policy.allows(cred) {
			l.log.Warn("rejected control connection from unauthorized user",
				"uid", cred.UID, "pid", cred.PID,
				"hint", "add the user to socket.allowed_users or socket.group")
			_ = conn.Close()
			continue
		}
		return conn, nil
	}
}

// applySocketOwnership chowns the socket per socket.owner/socket.group.
func applySocketOwnership(path string, cfg config.SocketConfig) error {
	if cfg.Owner == "" && cfg.Group == "" {
		return nil
	}
	uid, gid := -1, -1
	if cfg.Owner != "" {
		u, err := user.Lookup(cfg.Owner)
		if err != nil {
			return fmt.Errorf("socket.owner: %w", err)
		}
		if uid, err = strconv.Atoi(u.Uid); err != nil {
			return fmt.Errorf("socket.owner %q: uid %q is not numeric", cfg.Owner, u.Uid)
		}
	}
	if cfg.Group != "" {
		var err error
		if gid, err = lookupGID(cfg.Group); err != nil {
			return err
		}
	}
	return os.Chown(path, uid, gid)
}

func lookupGID(name string) (int, error) {
	g, err := user.LookupGroup(name)
	if err != nil {
		return 0, fmt.Errorf("socket.group: %w", err)
	}
	gid, err := strconv.Atoi(g.Gid)
	if err != nil {
		return 0, fmt.Errorf("socket.group %q: gid %q is not numeric", name, g.Gid)
	}
	return gid, nil
}

// checkLoopback refuses a TCP control endpoint that is reachable from
// other machines.
func checkLoopback(addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("socket.path %q: %w", addr, err)
	}
	if host == "localhost" {
		return nil
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("socket.path %q: tcp control endpoint must be a loopback address", addr)
	}
	return nil
}

// loadOrCreateToken returns the shared secret in path, creating a new
// random one (mode 0600) when the file does not exist yet.
func loadOrCreateToken(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err == nil {
		tok := strings.TrimSpace(string(b))
		if len(tok) < 32 {
			return "", fmt.Errorf("socket.token_file %s: token too short", path)
		}
		return tok, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("socket.token_file: %w", err)
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	tok := hex.EncodeToString(raw)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", fmt.Errorf("socket.token_file dir: %w", err)
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", fmt.Errorf("socket.token_file: %w", err)
	}
	if _, err := f.WriteString(tok + "\n"); err != nil {
		_ = f.Close()
		return "", err
	}
	return tok, f.Close()
}

func tokenOK(ctx context.Context, token string) bool {
	md, _ := metadata.FromIncomingContext(ctx)
	for _, v := range md.Get("authorization") {
		got, ok := strings.CutPrefix(v, "Bearer ")
		if ok && subtle.ConstantTimeCompare([]byte(got), []byte(token)) == 1 {
			return true
		}
	}
	return false
}

var errBadToken = status.Error(codes.Unauthenticated, "missing or invalid control token")

func newTokenUnaryInterceptor(token string) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		if !tokenOK(ctx, token) {
			return nil, errBadToken
		}
		return handler(ctx, req)
	}
}

func newTokenStreamInterceptor(token string) grpc.StreamServerInterceptor {
	return func(srv any, ss grpc.ServerStream, _ *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		if !tokenOK(ss.Context(), token) {
			return errBadToken
		}
		return handler(srv, ss)
	}
}
