//go:build !linux && !darwin

package rpc

import (
	"errors"
	"net"
)

// Unix-socket peer credentials are only implemented for Linux and
// macOS. Elsewhere (Windows) the daemon uses the tcp transport, which
// is guarded by checkLoopback and the control token instead.
func getPeerCred(*net.UnixConn) (peerCred, error) {
	return peerCred{}, errors.New("peer credentials not supported on this platform")
}
