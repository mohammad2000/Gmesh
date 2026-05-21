//go:build windows

package wireguard

import (
	"fmt"
	"net"

	"golang.zx2c4.com/wireguard/ipc"
)

// On Windows, wireguard-go's UAPI listener is a named pipe; there's
// no preceding UAPIOpen step. wgctrl on Windows speaks the same
// protocol over the named pipe so callers see no API difference.
func setupUAPI(realName string) (net.Listener, error) {
	l, err := ipc.UAPIListen(realName)
	if err != nil {
		return nil, fmt.Errorf("uapi listen (named pipe): %w", err)
	}
	return l, nil
}
