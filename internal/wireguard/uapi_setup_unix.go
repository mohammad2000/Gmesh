//go:build !windows

package wireguard

import (
	"fmt"
	"net"

	"golang.zx2c4.com/wireguard/ipc"
)

// setupUAPI prepares a wireguard-go UAPI listener for wgctrl to connect to.
// On unix-likes this means opening /var/run/wireguard/<name>.sock then
// calling UAPIListen with the open file; on Windows it's a single
// named-pipe call (see uapi_setup_windows.go).
func setupUAPI(realName string) (net.Listener, error) {
	f, err := ipc.UAPIOpen(realName)
	if err != nil {
		return nil, fmt.Errorf("uapi open: %w", err)
	}
	l, err := ipc.UAPIListen(realName, f)
	if err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("uapi listen: %w", err)
	}
	return l, nil
}
