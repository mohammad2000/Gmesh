//go:build darwin

package rpc

import (
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

func getPeerCred(c *net.UnixConn) (peerCred, error) {
	raw, err := c.SyscallConn()
	if err != nil {
		return peerCred{}, err
	}
	var xc *unix.Xucred
	var serr error
	if err := raw.Control(func(fd uintptr) {
		xc, serr = unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
	}); err != nil {
		return peerCred{}, err
	}
	if serr != nil {
		return peerCred{}, fmt.Errorf("LOCAL_PEERCRED: %w", serr)
	}
	cred := peerCred{UID: int(xc.Uid)}
	for i := 0; i < int(xc.Ngroups) && i < len(xc.Groups); i++ {
		cred.GIDs = append(cred.GIDs, int(xc.Groups[i]))
	}
	return cred, nil
}
