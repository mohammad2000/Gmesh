//go:build linux

package rpc

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

func getPeerCred(c *net.UnixConn) (peerCred, error) {
	raw, err := c.SyscallConn()
	if err != nil {
		return peerCred{}, err
	}
	var uc *unix.Ucred
	var serr error
	if err := raw.Control(func(fd uintptr) {
		uc, serr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		return peerCred{}, err
	}
	if serr != nil {
		return peerCred{}, fmt.Errorf("SO_PEERCRED: %w", serr)
	}
	cred := peerCred{UID: int(uc.Uid), PID: int(uc.Pid), GIDs: []int{int(uc.Gid)}}
	cred.GIDs = append(cred.GIDs, supplementaryGroups(int(uc.Pid))...)
	return cred, nil
}

// supplementaryGroups reads the caller's extra groups from /proc; the
// ucred only carries the primary gid. Best effort: a caller that
// exited already simply gets no extra groups.
func supplementaryGroups(pid int) []int {
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/status")
	if err != nil {
		return nil
	}
	for _, line := range strings.Split(string(b), "\n") {
		rest, ok := strings.CutPrefix(line, "Groups:")
		if !ok {
			continue
		}
		var out []int
		for _, f := range strings.Fields(rest) {
			if g, err := strconv.Atoi(f); err == nil {
				out = append(out, g)
			}
		}
		return out
	}
	return nil
}
