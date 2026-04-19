//go:build linux

package l7

import (
	"os"
	"os/exec"
)

// NewPlatformReader picks the best available conntrack source:
//
//   1. /proc/net/nf_conntrack if present (older kernels, ≤5.10).
//   2. The `conntrack` CLI if installed (modern kernels dropped the
//      /proc file in 5.11, but the netlink-backed tool still works).
//   3. A stub reader otherwise — classifier surface stays functional
//      with zero flows; operators install conntrack-tools to turn it
//      on.
func NewPlatformReader() Reader {
	if _, err := os.Stat("/proc/net/nf_conntrack"); err == nil {
		return NewConntrackReader("/proc/net/nf_conntrack")
	}
	if _, err := exec.LookPath("conntrack"); err == nil {
		return NewConntrackCLIReader("conntrack")
	}
	return NewStubReader()
}
