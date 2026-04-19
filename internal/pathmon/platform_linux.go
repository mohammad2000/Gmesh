//go:build linux

package pathmon

import "os/exec"

// NewPlatformProber picks the best probe implementation. On Linux with
// `ping` in PATH it returns LinuxPingProber; otherwise StubProber.
func NewPlatformProber() Prober {
	if _, err := exec.LookPath("ping"); err == nil {
		return NewLinuxPingProber()
	}
	return NewStubProber()
}
