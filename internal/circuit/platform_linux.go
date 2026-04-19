//go:build linux

package circuit

import (
	"log/slog"
	"os/exec"
)

func newPlatformManager(log *slog.Logger) Manager {
	if _, err := exec.LookPath("nft"); err == nil {
		return NewLinux(log)
	}
	return NewStub(log)
}
