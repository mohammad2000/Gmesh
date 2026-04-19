package egress

import (
	"log/slog"
	"os/exec"
)

// New returns the real Linux manager when the host has `ip` and `nft` on
// PATH, otherwise the in-memory stub.
func New(log *slog.Logger) Manager { return newPlatformManager(log) }

// NewExit returns the real exit manager on Linux; stub otherwise.
func NewExit(log *slog.Logger) ExitManager { return newPlatformExit(log) }

func binaryAvailable(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}
