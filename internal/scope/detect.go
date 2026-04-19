package scope

import (
	"log/slog"
	"os/exec"
)

// New returns the best available scope manager: LinuxManager on Linux
// hosts with `ip` and `wg` on PATH (and running as root is required but
// not checked here), otherwise the in-memory stub.
func New(log *slog.Logger) Manager { return newPlatformManager(log) }

// binaryAvailable is used by platform_linux.go to decide between Linux and stub.
func binaryAvailable(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}
