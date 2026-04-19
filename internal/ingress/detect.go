package ingress

import (
	"log/slog"
	"os/exec"
)

// New picks the best backend for the host.
func New(log *slog.Logger) Manager { return newPlatformManager(log) }

func binaryAvailable(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}
