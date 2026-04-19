package quota

import (
	"log/slog"
	"os/exec"
)

// New picks the best backend: Linux with `nft` installs the nft reader,
// everything else falls through to the in-memory stub.
func New(log *slog.Logger, pub Publisher, sw Switcher) Manager {
	return newPlatformManager(log, pub, sw)
}

func binaryAvailable(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}
