//go:build linux

package quota

import "log/slog"

func newPlatformManager(log *slog.Logger, pub Publisher, sw Switcher) Manager {
	if binaryAvailable("nft") {
		return NewLinux(log, pub, sw)
	}
	return NewStub(log, pub, sw)
}
