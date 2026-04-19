//go:build linux

package ingress

import "log/slog"

func newPlatformManager(log *slog.Logger) Manager {
	if binaryAvailable("nft") {
		return NewLinux(log)
	}
	return NewStub(log)
}
