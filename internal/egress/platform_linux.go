//go:build linux

package egress

import "log/slog"

func newPlatformManager(log *slog.Logger) Manager {
	if binaryAvailable("ip") && binaryAvailable("nft") {
		return NewLinux(log)
	}
	return NewStub(log)
}

func newPlatformExit(log *slog.Logger) ExitManager {
	if binaryAvailable("ip") && binaryAvailable("nft") {
		return NewLinuxExit(log)
	}
	return NewStubExit(log)
}
