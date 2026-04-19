//go:build linux

package scope

import "log/slog"

func newPlatformManager(log *slog.Logger) Manager {
	if binaryAvailable("ip") && binaryAvailable("wg") && binaryAvailable("iptables") {
		return NewLinux(log)
	}
	return NewStub(log)
}
