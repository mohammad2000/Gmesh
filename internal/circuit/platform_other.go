//go:build !linux

package circuit

import "log/slog"

func newPlatformManager(log *slog.Logger) Manager {
	return NewStub(log)
}
