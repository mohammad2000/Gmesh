//go:build !linux

package quota

import "log/slog"

func newPlatformManager(log *slog.Logger, pub Publisher, sw Switcher) Manager {
	return NewStub(log, pub, sw)
}
