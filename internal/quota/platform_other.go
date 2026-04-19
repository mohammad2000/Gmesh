//go:build !linux

package quota

import "log/slog"

func newPlatformManager(log *slog.Logger, pub Publisher, sw Switcher) Manager {
	m := NewStub(log, pub, sw)
	m.SetEnforcer(NewStubEnforcer(log))
	return m
}
