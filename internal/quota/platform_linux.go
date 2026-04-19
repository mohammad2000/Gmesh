//go:build linux

package quota

import "log/slog"

func newPlatformManager(log *slog.Logger, pub Publisher, sw Switcher) Manager {
	if binaryAvailable("nft") {
		m := NewLinux(log, pub, sw)
		m.SetEnforcer(NewLinuxEnforcer(log))
		return m
	}
	m := NewStub(log, pub, sw)
	m.SetEnforcer(NewStubEnforcer(log))
	return m
}
