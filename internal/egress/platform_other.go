//go:build !linux

package egress

import "log/slog"

func newPlatformManager(log *slog.Logger) Manager { return NewStub(log) }
func newPlatformExit(log *slog.Logger) ExitManager { return NewStubExit(log) }
