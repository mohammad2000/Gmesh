//go:build !linux

package scope

import "log/slog"

func newPlatformManager(log *slog.Logger) Manager { return NewStub(log) }
