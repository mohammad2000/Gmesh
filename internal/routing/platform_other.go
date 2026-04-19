//go:build !linux

package routing

import "log/slog"

func newPlatformManager(_ *slog.Logger) Manager { return NewInMemory() }
