//go:build linux

package routing

import "log/slog"

func newPlatformManager(log *slog.Logger) Manager { return NewLinux(log) }
