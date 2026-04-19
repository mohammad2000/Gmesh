//go:build !linux

package ingress

import "log/slog"

func newPlatformManager(log *slog.Logger) Manager { return NewStub(log) }
