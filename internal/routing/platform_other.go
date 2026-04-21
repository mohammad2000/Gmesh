//go:build !linux && !darwin

package routing

import "log/slog"

// Fallback in-memory stub for platforms where we haven't written a
// native route manager yet.
func newPlatformManager(_ *slog.Logger) Manager { return NewInMemory() }
