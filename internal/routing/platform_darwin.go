//go:build darwin

package routing

import "log/slog"

// On macOS, use the DarwinManager which shells out to `/sbin/route`.
func newPlatformManager(log *slog.Logger) Manager { return NewDarwin(log) }
