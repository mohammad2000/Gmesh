//go:build windows

package firewall

import "log/slog"

func platformBackend(log *slog.Logger) Backend { return NewWFP(log) }
