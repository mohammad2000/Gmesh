//go:build !windows

package firewall

import "log/slog"

func platformBackend(*slog.Logger) Backend { return nil }
