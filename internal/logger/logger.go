// Package logger wraps log/slog with gmeshd conventions: structured JSON in
// production, human-friendly text in dev, leveled via the GMESH_LOG_LEVEL env var.
package logger

import (
	"log/slog"
	"os"
	"strings"
)

// Init returns a configured slog.Logger and sets it as the default.
// Pass format = "json" or "text".
func Init(format, level string) *slog.Logger {
	var lvl slog.Level
	switch strings.ToLower(level) {
	case "debug":
		lvl = slog.LevelDebug
	case "warn":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}

	opts := &slog.HandlerOptions{Level: lvl, AddSource: lvl == slog.LevelDebug}

	var h slog.Handler
	if format == "json" {
		h = slog.NewJSONHandler(os.Stderr, opts)
	} else {
		h = slog.NewTextHandler(os.Stderr, opts)
	}

	l := slog.New(h)
	slog.SetDefault(l)
	return l
}
