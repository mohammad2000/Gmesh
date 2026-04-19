// Package version holds build-time info injected via -ldflags in the Makefile.
package version

var (
	Version   = "dev"
	Commit    = "unknown"
	BuildDate = "unknown"
)
