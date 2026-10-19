//go:build windows

package config

import (
	"os"
	"path/filepath"
)

// platformDefaults puts everything under %ProgramData%\Gritiva\gmesh (the
// installer limits it to SYSTEM and Administrators) and serves the control
// API on loopback TCP behind a bearer token, since Windows has no
// credential-checked unix socket.
func platformDefaults(c *Config) {
	pd := os.Getenv("ProgramData")
	if pd == "" {
		pd = `C:\ProgramData`
	}
	home := filepath.Join(pd, "Gritiva", "gmesh")
	c.Socket = SocketConfig{Network: "tcp", Path: "127.0.0.1:51821", TokenFile: filepath.Join(home, "control.token")}
	c.State.Dir = home
	c.Audit.Path = filepath.Join(home, "audit.log")
	c.Metrics.Enabled = false
	c.WireGuard.PreferKernel = false
}
