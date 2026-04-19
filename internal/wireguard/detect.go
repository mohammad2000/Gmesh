package wireguard

import (
	"log/slog"

	"golang.zx2c4.com/wireguard/wgctrl"
)

// New returns a Manager using the preferred backend when available, falling
// back as needed. If prefer is BackendUnknown, it picks kernel when present.
//
// The returned Manager is ready to use. Call Close when done.
func New(prefer Backend, log *slog.Logger) (Manager, error) {
	// Try kernel via wgctrl first (works only on Linux with the WG module).
	if prefer == BackendUnknown || prefer == BackendKernel {
		cli, err := wgctrl.New()
		if err == nil {
			log.Info("wireguard backend selected", "backend", "kernel")
			return newKernelManager(cli, log), nil
		}
		log.Warn("kernel WireGuard unavailable", "error", err)
	}

	// Userspace fallback (wireguard-go) — implemented in userspace.go.
	m, err := newUserspaceManager(log)
	if err != nil {
		return nil, err
	}
	log.Info("wireguard backend selected", "backend", "userspace")
	return m, nil
}
