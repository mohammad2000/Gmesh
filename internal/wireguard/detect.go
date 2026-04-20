package wireguard

import (
	"log/slog"
	"runtime"

	"golang.zx2c4.com/wireguard/wgctrl"
)

// New returns a Manager using the preferred backend when available, falling
// back as needed. If prefer is BackendUnknown, it picks kernel when present.
//
// Platform matrix:
//   - Linux: kernel WG via wgctrl (netlink). Falls back to userspace if the
//     module isn't loaded.
//   - macOS / non-Linux: always userspace (wireguard-go + utun). wgctrl.New()
//     returns a non-error client on macOS even without a kernel WG module,
//     so relying on its success as a "kernel works" check gives a false
//     positive and CreateInterface later blows up. Skip the kernel branch
//     outside Linux to avoid that trap.
//
// The returned Manager is ready to use. Call Close when done.
func New(prefer Backend, log *slog.Logger) (Manager, error) {
	if runtime.GOOS == "linux" && (prefer == BackendUnknown || prefer == BackendKernel) {
		cli, err := wgctrl.New()
		if err == nil {
			log.Info("wireguard backend selected", "backend", "kernel")
			return newKernelManager(cli, log), nil
		}
		log.Warn("kernel WireGuard unavailable on Linux; falling back to userspace", "error", err)
	}
	m, err := newUserspaceManager(log)
	if err != nil {
		return nil, err
	}
	log.Info("wireguard backend selected", "backend", "userspace")
	return m, nil
}
