package firewall

import (
	"log/slog"
	"os/exec"
)

// Detect picks the best available backend for the current host, preferring
// nftables, then iptables, then an in-memory backend (for non-Linux dev).
//
// preferNftables mirrors cfg.Firewall.UseNftables: if false and iptables is
// present, iptables wins.
func Detect(preferNftables bool, table, chain string, log *slog.Logger) Backend {
	if log == nil {
		log = slog.Default()
	}

	nftAvail := binaryAvailable("nft")
	iptAvail := iptablesAvailable()

	switch {
	case preferNftables && nftAvail:
		log.Info("firewall backend", "kind", "nftables")
		return NewNft(table, "inet", log)
	case iptAvail:
		log.Info("firewall backend", "kind", "iptables")
		return NewIptables(chain, log)
	case nftAvail:
		// preferNftables=false but no iptables — fall back to nft anyway.
		log.Info("firewall backend", "kind", "nftables-fallback")
		return NewNft(table, "inet", log)
	default:
		log.Warn("no firewall backend found; using in-memory stub")
		return NewMemory()
	}
}

func binaryAvailable(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}
