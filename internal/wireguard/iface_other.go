//go:build !linux

package wireguard

import "context"

// Non-Linux build: interface management is a no-op. Useful only for local
// compilation on macOS/Windows during development. Real deployment is Linux.
func ifaceEnsure(_ context.Context, _, _ string, _ int) error { return nil }
func ifaceDelete(_ string) error                              { return nil }
func ifaceExists(_ string) (bool, error)                      { return false, nil }
