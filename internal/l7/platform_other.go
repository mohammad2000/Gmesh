//go:build !linux

package l7

// NewPlatformReader returns a StubReader on non-Linux hosts. Tests and
// dev builds on macOS / Windows keep working; production Linux uses
// the conntrack reader.
func NewPlatformReader() Reader {
	return NewStubReader()
}
