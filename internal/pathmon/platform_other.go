//go:build !linux

package pathmon

// NewPlatformProber returns a StubProber on non-Linux systems.
func NewPlatformProber() Prober {
	return NewStubProber()
}
