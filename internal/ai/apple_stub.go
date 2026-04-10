//go:build !darwin || !apple_intelligence

package ai

// NewAppleIntelligence returns a no-op provider on platforms where Apple Intelligence
// is not supported or the dylib is not installed.
func NewAppleIntelligence() AIProvider {
	return &NoopProvider{}
}

// appendAppleFallback is a no-op on non-apple_intelligence builds.
func appendAppleFallback(chain []AIProvider) []AIProvider { return chain }
