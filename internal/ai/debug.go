package ai

import (
	"os"
	"strings"
)

// parseAIDebugEnv reads CTRLSCAN_AI_DEBUG and returns (debugEnabled, promptsEnabled).
// Valid values:
//
//	"all" or "1" or "true" - enable both debug and prompts
//	"prompts" - enable only prompts
//	"none" or "0" or "false" or "" - disable all
//
// Falls back to legacy provider-specific env vars for backward compatibility.
func parseAIDebugEnv() (debug bool, prompts bool) {
	debugEnv := strings.TrimSpace(strings.ToLower(os.Getenv("CTRLSCAN_AI_DEBUG")))

	switch debugEnv {
	case "all", "1", "true":
		return true, true
	case "prompts":
		return false, true
	case "none", "0", "false", "":
		return false, false
	}

	return false, false
}

// isDebug checks if AI debug is enabled via CTRLSCAN_AI_DEBUG env var.
func isDebug() bool {
	debug, _ := parseAIDebugEnv()
	return debug
}

// isDebugPrompts checks if AI prompt debugging is enabled via CTRLSCAN_AI_DEBUG env var.
func isDebugPrompts() bool {
	_, prompts := parseAIDebugEnv()
	return prompts
}

// getLegacyDebug checks legacy provider-specific env vars for backward compatibility.
// providerName is the provider identifier (e.g., "openai", "zai").
func getLegacyDebug(providerName string) bool {
	envName := "CTRLSCAN_" + strings.ToUpper(providerName) + "_DEBUG"
	return strings.EqualFold(strings.TrimSpace(os.Getenv(envName)), "1") ||
		strings.EqualFold(strings.TrimSpace(os.Getenv(envName)), "true")
}

// getLegacyDebugPrompts checks legacy provider-specific prompt debug env vars.
func getLegacyDebugPrompts(providerName string) bool {
	envName := "CTRLSCAN_" + strings.ToUpper(providerName) + "_DEBUG_PROMPTS"
	return strings.EqualFold(strings.TrimSpace(os.Getenv(envName)), "1") ||
		strings.EqualFold(strings.TrimSpace(os.Getenv(envName)), "true")
}
