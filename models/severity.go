package models

// SeverityLevel represents the severity of a security finding.
type SeverityLevel string

const (
	SeverityCritical SeverityLevel = "CRITICAL"
	SeverityHigh     SeverityLevel = "HIGH"
	SeverityMedium   SeverityLevel = "MEDIUM"
	SeverityLow      SeverityLevel = "LOW"
	SeverityInfo     SeverityLevel = "INFO"
	SeverityUnknown  SeverityLevel = "UNKNOWN"
)

// Weight returns a numeric weight for sorting (higher = more severe).
func (s SeverityLevel) Weight() int {
	switch s {
	case SeverityCritical:
		return 5
	case SeverityHigh:
		return 4
	case SeverityMedium:
		return 3
	case SeverityLow:
		return 2
	case SeverityInfo:
		return 1
	default:
		return 0
	}
}

func (s SeverityLevel) String() string {
	return string(s)
}

// MapSeverity normalises scanner-specific severity strings to SeverityLevel.
func MapSeverity(raw string) SeverityLevel {
	switch raw {
	case "CRITICAL", "critical":
		return SeverityCritical
	case "HIGH", "high", "ERROR", "error":
		return SeverityHigh
	case "MEDIUM", "medium", "MODERATE", "moderate", "WARNING", "warning":
		return SeverityMedium
	case "LOW", "low", "INFO", "info":
		return SeverityLow
	case "NEGLIGIBLE", "negligible":
		return SeverityInfo
	default:
		return SeverityUnknown
	}
}
