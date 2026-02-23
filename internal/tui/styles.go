package tui

import "github.com/charmbracelet/lipgloss"

var (
	accent     = lipgloss.Color("#14B8A6") // teal
	accentSoft = lipgloss.Color("#0F766E")
	orange     = lipgloss.Color("#F97316")
	green      = lipgloss.Color("#22C55E")
	yellow     = lipgloss.Color("#F59E0B")
	red        = lipgloss.Color("#EF4444")
	blue       = lipgloss.Color("#38BDF8")
	slate      = lipgloss.Color("#94A3B8")
	slateDim   = lipgloss.Color("#64748B")
	panelBg    = lipgloss.Color("#111827")
	bgDark     = lipgloss.Color("#0B1220")
	line       = lipgloss.Color("#1F2937")
	ink        = lipgloss.Color("#E5E7EB")

	titleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(ink).
			Background(bgDark).
			BorderStyle(lipgloss.ThickBorder()).
			BorderLeft(true).
			BorderTop(false).
			BorderRight(false).
			BorderBottom(false).
			BorderForeground(accent).
			Padding(0, 1)

	tabStyle = lipgloss.NewStyle().
			Foreground(slate).
			Background(bgDark).
			BorderStyle(lipgloss.RoundedBorder()).
			BorderForeground(line).
			Padding(0, 1)

	activeTabStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(bgDark).
			Background(accent).
			BorderStyle(lipgloss.RoundedBorder()).
			BorderForeground(accentSoft).
			Padding(0, 1)

	statusBarStyle = lipgloss.NewStyle().
			Foreground(slate).
			Background(bgDark).
			BorderTop(true).
			BorderStyle(lipgloss.NormalBorder()).
			BorderForeground(line).
			Padding(0, 1)

	criticalStyle = lipgloss.NewStyle().Bold(true).Foreground(red)
	highStyle     = lipgloss.NewStyle().Bold(true).Foreground(yellow)
	mediumStyle   = lipgloss.NewStyle().Foreground(blue)
	lowStyle      = lipgloss.NewStyle().Foreground(slate)
	okStyle       = lipgloss.NewStyle().Foreground(green)

	boxStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(line).
			Background(panelBg).
			Padding(1, 2)

	panelStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(line).
			Background(panelBg).
			Padding(1, 1)

	panelHeaderStyle = lipgloss.NewStyle().
				Bold(true).
				Foreground(ink)

	mutedBadgeStyle = lipgloss.NewStyle().
			Foreground(slate).
			Background(bgDark).
			BorderStyle(lipgloss.RoundedBorder()).
			BorderForeground(line).
			Padding(0, 1)

	keycapStyle = lipgloss.NewStyle().
			Foreground(ink).
			Background(lipgloss.Color("#1E293B")).
			BorderStyle(lipgloss.RoundedBorder()).
			BorderForeground(line).
			Padding(0, 1)

	selectedRowStyle = lipgloss.NewStyle().
				Background(lipgloss.Color("#0F172A")).
				BorderStyle(lipgloss.NormalBorder()).
				BorderLeft(true).
				BorderForeground(accent)

	dimStyle = lipgloss.NewStyle().Foreground(slateDim)
)

func severityStyle(severity string) lipgloss.Style {
	switch severity {
	case "CRITICAL":
		return criticalStyle
	case "HIGH":
		return highStyle
	case "MEDIUM":
		return mediumStyle
	default:
		return lowStyle
	}
}
