package tui

import (
	"context"
	"fmt"
	"time"

	"github.com/CosmoTheDev/ctrlscan-agent/internal/database"
	"github.com/CosmoTheDev/ctrlscan-agent/models"
	"github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// FindingsModel displays the findings table with filter/sort support.
type FindingsModel struct {
	db      database.DB
	vulns   []models.SCAVuln
	sast    []models.SASTFinding
	secrets []models.SecretsFinding
	width   int
	height  int
	cursor  int
	filter  string // "sca" | "sast" | "secrets" | "" (all)
	loading bool
}

type findingsLoadedMsg struct {
	vulns   []models.SCAVuln
	sast    []models.SASTFinding
	secrets []models.SecretsFinding
}

// NewFindingsModel creates a FindingsModel.
func NewFindingsModel(db database.DB) FindingsModel {
	return FindingsModel{db: db, loading: true}
}

func (f FindingsModel) Init() tea.Cmd {
	return f.loadCmd()
}

func (f FindingsModel) loadCmd() tea.Cmd {
	return func() tea.Msg {
		ctx := context.Background()
		var vulns []models.SCAVuln
		var sast []models.SASTFinding
		var secrets []models.SecretsFinding

		_ = f.db.Select(ctx, &vulns,
			`SELECT * FROM sca_vulns WHERE status = 'open' ORDER BY cvss DESC LIMIT 200`)
		_ = f.db.Select(ctx, &sast,
			`SELECT * FROM sast_findings WHERE status = 'open' ORDER BY severity LIMIT 200`)
		_ = f.db.Select(ctx, &secrets,
			`SELECT * FROM secrets_findings WHERE status = 'open' ORDER BY verified DESC, first_seen_at DESC LIMIT 200`)

		return findingsLoadedMsg{vulns: vulns, sast: sast, secrets: secrets}
	}
}

func (f FindingsModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case findingsLoadedMsg:
		f.vulns = msg.vulns
		f.sast = msg.sast
		f.secrets = msg.secrets
		f.loading = false
		return f, tea.Tick(30*time.Second, func(t time.Time) tea.Msg {
			return f.loadCmd()()
		})

	case tea.KeyMsg:
		switch msg.String() {
		case "j", "down":
			f.cursor++
		case "k", "up":
			if f.cursor > 0 {
				f.cursor--
			}
		case "s":
			f.filter = "sca"
			f.cursor = 0
		case "a":
			f.filter = "sast"
			f.cursor = 0
		case "e":
			f.filter = "secrets"
			f.cursor = 0
		case "0":
			f.filter = ""
			f.cursor = 0
		case "r":
			f.loading = true
			return f, f.loadCmd()
		}
	}
	f = f.clampCursor()
	return f, nil
}

func (f *FindingsModel) SetSize(w, h int) {
	f.width = w
	f.height = h
}

func (f FindingsModel) View() string {
	if f.loading && len(f.vulns) == 0 {
		return panelStyle.Width(max(20, f.width-2)).Render("Loading findings...")
	}

	rows := ""
	totalRows := 0
	lineLimit := f.height - 10
	if lineLimit < 5 {
		lineLimit = 5
	}

	if f.filter == "" || f.filter == "sca" {
		for _, v := range f.vulns {
			if totalRows >= lineLimit {
				break
			}
			rows += f.renderRow(totalRows,
				string(v.Severity),
				"SCA",
				truncate(v.CVE, 34),
				truncate(v.PackageName+"@"+v.VersionAffected, 22),
				truncate(v.VersionRemediation, 14),
			)
			totalRows++
		}
	}

	if f.filter == "" || f.filter == "sast" {
		for _, s := range f.sast {
			if totalRows >= lineLimit {
				break
			}
			rows += f.renderRow(totalRows,
				string(s.Severity),
				"SAST",
				truncate(s.CheckID, 34),
				truncate(s.FilePath, 22),
				"",
			)
			totalRows++
		}
	}

	if f.filter == "" || f.filter == "secrets" {
		for _, s := range f.secrets {
			if totalRows >= lineLimit {
				break
			}
			meta := ""
			if s.Verified {
				meta = "VERIFIED"
			}
			rows += f.renderRow(totalRows,
				"HIGH",
				"SECRET",
				truncate(s.DetectorName, 34),
				truncate(s.FilePath, 22),
				meta,
			)
			totalRows++
		}
	}

	if rows == "" {
		rows = dimStyle.Render("No open findings.\n")
	}

	filterBar := lipgloss.JoinHorizontal(lipgloss.Left,
		f.filterChip("All", "", len(f.vulns)+len(f.sast)+len(f.secrets), "0"),
		" ",
		f.filterChip("SCA", "sca", len(f.vulns), "s"),
		" ",
		f.filterChip("SAST", "sast", len(f.sast), "a"),
		" ",
		f.filterChip("Secrets", "secrets", len(f.secrets), "e"),
		"  ",
		keycapStyle.Render("r"),
		" ",
		dimStyle.Render("refresh"),
	)

	return lipgloss.JoinVertical(lipgloss.Left,
		panelStyle.Width(max(20, f.width-2)).Render(
			lipgloss.JoinVertical(lipgloss.Left,
				panelHeaderStyle.Render("Open Findings"),
				filterBar,
				"",
				dimStyle.Render("Severity   Type     Finding                             Package/File             Meta"),
				rows,
				"",
				dimStyle.Render("j/k navigate  s SCA  a SAST  e secrets  0 all"),
			),
		),
	)
}

func (f FindingsModel) renderRow(idx int, severity, kind, finding, target, meta string) string {
	cursor := " "
	if idx == f.cursor {
		cursor = "▌"
	}
	metaText := dimStyle.Render(meta)
	if meta == "VERIFIED" {
		metaText = lipgloss.NewStyle().Foreground(bgDark).Background(orange).Padding(0, 1).Render(meta)
	}

	line := lipgloss.JoinHorizontal(lipgloss.Left,
		lipgloss.NewStyle().Width(2).Foreground(accent).Render(cursor),
		lipgloss.NewStyle().Width(10).Render(severityStyle(severity).Render(severity)),
		lipgloss.NewStyle().Width(9).Foreground(slate).Render(kind),
		lipgloss.NewStyle().Width(36).Foreground(ink).Render(finding),
		lipgloss.NewStyle().Width(24).Foreground(slate).Render(target),
		metaText,
	)
	if idx == f.cursor {
		return selectedRowStyle.Width(max(20, f.width-6)).Render(line) + "\n"
	}
	return line + "\n"
}

func (f FindingsModel) filterChip(label, value string, count int, key string) string {
	text := fmt.Sprintf("%s %d", label, count)
	if f.filter == value {
		return activeTabStyle.Render(text)
	}
	return tabStyle.Render(text + " [" + key + "]")
}

func (f FindingsModel) totalRows() int {
	total := 0
	if f.filter == "" || f.filter == "sca" {
		total += len(f.vulns)
	}
	if f.filter == "" || f.filter == "sast" {
		total += len(f.sast)
	}
	if f.filter == "" || f.filter == "secrets" {
		total += len(f.secrets)
	}
	return total
}

func (f FindingsModel) clampCursor() FindingsModel {
	total := f.totalRows()
	if total == 0 {
		f.cursor = 0
		return f
	}
	if f.cursor < 0 {
		f.cursor = 0
	}
	if f.cursor >= total {
		f.cursor = total - 1
	}
	return f
}
