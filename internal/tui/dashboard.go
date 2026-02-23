package tui

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/CosmoTheDev/ctrlscan-agent/internal/database"
	"github.com/CosmoTheDev/ctrlscan-agent/models"
	"github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// DashboardModel shows the overview: recent scan jobs and finding counts.
type DashboardModel struct {
	db       database.DB
	jobs     []models.ScanJob
	width    int
	height   int
	lastLoad time.Time
	loading  bool
}

// dashLoadedMsg carries loaded scan jobs.
type dashLoadedMsg struct{ jobs []models.ScanJob }

// NewDashboardModel creates a DashboardModel.
func NewDashboardModel(db database.DB) DashboardModel {
	return DashboardModel{db: db, loading: true}
}

func (d DashboardModel) Init() tea.Cmd {
	return d.loadCmd()
}

func (d DashboardModel) loadCmd() tea.Cmd {
	return func() tea.Msg {
		var jobs []models.ScanJob
		ctx := context.Background()
		_ = d.db.Select(ctx, &jobs,
			`SELECT * FROM scan_jobs ORDER BY started_at DESC LIMIT 20`)
		return dashLoadedMsg{jobs: jobs}
	}
}

func (d DashboardModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case dashLoadedMsg:
		d.jobs = msg.jobs
		d.loading = false
		d.lastLoad = time.Now()
		// Refresh every 10 seconds.
		return d, tea.Tick(10*time.Second, func(t time.Time) tea.Msg {
			return d.loadCmd()()
		})
	case tea.KeyMsg:
		if msg.String() == "r" {
			d.loading = true
			return d, d.loadCmd()
		}
	}
	return d, nil
}

func (d *DashboardModel) SetSize(w, h int) {
	d.width = w
	d.height = h
}

func (d DashboardModel) View() string {
	if d.loading && len(d.jobs) == 0 {
		return panelStyle.Width(max(20, d.width-2)).Render("Loading scan jobs...")
	}

	// Summary counts.
	var critical, high, medium, low int
	for _, j := range d.jobs {
		critical += j.FindingsCritical
		high += j.FindingsHigh
		medium += j.FindingsMedium
		low += j.FindingsLow
	}

	cardW := 18
	if d.width >= 100 {
		cardW = 20
	}
	summary := lipgloss.JoinHorizontal(lipgloss.Top,
		renderCounter("Critical", critical, criticalStyle, cardW),
		renderCounter("High", high, highStyle, cardW),
		renderCounter("Medium", medium, mediumStyle, cardW),
		renderCounter("Low", low, lowStyle, cardW),
	)

	lineLimit := d.height - 12
	if lineLimit < 5 {
		lineLimit = 5
	}
	rows := ""
	for i, j := range d.jobs {
		if i >= lineLimit {
			break
		}
		status := j.Status
		statusFmt := mutedBadgeStyle.Render(status)
		if status == "completed" {
			statusFmt = lipgloss.NewStyle().Foreground(bgDark).Background(green).Padding(0, 1).Render(status)
		} else if status == "failed" {
			statusFmt = lipgloss.NewStyle().Foreground(bgDark).Background(red).Padding(0, 1).Render(status)
		} else if status == "running" {
			statusFmt = lipgloss.NewStyle().Foreground(bgDark).Background(blue).Padding(0, 1).Render(status)
		}
		repo := truncate(j.Provider+"/"+j.Owner+"/"+j.Repo, 34)
		branch := truncate(j.Branch, 12)
		counts := fmt.Sprintf("C:%d H:%d M:%d L:%d", j.FindingsCritical, j.FindingsHigh, j.FindingsMedium, j.FindingsLow)
		line := lipgloss.JoinHorizontal(lipgloss.Left,
			lipgloss.NewStyle().Width(36).Foreground(ink).Render(repo),
			lipgloss.NewStyle().Width(14).Foreground(slate).Render(branch),
			lipgloss.NewStyle().Width(14).Render(statusFmt),
			dimStyle.Render(counts),
		)
		rows += line + "\n"
	}

	if len(d.jobs) == 0 {
		rows = dimStyle.Render("No scans yet. Run: ctrlscan scan --repo <url>\n")
	}

	updated := "never"
	if !d.lastLoad.IsZero() {
		updated = d.lastLoad.Format("15:04:05")
	}
	refreshInfo := lipgloss.JoinHorizontal(lipgloss.Left,
		keycapStyle.Render("r"),
		" ",
		dimStyle.Render("refresh"),
		"   ",
		dimStyle.Render("updated "+updated),
	)

	return lipgloss.JoinVertical(lipgloss.Left,
		lipgloss.NewStyle().Padding(0, 1).Render(summary),
		panelStyle.Width(max(20, d.width-2)).Render(
			lipgloss.JoinVertical(lipgloss.Left,
				panelHeaderStyle.Render("Recent Scans"),
				dimStyle.Render("Repository                             Branch        Status         Findings"),
				rows,
				refreshInfo,
			),
		),
	)
}

func renderCounter(label string, count int, style lipgloss.Style, width int) string {
	return boxStyle.Width(width).Render(
		lipgloss.JoinVertical(lipgloss.Center,
			style.Bold(true).Render(fmt.Sprintf("%d", count)),
			dimStyle.Render(strings.ToUpper(label)),
		),
	) + "  "
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return "…" + s[len(s)-max+1:]
}
