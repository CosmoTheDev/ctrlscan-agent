package tui

import (
	"fmt"

	"github.com/CosmoTheDev/ctrlscan-agent/internal/config"
	"github.com/CosmoTheDev/ctrlscan-agent/internal/database"
	"github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// Tab represents a TUI navigation tab.
type Tab int

const (
	TabDashboard Tab = iota
	TabScans
	TabFindings
	TabFixQueue
)

var tabNames = []string{"Dashboard", "Scans", "Findings", "Fix Queue"}
var tabCompactNames = []string{"Dash", "Scans", "Findings", "Fix"}
var tabTinyNames = []string{"D", "S", "F", "Q"}

// App is the root bubbletea model.
type App struct {
	cfg       *config.Config
	db        database.DB
	width     int
	height    int
	activeTab Tab
	dashboard DashboardModel
	findings  FindingsModel
	statusMsg string
}

// NewApp creates the TUI application.
func NewApp(cfg *config.Config, db database.DB) *App {
	return &App{
		cfg:       cfg,
		db:        db,
		dashboard: NewDashboardModel(db),
		findings:  NewFindingsModel(db),
	}
}

// Run starts the bubbletea program.
func (a *App) Run() error {
	p := tea.NewProgram(a, tea.WithAltScreen(), tea.WithMouseCellMotion())
	_, err := p.Run()
	return err
}

// Init implements tea.Model.
func (a *App) Init() tea.Cmd {
	return tea.Batch(
		a.dashboard.Init(),
		a.findings.Init(),
	)
}

// Update implements tea.Model.
func (a *App) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmds []tea.Cmd

	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		a.width = msg.Width
		a.height = msg.Height
		contentW := msg.Width - 2
		if contentW < 20 {
			contentW = 20
		}
		contentH := msg.Height - 7
		if contentH < 8 {
			contentH = 8
		}
		a.dashboard.SetSize(contentW, contentH)
		a.findings.SetSize(contentW, contentH)

	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c":
			return a, tea.Quit
		case "1":
			a.activeTab = TabDashboard
		case "2":
			a.activeTab = TabScans
		case "3":
			a.activeTab = TabFindings
		case "4":
			a.activeTab = TabFixQueue
		case "tab":
			a.activeTab = (a.activeTab + 1) % Tab(len(tabNames))
		case "shift+tab":
			a.activeTab--
			if a.activeTab < 0 {
				a.activeTab = Tab(len(tabNames) - 1)
			}
		}
	}

	// Delegate to active view.
	switch a.activeTab {
	case TabDashboard:
		newDash, cmd := a.dashboard.Update(msg)
		a.dashboard = newDash.(DashboardModel)
		cmds = append(cmds, cmd)
	case TabFindings:
		newFindings, cmd := a.findings.Update(msg)
		a.findings = newFindings.(FindingsModel)
		cmds = append(cmds, cmd)
	}

	return a, tea.Batch(cmds...)
}

// View implements tea.Model.
func (a *App) View() string {
	if a.width == 0 {
		return "Loading..."
	}

	header := a.renderHeader()
	nav := a.renderTabs()

	// Active view content.
	var content string
	switch a.activeTab {
	case TabDashboard:
		content = a.dashboard.View()
	case TabFindings:
		content = a.findings.View()
	default:
		content = panelStyle.Width(max(20, a.width-4)).Render(
			lipgloss.JoinVertical(lipgloss.Left,
				panelHeaderStyle.Render(tabNames[a.activeTab]),
				"",
				dimStyle.Render("This view is not implemented yet."),
				dimStyle.Render("Use [Tab] / [Shift+Tab] to switch sections."),
			),
		)
	}

	contentBox := lipgloss.NewStyle().
		Width(a.width).
		Padding(0, 1).
		MaxHeight(max(1, a.height-4)).
		Render(content)

	status := lipgloss.NewStyle().
		Width(a.width).
		Padding(0, 1).
		Foreground(slateDim).
		Render("tab next  shift+tab prev  1-4 jump  q quit")

	return lipgloss.JoinVertical(lipgloss.Left,
		header,
		nav,
		contentBox,
		status,
	)
}

func (a *App) renderHeader() string {
	row := lipgloss.JoinHorizontal(lipgloss.Left,
		titleStyle.Render("ctrlscan"),
		"  ",
		dimStyle.Render("AI-powered CVE remediation agent"),
		"  ",
		mutedBadgeStyle.Render(" "+tabNames[a.activeTab]+" "),
	)
	return lipgloss.NewStyle().
		BorderBottom(true).
		BorderStyle(lipgloss.NormalBorder()).
		BorderForeground(line).
		Width(a.width).
		Padding(0, 1).
		Render(row)
}

func (a *App) renderTabs() string {
	labels := tabNames
	rendered := a.renderTabLabels(labels)
	maxWidth := a.width - 2
	if maxWidth < 10 {
		maxWidth = 10
	}
	if lipgloss.Width(rendered) > maxWidth {
		labels = tabCompactNames
		rendered = a.renderTabLabels(labels)
	}
	if lipgloss.Width(rendered) > maxWidth {
		rendered = a.renderTabLabels(tabTinyNames)
	}

	return lipgloss.NewStyle().
		Width(a.width).
		Padding(0, 1).
		Foreground(slate).
		Render(rendered)
}

func (a *App) renderTabLabels(labels []string) string {
	parts := make([]string, 0, len(labels))
	for i, name := range labels {
		label := fmt.Sprintf("%d:%s", i+1, name)
		if Tab(i) == a.activeTab {
			parts = append(parts, lipgloss.NewStyle().Bold(true).Foreground(accent).Render(label))
		} else {
			parts = append(parts, dimStyle.Render(label))
		}
		if i < len(labels)-1 {
			parts = append(parts, dimStyle.Render("  ·  "))
		}
	}
	return lipgloss.JoinHorizontal(lipgloss.Left, parts...)
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
