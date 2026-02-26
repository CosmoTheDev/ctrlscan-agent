package cmd

import (
	"fmt"
	"strings"

	"github.com/CosmoTheDev/ctrlscan-agent/internal/config"
	"github.com/charmbracelet/huh"
	"github.com/charmbracelet/lipgloss"
	"github.com/spf13/cobra"
)

var (
	configHeaderStyle  = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#7C3AED"))
	configTitleStyle   = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#F59E0B"))
	configSuccessStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#10B981"))
	configSectionStyle = lipgloss.NewStyle().Bold(true).MarginTop(1).MarginBottom(1)
	configDimStyle     = lipgloss.NewStyle().Foreground(lipgloss.Color("#6B7280"))
)

var configUICmd = &cobra.Command{
	Use:   "edit-ui",
	Short: "Interactive tabular configuration editor",
	Long: `Launches an interactive TUI to configure ctrlscan settings.

Navigate between sections using tabs. Edit values and save changes.

Sections:
  - Database: SQLite path, MySQL DSN
  - AI: Provider selection, API keys, models, fallback, debug settings
  - Git: GitHub, GitLab, Azure credentials
  - Agent: Mode, workers, scan targets, scanners
  - Gateway: Port configuration
  - Notify: Slack, Telegram, Email, webhook settings
  - Tools: Binary directory, Docker preference
`,
	RunE: runConfigUI,
}

func runConfigUI(cmd *cobra.Command, args []string) error {
	fmt.Println()
	fmt.Println(configHeaderStyle.Render("  ctrlscan — Configuration Editor"))
	fmt.Println(configDimStyle.Render("  Navigate sections with tabs • Edit values • Save when done\n"))

	cfg, err := config.Load(cfgFile)
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	var selectedTab string = "ai"

	form := huh.NewForm(
		huh.NewGroup(
			huh.NewSelect[string]().
				Title("Configuration Section").
				Description("Select a section to edit").
				Options(
					huh.NewOption("AI Provider & Settings", "ai"),
					huh.NewOption("Git Providers", "git"),
					huh.NewOption("Agent Settings", "agent"),
					huh.NewOption("Gateway", "gateway"),
					huh.NewOption("Notifications", "notify"),
					huh.NewOption("Tools", "tools"),
					huh.NewOption("Database", "database"),
				).
				Value(&selectedTab),
		),
	)

	if err := form.Run(); err != nil {
		return err
	}

	return runSectionEditor(cfg, selectedTab)
}

func runSectionEditor(cfg *config.Config, section string) error {
	var updated bool
	var err error

	for {
		switch section {
		case "ai":
			updated, err = editAISettings(cfg)
		case "git":
			updated, err = editGitSettings(cfg)
		case "agent":
			updated, err = editAgentSettings(cfg)
		case "gateway":
			updated, err = editGatewaySettings(cfg)
		case "notify":
			updated, err = editNotifySettings(cfg)
		case "tools":
			updated, err = editToolsSettings(cfg)
		case "database":
			updated, err = editDatabaseSettings(cfg)
		default:
			return fmt.Errorf("unknown section: %s", section)
		}

		if err != nil {
			return err
		}

		if !updated {
			return nil
		}

		var saveConfirm bool = false
		form := huh.NewForm(
			huh.NewGroup(
				huh.NewConfirm().
					Title("Save changes?").
					Description("Press Enter to save, Esc to return without saving").
					Value(&saveConfirm),
			),
		)
		if err := form.Run(); err != nil {
			return err
		}

		if saveConfirm {
			configPath, err := config.ConfigPath(cfgFile)
			if err != nil {
				return fmt.Errorf("getting config path: %w", err)
			}
			if err := config.Save(cfg, configPath); err != nil {
				return fmt.Errorf("saving config: %w", err)
			}
			fmt.Println(configSuccessStyle.Render("  ✓ Configuration saved"))
			return nil
		}
	}
}

func editAISettings(cfg *config.Config) (bool, error) {
	fmt.Println(configSectionStyle.Render("  AI Provider & Settings"))

	providerOptions := []huh.Option[string]{
		huh.NewOption("Scan-only (no AI)", "none"),
		huh.NewOption("OpenAI", "openai"),
		huh.NewOption("Anthropic Claude", "anthropic"),
		huh.NewOption("Z.AI", "zai"),
		huh.NewOption("Ollama (local)", "ollama"),
	}

	provider := cfg.AI.Provider
	if provider == "" {
		provider = "none"
	}

	var openAIKey = cfg.AI.OpenAIKey
	var anthropicKey = cfg.AI.AnthropicKey
	var zaiKey = cfg.AI.ZAIKey
	var model = cfg.AI.Model
	var baseURL = cfg.AI.BaseURL
	var ollamaURL = cfg.AI.OllamaURL
	var fallbackStr = strings.Join(cfg.AI.Fallback, ",")
	var aidebug = cfg.AI.AIDebug
	var minConfidenceStr = fmt.Sprintf("%.2f", cfg.AI.MinFixConfidence)
	var minConfBySeverity = cfg.AI.MinFixConfidenceBySeverity

	form := huh.NewForm(
		huh.NewGroup(
			huh.NewSelect[string]().
				Title("Provider").
				Options(providerOptions...).
				Value(&provider),
			huh.NewInput().
				Title("OpenAI API Key").
				Placeholder("sk-...").
				EchoMode(huh.EchoModePassword).
				Value(&openAIKey),
			huh.NewInput().
				Title("Anthropic API Key").
				Placeholder("sk-ant-...").
				EchoMode(huh.EchoModePassword).
				Value(&anthropicKey),
			huh.NewInput().
				Title("Z.AI API Key").
				Placeholder("Your API Key").
				EchoMode(huh.EchoModePassword).
				Value(&zaiKey),
			huh.NewInput().
				Title("Model").
				Placeholder("e.g., gpt-4o, claude-sonnet-4-6, glm-4.7").
				Value(&model),
			huh.NewInput().
				Title("Base URL (optional)").
				Placeholder("https://...").
				Value(&baseURL),
			huh.NewInput().
				Title("Ollama URL").
				Placeholder("http://localhost:11434").
				Value(&ollamaURL),
			huh.NewInput().
				Title("Fallback Providers").
				Description("Comma-separated: openai,anthropic,zai,ollama").
				Placeholder("openai,ollama").
				Value(&fallbackStr),
			huh.NewInput().
				Title("Debug Mode").
				Description("all, prompts, or none").
				Placeholder("all").
				Value(&aidebug),
			huh.NewInput().
				Title("Min Confidence (0-1)").
				Description("Minimum AI confidence to queue fixes").
				Value(&minConfidenceStr),
			huh.NewInput().
				Title("Min Confidence by Severity").
				Description("critical=0.6,high=0.4,medium=0.2,low=0.1").
				Placeholder("critical=0.6,high=0.4,medium=0.2,low=0.1").
				Value(&minConfBySeverity),
		),
	)

	if err := form.Run(); err != nil {
		return false, err
	}

	cfg.AI.Provider = provider
	cfg.AI.OpenAIKey = strings.TrimSpace(openAIKey)
	cfg.AI.AnthropicKey = strings.TrimSpace(anthropicKey)
	cfg.AI.ZAIKey = strings.TrimSpace(zaiKey)
	cfg.AI.Model = strings.TrimSpace(model)
	cfg.AI.BaseURL = strings.TrimSpace(baseURL)
	cfg.AI.OllamaURL = strings.TrimSpace(ollamaURL)
	cfg.AI.Fallback = parseCommaList(fallbackStr)
	cfg.AI.AIDebug = strings.TrimSpace(aidebug)
	cfg.AI.MinFixConfidence = parseFloatOrZero(minConfidenceStr)
	cfg.AI.MinFixConfidenceBySeverity = strings.TrimSpace(minConfBySeverity)

	return true, nil
}

func editGitSettings(cfg *config.Config) (bool, error) {
	fmt.Println(configSectionStyle.Render("  Git Providers"))

	var githubToken string
	var gitlabToken string
	var azureToken string
	var azureOrg string

	if len(cfg.Git.GitHub) > 0 {
		githubToken = cfg.Git.GitHub[0].Token
	}

	if len(cfg.Git.GitLab) > 0 {
		gitlabToken = cfg.Git.GitLab[0].Token
	}

	if len(cfg.Git.Azure) > 0 {
		azureToken = cfg.Git.Azure[0].Token
		azureOrg = cfg.Git.Azure[0].Org
	}

	form := huh.NewForm(
		huh.NewGroup(
			huh.NewInput().
				Title("GitHub Token").
				Placeholder("ghp_...").
				EchoMode(huh.EchoModePassword).
				Value(&githubToken),
			huh.NewInput().
				Title("GitLab Token").
				Placeholder("glpat-...").
				EchoMode(huh.EchoModePassword).
				Value(&gitlabToken),
			huh.NewInput().
				Title("Azure DevOps Token").
				Placeholder("").
				EchoMode(huh.EchoModePassword).
				Value(&azureToken),
			huh.NewInput().
				Title("Azure Organization").
				Placeholder("your-org").
				Value(&azureOrg),
		),
	)

	if err := form.Run(); err != nil {
		return false, err
	}

	cfg.Git.GitHub = []config.GitHubConfig{{Token: strings.TrimSpace(githubToken)}}
	if gitlabToken != "" {
		cfg.Git.GitLab = []config.GitLabConfig{{Token: strings.TrimSpace(gitlabToken)}}
	}
	if azureToken != "" {
		cfg.Git.Azure = []config.AzureConfig{{Token: strings.TrimSpace(azureToken), Org: strings.TrimSpace(azureOrg)}}
	}

	return true, nil
}

func editAgentSettings(cfg *config.Config) (bool, error) {
	fmt.Println(configSectionStyle.Render("  Agent Settings"))

	modeOptions := []huh.Option[string]{
		huh.NewOption("triage", "triage"),
		huh.NewOption("semi", "semi"),
		huh.NewOption("auto", "auto"),
	}

	mode := cfg.Agent.Mode
	if mode == "" {
		mode = "triage"
	}

	var workers string = fmt.Sprintf("%d", cfg.Agent.Workers)
	if cfg.Agent.Workers == 0 {
		workers = "3"
	}

	var scanTargetsStr = strings.Join(cfg.Agent.ScanTargets, ",")
	if len(scanTargetsStr) == 0 {
		scanTargetsStr = "own_repos"
	}

	var watchlistStr = strings.Join(cfg.Agent.Watchlist, ",")
	var scannersStr = strings.Join(cfg.Agent.Scanners, ",")
	if len(scannersStr) == 0 {
		scannersStr = "grype,opengrep,trufflehog,trivy"
	}

	form := huh.NewForm(
		huh.NewGroup(
			huh.NewSelect[string]().
				Title("Mode").
				Description("triage: AI prioritises, you approve. semi: AI generates, you review. auto: AI creates PRs.").
				Options(modeOptions...).
				Value(&mode),
			huh.NewInput().
				Title("Workers").
				Description("Parallel scan goroutines (1-64)").
				Placeholder("3").
				Value(&workers),
			huh.NewInput().
				Title("Scan Targets").
				Description("Comma-separated: own_repos, watchlist, cve_search, all").
				Placeholder("own_repos").
				Value(&scanTargetsStr),
			huh.NewInput().
				Title("Scanners").
				Description("Comma-separated: grype, opengrep, trufflehog, trivy").
				Placeholder("grype,opengrep,trufflehog,trivy").
				Value(&scannersStr),
			huh.NewInput().
				Title("Watchlist").
				Description("Comma-separated: owner/repo or org").
				Placeholder("owner/repo").
				Value(&watchlistStr),
		),
	)

	if err := form.Run(); err != nil {
		return false, err
	}

	cfg.Agent.Mode = mode
	cfg.Agent.Workers = parseIntOrDefault(workers, 3)
	cfg.Agent.ScanTargets = parseCommaList(scanTargetsStr)
	cfg.Agent.Scanners = parseCommaList(scannersStr)
	cfg.Agent.Watchlist = parseCommaList(watchlistStr)

	return true, nil
}

func editGatewaySettings(cfg *config.Config) (bool, error) {
	fmt.Println(configSectionStyle.Render("  Gateway Settings"))

	var port string = fmt.Sprintf("%d", cfg.Gateway.Port)
	if cfg.Gateway.Port == 0 {
		port = "6080"
	}

	form := huh.NewForm(
		huh.NewGroup(
			huh.NewInput().
				Title("Port").
				Description("HTTP port for gateway (default: 6080)").
				Placeholder("6080").
				Value(&port),
		),
	)

	if err := form.Run(); err != nil {
		return false, err
	}

	cfg.Gateway.Port = parseIntOrDefault(port, 6080)

	return true, nil
}

func editNotifySettings(cfg *config.Config) (bool, error) {
	fmt.Println(configSectionStyle.Render("  Notification Settings"))

	var slackURL = cfg.Notify.Slack.WebhookURL
	var telegramBotToken = cfg.Notify.Telegram.BotToken
	var telegramChatID = cfg.Notify.Telegram.ChatID
	var emailSMTPHost = cfg.Notify.Email.SMTPHost
	var emailSMTPPortStr = fmt.Sprintf("%d", cfg.Notify.Email.SMTPPort)
	if cfg.Notify.Email.SMTPPort == 0 {
		emailSMTPPortStr = "587"
	}
	var emailUsername = cfg.Notify.Email.Username
	var emailPassword = cfg.Notify.Email.Password
	var emailFrom = cfg.Notify.Email.From
	var emailTo = cfg.Notify.Email.To
	var webhookURL = cfg.Notify.Webhook.URL
	var webhookSecret = cfg.Notify.Webhook.Secret
	var minSeverity = cfg.Notify.MinSeverity
	var eventsStr = strings.Join(cfg.Notify.Events, ",")

	form := huh.NewForm(
		huh.NewGroup(
			huh.NewInput().
				Title("Slack Webhook URL").
				Placeholder("https://hooks.slack.com/...").
				Value(&slackURL),
			huh.NewInput().
				Title("Telegram Bot Token").
				Placeholder("Your bot token").
				Value(&telegramBotToken),
			huh.NewInput().
				Title("Telegram Chat ID").
				Placeholder("Your chat ID").
				Value(&telegramChatID),
			huh.NewInput().
				Title("Email SMTP Host").
				Placeholder("smtp.gmail.com").
				Value(&emailSMTPHost),
			huh.NewInput().
				Title("Email SMTP Port").
				Placeholder("587").
				Value(&emailSMTPPortStr),
			huh.NewInput().
				Title("Email Username").
				Placeholder("your@email.com").
				Value(&emailUsername),
			huh.NewInput().
				Title("Email Password").
				Placeholder("Your password").
				EchoMode(huh.EchoModePassword).
				Value(&emailPassword),
			huh.NewInput().
				Title("Email From").
				Placeholder("ctrlscan@yourdomain.com").
				Value(&emailFrom),
			huh.NewInput().
				Title("Email To").
				Placeholder("you@example.com").
				Value(&emailTo),
			huh.NewInput().
				Title("Webhook URL").
				Placeholder("https://your-endpoint.com/webhook").
				Value(&webhookURL),
			huh.NewInput().
				Title("Webhook Secret").
				Placeholder("HMAC signing key").
				EchoMode(huh.EchoModePassword).
				Value(&webhookSecret),
			huh.NewSelect[string]().
				Title("Min Severity").
				Options(
					huh.NewOption("All", ""),
					huh.NewOption("Critical", "critical"),
					huh.NewOption("High", "high"),
					huh.NewOption("Medium", "medium"),
					huh.NewOption("Low", "low"),
				).
				Value(&minSeverity),
			huh.NewInput().
				Title("Events").
				Description("Comma-separated: critical_finding, pr_opened, sweep_failed").
				Placeholder("critical_finding,pr_opened").
				Value(&eventsStr),
		),
	)

	if err := form.Run(); err != nil {
		return false, err
	}

	cfg.Notify.Slack.WebhookURL = strings.TrimSpace(slackURL)
	cfg.Notify.Telegram.BotToken = strings.TrimSpace(telegramBotToken)
	cfg.Notify.Telegram.ChatID = strings.TrimSpace(telegramChatID)
	cfg.Notify.Email.SMTPHost = strings.TrimSpace(emailSMTPHost)
	cfg.Notify.Email.SMTPPort = parseIntOrDefault(emailSMTPPortStr, 587)
	cfg.Notify.Email.Username = strings.TrimSpace(emailUsername)
	cfg.Notify.Email.Password = strings.TrimSpace(emailPassword)
	cfg.Notify.Email.From = strings.TrimSpace(emailFrom)
	cfg.Notify.Email.To = strings.TrimSpace(emailTo)
	cfg.Notify.Webhook.URL = strings.TrimSpace(webhookURL)
	cfg.Notify.Webhook.Secret = strings.TrimSpace(webhookSecret)
	cfg.Notify.MinSeverity = strings.TrimSpace(minSeverity)
	cfg.Notify.Events = parseCommaList(eventsStr)

	return true, nil
}

func editToolsSettings(cfg *config.Config) (bool, error) {
	fmt.Println(configSectionStyle.Render("  Tools Settings"))

	var binDir = cfg.Tools.BinDir
	if binDir == "" {
		binDir = "~/.ctrlscan/bin"
	}

	var preferDocker bool = cfg.Tools.PreferDocker

	form := huh.NewForm(
		huh.NewGroup(
			huh.NewInput().
				Title("Binary Directory").
				Placeholder("~/.ctrlscan/bin").
				Value(&binDir),
			huh.NewConfirm().
				Title("Prefer Docker").
				Description("Use Docker for scanner tools even if local binaries exist").
				Value(&preferDocker),
		),
	)

	if err := form.Run(); err != nil {
		return false, err
	}

	cfg.Tools.BinDir = strings.TrimSpace(binDir)
	cfg.Tools.PreferDocker = preferDocker

	return true, nil
}

func editDatabaseSettings(cfg *config.Config) (bool, error) {
	fmt.Println(configSectionStyle.Render("  Database Settings"))

	driverOptions := []huh.Option[string]{
		huh.NewOption("SQLite", "sqlite"),
		huh.NewOption("MySQL", "mysql"),
	}

	var driver = cfg.Database.Driver
	if driver == "" {
		driver = "sqlite"
	}
	var path = cfg.Database.Path
	if path == "" {
		path = "~/.ctrlscan/ctrlscan.db"
	}
	var dsn = cfg.Database.DSN

	form := huh.NewForm(
		huh.NewGroup(
			huh.NewSelect[string]().
				Title("Driver").
				Options(driverOptions...).
				Value(&driver),
			huh.NewInput().
				Title("SQLite Path").
				Placeholder("~/.ctrlscan/ctrlscan.db").
				Value(&path),
			huh.NewInput().
				Title("MySQL DSN").
				Placeholder("user:pass@tcp(host:3306)/dbname").
				Value(&dsn),
		),
	)

	if err := form.Run(); err != nil {
		return false, err
	}

	cfg.Database.Driver = driver
	cfg.Database.Path = strings.TrimSpace(path)
	cfg.Database.DSN = strings.TrimSpace(dsn)

	return true, nil
}

func parseCommaList(s string) []string {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	result := make([]string, 0, len(parts))
	for _, p := range parts {
		trimmed := strings.TrimSpace(p)
		if trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}

func parseFloatOrZero(s string) float64 {
	if s == "" {
		return 0
	}
	var f float64
	_, err := fmt.Sscanf(s, "%f", &f)
	if err != nil {
		return 0
	}
	return f
}

func parseIntOrDefault(s string, def int) int {
	if s == "" {
		return def
	}
	var i int
	_, err := fmt.Sscanf(s, "%d", &i)
	if err != nil {
		return def
	}
	return i
}
