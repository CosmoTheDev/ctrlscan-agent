package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/CosmoTheDev/ctrlscan-agent/internal/config"
	"github.com/charmbracelet/huh"
	"github.com/charmbracelet/lipgloss"
	"github.com/spf13/cobra"
)

var onboardCmd = &cobra.Command{
	Use:   "onboard",
	Short: "Interactive setup wizard for ctrlscan",
	Long: `Walks you through configuring ctrlscan:
  - AI provider (optional — enables triage, fix generation, and PR creation)
  - Git provider credentials (GitHub, GitLab, Azure DevOps)
  - Scanner tool selection and installation
  - Agent mode and scan targets

Without an AI key you get raw scan results stored in the database.
AI is required to automatically triage findings, generate code fixes, and open PRs.`,
	RunE: runOnboard,
}

var headerStyle = lipgloss.NewStyle().
	Bold(true).
	Foreground(lipgloss.Color("#7C3AED")).
	MarginBottom(1)

var successStyle = lipgloss.NewStyle().
	Foreground(lipgloss.Color("#10B981"))

var warnStyle = lipgloss.NewStyle().
	Foreground(lipgloss.Color("#F59E0B"))

var dimStyle = lipgloss.NewStyle().
	Foreground(lipgloss.Color("#6B7280"))

func runOnboard(cmd *cobra.Command, args []string) error {
	ctx := context.Background()
	_ = ctx

	fmt.Println()
	fmt.Println(headerStyle.Render("  ctrlscan — AI-powered CVE remediation agent"))
	fmt.Println(dimStyle.Render("  Open-source tool to scan repos and auto-generate vulnerability fixes.\n"))

	// Load existing config or start fresh.
	cfg, err := config.Load(cfgFile)
	if err != nil {
		cfg = &config.Config{}
	}

	// Ensure ~/.ctrlscan/ and ~/.ctrlscan/bin/ exist.
	if err := config.EnsureDir(); err != nil {
		return fmt.Errorf("creating ctrlscan directories: %w", err)
	}

	// --- Step 1: AI Provider (optional) ---
	fmt.Println(headerStyle.Render("  Step 1/7 · AI Provider (optional)"))
	fmt.Println(dimStyle.Render("  Without an AI key you still get full scan results — you just"))
	fmt.Println(dimStyle.Render("  analyse them yourself. AI is only needed for automatic triage,"))
	fmt.Println(dimStyle.Render("  code fix generation, and opening pull requests on your behalf.\n"))

	var openAIKey string
	if cfg.AI.OpenAIKey != "" {
		openAIKey = cfg.AI.OpenAIKey
	}

	var aiModel string = "gpt-4o"
	if cfg.AI.Model != "" {
		aiModel = cfg.AI.Model
	}
	const customModelSentinel = "__custom__"
	var aiModelChoice string
	switch aiModel {
	case "gpt-5.2", "gpt-5.1", "gpt-5.1-codex", "gpt-5", "gpt-5-codex", "gpt-5-chat-latest",
		"gpt-4.1", "gpt-4o", "o1", "o3",
		"gpt-5.1-codex-mini", "gpt-5-mini", "gpt-5-nano", "gpt-4.1-mini", "gpt-4.1-nano",
		"gpt-4o-mini", "o1-mini", "o3-mini", "o4-mini", "codex-mini-latest":
		aiModelChoice = aiModel
	default:
		aiModelChoice = customModelSentinel
	}
	var customAIModel string
	if aiModelChoice == customModelSentinel {
		customAIModel = aiModel
	}

	aiForm := huh.NewForm(
		huh.NewGroup(
			huh.NewInput().
				Title("OpenAI API Key (leave blank to skip)").
				Description("Get one at platform.openai.com → API Keys. Leave blank for scan-only mode.").
				Placeholder("sk-...  (optional)").
				EchoMode(huh.EchoModePassword).
				Value(&openAIKey),
			huh.NewSelect[string]().
				Title("Default model").
				Description("Only used when an API key is set. Choose from common options or enter a custom model ID.").
				Options(
					huh.NewOption("gpt-5.1-codex (high quality coding)", "gpt-5.1-codex"),
					huh.NewOption("gpt-5-codex (coding)", "gpt-5-codex"),
					huh.NewOption("gpt-5.2", "gpt-5.2"),
					huh.NewOption("gpt-5.1", "gpt-5.1"),
					huh.NewOption("gpt-5", "gpt-5"),
					huh.NewOption("gpt-5-chat-latest", "gpt-5-chat-latest"),
					huh.NewOption("gpt-4.1", "gpt-4.1"),
					huh.NewOption("gpt-4o", "gpt-4o"),
					huh.NewOption("o3", "o3"),
					huh.NewOption("o1", "o1"),
					huh.NewOption("gpt-5.1-codex-mini", "gpt-5.1-codex-mini"),
					huh.NewOption("gpt-5-mini", "gpt-5-mini"),
					huh.NewOption("gpt-5-nano", "gpt-5-nano"),
					huh.NewOption("gpt-4.1-mini", "gpt-4.1-mini"),
					huh.NewOption("gpt-4.1-nano", "gpt-4.1-nano"),
					huh.NewOption("gpt-4o-mini", "gpt-4o-mini"),
					huh.NewOption("o4-mini", "o4-mini"),
					huh.NewOption("o3-mini", "o3-mini"),
					huh.NewOption("o1-mini", "o1-mini"),
					huh.NewOption("codex-mini-latest", "codex-mini-latest"),
					huh.NewOption("Custom model ID…", customModelSentinel),
				).
				Value(&aiModelChoice),
			huh.NewInput().
				Title("Custom model ID (optional)").
				Description("Only used if 'Custom model ID…' is selected above. Example: gpt-5.1-codex").
				Placeholder("gpt-5.1-codex").
				Value(&customAIModel),
		),
	)
	if err := aiForm.Run(); err != nil {
		return err
	}
	if aiModelChoice == customModelSentinel {
		if strings.TrimSpace(customAIModel) != "" {
			aiModel = strings.TrimSpace(customAIModel)
		}
	} else {
		aiModel = aiModelChoice
	}
	if openAIKey != "" {
		cfg.AI.Provider = "openai"
		cfg.AI.OpenAIKey = openAIKey
		cfg.AI.Model = aiModel
		fmt.Println(successStyle.Render("  AI enabled — triage, fix generation, and PR creation active.\n"))
	} else {
		cfg.AI.Provider = ""
		cfg.AI.OpenAIKey = ""
		fmt.Println(dimStyle.Render("  Scan-only mode selected. Add a key later by re-running 'ctrlscan onboard'.\n"))
	}

	// --- Step 2: GitHub token ---
	fmt.Println(headerStyle.Render("\n  Step 2/7 · GitHub Credentials"))

	var githubToken string
	if len(cfg.Git.GitHub) > 0 {
		githubToken = cfg.Git.GitHub[0].Token
	}
	var githubHost string = "github.com"
	if len(cfg.Git.GitHub) > 0 && cfg.Git.GitHub[0].Host != "" {
		githubHost = cfg.Git.GitHub[0].Host
	}

	ghForm := huh.NewForm(
		huh.NewGroup(
			huh.NewInput().
				Title("GitHub Personal Access Token").
				Description("Create a classic token at https://github.com/settings/tokens/new. Grant read API access; add write access if you want ctrlscan to open PRs.").
				Placeholder("ghp_...").
				EchoMode(huh.EchoModePassword).
				Value(&githubToken),
			huh.NewInput().
				Title("GitHub host").
				Description("Use 'github.com' for public GitHub or your enterprise hostname").
				Value(&githubHost),
		),
	)
	if err := ghForm.Run(); err != nil {
		return err
	}
	cfg.Git.GitHub = []config.GitHubConfig{{Token: githubToken, Host: githubHost}}

	// --- Step 3: Optional providers ---
	fmt.Println(headerStyle.Render("\n  Step 3/7 · Additional Git Providers (optional)"))

	var addGitLab, addAzure bool
	extraForm := huh.NewForm(
		huh.NewGroup(
			huh.NewConfirm().
				Title("Add GitLab credentials?").
				Value(&addGitLab),
			huh.NewConfirm().
				Title("Add Azure DevOps credentials?").
				Value(&addAzure),
		),
	)
	if err := extraForm.Run(); err != nil {
		return err
	}

	if addGitLab {
		var glToken, glHost string = "", "gitlab.com"
		if len(cfg.Git.GitLab) > 0 {
			glToken = cfg.Git.GitLab[0].Token
			glHost = cfg.Git.GitLab[0].Host
		}
		glForm := huh.NewForm(huh.NewGroup(
			huh.NewInput().Title("GitLab token").Placeholder("glpat-...").EchoMode(huh.EchoModePassword).Value(&glToken),
			huh.NewInput().Title("GitLab host").Value(&glHost),
		))
		if err := glForm.Run(); err != nil {
			return err
		}
		cfg.Git.GitLab = []config.GitLabConfig{{Token: glToken, Host: glHost}}
	}

	if addAzure {
		var azToken, azOrg string
		if len(cfg.Git.Azure) > 0 {
			azToken = cfg.Git.Azure[0].Token
			azOrg = cfg.Git.Azure[0].Org
		}
		azForm := huh.NewForm(huh.NewGroup(
			huh.NewInput().Title("Azure DevOps PAT").EchoMode(huh.EchoModePassword).Value(&azToken),
			huh.NewInput().Title("Azure DevOps organisation name").Value(&azOrg),
		))
		if err := azForm.Run(); err != nil {
			return err
		}
		cfg.Git.Azure = []config.AzureConfig{{Token: azToken, Org: azOrg, Host: "dev.azure.com"}}
	}

	// --- Step 4: Scanner tool selection ---
	fmt.Println(headerStyle.Render("\n  Step 4/7 · Scanner Tools"))
	fmt.Println(dimStyle.Render("  Tools will be downloaded to ~/.ctrlscan/bin/\n"))

	var selectedScanners []string
	if len(cfg.Agent.Scanners) > 0 {
		selectedScanners = cfg.Agent.Scanners
	} else {
		selectedScanners = []string{"grype", "opengrep", "trufflehog"}
	}

	scannerForm := huh.NewForm(
		huh.NewGroup(
			huh.NewMultiSelect[string]().
				Title("Select scanners to install").
				Description("grype+syft are required for SCA (dependency scanning)").
				Options(
					huh.NewOption("grype + syft (SCA — dependency vulnerabilities)", "grype"),
					huh.NewOption("opengrep (SAST — code vulnerabilities)", "opengrep"),
					huh.NewOption("trufflehog (Secrets — leaked credentials)", "trufflehog"),
					huh.NewOption("trivy (IaC — misconfiguration scanning)", "trivy"),
				).
				Value(&selectedScanners),
		),
	)
	if err := scannerForm.Run(); err != nil {
		return err
	}
	cfg.Agent.Scanners = selectedScanners

	// --- Step 5: Agent mode ---
	fmt.Println(headerStyle.Render("\n  Step 5/7 · Agent Mode"))
	if cfg.AI.OpenAIKey == "" {
		fmt.Println(warnStyle.Render("  Note: all modes require an AI key to generate fixes and PRs."))
		fmt.Println(dimStyle.Render("  Without AI, the agent will discover and scan repos but stop there.\n"))
	}

	var agentMode string = "triage"
	if cfg.Agent.Mode != "" {
		agentMode = cfg.Agent.Mode
	}

	modeForm := huh.NewForm(
		huh.NewGroup(
			huh.NewSelect[string]().
				Title("Agent operation mode").
				Options(
					huh.NewOption("triage — scan, triage, and propose fixes (you approve each PR)", "triage"),
					huh.NewOption("semi — scan, generate fixes, open browser for you to review PR", "semi"),
					huh.NewOption("auto — fully autonomous: scan, fix, and open PRs hands-free", "auto"),
				).
				Value(&agentMode),
		),
	)
	if err := modeForm.Run(); err != nil {
		return err
	}
	cfg.Agent.Mode = agentMode

	// --- Step 6: Scan targets ---
	fmt.Println(headerStyle.Render("\n  Step 6/7 · Scan Targets"))

	var scanTargets []string
	if len(cfg.Agent.ScanTargets) > 0 {
		scanTargets = cfg.Agent.ScanTargets
	}

	targetForm := huh.NewForm(
		huh.NewGroup(
			huh.NewMultiSelect[string]().
				Title("Where should the agent look for repos to scan?").
				Options(
					huh.NewOption("My own repositories", "own_repos"),
					huh.NewOption("Configured org/user watchlist", "watchlist"),
					huh.NewOption("CVE-targeted public repos (search by CVE)", "cve_search"),
					huh.NewOption("All repos accessible with my token", "all_accessible"),
				).
				Value(&scanTargets),
		),
	)
	if err := targetForm.Run(); err != nil {
		return err
	}
	if len(scanTargets) == 0 {
		scanTargets = []string{"own_repos"}
	}
	cfg.Agent.ScanTargets = scanTargets

	if cfg.Agent.Workers == 0 {
		cfg.Agent.Workers = 3
	}

	// --- Step 7: Install tools ---
	fmt.Println(headerStyle.Render("\n  Step 7/7 · Installing Scanner Tools"))

	home, _ := os.UserHomeDir()
	binDir := filepath.Join(home, ".ctrlscan", "bin")

	installErrors := []string{}
	for _, scanner := range selectedScanners {
		if skipReason := scannerInstallSkipReason(scanner, binDir); skipReason != "" {
			fmt.Printf("  Installing %s... %s\n", scanner, dimStyle.Render(skipReason))
			continue
		}
		fmt.Printf("  Installing %s... ", scanner)
		if err := installScannerTool(scanner, binDir); err != nil {
			fmt.Println(warnStyle.Render("warning: " + err.Error()))
			installErrors = append(installErrors, scanner)
		} else {
			fmt.Println(successStyle.Render("done"))
		}
	}

	// Save config
	cfgPath, _ := config.ConfigPath(cfgFile)
	if err := config.Save(cfg, cfgPath); err != nil {
		return fmt.Errorf("saving config: %w", err)
	}

	// Print completion summary
	fmt.Println()
	fmt.Println(headerStyle.Render("  Setup complete!"))
	fmt.Printf("  Config saved to: %s\n", dimStyle.Render(cfgPath))
	fmt.Printf("  Binaries in:     %s\n\n", dimStyle.Render(binDir))

	fmt.Println(headerStyle.Render("  Add to your shell profile (.bashrc / .zshrc):"))
	fmt.Println()
	fmt.Printf("    %s\n\n",
		successStyle.Render(fmt.Sprintf(`export PATH="$HOME/.ctrlscan/bin:$PATH"`)))

	if len(installErrors) > 0 {
		fmt.Println(warnStyle.Render("  Some tools could not be installed automatically:"))
		for _, t := range installErrors {
			fmt.Printf("    - %s\n", t)
		}
		fmt.Println(dimStyle.Render("  Try: ctrlscan doctor --install-tools"))
		fmt.Println()
	}

	fmt.Println(dimStyle.Render("  Next steps:"))
	fmt.Println(dimStyle.Render("    ctrlscan doctor        — verify all tools and credentials"))
	fmt.Println(dimStyle.Render("    ctrlscan scan --repo <url>  — scan a specific repository"))
	fmt.Println(dimStyle.Render("    ctrlscan agent          — start the autonomous agent loop"))
	fmt.Println(dimStyle.Render("    ctrlscan ui             — launch the terminal dashboard"))
	fmt.Println()

	slog.Debug("Onboarding complete", "config", cfgPath)
	return nil
}

func scannerInstallSkipReason(scanner, binDir string) string {
	switch scanner {
	case "grype":
		grypePath := findTool("grype", binDir)
		syftPath := findTool("syft", binDir)
		if grypePath != "" && syftPath != "" {
			return fmt.Sprintf("already installed (grype: %s, syft: %s) — skipping", grypePath, syftPath)
		}
	case "opengrep", "trufflehog", "trivy":
		if path := findTool(scanner, binDir); path != "" {
			return fmt.Sprintf("already installed (%s) — skipping", path)
		}
	}
	return ""
}

// installScannerTool downloads a scanner binary to binDir.
func installScannerTool(scanner, binDir string) error {
	goos := runtime.GOOS
	goarch := runtime.GOARCH

	var installCmd *exec.Cmd

	switch scanner {
	case "grype":
		// Install syft first (required by grype for SBOM generation)
		if err := runInstallScript("https://raw.githubusercontent.com/anchore/syft/main/install.sh",
			"-b", binDir); err != nil {
			return fmt.Errorf("syft: %w", err)
		}
		return runInstallScript("https://raw.githubusercontent.com/anchore/grype/main/install.sh",
			"-b", binDir)

	case "trufflehog":
		return runInstallScript("https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh",
			"-b", binDir)

	case "trivy":
		return runInstallScript("https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh",
			"-b", binDir)

	case "opengrep":
		// opengrep distributes releases on GitHub — attempt via curl.
		return installOpengrep(goos, goarch, binDir)

	default:
		installCmd = exec.Command("which", scanner)
		if err := installCmd.Run(); err != nil {
			return fmt.Errorf("%s not found; install manually", scanner)
		}
		return nil
	}
}

// runInstallScript runs a shell install script from a URL.
func runInstallScript(url string, args ...string) error {
	allArgs := append([]string{"-sSfL", url, "|", "sh", "-s", "--"}, args...)
	_ = allArgs

	var lastErr error
	for attempt := 1; attempt <= 3; attempt++ {
		// Use sh -c to allow piped commands.
		cmdStr := fmt.Sprintf("curl -sSfL %s | sh -s -- %s", url, strings.Join(args, " "))
		// nosemgrep: go.lang.security.audit.dangerous-exec-command.dangerous-exec-command
		cmd := exec.Command("sh", "-c", cmdStr)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr

		if err := cmd.Run(); err == nil {
			return nil
		} else {
			lastErr = err
		}

		if attempt < 3 {
			time.Sleep(time.Duration(attempt) * time.Second)
		}
	}

	return lastErr
}

// installOpengrep downloads the opengrep binary from GitHub releases.
func installOpengrep(goos, goarch, binDir string) error {
	ctx := context.Background()
	release, err := fetchOpengrepLatestRelease(ctx)
	if err != nil {
		return fmt.Errorf("fetching opengrep release: %w", err)
	}

	assetName, url, err := selectOpengrepAsset(goos, goarch, release.Assets)
	if err != nil {
		return fmt.Errorf("selecting opengrep asset for %s/%s: %w", goos, goarch, err)
	}

	dest := filepath.Join(binDir, "opengrep")
	tmpDest := dest + ".download"
	// nosemgrep: go.lang.security.audit.dangerous-exec-command.dangerous-exec-command
	cmd := exec.Command("sh", "-c",
		fmt.Sprintf("curl --retry 3 --retry-all-errors -sSfL -o %q %q && mv %q %q && chmod +x %q",
			tmpDest, url, tmpDest, dest, dest))
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("downloading %s from %s: %w", assetName, url, err)
	}
	return nil
}

type opengrepRelease struct {
	TagName string              `json:"tag_name"`
	Assets  []opengrepAssetInfo `json:"assets"`
}

type opengrepAssetInfo struct {
	Name string `json:"name"`
	URL  string `json:"browser_download_url"`
}

func fetchOpengrepLatestRelease(ctx context.Context) (*opengrepRelease, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		"https://api.github.com/repos/opengrep/opengrep/releases/latest", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")

	client := &http.Client{Timeout: 20 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("github api status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var rel opengrepRelease
	if err := json.NewDecoder(resp.Body).Decode(&rel); err != nil {
		return nil, err
	}
	if rel.TagName == "" || len(rel.Assets) == 0 {
		return nil, fmt.Errorf("release metadata missing tag/assets")
	}
	return &rel, nil
}

func selectOpengrepAsset(goos, goarch string, assets []opengrepAssetInfo) (name string, url string, err error) {
	var candidates []string
	switch goos {
	case "darwin":
		switch goarch {
		case "arm64":
			candidates = []string{"opengrep_osx_arm64"}
		case "amd64":
			candidates = []string{"opengrep_osx_x86"}
		}
	case "linux":
		switch goarch {
		case "arm64":
			candidates = []string{"opengrep_manylinux_aarch64", "opengrep_musllinux_aarch64"}
		case "amd64":
			candidates = []string{"opengrep_manylinux_x86", "opengrep_musllinux_x86"}
		}
	case "windows":
		if goarch == "amd64" {
			candidates = []string{"opengrep_windows_x86.exe"}
		}
	}

	if len(candidates) == 0 {
		return "", "", fmt.Errorf("unsupported platform")
	}

	assetMap := make(map[string]string, len(assets))
	for _, a := range assets {
		assetMap[a.Name] = a.URL
	}
	for _, c := range candidates {
		if u := assetMap[c]; u != "" {
			return c, u, nil
		}
	}

	return "", "", fmt.Errorf("no matching asset found (tried: %s)", strings.Join(candidates, ", "))
}
