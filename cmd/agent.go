package cmd

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/CosmoTheDev/ctrlscan-agent/internal/agent"
	"github.com/CosmoTheDev/ctrlscan-agent/internal/config"
	"github.com/CosmoTheDev/ctrlscan-agent/internal/database"
	"github.com/spf13/cobra"
)

var (
	agentMode    string
	agentWorkers int
)

var agentCmd = &cobra.Command{
	Use:   "agent",
	Short: "Run the autonomous vulnerability remediation agent",
	Long: `Starts the ctrlscan agent loop. The agent will:
  1. Discover repositories based on configured scan targets
  2. Clone and scan each repository with the configured scanners
  3. Store all findings in the local database

  When an AI provider is configured (via 'ctrlscan onboard'):
  4. Triage and prioritise findings by real-world risk
  5. Generate minimal code patches for each finding
  6. Create pull requests (based on the agent mode)

  Without an AI key the agent runs in scan-only mode: repos are
  discovered and scanned, but no fixes or PRs are generated. Run
  'ctrlscan ui' or query the database to review raw findings.

Modes (require AI):
  triage  — scan, triage, and propose fixes; you approve each PR (default)
  semi    — scan, generate fix, open browser for your review
  auto    — fully autonomous: scan, fix, and open PRs

Examples:
  ctrlscan agent                    # scan-only if no AI key
  ctrlscan agent --mode triage      # AI-assisted triage
  ctrlscan agent --mode auto --workers 5`,
	RunE: runAgent,
}

func init() {
	agentCmd.Flags().StringVar(&agentMode, "mode", "",
		"Agent mode: triage|semi|auto (overrides config)")
	agentCmd.Flags().IntVar(&agentWorkers, "workers", 0,
		"Number of parallel scan workers (overrides config)")
}

func runAgent(cmd *cobra.Command, args []string) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Graceful shutdown on SIGINT/SIGTERM.
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigs
		fmt.Println("\nShutting down agent gracefully...")
		cancel()
	}()

	cfg, err := config.Load(cfgFile)
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	// CLI flags override config.
	if agentMode != "" {
		cfg.Agent.Mode = agentMode
	}
	if agentWorkers > 0 {
		cfg.Agent.Workers = agentWorkers
	}

	// Validate mode.
	switch cfg.Agent.Mode {
	case "triage", "semi", "auto":
	case "":
		cfg.Agent.Mode = "triage"
	default:
		return fmt.Errorf("invalid agent mode %q (valid: triage, semi, auto)", cfg.Agent.Mode)
	}

	db, err := database.New(cfg.Database)
	if err != nil {
		return fmt.Errorf("opening database: %w", err)
	}
	defer db.Close()

	if err := db.Migrate(ctx); err != nil {
		return fmt.Errorf("running migrations: %w", err)
	}

	slog.Info("Starting agent",
		"mode", cfg.Agent.Mode,
		"workers", cfg.Agent.Workers,
		"targets", cfg.Agent.ScanTargets,
	)

	fmt.Printf("ctrlscan agent starting (mode: %s, workers: %d)\n\n",
		cfg.Agent.Mode, cfg.Agent.Workers)

	// Warn clearly when running without AI.
	if cfg.AI.OpenAIKey == "" && (cfg.AI.Provider == "" || cfg.AI.Provider == "none") {
		fmt.Println(warnStyle.Render("  Scan-only mode: no AI provider configured."))
		fmt.Println(dimStyle.Render("  Repos will be discovered and scanned; results stored in the database."))
		fmt.Println(dimStyle.Render("  No triage, fix generation, or pull requests will be created."))
		fmt.Println(dimStyle.Render("  Run 'ctrlscan onboard' to add an OpenAI key and enable AI features."))
		fmt.Println()
	}

	fmt.Println("Press Ctrl+C to stop gracefully.")
	fmt.Println()

	orch := agent.NewOrchestrator(cfg, db)
	if err := orch.Run(ctx); err != nil && ctx.Err() == nil {
		return fmt.Errorf("agent error: %w", err)
	}

	fmt.Println("Agent stopped.")
	return nil
}
