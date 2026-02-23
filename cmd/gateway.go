package cmd

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/CosmoTheDev/ctrlscan-agent/internal/config"
	"github.com/CosmoTheDev/ctrlscan-agent/internal/database"
	"github.com/CosmoTheDev/ctrlscan-agent/internal/gateway"
	"github.com/spf13/cobra"
)

var gatewayPort int
var gatewayLogDir string

var gatewayCmd = &cobra.Command{
	Use:   "gateway",
	Short: "Start the ctrlscan gateway daemon",
	Long: `Starts the ctrlscan gateway: a long-running daemon that combines the
autonomous agent with a REST + SSE control plane.

The gateway runs the agent orchestrator continuously and exposes a local
HTTP API (default: http://127.0.0.1:6080) so you can:

  • View scan jobs, findings, and the fix queue in real time
  • Approve or reject AI-generated patches before PRs are opened
  • Create cron schedules that trigger the agent automatically
  • Trigger ad-hoc scans of specific repositories
  • Stream live events via GET /events (Server-Sent Events)

Example schedules:
  "0 2 * * *"   — every night at 02:00
  "@every 6h"   — every 6 hours
  "@daily"      — once per day at midnight

Unlike 'ctrlscan agent' (one-shot), the gateway stays running and lets
you orchestrate the agent over time without manual intervention.

Quick API reference:
  GET  /health                         liveness check
  GET  /api/status                     agent status snapshot
  GET  /api/jobs                       list scan jobs
  POST /api/scan                       trigger a scan (body: {"repo_url":"..."})
  GET  /api/findings                   list findings (?kind=sca|sast|secrets|iac)
  GET  /api/fix-queue                  list pending fixes
  POST /api/fix-queue/:id/approve      approve a fix (triggers PR creation)
  POST /api/fix-queue/:id/reject       reject a fix
  GET  /api/schedules                  list cron schedules
  POST /api/schedules                  create a schedule
  DELETE /api/schedules/:id            delete a schedule
  POST /api/schedules/:id/trigger      run a schedule immediately
  GET  /events                         SSE stream of live events`,
	RunE: runGateway,
}

func init() {
	gatewayCmd.Flags().IntVar(&gatewayPort, "port", 0,
		"HTTP port to listen on (default 6080, overrides config)")
	gatewayCmd.Flags().StringVar(&gatewayLogDir, "log-dir", "logs",
		"directory to write gateway/agent logs for later inspection")
}

func runGateway(cmd *cobra.Command, args []string) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigs
		fmt.Println("\nShutting down gateway gracefully...")
		cancel()
	}()

	cfg, err := config.Load(cfgFile)
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}
	effectiveCfgPath, _ := config.ConfigPath(cfgFile)

	logFilePath, closeLog, err := setupGatewayFileLogger(gatewayLogDir)
	if err != nil {
		return fmt.Errorf("initialising gateway logger: %w", err)
	}
	defer closeLog()

	if gatewayPort > 0 {
		cfg.Gateway.Port = gatewayPort
	}
	if cfg.Gateway.Port == 0 {
		cfg.Gateway.Port = 6080
	}

	// Validate agent mode if set.
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

	fmt.Printf("ctrlscan gateway starting\n")
	fmt.Printf("  Agent mode : %s\n", cfg.Agent.Mode)
	fmt.Printf("  Workers    : %d\n", cfg.Agent.Workers)
	fmt.Printf("  API        : http://127.0.0.1:%d\n", cfg.Gateway.Port)
	fmt.Printf("  Events     : http://127.0.0.1:%d/events\n\n", cfg.Gateway.Port)
	fmt.Printf("  UI         : http://127.0.0.1:%d/ui\n\n", cfg.Gateway.Port)
	fmt.Printf("  Logs       : %s\n\n", logFilePath)
	fmt.Println("Press Ctrl+C to stop gracefully.")
	fmt.Println("Gateway starts idle; trigger scans via /ui, API, or cron schedules.")
	fmt.Println()

	slog.Info("gateway logger initialised", "file", logFilePath)
	gw := gateway.New(cfg, db)
	gw.SetConfigPath(effectiveCfgPath)
	gw.SetLogDir(gatewayLogDir)
	return gw.Start(ctx)
}

func setupGatewayFileLogger(logDir string) (string, func(), error) {
	if logDir == "" {
		logDir = "logs"
	}
	if err := os.MkdirAll(logDir, 0o755); err != nil {
		return "", nil, fmt.Errorf("creating log dir %s: %w", logDir, err)
	}

	ts := time.Now().UTC().Format("20060102-150405")
	runLogPath := filepath.Join(logDir, fmt.Sprintf("gateway-%s.log", ts))
	runFile, err := os.OpenFile(runLogPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return "", nil, fmt.Errorf("opening run log file: %w", err)
	}

	latestPath := filepath.Join(logDir, "gateway.log")
	latestFile, err := os.OpenFile(latestPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		_ = runFile.Close()
		return "", nil, fmt.Errorf("opening latest log file: %w", err)
	}

	level := slog.LevelInfo
	if verbose {
		level = slog.LevelDebug
	}
	handler := slog.NewTextHandler(io.MultiWriter(os.Stdout, runFile, latestFile), &slog.HandlerOptions{
		Level:     level,
		AddSource: verbose,
	})
	slog.SetDefault(slog.New(handler))
	slog.SetLogLoggerLevel(level)

	cleanup := func() {
		_ = latestFile.Close()
		_ = runFile.Close()
	}
	return runLogPath, cleanup, nil
}
