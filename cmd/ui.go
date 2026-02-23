package cmd

import (
	"context"
	"fmt"

	"github.com/CosmoTheDev/ctrlscan-agent/internal/config"
	"github.com/CosmoTheDev/ctrlscan-agent/internal/database"
	"github.com/CosmoTheDev/ctrlscan-agent/internal/tui"
	"github.com/spf13/cobra"
)

var uiCmd = &cobra.Command{
	Use:   "ui",
	Short: "Launch the terminal dashboard",
	Long:  `Opens the interactive terminal UI for monitoring scans, reviewing findings, and managing the remediation queue.`,
	RunE:  runUI,
}

func runUI(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	cfg, err := config.Load(cfgFile)
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	db, err := database.New(cfg.Database)
	if err != nil {
		return fmt.Errorf("opening database: %w", err)
	}
	defer db.Close()

	if err := db.Migrate(ctx); err != nil {
		return fmt.Errorf("running migrations: %w", err)
	}

	app := tui.NewApp(cfg, db)
	return app.Run()
}
