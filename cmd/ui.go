package cmd

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/CosmoTheDev/ctrlscan-agent/internal/config"
	"github.com/CosmoTheDev/ctrlscan-agent/internal/database"
	"github.com/CosmoTheDev/ctrlscan-agent/internal/gateway"
	"github.com/CosmoTheDev/ctrlscan-agent/internal/tui"
	"github.com/spf13/cobra"
)

var uiTUI bool
var uiPort int

var uiCmd = &cobra.Command{
	Use:   "ui",
	Short: "Launch the dashboard (web UI by default)",
	Long: `Opens the ctrlscan dashboard for monitoring scans, reviewing findings,
and managing the remediation queue.

By default, this starts the gateway server and opens the web UI in your browser.
Use --tui for the terminal-based interface instead.`,
	RunE: runUI,
}

func init() {
	uiCmd.Flags().BoolVar(&uiTUI, "tui", false, "Use terminal UI instead of web UI")
	uiCmd.Flags().IntVar(&uiPort, "port", 6080, "Port for web UI server")
}

func runUI(cmd *cobra.Command, args []string) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

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

	// Use terminal UI if requested
	if uiTUI {
		app := tui.NewApp(cfg, db)
		return app.Run()
	}

	// Handle Ctrl+C gracefully
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigs
		fmt.Println("\nShutting down...")
		cancel()
	}()

	// Set the port
	if uiPort > 0 {
		cfg.Gateway.Port = uiPort
	}
	if cfg.Gateway.Port == 0 {
		cfg.Gateway.Port = 6080
	}

	fmt.Printf("Starting ctrlscan web UI on http://127.0.0.1:%d/ui\n", cfg.Gateway.Port)
	fmt.Println("Press Ctrl+C to stop")
	fmt.Println()

	// Open browser after a short delay
	go func() {
		time.Sleep(800 * time.Millisecond)
		url := fmt.Sprintf("http://127.0.0.1:%d/ui", cfg.Gateway.Port)
		if err := openBrowser(url); err != nil {
			fmt.Printf("Open %s in your browser\n", url)
		}
	}()

	// Start gateway server
	gw := gateway.New(cfg, db)
	return gw.Start(ctx)
}

// openBrowser opens the specified URL in the default browser.
func openBrowser(url string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	default: // linux, etc.
		cmd = exec.Command("xdg-open", url)
	}
	return cmd.Start()
}
