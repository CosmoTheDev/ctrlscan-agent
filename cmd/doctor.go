package cmd

import (
	"context"
	"fmt"
	"os/exec"
	"path/filepath"

	"github.com/CosmoTheDev/ctrlscan-agent/internal/config"
	"github.com/CosmoTheDev/ctrlscan-agent/internal/database"
	"github.com/spf13/cobra"
)

var installTools bool

var doctorCmd = &cobra.Command{
	Use:   "doctor",
	Short: "Verify tools, credentials, and system health",
	Long: `Checks that all configured scanner tools are available, credentials
are set, and the database can be reached.

Use --install-tools to attempt automatic installation of missing tools.`,
	RunE: runDoctor,
}

func init() {
	doctorCmd.Flags().BoolVar(&installTools, "install-tools", false,
		"Attempt to install any missing scanner tools")
}

func runDoctor(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	cfg, err := config.Load(cfgFile)
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	allOK := true

	fmt.Println("=== ctrlscan doctor ===")
	fmt.Println()

	// Check database
	fmt.Print("Database ................. ")
	db, err := database.New(cfg.Database)
	if err != nil {
		fmt.Printf("FAIL (%s)\n", err)
		allOK = false
	} else {
		if err := db.Ping(ctx); err != nil {
			fmt.Printf("FAIL (%s)\n", err)
			allOK = false
		} else {
			fmt.Printf("OK (%s: %s)\n", db.Driver(), cfg.Database.Path)
		}
		db.Close()
	}

	// Check AI config
	fmt.Print("AI provider .............. ")
	switch {
	case cfg.AI.Provider == "" || cfg.AI.Provider == "none":
		fmt.Println("disabled (scan-only mode — run 'ctrlscan onboard' to enable AI features)")
	case cfg.AI.OpenAIKey == "" && cfg.AI.Provider == "openai":
		fmt.Println("WARN (OpenAI key missing — run 'ctrlscan onboard')")
		allOK = false
	default:
		fmt.Printf("OK (%s / %s)\n", cfg.AI.Provider, cfg.AI.Model)
	}

	// Check GitHub token
	fmt.Print("GitHub token ............. ")
	if len(cfg.Git.GitHub) == 0 || cfg.Git.GitHub[0].Token == "" {
		fmt.Println("WARN (not configured — run 'ctrlscan onboard')")
		allOK = false
	} else {
		fmt.Printf("OK (%s)\n", cfg.Git.GitHub[0].Host)
	}

	// Check scanner tools
	fmt.Println()
	fmt.Println("Scanner tools:")
	binDir := cfg.Tools.BinDir

	tools := []struct {
		name    string
		command string
	}{
		{"grype", "grype"},
		{"syft", "syft"},
		{"opengrep", "opengrep"},
		{"trufflehog", "trufflehog"},
		{"trivy", "trivy"},
	}

	for _, t := range tools {
		fmt.Printf("  %-14s ... ", t.name)
		path := findTool(t.command, binDir)
		if path == "" {
			if installTools {
				fmt.Print("missing — installing... ")
				if err := installScannerTool(t.name, binDir); err != nil {
					fmt.Printf("FAIL (%s)\n", err)
					allOK = false
				} else {
					fmt.Println("done")
				}
			} else {
				fmt.Printf("MISSING (install with: ctrlscan doctor --install-tools)\n")
			}
		} else {
			fmt.Printf("OK (%s)\n", path)
		}
	}

	// Check Docker
	fmt.Print("\nDocker ................... ")
	if _, err := exec.LookPath("docker"); err != nil {
		fmt.Println("NOT FOUND (optional — local binaries preferred)")
	} else {
		dockerInfo := exec.CommandContext(ctx, "docker", "info", "--format", "{{.ServerVersion}}")
		out, err := dockerInfo.Output()
		if err != nil {
			fmt.Println("NOT RUNNING (optional)")
		} else {
			fmt.Printf("OK (v%s)\n", string(out))
		}
	}

	fmt.Println()
	if allOK {
		fmt.Println(successStyle.Render("All checks passed — ctrlscan is ready!"))
	} else {
		fmt.Println(warnStyle.Render("Some checks failed — run 'ctrlscan onboard' to fix."))
	}

	return nil
}

// findTool searches for a tool binary in binDir, then in PATH.
func findTool(name, binDir string) string {
	// Check binDir first.
	candidate := filepath.Join(binDir, name)
	if isExecutable(candidate) {
		return candidate
	}
	// Fall back to PATH.
	if p, err := exec.LookPath(name); err == nil {
		return p
	}
	return ""
}

func isExecutable(path string) bool {
	// nosemgrep: go.lang.security.audit.dangerous-exec-command.dangerous-exec-command
	cmd := exec.Command(path, "--version")
	err := cmd.Run()
	return err == nil
}
