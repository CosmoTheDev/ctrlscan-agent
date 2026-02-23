package cmd

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/CosmoTheDev/ctrlscan-agent/internal/config"
	"github.com/CosmoTheDev/ctrlscan-agent/internal/database"
	"github.com/CosmoTheDev/ctrlscan-agent/internal/repository"
	"github.com/CosmoTheDev/ctrlscan-agent/internal/scanner"
	"github.com/spf13/cobra"
)

var (
	scanRepoURL    string
	scanBranch     string
	scanScanners   []string
	scanParallel   bool
	scanOutputFmt  string
)

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Scan a repository for vulnerabilities",
	Long: `Clones a repository and runs the configured scanners against it.

Examples:
  ctrlscan scan --repo https://github.com/example/myapp
  ctrlscan scan --repo https://github.com/example/myapp --branch develop
  ctrlscan scan --repo https://github.com/example/myapp --scanners grype,trufflehog`,
	RunE: runScan,
}

func init() {
	scanCmd.Flags().StringVar(&scanRepoURL, "repo", "", "Repository URL to scan (required)")
	scanCmd.Flags().StringVar(&scanBranch, "branch", "", "Branch to scan (default: repo default branch)")
	scanCmd.Flags().StringSliceVar(&scanScanners, "scanners", nil, "Comma-separated list of scanners to run (overrides config)")
	scanCmd.Flags().BoolVar(&scanParallel, "parallel", true, "Run scanners in parallel")
	scanCmd.Flags().StringVar(&scanOutputFmt, "output", "table", "Output format: table|json|yaml")
	_ = scanCmd.MarkFlagRequired("repo")
}

func runScan(cmd *cobra.Command, args []string) error {
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

	// Determine which scanners to run.
	scannerNames := cfg.Agent.Scanners
	if len(scanScanners) > 0 {
		scannerNames = scanScanners
	}
	if len(scannerNames) == 0 {
		scannerNames = []string{"grype", "opengrep", "trufflehog"}
	}

	// Parse repo URL to determine provider.
	provider, err := repository.DetectProvider(scanRepoURL)
	if err != nil {
		return fmt.Errorf("detecting git provider from URL: %w", err)
	}

	// Get auth token for provider.
	token := repository.TokenForProvider(cfg, provider, scanRepoURL)

	slog.Info("Starting scan",
		"repo", scanRepoURL,
		"branch", scanBranch,
		"provider", provider,
		"scanners", strings.Join(scannerNames, ","),
	)

	fmt.Printf("Scanning %s\n", scanRepoURL)
	fmt.Printf("Provider: %s | Scanners: %s\n\n", provider, strings.Join(scannerNames, ", "))

	// Clone the repository.
	cm := repository.NewCloneManager(cfg.Tools.BinDir)
	cloneResult, err := cm.Clone(ctx, scanRepoURL, token, scanBranch)
	if err != nil {
		return fmt.Errorf("cloning repository: %w", err)
	}
	defer cm.Cleanup(cloneResult)

	slog.Info("Repository cloned",
		"path", cloneResult.LocalPath,
		"commit", cloneResult.Commit,
		"branch", cloneResult.Branch,
	)
	fmt.Printf("Cloned to: %s (commit: %s)\n\n", cloneResult.LocalPath, cloneResult.Commit[:8])

	// Build scanner instances.
	scanners := scanner.BuildScanners(scannerNames, cfg.Tools.BinDir, cfg.Tools.PreferDocker)

	// Create scan job.
	jobKey := fmt.Sprintf("%s:%s:%s:%s",
		provider, cloneResult.Owner, cloneResult.Repo, cloneResult.Branch)

	// Run scans.
	runner := scanner.NewRunner(scanners, db)
	results, err := runner.Run(ctx, &scanner.RunOptions{
		RepoPath:  cloneResult.LocalPath,
		JobKey:    jobKey,
		Provider:  provider,
		Owner:     cloneResult.Owner,
		Repo:      cloneResult.Repo,
		Branch:    cloneResult.Branch,
		Commit:    cloneResult.Commit,
		Parallel:  scanParallel,
	})
	if err != nil {
		return fmt.Errorf("running scans: %w", err)
	}

	// Print summary.
	printScanSummary(results, scanOutputFmt)

	return nil
}

func printScanSummary(results *scanner.RunResults, format string) {
	fmt.Println("=== Scan Results ===")
	fmt.Printf("Status: %s\n\n", results.Status)

	total := struct{ critical, high, medium, low int }{}

	for name, r := range results.ScannerResults {
		fmt.Printf("[%s] %s — %d findings (%.1fs)\n",
			r.Status, name, r.FindingsCount, r.DurationSec)
		total.critical += r.Critical
		total.high += r.High
		total.medium += r.Medium
		total.low += r.Low
	}

	fmt.Println()
	fmt.Printf("Totals — Critical: %d  High: %d  Medium: %d  Low: %d\n",
		total.critical, total.high, total.medium, total.low)
	fmt.Println()
	fmt.Printf("Findings saved to database. Run 'ctrlscan ui' to review.\n")
}
