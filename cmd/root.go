package cmd

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// Version is set at build time via -ldflags.
var Version = "dev"

var (
	cfgFile string
	verbose bool
)

// rootCmd is the base command when called without any subcommands.
var rootCmd = &cobra.Command{
	Use:   "ctrlscan",
	Short: "AI-powered vulnerability scanning and automated CVE remediation",
	Long: `ctrlscan is an open-source agent that scans repositories for security
vulnerabilities, then uses AI to generate fixes and create pull requests
automatically — helping developers contribute CVE remediations at scale.

Get started:
  ctrlscan onboard    Interactive setup wizard
  ctrlscan doctor     Verify tools and credentials
  ctrlscan scan       Scan a repository
  ctrlscan agent      Run the autonomous remediation agent (one-shot)
  ctrlscan gateway    Start the persistent gateway daemon with REST API
  ctrlscan ui         Launch the terminal UI`,
	SilenceUsage:  true,
	SilenceErrors: true,
}

// Execute is the entry point called from main.go.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)

	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "",
		"config file (default: ~/.ctrlscan/config.json)")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false,
		"enable verbose/debug output")

	rootCmd.Version = Version
	rootCmd.AddCommand(
		onboardCmd,
		scanCmd,
		agentCmd,
		gatewayCmd,
		uiCmd,
		repoCmd,
		configCmd,
		doctorCmd,
		registerCmd,
	)
}

func initConfig() {
	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	}
	if verbose {
		slog.SetLogLoggerLevel(slog.LevelDebug)
		slog.Debug("Verbose logging enabled")
	}
}
