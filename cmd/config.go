package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"

	"github.com/CosmoTheDev/ctrlscan-agent/internal/config"
	"github.com/spf13/cobra"
)

var configCmd = &cobra.Command{
	Use:   "config",
	Short: "View and manage ctrlscan configuration",
}

var configShowCmd = &cobra.Command{
	Use:   "show",
	Short: "Print the current configuration (secrets redacted)",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := config.Load(cfgFile)
		if err != nil {
			return err
		}
		// Redact secrets.
		if cfg.AI.OpenAIKey != "" {
			cfg.AI.OpenAIKey = "sk-***"
		}
		if cfg.AI.AnthropicKey != "" {
			cfg.AI.AnthropicKey = "sk-ant-***"
		}
		for i := range cfg.Git.GitHub {
			if cfg.Git.GitHub[i].Token != "" {
				cfg.Git.GitHub[i].Token = "ghp-***"
			}
		}
		for i := range cfg.Git.GitLab {
			if cfg.Git.GitLab[i].Token != "" {
				cfg.Git.GitLab[i].Token = "glpat-***"
			}
		}
		for i := range cfg.Git.Azure {
			if cfg.Git.Azure[i].Token != "" {
				cfg.Git.Azure[i].Token = "***"
			}
		}
		if cfg.ControlPlane.APIKey != "" {
			cfg.ControlPlane.APIKey = "ctrlscan-***"
		}
		// Notify channel secrets
		if cfg.Notify.Telegram.BotToken != "" {
			cfg.Notify.Telegram.BotToken = "tg-***"
		}
		if cfg.Notify.Email.Password != "" {
			cfg.Notify.Email.Password = "***"
		}
		if cfg.Notify.Webhook.Secret != "" {
			cfg.Notify.Webhook.Secret = "***"
		}

		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(cfg)
	},
}

var configPathCmd = &cobra.Command{
	Use:   "path",
	Short: "Print the path to the config file",
	RunE: func(cmd *cobra.Command, args []string) error {
		p, err := config.ConfigPath(cfgFile)
		if err != nil {
			return err
		}
		fmt.Println(p)
		return nil
	},
}

var configEditCmd = &cobra.Command{
	Use:   "edit",
	Short: "Open the config file in $EDITOR",
	RunE: func(cmd *cobra.Command, args []string) error {
		p, err := config.ConfigPath(cfgFile)
		if err != nil {
			return err
		}
		editor := os.Getenv("EDITOR")
		if editor == "" {
			editor = "nano"
		}
		fmt.Printf("Opening %s with %s...\n", p, editor)
		c := exec.Command(editor, p) // #nosec G204 -- editor is from $EDITOR env var, intentional user-controlled binary
		c.Stdin = os.Stdin
		c.Stdout = os.Stdout
		c.Stderr = os.Stderr
		return c.Run()
	},
}

func init() {
	configCmd.AddCommand(configShowCmd, configPathCmd, configEditCmd, configUICmd)
}
