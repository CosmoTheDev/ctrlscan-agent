package cmd

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/CosmoTheDev/ctrlscan-agent/internal/config"
	"github.com/CosmoTheDev/ctrlscan-agent/internal/controlplane"
	"github.com/charmbracelet/huh"
	"github.com/spf13/cobra"
)

var (
	registerKey         string
	registerURL         string
	registerDisplayName string
)

var registerCmd = &cobra.Command{
	Use:   "register",
	Short: "Connect this agent to the ctrlscan.com control plane",
	Long: `Registers this agent with ctrlscan.com so it can submit public repository
scan data and appear in the public dashboard.

Integration is fully optional and privacy-first:
  - Only repos you explicitly list in submit_allowlist are ever submitted.
  - Before submitting, the agent verifies the repo is publicly visible.
  - Private repos are never sent to the control plane.

Two usage modes:

  1. Provide an existing API key (obtained from ctrlscan.com):
       ctrlscan register --key ctrlscan_xxxxx

  2. Register interactively (agent creates a new entry via the API):
       ctrlscan register`,
	RunE: runRegister,
}

func init() {
	registerCmd.Flags().StringVar(&registerKey, "key", "",
		"existing API key from ctrlscan.com (skips interactive registration)")
	registerCmd.Flags().StringVar(&registerURL, "url", "",
		"control plane base URL (default: https://ctrlscan.com)")
	registerCmd.Flags().StringVar(&registerDisplayName, "name", "",
		"display name for this agent on ctrlscan.com")
}

func runRegister(cmd *cobra.Command, args []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	cfg, err := config.Load(cfgFile)
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	cpURL := registerURL
	if cpURL == "" && cfg.ControlPlane.URL != "" {
		cpURL = cfg.ControlPlane.URL
	}

	var apiKey, agentKey, displayName string

	if registerKey != "" {
		// --- Flow A: validate an existing key ---
		fmt.Println(headerStyle.Render("Connecting to ctrlscan.com"))
		fmt.Println()
		apiKey = strings.TrimSpace(registerKey)
		client := controlplane.NewWithKey(cpURL, apiKey)
		fmt.Print("Validating API key ... ")
		info, err := client.Ping(ctx)
		if err != nil {
			fmt.Println("FAIL")
			return fmt.Errorf("key validation failed: %w\n\nCheck your API key and network connection.", err)
		}
		fmt.Printf("OK\n\n")
		agentKey = info.AgentKey
		displayName = info.DisplayName
		fmt.Printf("  Agent:    %s\n", displayName)
		fmt.Printf("  Key:      %s\n", agentKey)
		fmt.Printf("  Status:   %s\n", info.Status)
		if info.LastSeenAt != nil {
			fmt.Printf("  Last seen: %s\n", *info.LastSeenAt)
		}
	} else {
		// --- Flow B: interactive registration ---
		fmt.Println(headerStyle.Render("Register with ctrlscan.com"))
		fmt.Println()
		fmt.Println(dimStyle.Render("This creates a new agent entry on ctrlscan.com and issues an API key."))
		fmt.Println()

		name := registerDisplayName
		if name == "" && cfg.ControlPlane.DisplayName != "" {
			name = cfg.ControlPlane.DisplayName
		}

		var confirmed bool
		form := huh.NewForm(
			huh.NewGroup(
				huh.NewInput().
					Title("Agent display name").
					Description("Shown on ctrlscan.com alongside your agent's submissions.").
					Value(&name).
					Validate(func(s string) error {
						if strings.TrimSpace(s) == "" {
							return fmt.Errorf("display name cannot be empty")
						}
						return nil
					}),
				huh.NewConfirm().
					Title("Register this agent with ctrlscan.com?").
					Value(&confirmed),
			),
		)
		if err := form.Run(); err != nil {
			return fmt.Errorf("cancelled: %w", err)
		}
		if !confirmed {
			fmt.Println(dimStyle.Render("Registration cancelled."))
			return nil
		}

		provider := deriveProviderLabel(cfg)
		client := controlplane.NewWithKey(cpURL, "")
		fmt.Print("Registering ... ")
		resp, err := client.Register(ctx, controlplane.RegisterRequest{
			DisplayName: strings.TrimSpace(name),
			Provider:    provider,
			Description: fmt.Sprintf("ctrlscan-agent on %s", provider),
		})
		if err != nil {
			fmt.Println("FAIL")
			return fmt.Errorf("registration failed: %w", err)
		}
		fmt.Println("OK")
		apiKey = resp.APIKey
		agentKey = resp.AgentKey
		displayName = strings.TrimSpace(name)
	}

	// Save to config.
	cfg.ControlPlane.Enabled = true
	cfg.ControlPlane.APIKey = apiKey
	cfg.ControlPlane.AgentKey = agentKey
	cfg.ControlPlane.DisplayName = displayName
	if cfg.ControlPlane.URL == "" {
		cfg.ControlPlane.URL = cpURL
	}
	// Default: always verify repos are public before submitting.
	cfg.ControlPlane.AutoVerifyPublic = true

	cfgPath, _ := config.ConfigPath(cfgFile)
	if err := config.Save(cfg, cfgPath); err != nil {
		return fmt.Errorf("saving config: %w", err)
	}

	fmt.Println()
	fmt.Println(successStyle.Render("✓ Registered successfully"))
	fmt.Println()
	fmt.Printf("  Agent key:   %s\n", agentKey)
	fmt.Printf("  Config:      %s\n", cfgPath)
	fmt.Println()
	fmt.Println(dimStyle.Render("Next steps:"))
	fmt.Println(dimStyle.Render("  • Add repos to your allowlist:  ctrlscan config edit"))
	fmt.Println(dimStyle.Render(`    Set "submit_allowlist": ["owner/repo"] under "controlplane"`))
	fmt.Println(dimStyle.Render("  • Verify connection:            ctrlscan doctor"))
	fmt.Println()

	return nil
}

// deriveProviderLabel builds a human-readable provider string from AI config.
// e.g. "openai-gpt-4o", "ollama-llama3.2", "none"
func deriveProviderLabel(cfg *config.Config) string {
	p := strings.TrimSpace(cfg.AI.Provider)
	m := strings.TrimSpace(cfg.AI.Model)
	if p == "" || p == "none" {
		return "none"
	}
	if m != "" {
		return p + "-" + m
	}
	return p
}
