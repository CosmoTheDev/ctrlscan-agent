package cmd

import (
	"fmt"

	"github.com/CosmoTheDev/ctrlscan-agent/internal/config"
	"github.com/spf13/cobra"
)

var repoCmd = &cobra.Command{
	Use:   "repo",
	Short: "Manage repository watchlists",
	Long:  `Add, remove, and list repositories in your scan watchlist.`,
}

var repoAddCmd = &cobra.Command{
	Use:   "add <owner/repo or owner>",
	Short: "Add a repository or org to the watchlist",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := config.Load(cfgFile)
		if err != nil {
			return err
		}
		target := args[0]
		for _, w := range cfg.Agent.Watchlist {
			if w == target {
				fmt.Printf("%s is already in the watchlist\n", target)
				return nil
			}
		}
		cfg.Agent.Watchlist = append(cfg.Agent.Watchlist, target)
		cfgPath, _ := config.ConfigPath(cfgFile)
		if err := config.Save(cfg, cfgPath); err != nil {
			return err
		}
		fmt.Printf("Added %s to watchlist\n", target)
		return nil
	},
}

var repoRemoveCmd = &cobra.Command{
	Use:   "remove <owner/repo or owner>",
	Short: "Remove an entry from the watchlist",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := config.Load(cfgFile)
		if err != nil {
			return err
		}
		target := args[0]
		newList := make([]string, 0, len(cfg.Agent.Watchlist))
		found := false
		for _, w := range cfg.Agent.Watchlist {
			if w == target {
				found = true
				continue
			}
			newList = append(newList, w)
		}
		if !found {
			fmt.Printf("%s is not in the watchlist\n", target)
			return nil
		}
		cfg.Agent.Watchlist = newList
		cfgPath, _ := config.ConfigPath(cfgFile)
		if err := config.Save(cfg, cfgPath); err != nil {
			return err
		}
		fmt.Printf("Removed %s from watchlist\n", target)
		return nil
	},
}

var repoListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all watchlist entries",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := config.Load(cfgFile)
		if err != nil {
			return err
		}
		if len(cfg.Agent.Watchlist) == 0 {
			fmt.Println("Watchlist is empty. Add repos with: ctrlscan repo add <owner/repo>")
			return nil
		}
		fmt.Println("Watchlist:")
		for _, w := range cfg.Agent.Watchlist {
			fmt.Printf("  - %s\n", w)
		}
		return nil
	},
}

func init() {
	repoCmd.AddCommand(repoAddCmd, repoRemoveCmd, repoListCmd)
}
