package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/viper"
)

const (
	DefaultConfigDir  = ".ctrlscan"
	DefaultConfigFile = "config.json"
	DefaultBinDir     = ".ctrlscan/bin"
	DefaultDBFile     = ".ctrlscan/ctrlscan.db"
)

// Load reads the config file (creating it with defaults if absent) and returns
// a populated Config. The configPath flag may override the default location.
func Load(configPath string) (*Config, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("cannot determine home directory: %w", err)
	}

	v := viper.New()
	v.SetConfigType("json")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	if configPath != "" {
		v.SetConfigFile(configPath)
	} else {
		v.SetConfigName("config")
		v.AddConfigPath(filepath.Join(home, DefaultConfigDir))
	}

	setDefaults(v, home)

	if err := v.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			// Config file exists but is malformed.
			if !isNotExist(err) {
				return nil, fmt.Errorf("reading config: %w", err)
			}
		}
		// No config yet — we'll create it with defaults after unmarshal.
	}

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}

	expandPaths(&cfg, home)
	return &cfg, nil
}

// Save writes the config to disk as JSON.
func Save(cfg *Config, configPath string) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("cannot determine home directory: %w", err)
	}

	if configPath == "" {
		configPath = filepath.Join(home, DefaultConfigDir, DefaultConfigFile)
	}

	if err := os.MkdirAll(filepath.Dir(configPath), 0o700); err != nil {
		return fmt.Errorf("creating config directory: %w", err)
	}

	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("serialising config: %w", err)
	}

	return os.WriteFile(configPath, data, 0o600)
}

// ConfigPath returns the effective config file path.
func ConfigPath(override string) (string, error) {
	if override != "" {
		return override, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, DefaultConfigDir, DefaultConfigFile), nil
}

// EnsureDir creates ~/.ctrlscan/bin and ~/.ctrlscan if they don't exist.
func EnsureDir() error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	dirs := []string{
		filepath.Join(home, DefaultConfigDir),
		filepath.Join(home, DefaultBinDir),
	}
	for _, d := range dirs {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return fmt.Errorf("creating directory %s: %w", d, err)
		}
	}
	return nil
}

// setDefaults populates viper with sensible out-of-the-box values.
func setDefaults(v *viper.Viper, home string) {
	v.SetDefault("database.driver", "sqlite")
	v.SetDefault("database.path", filepath.Join(home, DefaultDBFile))
	v.SetDefault("database.dsn", "")

	v.SetDefault("ai.provider", "")
	v.SetDefault("ai.model", "gpt-4o")
	v.SetDefault("ai.base_url", "")
	v.SetDefault("ai.ollama_url", "http://localhost:11434")
	v.SetDefault("ai.optimize_for_local", false)

	v.SetDefault("agent.mode", "triage")
	v.SetDefault("agent.workers", 3)
	v.SetDefault("agent.scan_targets", []string{"own_repos"})
	v.SetDefault("agent.scanners", []string{"grype", "opengrep", "trufflehog"})

	v.SetDefault("tools.bin_dir", filepath.Join(home, DefaultBinDir))
	v.SetDefault("tools.prefer_docker", false)
}

// expandPaths resolves ~ in configured paths.
func expandPaths(cfg *Config, home string) {
	cfg.Database.Path = expandHome(cfg.Database.Path, home)
	cfg.Tools.BinDir = expandHome(cfg.Tools.BinDir, home)
}

func expandHome(path, home string) string {
	if strings.HasPrefix(path, "~/") {
		return filepath.Join(home, path[2:])
	}
	return path
}

func isNotExist(err error) bool {
	return os.IsNotExist(err) || strings.Contains(err.Error(), "no such file")
}
