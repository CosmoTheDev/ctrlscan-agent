package config

// Config is the root configuration structure for ctrlscan.
// Serialised to ~/.ctrlscan/config.json.
type Config struct {
	Database DatabaseConfig `mapstructure:"database" json:"database"`
	AI       AIConfig       `mapstructure:"ai"       json:"ai"`
	Git      GitConfig      `mapstructure:"git"      json:"git"`
	Agent    AgentConfig    `mapstructure:"agent"    json:"agent"`
	Tools    ToolsConfig    `mapstructure:"tools"    json:"tools"`
	Gateway  GatewayConfig  `mapstructure:"gateway"  json:"gateway"`
}

// DatabaseConfig controls the storage backend.
type DatabaseConfig struct {
	// Driver is "sqlite" (default) or "mysql".
	Driver string `mapstructure:"driver" json:"driver"`
	// Path is the SQLite file path (expanded at runtime).
	Path string `mapstructure:"path"   json:"path"`
	// DSN is the MySQL data source name (used when Driver == "mysql").
	DSN string `mapstructure:"dsn"    json:"dsn"`
}

// AIConfig controls the AI provider used for triage and fix generation.
type AIConfig struct {
	// Provider is "openai" (default) or "ollama".
	Provider  string `mapstructure:"provider"       json:"provider"`
	OpenAIKey string `mapstructure:"openai_api_key" json:"openai_api_key"`
	Model     string `mapstructure:"model"          json:"model"`
	// BaseURL overrides the API endpoint (useful for Azure OpenAI or proxies).
	BaseURL string `mapstructure:"base_url" json:"base_url"`
	// OllamaURL is used when Provider == "ollama".
	OllamaURL string `mapstructure:"ollama_url" json:"ollama_url"`
	// OptimizeForLocal enables smaller prompts / chunking and stricter local timeouts.
	OptimizeForLocal bool `mapstructure:"optimize_for_local" json:"optimize_for_local"`
	// MinFixConfidence is the minimum AI confidence (0.0-1.0) required to queue
	// a generated fix. Set to 0 to keep all fixes, including low-confidence ones.
	MinFixConfidence float64 `mapstructure:"min_fix_confidence" json:"min_fix_confidence"`
}

// GitConfig holds credentials for each supported git hosting platform.
type GitConfig struct {
	GitHub []GitHubConfig `mapstructure:"github" json:"github"`
	GitLab []GitLabConfig `mapstructure:"gitlab" json:"gitlab"`
	Azure  []AzureConfig  `mapstructure:"azure"  json:"azure"`
}

// GitHubConfig holds credentials for a single GitHub instance.
type GitHubConfig struct {
	Token string `mapstructure:"token" json:"token"`
	// Host allows enterprise GitHub (e.g. github.mycompany.com).
	Host string `mapstructure:"host"  json:"host"`
}

// GitLabConfig holds credentials for a single GitLab instance.
type GitLabConfig struct {
	Token string `mapstructure:"token" json:"token"`
	Host  string `mapstructure:"host"  json:"host"`
}

// AzureConfig holds credentials for an Azure DevOps organisation.
type AzureConfig struct {
	Token string `mapstructure:"token" json:"token"`
	Org   string `mapstructure:"org"   json:"org"`
	Host  string `mapstructure:"host"  json:"host"`
}

// AgentConfig controls the autonomous agent behaviour.
type AgentConfig struct {
	// Mode is "triage" (default), "semi", or "auto".
	Mode string `mapstructure:"mode"    json:"mode"`
	// Workers is the number of parallel scan goroutines.
	Workers int `mapstructure:"workers" json:"workers"`
	// ScanTargets specifies discovery sources: own_repos, watchlist, cve_search, all.
	ScanTargets []string `mapstructure:"scan_targets" json:"scan_targets"`
	// Watchlist is a list of "owner/repo" or "owner" entries to monitor.
	Watchlist []string `mapstructure:"watchlist"    json:"watchlist"`
	// Scanners lists which tools to run.
	Scanners []string `mapstructure:"scanners"     json:"scanners"`
}

// GatewayConfig controls the persistent gateway daemon.
type GatewayConfig struct {
	// Port is the localhost HTTP port the gateway listens on (default: 6080).
	Port int `mapstructure:"port" json:"port"`
}

// ToolsConfig controls where scanner binaries live.
type ToolsConfig struct {
	// BinDir is the directory where scanner tools are installed.
	BinDir string `mapstructure:"bin_dir"       json:"bin_dir"`
	// PreferDocker forces docker execution even when local binaries are present.
	PreferDocker bool `mapstructure:"prefer_docker" json:"prefer_docker"`
}
