package config

// Config is the root configuration structure for ctrlscan.
// Serialised to ~/.ctrlscan/config.json.
type Config struct {
	Database     DatabaseConfig     `mapstructure:"database"     json:"database"`
	AI           AIConfig           `mapstructure:"ai"           json:"ai"`
	Git          GitConfig          `mapstructure:"git"          json:"git"`
	Agent        AgentConfig        `mapstructure:"agent"        json:"agent"`
	Tools        ToolsConfig        `mapstructure:"tools"        json:"tools"`
	Gateway      GatewayConfig      `mapstructure:"gateway"      json:"gateway"`
	ControlPlane ControlPlaneConfig `mapstructure:"controlplane" json:"controlplane"`
	Notify       NotifyConfig       `mapstructure:"notify"       json:"notify"`
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
	// Provider is "openai" (default), "ollama", "anthropic", or "zai".
	Provider  string `mapstructure:"provider"       json:"provider"`
	OpenAIKey string `mapstructure:"openai_api_key" json:"openai_api_key"`
	// AnthropicKey is the API key for Anthropic Claude (provider = "anthropic").
	AnthropicKey string `mapstructure:"anthropic_api_key" json:"anthropic_api_key"`
	// ZAIKey is the API key for Z.AI (provider = "zai").
	ZAIKey string `mapstructure:"zai_api_key" json:"zai_api_key"`
	Model  string `mapstructure:"model"             json:"model"`
	// BaseURL overrides the API endpoint (useful for Azure OpenAI or proxies).
	BaseURL string `mapstructure:"base_url" json:"base_url"`
	// OllamaURL is used when Provider == "ollama".
	OllamaURL string `mapstructure:"ollama_url" json:"ollama_url"`
	// OptimizeForLocal enables smaller prompts / chunking and stricter local timeouts.
	OptimizeForLocal bool `mapstructure:"optimize_for_local" json:"optimize_for_local"`
	// MinFixConfidence is the minimum AI confidence (0.0-1.0) required to queue
	// a generated fix. Set to 0 to keep all fixes, including low-confidence ones.
	MinFixConfidence float64 `mapstructure:"min_fix_confidence" json:"min_fix_confidence"`
	// MinFixConfidenceBySeverity allows setting per-severity confidence thresholds.
	// Format: "critical=0.7,high=0.5,medium=0.3,low=0.1"
	// If not set, defaults: critical=0.6, high=0.4, medium=0.2, low=0.1
	MinFixConfidenceBySeverity string `mapstructure:"min_fix_confidence_by_severity" json:"min_fix_confidence_by_severity"`
	// Fallback is an ordered list of providers to try if the primary fails.
	// Each entry follows the same format as Provider: "openai", "anthropic", "ollama", "none"
	Fallback []string `mapstructure:"fallback" json:"fallback"`
	// AIDebug controls AI provider debug logging. Valid values: "all", "prompts", "none".
	// Also accepts legacy provider-specific env vars (CTRLSCAN_OPENAI_DEBUG, etc.).
	AIDebug string `mapstructure:"ai_debug" json:"ai_debug"`
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

// ControlPlaneConfig holds optional integration settings for ctrlscan.com.
// Everything here is opt-in — Enabled is false by default.
// Users register at ctrlscan.com to obtain an API key, then run:
//
//	ctrlscan register --key ctrlscan_xxxxx
//
// Only repos in SubmitAllowlist are ever considered for submission, and each
// repo is verified to be publicly visible before any data is sent.
type ControlPlaneConfig struct {
	// Enabled must be explicitly set to true before any data is sent to the control plane.
	Enabled bool `mapstructure:"enabled" json:"enabled"`
	// URL is the base URL of the ctrlscan control plane (default: https://ctrlscan.com).
	URL string `mapstructure:"url" json:"url"`
	// APIKey is the Bearer token issued by ctrlscan.com after registration.
	// Store this carefully — it authenticates this agent to the control plane.
	APIKey string `mapstructure:"api_key" json:"api_key"` // #nosec G101 -- config field, not a hardcoded credential
	// AgentKey is the stable public identifier for this agent on ctrlscan.com.
	AgentKey string `mapstructure:"agent_key" json:"agent_key"`
	// DisplayName is the human-readable name shown on ctrlscan.com.
	DisplayName string `mapstructure:"display_name" json:"display_name"`
	// SubmitAllowlist is a list of repos or orgs the agent is permitted to submit
	// data for. Entries may be "owner/repo" (exact) or "owner" (entire org).
	// When empty, no submissions are made even if Enabled is true.
	SubmitAllowlist []string `mapstructure:"submit_allowlist" json:"submit_allowlist"`
	// AutoVerifyPublic controls whether the agent checks repo visibility via the
	// provider's public API before submitting. Strongly recommended; defaults true.
	AutoVerifyPublic bool `mapstructure:"auto_verify_public" json:"auto_verify_public"`
}

// ToolsConfig controls where scanner binaries live.
type ToolsConfig struct {
	// BinDir is the directory where scanner tools are installed.
	BinDir string `mapstructure:"bin_dir"       json:"bin_dir"`
	// PreferDocker forces docker execution even when local binaries are present.
	PreferDocker bool `mapstructure:"prefer_docker" json:"prefer_docker"`
}

// NotifyConfig controls outbound push notifications.
type NotifyConfig struct {
	Slack    SlackNotifyConfig    `mapstructure:"slack"        json:"slack"`
	Telegram TelegramNotifyConfig `mapstructure:"telegram"     json:"telegram"`
	Email    EmailNotifyConfig    `mapstructure:"email"        json:"email"`
	Webhook  WebhookNotifyConfig  `mapstructure:"webhook"      json:"webhook"`
	// MinSeverity controls which findings trigger notifications.
	// Valid values: "critical", "high", "medium", "low", "" (all).
	MinSeverity string `mapstructure:"min_severity" json:"min_severity"`
	// Events is the explicit list of event types to notify on.
	// Empty means use defaults: critical_finding, pr_opened, sweep_failed.
	Events []string `mapstructure:"events" json:"events"`
}

// SlackNotifyConfig holds the Slack incoming webhook URL.
type SlackNotifyConfig struct {
	WebhookURL string `mapstructure:"webhook_url" json:"webhook_url"`
}

// TelegramNotifyConfig holds Telegram Bot API credentials.
type TelegramNotifyConfig struct {
	BotToken string `mapstructure:"bot_token" json:"bot_token"`
	ChatID   string `mapstructure:"chat_id"   json:"chat_id"`
}

// EmailNotifyConfig holds SMTP settings for email notifications.
type EmailNotifyConfig struct {
	SMTPHost string `mapstructure:"smtp_host" json:"smtp_host"`
	SMTPPort int    `mapstructure:"smtp_port" json:"smtp_port"`
	Username string `mapstructure:"username"  json:"username"`
	Password string `mapstructure:"password"  json:"password"` // #nosec G101 -- config field, not a hardcoded credential
	From     string `mapstructure:"from"      json:"from"`
	To       string `mapstructure:"to"        json:"to"`
	UseTLS   bool   `mapstructure:"use_tls"   json:"use_tls"`
}

// WebhookNotifyConfig holds generic HTTP webhook settings.
type WebhookNotifyConfig struct {
	URL    string `mapstructure:"url"    json:"url"`
	Secret string `mapstructure:"secret" json:"secret"` // HMAC-SHA256 signing key // #nosec G101 -- config field, not a hardcoded credential
}
