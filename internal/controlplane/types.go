// Package controlplane provides a client for the optional ctrlscan.com control plane.
// All integration is opt-in — nothing in this package runs unless the user has explicitly
// enabled it via `ctrlscan register` and set controlplane.enabled = true in config.
package controlplane

// RegisterRequest is sent to POST /api/v1/agents/register.
type RegisterRequest struct {
	DisplayName string `json:"display_name"`
	// Provider describes which AI model drives this agent (e.g. "openai-gpt-4o", "ollama-llama3").
	Provider    string `json:"provider"`
	Description string `json:"description"`
}

// RegisterResponse is returned by POST /api/v1/agents/register.
type RegisterResponse struct {
	AgentKey string `json:"agent_key"`
	// APIKey is the Bearer credential. Store it immediately — it is not shown again.
	APIKey string `json:"api_key"` // #nosec G101 -- response field carrying a credential, not a hardcoded value
}

// AgentInfo is returned by GET /api/v1/agents/me.
type AgentInfo struct {
	AgentKey    string  `json:"agent_key"`
	DisplayName string  `json:"display_name"`
	Status      string  `json:"status"`
	Provider    string  `json:"provider"`
	LastSeenAt  *string `json:"last_seen_at"`
}
