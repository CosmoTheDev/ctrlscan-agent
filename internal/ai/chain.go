package ai

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/CosmoTheDev/ctrlscan-agent/internal/config"
	"github.com/CosmoTheDev/ctrlscan-agent/models"
)

const (
	failureThreshold = 3
	resetTimeout     = 2 * time.Minute
)

type circuitBreaker struct {
	mu           sync.Mutex
	failures     int
	lastFailedAt time.Time
	state        string
}

func newCircuitBreaker() *circuitBreaker {
	return &circuitBreaker{
		state: "closed",
	}
}

func (cb *circuitBreaker) allow() bool {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	if cb.state == "closed" {
		return true
	}

	if cb.state == "open" {
		if time.Since(cb.lastFailedAt) >= resetTimeout {
			cb.state = "half-open"
			return true
		}
		return false
	}

	return true
}

func (cb *circuitBreaker) recordSuccess() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	cb.failures = 0
	cb.state = "closed"
}

func (cb *circuitBreaker) recordFailure() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	cb.failures++
	cb.lastFailedAt = time.Now()

	if cb.failures >= failureThreshold {
		cb.state = "open"
		slog.Debug("ai: circuit breaker opened", "failures", cb.failures)
	}
}

type ChainProvider struct {
	providers []AIProvider
	breakers  map[string]*circuitBreaker
	mu        sync.RWMutex
	current   string
	fallback  bool
}

func NewChain(providers []AIProvider) *ChainProvider {
	breakers := make(map[string]*circuitBreaker)
	for _, p := range providers {
		breakers[p.Name()] = newCircuitBreaker()
	}

	current := ""
	if len(providers) > 0 {
		current = providers[0].Name()
	}

	return &ChainProvider{
		providers: providers,
		breakers:  breakers,
		current:   current,
	}
}

func (c *ChainProvider) Name() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return "chain"
}

func (c *ChainProvider) IsAvailable(ctx context.Context) bool {
	for _, p := range c.providers {
		if p.IsAvailable(ctx) {
			return true
		}
	}
	return false
}

func (c *ChainProvider) TriageFindings(ctx context.Context, findings []models.FindingSummary) (*TriageResult, error) {
	var lastErr error
	var usedFallback bool

	for _, p := range c.providers {
		if !c.breakers[p.Name()].allow() {
			slog.Debug("ai: circuit open, skipping provider", "provider", p.Name())
			continue
		}

		result, err := p.TriageFindings(ctx, findings)
		if err == nil {
			c.breakers[p.Name()].recordSuccess()
			c.mu.Lock()
			c.current = p.Name()
			c.fallback = usedFallback
			c.mu.Unlock()

			if usedFallback {
				slog.Info("ai: provider succeeded after failover", "provider", p.Name())
			}
			return result, nil
		}

		if isRetriableError(err) {
			c.breakers[p.Name()].recordFailure()
		} else if isAuthError(err) {
			c.breakers[p.Name()].recordFailure()
			cb := c.breakers[p.Name()]
			cb.mu.Lock()
			cb.state = "open"
			cb.mu.Unlock()
			slog.Warn("ai: auth error, opening circuit", "provider", p.Name(), "error", err)
		}

		slog.Warn("ai: provider failed, trying next", "provider", p.Name(), "error", err)
		lastErr = err
		usedFallback = true
	}

	return nil, fmt.Errorf("all AI providers failed; last error: %w", lastErr)
}

func (c *ChainProvider) GenerateFix(ctx context.Context, req FixRequest) (*FixResult, error) {
	var lastErr error
	var usedFallback bool

	for _, p := range c.providers {
		if !c.breakers[p.Name()].allow() {
			slog.Debug("ai: circuit open, skipping provider", "provider", p.Name())
			continue
		}

		result, err := p.GenerateFix(ctx, req)
		if err == nil {
			c.breakers[p.Name()].recordSuccess()
			c.mu.Lock()
			c.current = p.Name()
			c.fallback = usedFallback
			c.mu.Unlock()

			if usedFallback {
				slog.Info("ai: provider succeeded after failover", "provider", p.Name())
			}
			return result, nil
		}

		if isRetriableError(err) {
			c.breakers[p.Name()].recordFailure()
		} else if isAuthError(err) {
			c.breakers[p.Name()].recordFailure()
			cb := c.breakers[p.Name()]
			cb.mu.Lock()
			cb.state = "open"
			cb.mu.Unlock()
			slog.Warn("ai: auth error, opening circuit", "provider", p.Name(), "error", err)
		}

		slog.Warn("ai: provider failed, trying next", "provider", p.Name(), "error", err)
		lastErr = err
		usedFallback = true
	}

	return nil, fmt.Errorf("all AI providers failed; last error: %w", lastErr)
}

func (c *ChainProvider) GeneratePRDescription(ctx context.Context, fixes []FixResult) (*PRDescription, error) {
	var lastErr error
	var usedFallback bool

	for _, p := range c.providers {
		if !c.breakers[p.Name()].allow() {
			slog.Debug("ai: circuit open, skipping provider", "provider", p.Name())
			continue
		}

		result, err := p.GeneratePRDescription(ctx, fixes)
		if err == nil {
			c.breakers[p.Name()].recordSuccess()
			c.mu.Lock()
			c.current = p.Name()
			c.fallback = usedFallback
			c.mu.Unlock()

			if usedFallback {
				slog.Info("ai: provider succeeded after failover", "provider", p.Name())
			}
			return result, nil
		}

		if isRetriableError(err) {
			c.breakers[p.Name()].recordFailure()
		} else if isAuthError(err) {
			c.breakers[p.Name()].recordFailure()
			cb := c.breakers[p.Name()]
			cb.mu.Lock()
			cb.state = "open"
			cb.mu.Unlock()
			slog.Warn("ai: auth error, opening circuit", "provider", p.Name(), "error", err)
		}

		slog.Warn("ai: provider failed, trying next", "provider", p.Name(), "error", err)
		lastErr = err
		usedFallback = true
	}

	return nil, fmt.Errorf("all AI providers failed; last error: %w", lastErr)
}

func isRetriableError(err error) bool {
	if err == nil {
		return false
	}

	errStr := err.Error()
	switch {
	case strings.Contains(errStr, "status 429"):
		return true
	case strings.Contains(errStr, "status 5"):
		return true
	case strings.Contains(errStr, "timeout") || strings.Contains(errStr, "connection refused"):
		return true
	case strings.Contains(errStr, "status 4"):
		return false
	case strings.Contains(errStr, "status 401") || strings.Contains(errStr, "status 403"):
		return false
	default:
		return true
	}
}

func isAuthError(err error) bool {
	if err == nil {
		return false
	}

	errStr := err.Error()
	return strings.Contains(errStr, "status 401") || strings.Contains(errStr, "status 403")
}

func (c *ChainProvider) CurrentProvider() (provider string, fallback bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.current, c.fallback
}

func newSingle(provider string, cfg config.AIConfig) (AIProvider, error) {
	switch provider {
	case "", "none":
		return &NoopProvider{}, nil
	case "openai":
		if cfg.OpenAIKey == "" {
			return &NoopProvider{}, nil
		}
		return NewOpenAI(cfg)
	case "ollama":
		return NewOllama(cfg)
	case "anthropic":
		if cfg.AnthropicKey == "" {
			return &NoopProvider{}, nil
		}
		return NewAnthropic(cfg), nil
	case "zai":
		if cfg.ZAIKey == "" {
			return &NoopProvider{}, nil
		}
		return NewZAI(cfg)
	default:
		return nil, fmt.Errorf("unsupported AI provider %q (supported: openai, ollama, anthropic, zai)", provider)
	}
}
