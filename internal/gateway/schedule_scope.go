package gateway

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/CosmoTheDev/ctrlscan-agent/internal/agent"
)

type ScheduleScope struct {
	Targets       []string                `json:"targets,omitempty"`
	Mode          string                  `json:"mode,omitempty"`
	Repos         []agent.SelectedRepo    `json:"repos,omitempty"`
	Owners        []ScheduleOwnerSelector `json:"owners,omitempty"`
	OwnerPrefixes []ScheduleOwnerSelector `json:"owner_prefixes,omitempty"`
}

type ScheduleOwnerSelector struct {
	Provider string `json:"provider"`
	Host     string `json:"host,omitempty"`
	Owner    string `json:"owner"`
}

func parseScheduleScope(sched Schedule) (ScheduleScope, error) {
	if strings.TrimSpace(sched.ScopeJSON) != "" {
		return parseScheduleScopeJSON(sched.ScopeJSON)
	}
	return scheduleScopeFromLegacy(sched)
}

func parseScheduleScopeJSON(raw string) (ScheduleScope, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ScheduleScope{}, nil
	}
	var scope ScheduleScope
	if err := json.Unmarshal([]byte(raw), &scope); err != nil {
		return ScheduleScope{}, fmt.Errorf("invalid scope_json: %w", err)
	}
	scope.Mode = strings.TrimSpace(scope.Mode)
	if err := validateScanTargets(scope.Targets); err != nil {
		return ScheduleScope{}, err
	}
	if !isValidAgentMode(scope.Mode) {
		return ScheduleScope{}, fmt.Errorf("invalid schedule mode %q", scope.Mode)
	}
	if err := validateSelectedRepos(scope.Repos); err != nil {
		return ScheduleScope{}, err
	}
	if err := validateScheduleOwnerSelectors(scope.Owners, false); err != nil {
		return ScheduleScope{}, err
	}
	if err := validateScheduleOwnerSelectors(scope.OwnerPrefixes, true); err != nil {
		return ScheduleScope{}, err
	}
	return scope, nil
}

func validateScheduleOwnerSelectors(in []ScheduleOwnerSelector, allowPrefix bool) error {
	seen := map[string]struct{}{}
	for i, s := range in {
		p := strings.TrimSpace(strings.ToLower(s.Provider))
		h := strings.TrimSpace(strings.ToLower(s.Host))
		o := strings.TrimSpace(s.Owner)
		if p == "" || o == "" {
			return fmt.Errorf("owner selector %d must include provider and owner", i)
		}
		if p != "github" && p != "gitlab" && p != "azure" {
			return fmt.Errorf("owner selector %d has unsupported provider %q", i, s.Provider)
		}
		if !allowPrefix && strings.Contains(o, "*") {
			return fmt.Errorf("owner selector %d owner must be exact (no wildcard)", i)
		}
		key := p + "|" + h + "|" + strings.ToLower(o)
		if _, ok := seen[key]; ok {
			return fmt.Errorf("duplicate owner selector %d", i)
		}
		seen[key] = struct{}{}
	}
	return nil
}

func scheduleScopeFromLegacy(sched Schedule) (ScheduleScope, error) {
	targets, err := parseScheduleTargetsJSON(sched.Targets)
	if err != nil {
		return ScheduleScope{}, err
	}
	repos, err := parseScheduleSelectedReposJSON(sched.SelectedRepos)
	if err != nil {
		return ScheduleScope{}, err
	}
	mode := strings.TrimSpace(sched.Mode)
	if !isValidAgentMode(mode) {
		return ScheduleScope{}, fmt.Errorf("invalid schedule mode %q", sched.Mode)
	}
	return ScheduleScope{
		Targets: targets,
		Mode:    mode,
		Repos:   repos,
	}, nil
}

func applyScopeToScheduleFields(s *Schedule, scope ScheduleScope) error {
	scope.Mode = strings.TrimSpace(scope.Mode)
	if err := validateScanTargets(scope.Targets); err != nil {
		return err
	}
	if !isValidAgentMode(scope.Mode) {
		return fmt.Errorf("invalid schedule mode %q", scope.Mode)
	}
	if err := validateSelectedRepos(scope.Repos); err != nil {
		return err
	}
	if err := validateScheduleOwnerSelectors(scope.Owners, false); err != nil {
		return err
	}
	if err := validateScheduleOwnerSelectors(scope.OwnerPrefixes, true); err != nil {
		return err
	}

	scopeJSONBytes, err := json.Marshal(scope)
	if err != nil {
		return fmt.Errorf("marshal scope_json: %w", err)
	}
	reposJSONBytes, err := json.Marshal(scope.Repos)
	if err != nil {
		return fmt.Errorf("marshal selected_repos: %w", err)
	}
	targetsJSONBytes, err := json.Marshal(scope.Targets)
	if err != nil {
		return fmt.Errorf("marshal targets: %w", err)
	}

	s.ScopeJSON = string(scopeJSONBytes)
	s.Targets = string(targetsJSONBytes)
	s.SelectedRepos = string(reposJSONBytes)
	s.Mode = scope.Mode
	return nil
}
