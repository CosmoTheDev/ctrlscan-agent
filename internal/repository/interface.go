package repository

import (
	"context"
	"fmt"
	"strings"

	"github.com/CosmoTheDev/ctrlscan-agent/internal/config"
	"github.com/CosmoTheDev/ctrlscan-agent/models"
)

// RepoProvider abstracts operations against a Git hosting platform.
// Implementations: GitHub, GitLab, Azure DevOps.
type RepoProvider interface {
	// Name identifies the provider (e.g. "github", "gitlab", "azure").
	Name() string

	// ListRepos returns all repositories the authenticated user can access.
	ListRepos(ctx context.Context, opts ListReposOptions) ([]models.Repo, error)

	// GetRepo returns a single repository.
	GetRepo(ctx context.Context, owner, name string) (*models.Repo, error)

	// ForkRepo forks owner/name to the authenticated user's namespace.
	ForkRepo(ctx context.Context, owner, name string) (*models.Repo, error)

	// CreatePR opens a pull request on the upstream repository.
	CreatePR(ctx context.Context, opts CreatePROptions) (*models.PullRequest, error)

	// SearchRepos searches for repositories matching the query.
	SearchRepos(ctx context.Context, query string) ([]models.Repo, error)

	// AuthToken returns the credential used for git clone.
	AuthToken() string
}

// ListReposOptions controls pagination and filtering for ListRepos.
type ListReposOptions struct {
	PerPage    int
	Page       int
	Visibility string // "public" | "private" | "all"
	Affiliation string // "owner" | "collaborator" | "organization_member"
}

// CreatePROptions contains all fields needed to open a pull request.
type CreatePROptions struct {
	Owner      string
	Repo       string
	Title      string
	Body       string
	HeadBranch string // branch containing the fix
	BaseBranch string // target branch (usually "main" or "master")
	Draft      bool
}

// DetectProvider infers the hosting platform from a repository URL.
func DetectProvider(repoURL string) (string, error) {
	lower := strings.ToLower(repoURL)
	switch {
	case strings.Contains(lower, "github.com"):
		return "github", nil
	case strings.Contains(lower, "gitlab.com") || strings.Contains(lower, "gitlab."):
		return "gitlab", nil
	case strings.Contains(lower, "dev.azure.com") || strings.Contains(lower, "visualstudio.com"):
		return "azure", nil
	default:
		// Try to guess from common enterprise patterns.
		if strings.Contains(lower, "github.") {
			return "github", nil
		}
		return "", fmt.Errorf("cannot detect provider from URL %q; use --provider flag", repoURL)
	}
}

// TokenForProvider returns the auth token for the detected provider from cfg.
func TokenForProvider(cfg *config.Config, provider, repoURL string) string {
	switch provider {
	case "github":
		for _, g := range cfg.Git.GitHub {
			if g.Token != "" {
				return g.Token
			}
		}
	case "gitlab":
		for _, g := range cfg.Git.GitLab {
			if g.Token != "" {
				return g.Token
			}
		}
	case "azure":
		for _, a := range cfg.Git.Azure {
			if a.Token != "" {
				return a.Token
			}
		}
	}
	return ""
}

// New returns the appropriate RepoProvider for the given platform.
func New(provider string, cfg *config.Config) (RepoProvider, error) {
	switch provider {
	case "github":
		if len(cfg.Git.GitHub) == 0 || cfg.Git.GitHub[0].Token == "" {
			return nil, fmt.Errorf("no GitHub token configured; run 'ctrlscan onboard'")
		}
		return NewGitHub(cfg.Git.GitHub[0])
	case "gitlab":
		if len(cfg.Git.GitLab) == 0 || cfg.Git.GitLab[0].Token == "" {
			return nil, fmt.Errorf("no GitLab token configured; run 'ctrlscan onboard'")
		}
		return NewGitLab(cfg.Git.GitLab[0])
	case "azure":
		if len(cfg.Git.Azure) == 0 || cfg.Git.Azure[0].Token == "" {
			return nil, fmt.Errorf("no Azure DevOps token configured; run 'ctrlscan onboard'")
		}
		return NewAzureDevOps(cfg.Git.Azure[0])
	default:
		return nil, fmt.Errorf("unsupported provider %q", provider)
	}
}
