package repository

import (
	"context"
	"fmt"
	"strings"

	"github.com/CosmoTheDev/ctrlscan-agent/internal/config"
	"github.com/CosmoTheDev/ctrlscan-agent/models"
	gitlab "gitlab.com/gitlab-org/api/client-go"
)

// GitLabProvider implements RepoProvider for GitLab (cloud and self-hosted).
type GitLabProvider struct {
	client *gitlab.Client
	token  string
	host   string
}

// NewGitLab creates a GitLabProvider from the given configuration.
func NewGitLab(cfg config.GitLabConfig) (*GitLabProvider, error) {
	opts := []gitlab.ClientOptionFunc{}
	if cfg.Host != "" && cfg.Host != "gitlab.com" {
		base := fmt.Sprintf("https://%s/api/v4/", cfg.Host)
		opts = append(opts, gitlab.WithBaseURL(base))
	}

	client, err := gitlab.NewClient(cfg.Token, opts...)
	if err != nil {
		return nil, fmt.Errorf("creating GitLab client: %w", err)
	}

	return &GitLabProvider{client: client, token: cfg.Token, host: cfg.Host}, nil
}

func (g *GitLabProvider) Name() string      { return "gitlab" }
func (g *GitLabProvider) AuthToken() string { return g.token }

func (g *GitLabProvider) ListRepos(ctx context.Context, opts ListReposOptions) ([]models.Repo, error) {
	perPage := opts.PerPage
	if perPage == 0 {
		perPage = 100
	}
	page := opts.Page
	if page == 0 {
		page = 1
	}

	owned := true
	projects, _, err := g.client.Projects.ListProjects(&gitlab.ListProjectsOptions{
		Owned:       &owned,
		ListOptions: gitlab.ListOptions{PerPage: int64(perPage), Page: int64(page)},
	})
	if err != nil {
		return nil, fmt.Errorf("listing GitLab projects: %w", err)
	}

	return g.convertProjects(projects), nil
}

func (g *GitLabProvider) GetRepo(ctx context.Context, owner, name string) (*models.Repo, error) {
	nameWithNS := owner + "/" + name
	proj, _, err := g.client.Projects.GetProject(nameWithNS, nil)
	if err != nil {
		return nil, fmt.Errorf("getting GitLab project %s: %w", nameWithNS, err)
	}
	repos := g.convertProjects([]*gitlab.Project{proj})
	return &repos[0], nil
}

func (g *GitLabProvider) ForkRepo(ctx context.Context, owner, name string) (*models.Repo, error) {
	nameWithNS := owner + "/" + name
	fork, _, err := g.client.Projects.ForkProject(nameWithNS, &gitlab.ForkProjectOptions{})
	if err != nil {
		return nil, fmt.Errorf("forking GitLab project %s: %w", nameWithNS, err)
	}
	repos := g.convertProjects([]*gitlab.Project{fork})
	return &repos[0], nil
}

func (g *GitLabProvider) CreatePR(ctx context.Context, opts CreatePROptions) (*models.PullRequest, error) {
	nameWithNS := opts.Owner + "/" + opts.Repo
	mr, _, err := g.client.MergeRequests.CreateMergeRequest(nameWithNS, &gitlab.CreateMergeRequestOptions{
		Title:              &opts.Title,
		Description:        &opts.Body,
		SourceBranch:       &opts.HeadBranch,
		TargetBranch:       &opts.BaseBranch,
	})
	if err != nil {
		return nil, fmt.Errorf("creating MR on %s: %w", nameWithNS, err)
	}
	host := g.host
	if host == "" {
		host = "gitlab.com"
	}
	return &models.PullRequest{
		ID:         int64(mr.ID),
		Number:     int(mr.IID),
		Title:      mr.Title,
		Body:       mr.Description,
		URL:        fmt.Sprintf("https://%s/%s/-/merge_requests/%d", host, nameWithNS, mr.IID),
		State:      mr.State,
		HeadBranch: mr.SourceBranch,
		BaseBranch: mr.TargetBranch,
		CreatedAt:  *mr.CreatedAt,
	}, nil
}

func (g *GitLabProvider) SearchRepos(ctx context.Context, query string) ([]models.Repo, error) {
	projects, _, err := g.client.Projects.ListProjects(&gitlab.ListProjectsOptions{
		Search:      &query,
		ListOptions: gitlab.ListOptions{PerPage: 100},
	})
	if err != nil {
		return nil, fmt.Errorf("searching GitLab projects: %w", err)
	}
	return g.convertProjects(projects), nil
}

func (g *GitLabProvider) convertProjects(projects []*gitlab.Project) []models.Repo {
	repos := make([]models.Repo, 0, len(projects))
	host := g.host
	if host == "" {
		host = "gitlab.com"
	}
	for _, p := range projects {
		if p == nil {
			continue
		}
		parts := strings.SplitN(p.PathWithNamespace, "/", 2)
		owner, name := "", p.Name
		if len(parts) == 2 {
			owner = parts[0]
			name = parts[1]
		}
		repos = append(repos, models.Repo{
			ID:            fmt.Sprintf("%d", p.ID),
			Provider:      "gitlab",
			Host:          host,
			Owner:         owner,
			Name:          name,
			FullName:      p.PathWithNamespace,
			CloneURL:      p.HTTPURLToRepo,
			HTMLURL:       p.WebURL,
			DefaultBranch: p.DefaultBranch,
			Private:       p.Visibility == gitlab.PrivateVisibility,
			Fork:          p.ForkedFromProject != nil,
			Description:   p.Description,
			Stars:         int(p.StarCount),
		})
	}
	return repos
}
