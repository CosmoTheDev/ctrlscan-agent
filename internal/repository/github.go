package repository

import (
	"context"
	"fmt"
	"net/url"

	"github.com/CosmoTheDev/ctrlscan-agent/internal/config"
	"github.com/CosmoTheDev/ctrlscan-agent/models"
	gogithub "github.com/google/go-github/v68/github"
	"golang.org/x/oauth2"
)

// GitHubProvider implements RepoProvider for GitHub and GitHub Enterprise.
type GitHubProvider struct {
	client *gogithub.Client
	token  string
	host   string
}

// NewGitHub creates a GitHubProvider from the given configuration.
func NewGitHub(cfg config.GitHubConfig) (*GitHubProvider, error) {
	ts := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: cfg.Token})
	tc := oauth2.NewClient(context.Background(), ts)
	client := gogithub.NewClient(tc)

	// Support GitHub Enterprise by overriding the base URL.
	if cfg.Host != "" && cfg.Host != "github.com" {
		base := fmt.Sprintf("https://%s/api/v3/", cfg.Host)
		upload := fmt.Sprintf("https://%s/api/uploads/", cfg.Host)
		var err error
		client, err = client.WithEnterpriseURLs(base, upload)
		if err != nil {
			return nil, fmt.Errorf("configuring GitHub enterprise URLs: %w", err)
		}
	}

	return &GitHubProvider{client: client, token: cfg.Token, host: cfg.Host}, nil
}

func (g *GitHubProvider) Name() string     { return "github" }
func (g *GitHubProvider) AuthToken() string { return g.token }

func (g *GitHubProvider) ListRepos(ctx context.Context, opts ListReposOptions) ([]models.Repo, error) {
	perPage := opts.PerPage
	if perPage == 0 {
		perPage = 100
	}
	page := opts.Page
	if page == 0 {
		page = 1
	}

	ghRepos, _, err := g.client.Repositories.List(ctx, "", &gogithub.RepositoryListOptions{
		Visibility:  opts.Visibility,
		Affiliation: opts.Affiliation,
		ListOptions: gogithub.ListOptions{PerPage: perPage, Page: page},
	})
	if err != nil {
		return nil, fmt.Errorf("listing GitHub repos: %w", err)
	}

	return g.convertRepos(ghRepos), nil
}

func (g *GitHubProvider) GetRepo(ctx context.Context, owner, name string) (*models.Repo, error) {
	r, _, err := g.client.Repositories.Get(ctx, owner, name)
	if err != nil {
		return nil, fmt.Errorf("getting GitHub repo %s/%s: %w", owner, name, err)
	}
	repos := g.convertRepos([]*gogithub.Repository{r})
	return &repos[0], nil
}

func (g *GitHubProvider) ForkRepo(ctx context.Context, owner, name string) (*models.Repo, error) {
	fork, _, err := g.client.Repositories.CreateFork(ctx, owner, name, nil)
	if err != nil {
		return nil, fmt.Errorf("forking %s/%s: %w", owner, name, err)
	}
	repos := g.convertRepos([]*gogithub.Repository{fork})
	return &repos[0], nil
}

func (g *GitHubProvider) CreatePR(ctx context.Context, opts CreatePROptions) (*models.PullRequest, error) {
	pr, _, err := g.client.PullRequests.Create(ctx, opts.Owner, opts.Repo, &gogithub.NewPullRequest{
		Title:               gogithub.Ptr(opts.Title),
		Body:                gogithub.Ptr(opts.Body),
		Head:                gogithub.Ptr(opts.HeadBranch),
		Base:                gogithub.Ptr(opts.BaseBranch),
		Draft:               gogithub.Ptr(opts.Draft),
		MaintainerCanModify: gogithub.Ptr(true),
	})
	if err != nil {
		return nil, fmt.Errorf("creating PR on %s/%s: %w", opts.Owner, opts.Repo, err)
	}
	return &models.PullRequest{
		ID:         pr.GetID(),
		Number:     pr.GetNumber(),
		Title:      pr.GetTitle(),
		Body:       pr.GetBody(),
		URL:        pr.GetHTMLURL(),
		State:      pr.GetState(),
		HeadBranch: pr.GetHead().GetRef(),
		BaseBranch: pr.GetBase().GetRef(),
		CreatedAt:  pr.GetCreatedAt().Time,
	}, nil
}

func (g *GitHubProvider) SearchRepos(ctx context.Context, query string) ([]models.Repo, error) {
	result, _, err := g.client.Search.Repositories(ctx, query, &gogithub.SearchOptions{
		ListOptions: gogithub.ListOptions{PerPage: 100},
	})
	if err != nil {
		return nil, fmt.Errorf("searching GitHub repos: %w", err)
	}
	return g.convertRepos(result.Repositories), nil
}

func (g *GitHubProvider) convertRepos(ghRepos []*gogithub.Repository) []models.Repo {
	repos := make([]models.Repo, 0, len(ghRepos))
	for _, r := range ghRepos {
		if r == nil {
			continue
		}
		cloneURL := r.GetCloneURL()
		if cloneURL == "" {
			cloneURL = r.GetSSHURL()
		}
		host := g.host
		if host == "" {
			host = "github.com"
		}
		// Extract host from clone URL if needed.
		if u, err := url.Parse(cloneURL); err == nil && u.Host != "" {
			host = u.Host
		}
		repos = append(repos, models.Repo{
			ID:            fmt.Sprintf("%d", r.GetID()),
			Provider:      "github",
			Host:          host,
			Owner:         r.GetOwner().GetLogin(),
			Name:          r.GetName(),
			FullName:      r.GetFullName(),
			CloneURL:      cloneURL,
			HTMLURL:       r.GetHTMLURL(),
			DefaultBranch: r.GetDefaultBranch(),
			Private:       r.GetPrivate(),
			Fork:          r.GetFork(),
			Language:      r.GetLanguage(),
			Description:   r.GetDescription(),
			Stars:         r.GetStargazersCount(),
			LastPushedAt:  r.GetPushedAt().Time,
		})
	}
	return repos
}
