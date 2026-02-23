package repository

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/CosmoTheDev/ctrlscan-agent/internal/config"
	"github.com/CosmoTheDev/ctrlscan-agent/models"
)

// AzureDevOpsProvider implements RepoProvider for Azure DevOps.
// Uses the Azure DevOps REST API v7.1.
type AzureDevOpsProvider struct {
	token  string
	org    string
	host   string
	client *http.Client
}

// NewAzureDevOps creates an AzureDevOpsProvider.
func NewAzureDevOps(cfg config.AzureConfig) (*AzureDevOpsProvider, error) {
	if cfg.Org == "" {
		return nil, fmt.Errorf("azure DevOps organisation name is required")
	}
	host := cfg.Host
	if host == "" {
		host = "dev.azure.com"
	}
	return &AzureDevOpsProvider{
		token:  cfg.Token,
		org:    cfg.Org,
		host:   host,
		client: &http.Client{},
	}, nil
}

func (a *AzureDevOpsProvider) Name() string      { return "azure" }
func (a *AzureDevOpsProvider) AuthToken() string { return a.token }

func (a *AzureDevOpsProvider) baseURL() string {
	return fmt.Sprintf("https://%s/%s", a.host, a.org)
}

func (a *AzureDevOpsProvider) do(ctx context.Context, method, urlStr string, body io.Reader) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, method, urlStr, body)
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth("", a.token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := a.client.Do(req) // #nosec G704 -- URL is built from admin-supplied config, not user input
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("azure DevOps API error %d: %s", resp.StatusCode, string(data))
	}
	return data, nil
}

func (a *AzureDevOpsProvider) ListRepos(ctx context.Context, opts ListReposOptions) ([]models.Repo, error) {
	// Azure DevOps: list all projects, then list repos per project.
	projectsURL := fmt.Sprintf("%s/_apis/projects?api-version=7.1", a.baseURL())
	data, err := a.do(ctx, http.MethodGet, projectsURL, nil)
	if err != nil {
		return nil, fmt.Errorf("listing Azure DevOps projects: %w", err)
	}

	var projectsResp struct {
		Value []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"value"`
	}
	if err := json.Unmarshal(data, &projectsResp); err != nil {
		return nil, fmt.Errorf("parsing projects response: %w", err)
	}

	var allRepos []models.Repo
	for _, proj := range projectsResp.Value {
		reposURL := fmt.Sprintf("%s/%s/_apis/git/repositories?api-version=7.1", a.baseURL(), proj.Name)
		repoData, err := a.do(ctx, http.MethodGet, reposURL, nil)
		if err != nil {
			continue // non-fatal per project
		}
		var reposResp struct {
			Value []struct {
				ID            string `json:"id"`
				Name          string `json:"name"`
				RemoteURL     string `json:"remoteUrl"`
				WebURL        string `json:"webUrl"`
				DefaultBranch string `json:"defaultBranch"`
			} `json:"value"`
		}
		if err := json.Unmarshal(repoData, &reposResp); err != nil {
			continue
		}
		for _, r := range reposResp.Value {
			branch := r.DefaultBranch
			branch = strings.TrimPrefix(branch, "refs/heads/")
			allRepos = append(allRepos, models.Repo{
				ID:            r.ID,
				Provider:      "azure",
				Host:          a.host,
				Owner:         a.org + "/" + proj.Name,
				Name:          r.Name,
				FullName:      a.org + "/" + proj.Name + "/" + r.Name,
				CloneURL:      r.RemoteURL,
				HTMLURL:       r.WebURL,
				DefaultBranch: branch,
			})
		}
	}
	return allRepos, nil
}

func (a *AzureDevOpsProvider) GetRepo(ctx context.Context, owner, name string) (*models.Repo, error) {
	// owner format: "org/project"
	parts := strings.SplitN(owner, "/", 2)
	project := parts[len(parts)-1]
	urlStr := fmt.Sprintf("%s/%s/_apis/git/repositories/%s?api-version=7.1",
		a.baseURL(), project, name)
	data, err := a.do(ctx, http.MethodGet, urlStr, nil)
	if err != nil {
		return nil, fmt.Errorf("getting Azure DevOps repo: %w", err)
	}
	var r struct {
		ID            string `json:"id"`
		Name          string `json:"name"`
		RemoteURL     string `json:"remoteUrl"`
		WebURL        string `json:"webUrl"`
		DefaultBranch string `json:"defaultBranch"`
	}
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, err
	}
	branch := strings.TrimPrefix(r.DefaultBranch, "refs/heads/")
	return &models.Repo{
		ID:            r.ID,
		Provider:      "azure",
		Host:          a.host,
		Owner:         owner,
		Name:          r.Name,
		FullName:      owner + "/" + r.Name,
		CloneURL:      r.RemoteURL,
		HTMLURL:       r.WebURL,
		DefaultBranch: branch,
	}, nil
}

// ForkRepo is not supported in Azure DevOps; clone URL is returned as-is.
func (a *AzureDevOpsProvider) ForkRepo(ctx context.Context, owner, name string) (*models.Repo, error) {
	return nil, fmt.Errorf("forking is not supported in Azure DevOps; clone the repo directly")
}

func (a *AzureDevOpsProvider) CreatePR(ctx context.Context, opts CreatePROptions) (*models.PullRequest, error) {
	parts := strings.SplitN(opts.Owner, "/", 2)
	project := parts[len(parts)-1]

	body := fmt.Sprintf(`{
		"title": %q,
		"description": %q,
		"sourceRefName": "refs/heads/%s",
		"targetRefName": "refs/heads/%s"
	}`, opts.Title, opts.Body, opts.HeadBranch, opts.BaseBranch)

	urlStr := fmt.Sprintf("%s/%s/_apis/git/repositories/%s/pullrequests?api-version=7.1",
		a.baseURL(), project, opts.Repo)
	data, err := a.do(ctx, http.MethodPost, urlStr, strings.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("creating Azure DevOps PR: %w", err)
	}

	var pr struct {
		PullRequestID int    `json:"pullRequestId"`
		Title         string `json:"title"`
		Description   string `json:"description"`
		Status        string `json:"status"`
	}
	if err := json.Unmarshal(data, &pr); err != nil {
		return nil, err
	}

	prURL := fmt.Sprintf("https://%s/%s/%s/_git/%s/pullrequest/%d",
		a.host, a.org, project, opts.Repo, pr.PullRequestID)

	return &models.PullRequest{
		Number:     pr.PullRequestID,
		Title:      pr.Title,
		Body:       pr.Description,
		URL:        prURL,
		State:      pr.Status,
		HeadBranch: opts.HeadBranch,
		BaseBranch: opts.BaseBranch,
	}, nil
}

func (a *AzureDevOpsProvider) SearchRepos(ctx context.Context, query string) ([]models.Repo, error) {
	// Azure DevOps search requires the search extension; fall back to list + filter.
	all, err := a.ListRepos(ctx, ListReposOptions{})
	if err != nil {
		return nil, err
	}
	var results []models.Repo
	lower := strings.ToLower(query)
	for _, r := range all {
		if strings.Contains(strings.ToLower(r.Name), lower) ||
			strings.Contains(strings.ToLower(r.Description), lower) {
			results = append(results, r)
		}
	}
	return results, nil
}
