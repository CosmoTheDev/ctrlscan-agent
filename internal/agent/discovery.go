package agent

import (
	"context"
	"log/slog"

	"github.com/CosmoTheDev/ctrlscan-agent/internal/config"
	"github.com/CosmoTheDev/ctrlscan-agent/internal/database"
	"github.com/CosmoTheDev/ctrlscan-agent/internal/repository"
)

// DiscoveryAgent finds repositories to scan and feeds them into the work queue.
// It supports multiple discovery strategies configured via agent.scan_targets.
type DiscoveryAgent struct {
	cfg       *config.Config
	db        database.DB
	providers []repository.RepoProvider
}

// NewDiscoveryAgent creates a DiscoveryAgent.
func NewDiscoveryAgent(cfg *config.Config, db database.DB, providers []repository.RepoProvider) *DiscoveryAgent {
	return &DiscoveryAgent{cfg: cfg, db: db, providers: providers}
}

// RunOnce performs a single discovery sweep and returns. The orchestrator is
// responsible for looping and triggering additional sweeps.
func (d *DiscoveryAgent) RunOnce(ctx context.Context, out chan<- repoJob) {
	d.discover(ctx, out)
}

func (d *DiscoveryAgent) discover(ctx context.Context, out chan<- repoJob) {
	targets := d.cfg.Agent.ScanTargets
	if len(targets) == 0 {
		targets = []string{"own_repos"}
	}

	slog.Info("Discovery sweep starting", "targets", targets)

	for _, target := range targets {
		if ctx.Err() != nil {
			return
		}
		switch target {
		case "own_repos":
			d.discoverOwnRepos(ctx, out)
		case "watchlist":
			d.discoverWatchlist(ctx, out)
		case "cve_search":
			d.discoverCVETargets(ctx, out)
		case "all_accessible":
			d.discoverAllAccessible(ctx, out)
		case "advisory_feed":
			if err := d.runAdvisoryFeedDiscovery(ctx, out); err != nil {
				slog.Warn("discovery: advisory feed failed", "error", err)
			}
		default:
			slog.Warn("Unknown scan target", "target", target)
		}
	}

	slog.Info("Discovery sweep complete")
}

func (d *DiscoveryAgent) discoverOwnRepos(ctx context.Context, out chan<- repoJob) {
	for _, p := range d.providers {
		repos, err := p.ListRepos(ctx, repository.ListReposOptions{
			PerPage:    100,
			Visibility: "all",
		})
		if err != nil {
			slog.Warn("Failed to list repos", "provider", p.Name(), "error", err)
			continue
		}
		slog.Info("Discovered repos", "provider", p.Name(), "count", len(repos))
		for _, r := range repos {
			select {
			case out <- repoJob{
				Provider: p,
				Owner:    r.Owner,
				Name:     r.Name,
				CloneURL: r.CloneURL,
				Branch:   r.DefaultBranch,
			}:
			case <-ctx.Done():
				return
			}
		}
	}
}

func (d *DiscoveryAgent) discoverWatchlist(ctx context.Context, out chan<- repoJob) {
	for _, entry := range d.cfg.Agent.Watchlist {
		if ctx.Err() != nil {
			return
		}
		// entry is "owner/repo" or "owner" (org)
		for _, p := range d.providers {
			repos, err := p.SearchRepos(ctx, entry)
			if err != nil {
				slog.Warn("Watchlist search failed", "entry", entry, "provider", p.Name(), "error", err)
				continue
			}
			for _, r := range repos {
				select {
				case out <- repoJob{
					Provider: p,
					Owner:    r.Owner,
					Name:     r.Name,
					CloneURL: r.CloneURL,
					Branch:   r.DefaultBranch,
				}:
				case <-ctx.Done():
					return
				}
			}
		}
	}
}

func (d *DiscoveryAgent) discoverCVETargets(ctx context.Context, out chan<- repoJob) {
	// Query the GitHub Advisory Database (GHSA) for recent CVEs and search
	// for repos that use the affected packages.
	// Implementation: search GitHub for repos with specific dependency files
	// containing affected packages.
	for _, p := range d.providers {
		// Search for repos with recent vulnerability-relevant topics.
		queries := []string{
			"topic:security language:Go",
			"topic:security language:JavaScript stars:>100",
			"topic:security language:Python stars:>100",
		}
		for _, q := range queries {
			if ctx.Err() != nil {
				return
			}
			repos, err := p.SearchRepos(ctx, q)
			if err != nil {
				slog.Warn("CVE search failed", "query", q, "provider", p.Name(), "error", err)
				continue
			}
			for _, r := range repos {
				select {
				case out <- repoJob{
					Provider: p,
					Owner:    r.Owner,
					Name:     r.Name,
					CloneURL: r.CloneURL,
					Branch:   r.DefaultBranch,
				}:
				case <-ctx.Done():
					return
				}
			}
		}
	}
}

func (d *DiscoveryAgent) discoverAllAccessible(ctx context.Context, out chan<- repoJob) {
	for _, p := range d.providers {
		page := 1
		for {
			if ctx.Err() != nil {
				return
			}
			repos, err := p.ListRepos(ctx, repository.ListReposOptions{
				PerPage:     100,
				Page:        page,
				Visibility:  "all",
				Affiliation: "owner,collaborator,organization_member",
			})
			if err != nil {
				slog.Warn("Failed to list all accessible repos", "provider", p.Name(), "error", err)
				break
			}
			if len(repos) == 0 {
				break
			}
			for _, r := range repos {
				select {
				case out <- repoJob{
					Provider: p,
					Owner:    r.Owner,
					Name:     r.Name,
					CloneURL: r.CloneURL,
					Branch:   r.DefaultBranch,
				}:
				case <-ctx.Done():
					return
				}
			}
			page++
		}
	}
}
