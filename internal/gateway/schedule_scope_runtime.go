package gateway

import (
	"context"
	"fmt"
	"strings"

	"github.com/CosmoTheDev/ctrlscan-agent/internal/agent"
	"github.com/CosmoTheDev/ctrlscan-agent/internal/repository"
	"github.com/CosmoTheDev/ctrlscan-agent/models"
)

func (gw *Gateway) resolveScheduleSelectedRepos(ctx context.Context, scope ScheduleScope) ([]agent.SelectedRepo, error) {
	hasDynamicFilters := len(scope.Owners) > 0 || len(scope.OwnerPrefixes) > 0
	if !hasDynamicFilters {
		return append([]agent.SelectedRepo(nil), scope.Repos...), nil
	}

	providers := gw.orch.RepoProvidersForPreview()
	reposByKey := map[string]agent.SelectedRepo{}
	for _, r := range scope.Repos {
		reposByKey[selectedRepoKey(r)] = r
	}

	for _, p := range providers {
		seenPageKeys := map[string]struct{}{}
		pageChanged := true
		for page := 1; page <= 100 && pageChanged; page++ {
			pageChanged = false
			repos, err := p.ListRepos(ctx, repository.ListReposOptions{
				PerPage:    100,
				Page:       page,
				Visibility: "all",
			})
			if err != nil {
				return nil, fmt.Errorf("listing repos for %s (page %d): %w", p.Name(), page, err)
			}
			if len(repos) == 0 {
				break
			}
			for _, repo := range repos {
				pageKey := strings.ToLower(repo.Provider + "|" + repo.Host + "|" + repo.Owner + "|" + repo.Name)
				if _, seen := seenPageKeys[pageKey]; !seen {
					seenPageKeys[pageKey] = struct{}{}
					pageChanged = true
				}
				if !repoMatchesScheduleScope(repo, scope) {
					continue
				}
				sel := agent.SelectedRepo{
					Provider: repo.Provider,
					Host:     repo.Host,
					Owner:    repo.Owner,
					Name:     repo.Name,
				}
				reposByKey[selectedRepoKey(sel)] = sel
			}
			if len(repos) < 100 {
				break
			}
		}
	}

	out := make([]agent.SelectedRepo, 0, len(reposByKey))
	for _, r := range reposByKey {
		out = append(out, r)
	}
	if err := validateSelectedRepos(out); err != nil {
		return nil, err
	}
	return out, nil
}

func repoMatchesScheduleScope(repo models.Repo, scope ScheduleScope) bool {
	for _, s := range scope.Owners {
		if ownerSelectorMatchesRepo(s, repo, false) {
			return true
		}
	}
	for _, s := range scope.OwnerPrefixes {
		if ownerSelectorMatchesRepo(s, repo, true) {
			return true
		}
	}
	return false
}

func ownerSelectorMatchesRepo(sel ScheduleOwnerSelector, repo models.Repo, prefix bool) bool {
	if !strings.EqualFold(strings.TrimSpace(sel.Provider), strings.TrimSpace(repo.Provider)) {
		return false
	}
	if strings.TrimSpace(sel.Host) != "" && !strings.EqualFold(strings.TrimSpace(sel.Host), strings.TrimSpace(repo.Host)) {
		return false
	}
	wantOwner := strings.ToLower(strings.TrimSpace(sel.Owner))
	gotOwner := strings.ToLower(strings.TrimSpace(repo.Owner))
	if !prefix {
		return wantOwner == gotOwner
	}
	return gotOwner == wantOwner || strings.HasPrefix(gotOwner, strings.TrimSuffix(wantOwner, "/")+"/")
}

func selectedRepoKey(r agent.SelectedRepo) string {
	return strings.ToLower(strings.TrimSpace(r.Provider)) + "|" +
		strings.ToLower(strings.TrimSpace(r.Host)) + "|" +
		strings.ToLower(strings.TrimSpace(r.Owner)) + "|" +
		strings.ToLower(strings.TrimSpace(r.Name))
}
