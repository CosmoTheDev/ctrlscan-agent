package repository

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	gogit "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	githttp "github.com/go-git/go-git/v5/plumbing/transport/http"
)

// CloneResult holds information about a completed clone operation.
type CloneResult struct {
	LocalPath string
	Owner     string
	Repo      string
	Branch    string
	Commit    string
	tmpDir    bool // true if we created a temp dir and should clean it
}

// CloneManager handles cloning repositories to temporary directories using go-git.
type CloneManager struct {
	binDir string
}

// NewCloneManager creates a CloneManager.
func NewCloneManager(binDir string) *CloneManager {
	return &CloneManager{binDir: binDir}
}

// Clone clones the repository at repoURL to a temporary directory.
// token is used for HTTPS authentication; branch is optional (defaults to HEAD).
func (cm *CloneManager) Clone(ctx context.Context, repoURL, token, branch string) (*CloneResult, error) {
	tmpDir, err := os.MkdirTemp("", "ctrlscan-clone-*")
	if err != nil {
		return nil, fmt.Errorf("creating temp directory: %w", err)
	}

	cloneOpts := &gogit.CloneOptions{
		URL:      repoURL,
		Depth:    1, // shallow clone for speed
		Progress: nil,
	}

	if token != "" {
		cloneOpts.Auth = &githttp.BasicAuth{
			Username: "ctrlscan",
			Password: token,
		}
	}

	if branch != "" {
		cloneOpts.ReferenceName = plumbing.NewBranchReferenceName(branch)
		cloneOpts.SingleBranch = true
	}

	slog.Debug("Cloning repository",
		"url", repoURL,
		"branch", branch,
		"depth", 1,
		"dest", tmpDir,
	)

	repo, err := gogit.PlainCloneContext(ctx, tmpDir, false, cloneOpts)
	if err != nil {
		os.RemoveAll(tmpDir)
		return nil, fmt.Errorf("cloning %s: %w", repoURL, err)
	}

	// Resolve the HEAD commit.
	head, err := repo.Head()
	if err != nil {
		os.RemoveAll(tmpDir)
		return nil, fmt.Errorf("resolving HEAD: %w", err)
	}

	resolvedBranch := head.Name().Short()
	if resolvedBranch == "" {
		resolvedBranch = branch
	}

	owner, repoName := parseOwnerRepo(repoURL)

	return &CloneResult{
		LocalPath: tmpDir,
		Owner:     owner,
		Repo:      repoName,
		Branch:    resolvedBranch,
		Commit:    head.Hash().String(),
		tmpDir:    true,
	}, nil
}

// Cleanup removes the temporary directory created during Clone.
func (cm *CloneManager) Cleanup(result *CloneResult) {
	if result == nil || !result.tmpDir {
		return
	}
	if err := os.RemoveAll(result.LocalPath); err != nil {
		slog.Warn("Failed to clean up clone directory",
			"path", result.LocalPath, "error", err)
	}
}

// CloneDir clones into a specific destination directory (non-temporary).
func (cm *CloneManager) CloneDir(ctx context.Context, repoURL, token, branch, destDir string) (*CloneResult, error) {
	if err := os.MkdirAll(filepath.Dir(destDir), 0o755); err != nil {
		return nil, fmt.Errorf("creating destination parent: %w", err)
	}

	cloneOpts := &gogit.CloneOptions{
		URL:   repoURL,
		Depth: 1,
	}

	if token != "" {
		cloneOpts.Auth = &githttp.BasicAuth{
			Username: "ctrlscan",
			Password: token,
		}
	}

	if branch != "" {
		cloneOpts.ReferenceName = plumbing.NewBranchReferenceName(branch)
		cloneOpts.SingleBranch = true
	}

	repo, err := gogit.PlainCloneContext(ctx, destDir, false, cloneOpts)
	if err != nil {
		return nil, fmt.Errorf("cloning %s to %s: %w", repoURL, destDir, err)
	}

	head, err := repo.Head()
	if err != nil {
		return nil, fmt.Errorf("resolving HEAD: %w", err)
	}

	owner, repoName := parseOwnerRepo(repoURL)
	return &CloneResult{
		LocalPath: destDir,
		Owner:     owner,
		Repo:      repoName,
		Branch:    head.Name().Short(),
		Commit:    head.Hash().String(),
		tmpDir:    false,
	}, nil
}

// parseOwnerRepo extracts the owner and repository name from a git URL.
// Supports HTTPS (https://github.com/owner/repo.git) and SSH (git@github.com:owner/repo.git).
func parseOwnerRepo(repoURL string) (owner, repo string) {
	u := repoURL
	// Remove .git suffix.
	u = strings.TrimSuffix(u, ".git")

	// HTTPS format.
	if strings.Contains(u, "://") {
		parts := strings.Split(u, "/")
		if len(parts) >= 2 {
			repo = parts[len(parts)-1]
			owner = parts[len(parts)-2]
			return
		}
	}

	// SSH format: git@github.com:owner/repo
	if idx := strings.Index(u, ":"); idx != -1 {
		path := u[idx+1:]
		parts := strings.SplitN(path, "/", 2)
		if len(parts) == 2 {
			owner = parts[0]
			repo = parts[1]
			return
		}
	}

	return "", u
}
