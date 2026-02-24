package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	aiPkg "github.com/CosmoTheDev/ctrlscan-agent/internal/ai"
	"github.com/CosmoTheDev/ctrlscan-agent/internal/config"
	"github.com/CosmoTheDev/ctrlscan-agent/internal/database"
	"github.com/CosmoTheDev/ctrlscan-agent/internal/repository"
	"github.com/CosmoTheDev/ctrlscan-agent/models"
)

// PRAgent reads approved fixes from fix_queue, applies them, and creates PRs.
type PRAgent struct {
	cfg *config.Config
	db  database.DB
	ai  aiPkg.AIProvider
}

// NewPRAgent creates a PRAgent.
func NewPRAgent(cfg *config.Config, db database.DB, ai aiPkg.AIProvider) *PRAgent {
	return &PRAgent{cfg: cfg, db: db, ai: ai}
}

// ProcessApprovedFixes polls fix_queue for approved fixes and creates PRs.
// Call this from the orchestrator or a separate goroutine.
func (a *PRAgent) ProcessApprovedFixes(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			a.drainApprovedFixes(ctx)
		case <-ctx.Done():
			return
		}
	}
}

func (a *PRAgent) drainApprovedFixes(ctx context.Context) {
	type fixRow struct {
		ID             int64  `db:"id"`
		ScanJobID      int64  `db:"scan_job_id"`
		FindingType    string `db:"finding_type"`
		FindingID      int64  `db:"finding_id"`
		ApplyHintsJSON string `db:"apply_hints_json"`
		Patch          string `db:"patch"`
		PRTitle        string `db:"pr_title"`
		PRBody         string `db:"pr_body"`
		Status         string `db:"status"`
		PRNumber       int    `db:"pr_number"`
		PRURL          string `db:"pr_url"`
	}
	var rows []fixRow
	if err := a.db.Select(ctx, &rows,
		`SELECT id, scan_job_id, finding_type, finding_id, apply_hints_json, patch, pr_title, pr_body, status, pr_number, pr_url
		   FROM fix_queue
		  WHERE status = 'approved'
		  ORDER BY id ASC
		  LIMIT 20`); err != nil {
		slog.Warn("Failed to load approved fixes", "error", err)
		return
	}

	for _, row := range rows {
		if ctx.Err() != nil {
			return
		}
		fix := models.FixQueue{
			ID:             row.ID,
			ScanJobID:      row.ScanJobID,
			FindingType:    row.FindingType,
			FindingID:      row.FindingID,
			ApplyHintsJSON: row.ApplyHintsJSON,
			Patch:          row.Patch,
			PRTitle:        row.PRTitle,
			PRBody:         row.PRBody,
			Status:         row.Status,
			PRNumber:       row.PRNumber,
			PRURL:          row.PRURL,
		}
		if err := a.createPR(ctx, fix); err != nil {
			if isRetryablePRCreationError(err) {
				slog.Warn("PR creation delayed; will retry",
					"fix_id", fix.ID,
					"error", err,
				)
				// Keep status=approved so the PR worker can retry on the next pass.
				continue
			}
			slog.Error("PR creation failed", "fix_id", fix.ID, "error", err)
			_ = a.db.Exec(ctx,
				`UPDATE fix_queue SET status = 'pr_failed' WHERE id = ?`, fix.ID)
		}
	}
}

func (a *PRAgent) createPR(ctx context.Context, fix models.FixQueue) error {
	hints := parseApplyHintsJSON(fix.ApplyHintsJSON)
	slog.Info("Creating PR for fix",
		"fix_id", fix.ID,
		"scan_job_id", fix.ScanJobID,
		"apply_strategy", strings.TrimSpace(hints.ApplyStrategy),
		"hint_target_files", len(hints.TargetFiles),
		"hint_checks", len(hints.PostApplyChecks),
	)

	// Load the scan job to get repo details.
	var job struct {
		ID       int64  `db:"id"`
		Provider string `db:"provider"`
		Owner    string `db:"owner"`
		Repo     string `db:"repo"`
		Branch   string `db:"branch"`
	}
	if err := a.db.Get(ctx, &job, `
		SELECT id, provider, owner, repo, branch
		FROM scan_jobs
		WHERE id = ?`, fix.ScanJobID); err != nil {
		return fmt.Errorf("loading scan job: %w", err)
	}

	// Build the repository provider.
	provider, err := repository.New(job.Provider, a.cfg)
	if err != nil {
		return fmt.Errorf("building provider: %w", err)
	}

	// Prefer fork-based PRs, but fall back to direct-branch PRs when forking
	// fails and the token has write access to the upstream repository.
	var (
		cloneURL string
		headRef  string
		forkMode bool
	)
	fork, err := provider.ForkRepo(ctx, job.Owner, job.Repo)
	if err != nil {
		slog.Warn("Fork failed; attempting direct PR fallback",
			"owner", job.Owner,
			"repo", job.Repo,
			"error", err,
		)
		upstream, getErr := provider.GetRepo(ctx, job.Owner, job.Repo)
		if getErr != nil {
			return fmt.Errorf("forking %s/%s: %w (direct fallback get repo failed: %v)", job.Owner, job.Repo, err, getErr)
		}
		cloneURL = upstream.CloneURL
		forkMode = false
	} else {
		cloneURL = fork.CloneURL
		forkMode = true
	}

	// Clone target remote (fork preferred, upstream on fallback) to a temp directory.
	cm := repository.NewCloneManager(a.cfg.Tools.BinDir)
	cloneResult, err := cm.Clone(ctx, cloneURL, provider.AuthToken(), job.Branch)
	if err != nil {
		if forkMode {
			return fmt.Errorf("cloning fork: %w", err)
		}
		return fmt.Errorf("cloning upstream for direct PR fallback: %w", err)
	}
	defer cm.Cleanup(cloneResult)

	// Create a fix branch.
	branchName := fmt.Sprintf("ctrlscan/fix-%d-%d", fix.ScanJobID, fix.ID)
	if err := gitCreateBranch(cloneResult.LocalPath, branchName); err != nil {
		return fmt.Errorf("creating branch: %w", err)
	}

	// Apply the change (patch by default, deterministic dependency bump when requested).
	if strings.EqualFold(strings.TrimSpace(hints.ApplyStrategy), "dependency_bump") {
		if err := applyDependencyBump(ctx, cloneResult.LocalPath, hints); err != nil {
			return fmt.Errorf("applying dependency bump (ecosystem=%s pkg=%s version=%s): %w",
				strings.TrimSpace(hints.Ecosystem), strings.TrimSpace(hints.DependencyName), strings.TrimSpace(hints.TargetVersion), err)
		}
	} else if err := applyPatch(cloneResult.LocalPath, fix.Patch); err != nil {
		return fmt.Errorf("applying patch (strategy=%s targets=%d): %w",
			strings.TrimSpace(hints.ApplyStrategy), len(hints.TargetFiles), err)
	}

	// Commit the change.
	commitMsg := fix.PRTitle + "\n\nGenerated by ctrlscan."
	if err := gitCommit(cloneResult.LocalPath, commitMsg); err != nil {
		return fmt.Errorf("committing fix: %w", err)
	}

	// Push branch.
	if err := gitPush(cloneResult.LocalPath, branchName, provider.AuthToken(), cloneURL); err != nil {
		if forkMode {
			return fmt.Errorf("pushing fork branch: %w", err)
		}
		return fmt.Errorf("pushing direct branch to upstream: %w", err)
	}
	if forkMode {
		// GitHub/GitLab generally require the fork owner's branch namespace.
		// If owner is empty for any reason, fall back to bare branch.
		if strings.TrimSpace(fork.Owner) != "" {
			headRef = fmt.Sprintf("%s:%s", fork.Owner, branchName)
		}
	}
	if headRef == "" {
		headRef = branchName
	}

	// Generate PR description.
	prDesc := &aiPkg.PRDescription{
		Title: fix.PRTitle,
		Body:  fix.PRBody,
	}

	// Create the pull request against the original (not fork).
	pr, err := provider.CreatePR(ctx, repository.CreatePROptions{
		Owner:      job.Owner,
		Repo:       job.Repo,
		Title:      prDesc.Title,
		Body:       prDesc.Body,
		HeadBranch: headRef,
		BaseBranch: job.Branch,
		Draft:      a.cfg.Agent.Mode == "triage", // draft in triage mode
	})
	if err != nil {
		return fmt.Errorf("creating PR: %w", err)
	}

	slog.Info("PR created", "url", pr.URL, "number", pr.Number)

	// Update fix_queue status.
	now := time.Now().UTC().Format(time.RFC3339)
	if err := a.db.Exec(ctx,
		`UPDATE fix_queue SET status = 'pr_open', pr_number = ?, pr_url = ?, approved_at = ? WHERE id = ?`,
		pr.Number, pr.URL, now, fix.ID,
	); err != nil {
		slog.Warn("Failed to update fix_queue", "error", err)
	}

	// In semi/auto mode: open browser.
	if a.cfg.Agent.Mode == "semi" || a.cfg.Agent.Mode == "auto" {
		openBrowser(pr.URL)
	}

	return nil
}

func parseApplyHintsJSON(raw string) aiPkg.ApplyHints {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return aiPkg.ApplyHints{}
	}
	var hints aiPkg.ApplyHints
	if err := json.Unmarshal([]byte(raw), &hints); err != nil {
		slog.Warn("Failed to parse fix apply_hints_json", "error", err)
		return aiPkg.ApplyHints{}
	}
	return hints
}

// --- git helpers ---

func gitCreateBranch(repoPath, branch string) error {
	return runGit(repoPath, "checkout", "-b", branch)
}

func gitCommit(repoPath, message string) error {
	if err := runGit(repoPath, "add", "-A"); err != nil {
		return err
	}
	return runGit(repoPath, "commit", "-m", message,
		"--author", "ctrlscan <ctrlscan@users.noreply.github.com>")
}

func gitPush(repoPath, branch, token, remoteURL string) error {
	// Inject token into the remote URL.
	authedURL := injectToken(remoteURL, token)
	if err := runGit(repoPath, "remote", "set-url", "origin", authedURL); err != nil {
		return err
	}
	return runGit(repoPath, "push", "-u", "origin", branch)
}

func applyPatch(repoPath, patch string) error {
	patch = cleanPatch(patch) // strip markdown fences, normalise CRLF
	if strings.TrimSpace(patch) == "" {
		return fmt.Errorf("empty patch")
	}
	if !looksLikeUnifiedDiffPatch(patch) {
		return fmt.Errorf("invalid patch format (expected unified diff with ---/+++/@@ hunks)")
	}
	patchFile := filepath.Join(repoPath, ".ctrlscan.patch")
	if err := os.WriteFile(patchFile, []byte(patch), 0o600); err != nil {
		return err
	}
	defer os.Remove(patchFile)
	if err := runGit(repoPath, "apply", patchFile); err != nil {
		// Fallback: apply additions directly by content-searching for context
		// anchors. Handles bare @@ headers and non-adjacent context that AI
		// models produce.
		if fbErr := applyAdditionsDirectly(repoPath, patch); fbErr != nil {
			return fmt.Errorf("%w (direct-edit fallback also failed: %v)", err, fbErr)
		}
		return nil
	}
	return nil
}

// applyAdditionsDirectly applies an addition-only patch by finding each hunk's
// context anchor line by content and inserting the added lines at that position.
// It does not rely on correct @@ line numbers and handles non-adjacent context.
func applyAdditionsDirectly(repoPath, patch string) error {
	// Resolve target file from "+++ b/path".
	var targetFile string
	for _, l := range strings.Split(patch, "\n") {
		if strings.HasPrefix(l, "+++ ") {
			p := strings.TrimPrefix(l, "+++ ")
			p = strings.TrimPrefix(p, "b/")
			targetFile = strings.TrimSpace(p)
			break
		}
	}
	if targetFile == "" {
		return fmt.Errorf("no target file in patch")
	}
	filePath, err := safeRepoJoin(repoPath, targetFile)
	if err != nil {
		return fmt.Errorf("unsafe path %q: %w", targetFile, err)
	}
	content, err := os.ReadFile(filePath) // #nosec G304 -- path validated by safeRepoJoin
	if err != nil {
		return fmt.Errorf("reading %s: %w", targetFile, err)
	}
	fileLines := strings.Split(strings.ReplaceAll(string(content), "\r\n", "\n"), "\n")

	type hunkLine struct {
		kind rune   // '+', '-', ' '
		text string // content without leading sigil
	}

	// Parse all hunks from the patch.
	var allHunks [][]hunkLine
	var current []hunkLine
	inHunk := false
	for _, l := range strings.Split(patch, "\n") {
		if strings.HasPrefix(l, "@@") {
			if inHunk && len(current) > 0 {
				allHunks = append(allHunks, current)
			}
			current = nil
			inHunk = true
			continue
		}
		if strings.HasPrefix(l, "--- ") || strings.HasPrefix(l, "+++ ") {
			continue
		}
		if !inHunk {
			continue
		}
		switch {
		case strings.HasPrefix(l, "+"):
			current = append(current, hunkLine{'+', strings.TrimPrefix(l, "+")})
		case strings.HasPrefix(l, "-"):
			current = append(current, hunkLine{'-', strings.TrimPrefix(l, "-")})
		default:
			// context line (space prefix or bare empty line at end of patch)
			text := strings.TrimPrefix(l, " ")
			if strings.TrimSpace(text) == "" {
				continue // skip trailing blank lines
			}
			current = append(current, hunkLine{' ', text})
		}
	}
	if inHunk && len(current) > 0 {
		allHunks = append(allHunks, current)
	}
	if len(allHunks) == 0 {
		return fmt.Errorf("no hunks parsed")
	}

	// Reject if any hunk contains deletions — we only handle additions here.
	for _, hunk := range allHunks {
		for _, hl := range hunk {
			if hl.kind == '-' {
				return fmt.Errorf("patch contains deletions; direct-edit fallback requires addition-only patches")
			}
		}
	}

	// Apply each hunk in order. We search by content so searchFrom only
	// prevents matching something inserted by an earlier hunk.
	searchFrom := 0
	for _, hunk := range allHunks {
		i := 0
		for i < len(hunk) {
			// Skip leading context lines.
			for i < len(hunk) && hunk[i].kind == ' ' {
				i++
			}
			if i >= len(hunk) {
				break
			}
			// Collect this block of additions.
			var additions []string
			for i < len(hunk) && hunk[i].kind == '+' {
				additions = append(additions, hunk[i].text)
				i++
			}
			if len(additions) == 0 {
				i++
				continue
			}
			// Determine the insertion point.
			var insertAt int
			if i < len(hunk) && hunk[i].kind == ' ' {
				// Insert just before the first context line after the additions.
				afterAnchor := hunk[i].text
				pos := findLineByContent(fileLines, afterAnchor, searchFrom)
				if pos < 0 {
					return fmt.Errorf("after-context %q not found in %s", afterAnchor, targetFile)
				}
				insertAt = pos
			} else {
				// No after-context: find the last context line before additions
				// and insert just after it.
				beforeAnchor := ""
				for j := i - len(additions) - 1; j >= 0; j-- {
					if hunk[j].kind == ' ' {
						beforeAnchor = hunk[j].text
						break
					}
				}
				if beforeAnchor == "" {
					return fmt.Errorf("no context anchor found for hunk additions")
				}
				pos := findLineByContent(fileLines, beforeAnchor, searchFrom)
				if pos < 0 {
					return fmt.Errorf("before-context %q not found in %s", beforeAnchor, targetFile)
				}
				insertAt = pos + 1
			}
			// Insert additions into fileLines.
			newLines := make([]string, 0, len(fileLines)+len(additions))
			newLines = append(newLines, fileLines[:insertAt]...)
			newLines = append(newLines, additions...)
			newLines = append(newLines, fileLines[insertAt:]...)
			fileLines = newLines
			searchFrom = insertAt + len(additions)
		}
	}

	return os.WriteFile(filePath, []byte(strings.Join(fileLines, "\n")), 0o600)
}

// findLineByContent returns the index of the first line in lines (at or after
// startFrom) whose content matches target (trailing whitespace ignored).
func findLineByContent(lines []string, target string, startFrom int) int {
	t := strings.TrimRight(target, " \t")
	for i := startFrom; i < len(lines); i++ {
		if strings.TrimRight(lines[i], " \t") == t {
			return i
		}
	}
	return -1
}

func applyDependencyBump(ctx context.Context, repoPath string, hints aiPkg.ApplyHints) error {
	pkg := strings.TrimSpace(hints.DependencyName)
	ver := strings.TrimSpace(hints.TargetVersion)
	if pkg == "" || ver == "" {
		return fmt.Errorf("missing dependency_name or target_version in apply hints")
	}
	eco := strings.ToLower(strings.TrimSpace(hints.Ecosystem))
	switch eco {
	case "go":
		workdir := repoPath
		if mp := strings.TrimSpace(hints.ManifestPath); mp != "" {
			workdir = filepath.Join(repoPath, filepath.Dir(mp))
		}
		if err := runCmd(ctx, workdir, "go", "get", fmt.Sprintf("%s@%s", pkg, ver)); err != nil {
			return err
		}
		_ = runCmd(ctx, workdir, "go", "mod", "tidy")
		return nil
	case "npm":
		workdir := repoPath
		basePath := strings.TrimSpace(hints.LockfilePath)
		if basePath == "" {
			basePath = strings.TrimSpace(hints.ManifestPath)
		}
		if basePath != "" {
			workdir = filepath.Join(repoPath, filepath.Dir(basePath))
		}
		if err := runCmd(ctx, workdir, "npm", "install", "--package-lock-only", "--ignore-scripts", fmt.Sprintf("%s@%s", pkg, ver)); err != nil {
			return err
		}
		return nil
	default:
		return fmt.Errorf("unsupported dependency_bump ecosystem %q", hints.Ecosystem)
	}
}

func runCmd(ctx context.Context, dir, name string, args ...string) error {
	switch name {
	case "go", "npm":
	default:
		return fmt.Errorf("runCmd: disallowed command %q", name)
	}
	cmd := exec.CommandContext(ctx, name, args...) // #nosec G204 -- name validated against allowlist above; //nolint:gosec // nosemgrep: go.lang.security.audit.dangerous-exec-command.dangerous-exec-command
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %w\n%s", name, strings.Join(args, " "), err, string(out))
	}
	return nil
}

func runGit(dir string, args ...string) error {
	cmd := exec.Command("git", args...) // #nosec G204 -- "git" is a literal; args are controlled by callers
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("git %s: %w\n%s", strings.Join(args, " "), err, string(out))
	}
	return nil
}

// safeRepoJoin joins base and rel, returning an error if the result would
// escape the base directory. This prevents path traversal when rel comes from
// external sources such as scan findings or AI-generated patch headers.
func safeRepoJoin(base, rel string) (string, error) {
	absBase, err := filepath.Abs(base)
	if err != nil {
		return "", fmt.Errorf("resolving repo root: %w", err)
	}
	joined := filepath.Join(absBase, filepath.Clean(rel))
	if joined != absBase && !strings.HasPrefix(joined, absBase+string(filepath.Separator)) {
		return "", fmt.Errorf("path %q escapes repo root", rel)
	}
	return joined, nil
}

func injectToken(repoURL, token string) string {
	if token == "" || !strings.Contains(repoURL, "://") {
		return repoURL
	}
	parts := strings.SplitN(repoURL, "://", 2)
	return parts[0] + "://ctrlscan:" + token + "@" + parts[1]
}

func isRetryablePRCreationError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "job scheduled on github side"),
		strings.Contains(msg, "try again later"),
		strings.Contains(msg, "rate limit"),
		strings.Contains(msg, "timeout"),
		strings.Contains(msg, "temporar"),
		strings.Contains(msg, "5xx"):
		return true
	default:
		return false
	}
}
