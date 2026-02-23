package models

import "time"

// Repo represents a source-code repository from any provider.
type Repo struct {
	ID            string    `json:"id"`
	Provider      string    `json:"provider"`   // github | gitlab | azure
	Host          string    `json:"host"`        // github.com | gitlab.com | dev.azure.com
	Owner         string    `json:"owner"`
	Name          string    `json:"name"`
	FullName      string    `json:"full_name"`   // owner/name
	CloneURL      string    `json:"clone_url"`
	HTMLURL       string    `json:"html_url"`
	DefaultBranch string    `json:"default_branch"`
	Private       bool      `json:"private"`
	Fork          bool      `json:"fork"`
	Language      string    `json:"language"`
	Description   string    `json:"description"`
	Stars         int       `json:"stars"`
	LastPushedAt  time.Time `json:"last_pushed_at"`
}

// PullRequest represents a pull request created by the agent.
type PullRequest struct {
	ID         int64     `json:"id"`
	Number     int       `json:"number"`
	Title      string    `json:"title"`
	Body       string    `json:"body"`
	URL        string    `json:"url"`
	State      string    `json:"state"`   // open | closed | merged
	HeadBranch string    `json:"head_branch"`
	BaseBranch string    `json:"base_branch"`
	CreatedAt  time.Time `json:"created_at"`
}

// RepoQueue tracks repos discovered and pending scanning.
type RepoQueue struct {
	ID           int64     `json:"id"            db:"id"`
	Provider     string    `json:"provider"      db:"provider"`
	Host         string    `json:"host"          db:"host"`
	Owner        string    `json:"owner"         db:"owner"`
	Name         string    `json:"name"          db:"name"`
	FullName     string    `json:"full_name"     db:"full_name"`
	CloneURL     string    `json:"clone_url"     db:"clone_url"`
	DefaultBranch string   `json:"default_branch" db:"default_branch"`
	Status       string    `json:"status"        db:"status"`    // pending | scanning | done | failed
	Priority     int       `json:"priority"      db:"priority"`
	DiscoveredAt time.Time `json:"discovered_at" db:"discovered_at"`
	ScannedAt    *time.Time `json:"scanned_at"   db:"scanned_at"`
}
