# ctrlscan

AI-powered vulnerability scanning agent that helps developers reduce CVEs at scale.

ctrlscan discovers repositories, scans them for security vulnerabilities using industry-standard
tools, and uses AI to automatically generate fixes and create pull requests — turning a single
developer into a force multiplier for open-source security.

## How it works

```
Discover repos → Clone & scan → AI triage → Generate patches → Open PRs
```

1. **Discover** — scans your own repos, configured watchlists, or CVE-targeted public repos
2. **Scan** — runs grype (SCA), opengrep (SAST), trufflehog (secrets), and trivy (IaC)
3. **Triage** — AI prioritises findings by real-world risk
4. **Fix** — AI generates minimal, correct code patches
5. **PR** — forks the repo, applies the fix, opens a pull request

## Install

```bash
# Quick install (prefers GitHub release binaries; falls back to source build)
curl -sSfL https://raw.githubusercontent.com/CosmoTheDev/ctrlscan-agent/main/install/install.sh | sh

# Or build from source
git clone https://github.com/CosmoTheDev/ctrlscan-agent
cd ctrlscan-agent
make install
```

Then add to your shell profile:

```bash
export PATH="$HOME/.ctrlscan/bin:$PATH"
```

Windows (PowerShell):

```powershell
$script = Join-Path $env:TEMP 'ctrlscan-install.ps1'
irm https://raw.githubusercontent.com/CosmoTheDev/ctrlscan-agent/main/install/install.ps1 -OutFile $script
powershell -ExecutionPolicy Bypass -File $script
```

Package managers (after publishing):

```bash
brew tap CosmoTheDev/tap && brew install ctrlscan
```

```powershell
scoop bucket add ctrlscan https://github.com/CosmoTheDev/scoop-bucket
scoop install ctrlscan
choco install ctrlscan
```

Maintainer distribution/publishing guide: `docs/distribution.md`

## Quick start

```bash
# 1. Run the interactive setup wizard
ctrlscan onboard

# 2. Verify everything is working
ctrlscan doctor

# 3. Scan a repository
ctrlscan scan --repo https://github.com/example/myapp

# 4. Launch the terminal dashboard
ctrlscan ui

# 5. Start the autonomous agent
ctrlscan agent
```

## Agent modes

| Mode | Description |
|------|-------------|
| `triage` | Scan, triage findings, propose fixes — **you approve each PR** (default) |
| `semi` | Scan, generate fix, open browser for review with one click |
| `auto` | Fully autonomous: scan, fix, and open PRs hands-free |

```bash
ctrlscan agent --mode triage   # safe default
ctrlscan agent --mode auto     # lights-out remediation
```

## Scanner tools

ctrlscan installs these tools to `~/.ctrlscan/bin/`:

| Tool | Category | What it finds |
|------|----------|---------------|
| syft + grype | SCA | Vulnerable dependencies (CVEs) |
| opengrep | SAST | Code-level security bugs |
| trufflehog | Secrets | Leaked credentials and API keys |
| trivy | IaC | Infrastructure misconfigurations |

All tools can also run via Docker if local binaries are unavailable.

## Configuration

Config lives at `~/.ctrlscan/config.json`. Manage it with:

```bash
ctrlscan config show    # view current config (secrets redacted)
ctrlscan config edit    # open in $EDITOR
ctrlscan config edit-ui # interactive tabular configuration editor
ctrlscan config path    # print config file path
```

Environment variables override config: `CTRLSCAN_AI_OPENAI_API_KEY=sk-...`

## Git providers

| Provider | Status |
|----------|--------|
| GitHub (cloud + enterprise) | Supported |
| GitLab (cloud + self-hosted) | Supported |
| Azure DevOps | Supported |
| Bitbucket | Planned |

## Repository watchlist

```bash
ctrlscan repo add owner/repo    # watch a specific repo
ctrlscan repo add myorg         # watch an entire org
ctrlscan repo list              # show watchlist
ctrlscan repo remove owner/repo
```

## Commands

```
ctrlscan onboard     Interactive setup wizard
ctrlscan scan        Scan a repository
ctrlscan agent       Run the autonomous agent loop
ctrlscan ui          Terminal dashboard
ctrlscan doctor      Verify tools and credentials
ctrlscan repo        Manage watchlists
ctrlscan config      View/edit configuration
ctrlscan config edit-ui Interactive tabular configuration editor
```

## Requirements

- Go 1.21+ (for building from source)
- `curl`, `git` (for tool installation)
- AI provider for triage/fixes/PRs: OpenAI API key, local Ollama, or LM Studio (OpenAI-compatible local endpoint)
- GitHub/GitLab/Azure token for API access (for GitHub classic PATs, create one at `https://github.com/settings/tokens/new`; add write access if you want PR creation)

## Codex MCP (Playwright + SQLite)

This repo includes a project-scoped Codex MCP config at `.codex/config.toml` for Playwright (browser automation) and SQLite (database inspection/querying), so agents can troubleshoot and test against the local ctrlscan DB. See `docs/codex-playwright-mcp.md`.

## Gateway API (scan management)

Useful endpoints when running `ctrlscan gateway`:

- `GET /api/jobs` — list recent scan jobs
- `DELETE /api/jobs/{id}` — delete one scan job and related records
- `DELETE /api/jobs` — bulk delete with JSON body
  - by ids: `{"ids":[12,13,14]}`
  - delete all (explicit only): `{"delete_all":true}`

Example responses:

```json
{"deleted_count":1,"deleted_ids":[74],"not_found_ids":[]}
```

```json
{"deleted_count":2,"deleted_ids":[73,72],"not_found_ids":[999999]}
```

Safety behavior:

- `DELETE /api/jobs` rejects ambiguous requests when no `ids` and no `delete_all=true`.
- Delete-all is only allowed when `delete_all` is explicitly set to `true`.

## Architecture

See [CTRLSCAN_AGENT_PLAN.md](./CTRLSCAN_AGENT_PLAN.md) for full architecture documentation,
interface contracts, and extension guides.

## Security CI

This repo includes GitHub Actions for:

- CodeQL (Go)
- `govulncheck` and `gosec`
- Trivy filesystem scanning
- Gitleaks secret scanning
- Dependency Review on PRs

## License

See [LICENSE](./LICENSE).
