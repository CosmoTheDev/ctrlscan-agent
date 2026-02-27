package gateway

import (
	"context"
	"net/http"
	"strings"
)

// --- Row/type definitions ---

// vulnRow is the unified cross-job vulnerability row returned by /api/vulnerabilities.
type vulnRow struct {
	ID         int64  `db:"id"              json:"id"`
	ScanJobID  int64  `db:"scan_job_id"     json:"scan_job_id"`
	Kind       string `db:"kind"            json:"kind"`
	Scanner    string `db:"scanner"         json:"scanner"`
	Severity   string `db:"severity"        json:"severity"`
	Title      string `db:"title"           json:"title"`
	FilePath   string `db:"file_path"       json:"file_path"`
	Line       int    `db:"line"            json:"line"`
	Message    string `db:"message"         json:"message"`
	Package    string `db:"package_name"    json:"package"`
	Version    string `db:"package_version" json:"version"`
	FixHint    string `db:"fix_hint"        json:"fix_hint,omitempty"`
	Status     string `db:"status"          json:"status"`
	FirstSeen  string `db:"first_seen_at"   json:"first_seen"`
	Provider   string `db:"provider"        json:"provider"`
	Owner      string `db:"owner"           json:"owner"`
	Repo       string `db:"repo"            json:"repo"`
	Branch     string `db:"branch"          json:"branch"`
	FixQueueID int64  `db:"fix_queue_id"    json:"fix_queue_id"`
	FixStatus  string `db:"fix_status"      json:"fix_status"`
	FixPRURL   string `db:"fix_pr_url"      json:"fix_pr_url"`
	FixPRTitle string `db:"fix_pr_title"    json:"fix_pr_title"`
}

// vulnParams holds all parsed filter parameters for the /api/vulnerabilities handler.
type vulnParams struct {
	severity string
	kind     string
	scanner  string
	repo     string
	searchQ  string
	status   string
	cves     []string // exact title matches (CVE/GHSA IDs)
}

// vulnFromJoins is the common FROM+JOIN block used in all vuln queries.
const vulnFromJoins = `
	FROM scan_job_findings sjf
	JOIN scan_jobs sj ON sj.id = sjf.scan_job_id
	LEFT JOIN fix_queue fq ON fq.scan_job_id = sjf.scan_job_id
		AND fq.finding_type = sjf.kind
		AND fq.finding_id = sjf.id`

// vulnFromJoinsNoFix is the FROM+JOIN without fix_queue for facet queries.
const vulnFromJoinsNoFix = `
	FROM scan_job_findings sjf
	JOIN scan_jobs sj ON sj.id = sjf.scan_job_id`

// buildVulnWhere builds a WHERE clause for vuln queries, optionally excluding one dimension
// so cascading facets work correctly (each facet is computed without its own filter applied).
func buildVulnWhere(p vulnParams, exclude string) (string, []any) {
	var clauses []string
	var args []any

	likePat := func(s string) string {
		return "%" + strings.ReplaceAll(strings.ReplaceAll(s, "%", "\\%"), "_", "\\_") + "%"
	}

	if p.severity != "" && exclude != "severity" {
		clauses = append(clauses, "sjf.severity = ?")
		args = append(args, p.severity)
	}
	if p.kind != "" && exclude != "kind" {
		clauses = append(clauses, "sjf.kind = ?")
		args = append(args, p.kind)
	}
	if p.scanner != "" && exclude != "scanner" {
		clauses = append(clauses, "sjf.scanner = ?")
		args = append(args, p.scanner)
	}
	if p.status != "" && p.status != "all" && exclude != "status" {
		clauses = append(clauses, "sjf.status = ?")
		args = append(args, p.status)
	}
	if p.repo != "" && exclude != "repo" {
		pat := likePat(p.repo)
		clauses = append(clauses, "(sj.owner LIKE ? OR sj.repo LIKE ? OR (sj.owner || '/' || sj.repo) LIKE ?)")
		args = append(args, pat, pat, pat)
	}
	if p.searchQ != "" && exclude != "q" {
		pat := likePat(p.searchQ)
		clauses = append(clauses,
			"(LOWER(sjf.title) LIKE ? OR LOWER(sjf.file_path) LIKE ? OR LOWER(sjf.message) LIKE ? OR LOWER(sjf.package_name) LIKE ?)")
		args = append(args, pat, pat, pat, pat)
	}
	if len(p.cves) > 0 && exclude != "cves" {
		parts := make([]string, len(p.cves))
		for i, c := range p.cves {
			parts[i] = "sjf.title = ?"
			args = append(args, c)
		}
		clauses = append(clauses, "("+strings.Join(parts, " OR ")+")")
	}

	if len(clauses) == 0 {
		return "", args
	}
	return " WHERE " + strings.Join(clauses, " AND "), args
}

// vulnFacetStrings runs a DISTINCT query and returns the string results, silently ignoring errors.
func (gw *Gateway) vulnFacetStrings(ctx context.Context, selectExpr, fromJoins, whereStr string, args []any) []string {
	type row struct {
		V string `db:"v"`
	}
	var rows []row
	_ = gw.db.Select(ctx, &rows, "SELECT DISTINCT "+selectExpr+" AS v"+fromJoins+whereStr+" ORDER BY v LIMIT 500", args...)
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		if r.V != "" {
			out = append(out, r.V)
		}
	}
	return out
}

func (gw *Gateway) handleListVulnerabilities(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	q := r.URL.Query()

	// Parse CVEs (comma-separated or repeated param)
	var cves []string
	for _, raw := range append(q["cves"], strings.Split(q.Get("cve"), ",")...) {
		for _, c := range strings.Split(raw, ",") {
			c = strings.TrimSpace(c)
			if c != "" {
				cves = append(cves, c)
			}
		}
	}
	// deduplicate
	seen := map[string]bool{}
	unique := cves[:0]
	for _, c := range cves {
		if !seen[c] {
			seen[c] = true
			unique = append(unique, c)
		}
	}
	cves = unique

	status := strings.TrimSpace(q.Get("status"))
	if status == "" {
		status = "open"
	}
	p := vulnParams{
		severity: strings.TrimSpace(q.Get("severity")),
		kind:     strings.TrimSpace(q.Get("kind")),
		scanner:  strings.TrimSpace(q.Get("scanner")),
		repo:     strings.TrimSpace(q.Get("repo")),
		searchQ:  strings.ToLower(strings.TrimSpace(q.Get("q"))),
		status:   status,
		cves:     cves,
	}
	pg := parsePaginationParams(r, 50, 10000)

	// Main query
	whereStr, args := buildVulnWhere(p, "")

	type countRow struct {
		N int `db:"n"`
	}
	var cnt countRow
	countArgs := make([]any, len(args))
	copy(countArgs, args)
	// nosemgrep: go.lang.security.injection.tainted-sql-string.tainted-sql-string — whereStr is built with parameterized placeholders only; values are in args.
	if err := gw.db.Get(ctx, &cnt, "SELECT COUNT(*) AS n"+vulnFromJoinsNoFix+whereStr, countArgs...); err != nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"items": []vulnRow{}, "total": 0, "page": pg.Page, "page_size": pg.PageSize, "total_pages": 1,
			"severity_totals": map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0, "fixed": 0},
			"facets":          map[string]any{"severities": []string{}, "kinds": []string{}, "scanners": []string{}, "repos": []string{}, "cves": []string{}},
		})
		return
	}

	pagedArgs := append(args, pg.PageSize, pg.Offset)
	var rows []vulnRow
	// nosemgrep: go.lang.security.injection.tainted-sql-string.tainted-sql-string — whereStr contains only parameterized placeholders; values are in pagedArgs.
	selectQ := `SELECT sjf.id, sjf.scan_job_id, sjf.kind, sjf.scanner, sjf.severity, sjf.title,
		sjf.file_path, sjf.line, sjf.message, sjf.package_name, sjf.package_version,
		sjf.fix_hint, sjf.status, sjf.first_seen_at,
		sj.provider, sj.owner, sj.repo, sj.branch,
		COALESCE(fq.id, 0) AS fix_queue_id,
		COALESCE(fq.status, '') AS fix_status,
		COALESCE(fq.pr_url, '') AS fix_pr_url,
		COALESCE(fq.pr_title, '') AS fix_pr_title` + vulnFromJoins + whereStr + ` ORDER BY sjf.id DESC LIMIT ? OFFSET ?`
	_ = gw.db.Select(ctx, &rows, selectQ, pagedArgs...)
	if rows == nil {
		rows = []vulnRow{}
	}

	// Severity totals (without severity filter so user sees full breakdown)
	sevWhere, sevArgs := buildVulnWhere(p, "severity")
	type sevRow struct {
		Sev string `db:"sev"`
		N   int    `db:"n"`
	}
	var sevRows []sevRow
	_ = gw.db.Select(ctx, &sevRows, "SELECT UPPER(sjf.severity) AS sev, COUNT(*) AS n"+vulnFromJoinsNoFix+sevWhere+" GROUP BY sjf.severity", sevArgs...) // nosemgrep: go.lang.security.injection.tainted-sql-string.tainted-sql-string
	sevTotals := map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0, "fixed": 0}
	for _, sr := range sevRows {
		switch sr.Sev {
		case "CRITICAL":
			sevTotals["critical"] = sr.N
		case "HIGH":
			sevTotals["high"] = sr.N
		case "MEDIUM":
			sevTotals["medium"] = sr.N
		case "LOW":
			sevTotals["low"] = sr.N
		}
	}
	// Fixed count (without status filter)
	fixedWhere, fixedArgs := buildVulnWhere(p, "status")
	fixedWhere2 := "sjf.status = 'fixed'"
	if fixedWhere != "" {
		fixedWhere2 = fixedWhere + " AND sjf.status = 'fixed'"
	} else {
		fixedWhere2 = " WHERE sjf.status = 'fixed'"
	}
	var fixedCnt countRow
	_ = gw.db.Get(ctx, &fixedCnt, "SELECT COUNT(*) AS n"+vulnFromJoinsNoFix+fixedWhere2, fixedArgs...) // nosemgrep: go.lang.security.injection.tainted-sql-string.tainted-sql-string
	sevTotals["fixed"] = fixedCnt.N

	// Cascading facets — each dimension computed without its own filter
	sevFacetWhere, sevFacetArgs := buildVulnWhere(p, "severity")
	kindFacetWhere, kindFacetArgs := buildVulnWhere(p, "kind")
	scannerFacetWhere, scannerFacetArgs := buildVulnWhere(p, "scanner")
	repoFacetWhere, repoFacetArgs := buildVulnWhere(p, "repo")
	// CVE facets: titles matching CVE-/GHSA- with all filters applied
	cveFacetWhere, cveFacetArgs := buildVulnWhere(p, "cves")
	cveFilterClause := "(sjf.title LIKE 'CVE-%' OR sjf.title LIKE 'GHSA-%')"
	if cveFacetWhere != "" {
		cveFacetWhere = cveFacetWhere + " AND " + cveFilterClause
	} else {
		cveFacetWhere = " WHERE " + cveFilterClause
	}

	facets := map[string]any{
		"severities": gw.vulnFacetStrings(ctx, "UPPER(sjf.severity)", vulnFromJoinsNoFix, sevFacetWhere, sevFacetArgs),
		"kinds":      gw.vulnFacetStrings(ctx, "sjf.kind", vulnFromJoinsNoFix, kindFacetWhere, kindFacetArgs),
		"scanners":   gw.vulnFacetStrings(ctx, "sjf.scanner", vulnFromJoinsNoFix, scannerFacetWhere, scannerFacetArgs),
		"repos":      gw.vulnFacetStrings(ctx, "sj.owner || '/' || sj.repo", vulnFromJoinsNoFix, repoFacetWhere, repoFacetArgs),
		"cves":       gw.vulnFacetStrings(ctx, "sjf.title", vulnFromJoinsNoFix, cveFacetWhere, cveFacetArgs),
	}

	total := cnt.N
	totalPages := 1
	if total > 0 {
		totalPages = (total + pg.PageSize - 1) / pg.PageSize
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"items":           rows,
		"total":           total,
		"page":            pg.Page,
		"page_size":       pg.PageSize,
		"total_pages":     totalPages,
		"severity_totals": sevTotals,
		"facets":          facets,
	})
}
