package osv

// PackageQuery is a single entry in a batch query request.
type PackageQuery struct {
	Package   PackageID `json:"package"`
	Version   string    `json:"version,omitempty"`
	FindingID int64     `json:"-"` // internal correlation; not sent to API
}

// PackageID identifies a package in the OSV ecosystem.
type PackageID struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}

// BatchQueryRequest is the body for POST /v1/querybatch.
type BatchQueryRequest struct {
	Queries []batchQueryEntry `json:"queries"`
}

type batchQueryEntry struct {
	Package PackageID `json:"package"`
	Version string    `json:"version,omitempty"`
}

// BatchQueryResponse is the response from POST /v1/querybatch.
type BatchQueryResponse struct {
	Results []QueryResult `json:"results"`
}

// QueryResult is the result for a single package query.
type QueryResult struct {
	Vulns []Vuln `json:"vulns"`
}

// Vuln represents a single OSV vulnerability record.
type Vuln struct {
	ID         string      `json:"id"`       // e.g. "GHSA-xxxx-yyyy-zzzz" or "GO-2023-1234"
	Aliases    []string    `json:"aliases"`  // e.g. ["CVE-2021-23337"]
	Severity   []Severity  `json:"severity"`
	References []Reference `json:"references"`
	Affected   []Affected  `json:"affected"`
	Published  string      `json:"published"` // RFC3339
	Modified   string      `json:"modified"`  // RFC3339
}

// Severity holds a CVSS score entry.
type Severity struct {
	Type  string `json:"type"`  // "CVSS_V3" or "CVSS_V2"
	Score string `json:"score"` // e.g. "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
}

// Reference is an external link associated with a vulnerability.
type Reference struct {
	Type string `json:"type"` // "WEB", "ADVISORY", "FIX", "REPORT"
	URL  string `json:"url"`
}

// Affected describes which package versions are affected.
type Affected struct {
	Package  PackageID       `json:"package"`
	Ranges   []AffectedRange `json:"ranges"`
	Versions []string        `json:"versions"`
}

// AffectedRange describes a version range that is affected.
type AffectedRange struct {
	Type   string          `json:"type"` // "SEMVER", "ECOSYSTEM", "GIT"
	Events []RangeEvent    `json:"events"`
}

// RangeEvent marks the start/end of an affected range.
type RangeEvent struct {
	Introduced string `json:"introduced,omitempty"`
	Fixed      string `json:"fixed,omitempty"`
}

// ListResult is the response from GET /v1/vulns.
type ListResult struct {
	Vulns         []Vuln `json:"vulns"`
	NextPageToken string `json:"next_page_token"`
}
