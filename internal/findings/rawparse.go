package findings

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// NormalizedFinding is a scanner-agnostic finding record parsed from raw scanner output.
// It is intentionally snapshot-oriented and independent from DB row IDs.
type NormalizedFinding struct {
	Kind        string
	Scanner     string
	Fingerprint string
	Severity    string
	Title       string
	FilePath    string
	Line        int
	Message     string
	Package     string
	Version     string
	Fix         string
	Status      string
}

// ParseRawScannerOutput parses one scanner's raw output into normalized findings.
func ParseRawScannerOutput(scannerName string, data []byte) []NormalizedFinding {
	switch strings.ToLower(strings.TrimSpace(scannerName)) {
	case "opengrep":
		return parseOpengrepRawFindings(data)
	case "grype":
		return parseGrypeRawFindings(data)
	case "trivy":
		return parseTrivyRawFindings(data)
	case "trufflehog":
		return parseTrufflehogRawFindings(data)
	default:
		return nil
	}
}

func parseOpengrepRawFindings(data []byte) []NormalizedFinding {
	var payload struct {
		Results []struct {
			CheckID string `json:"check_id"`
			Path    string `json:"path"`
			Start   struct {
				Line int `json:"line"`
			} `json:"start"`
			Extra struct {
				Message  string `json:"message"`
				Severity string `json:"severity"`
			} `json:"extra"`
		} `json:"results"`
	}
	if err := json.Unmarshal(data, &payload); err != nil {
		return nil
	}
	out := make([]NormalizedFinding, 0, len(payload.Results))
	for _, r := range payload.Results {
		f := NormalizedFinding{
			Kind:     "sast",
			Scanner:  "opengrep",
			Severity: strings.ToUpper(strings.TrimSpace(r.Extra.Severity)),
			Title:    strings.TrimSpace(r.CheckID),
			FilePath: normalizeRepoRelativePath(r.Path),
			Line:     r.Start.Line,
			Message:  strings.TrimSpace(r.Extra.Message),
			Status:   "open",
		}
		f.Fingerprint = fingerprintForFinding(f)
		out = append(out, f)
	}
	return out
}

func parseGrypeRawFindings(data []byte) []NormalizedFinding {
	var payload struct {
		Matches []struct {
			Vulnerability struct {
				ID          string `json:"id"`
				Severity    string `json:"severity"`
				Description string `json:"description"`
				Fix         struct {
					Versions []string `json:"versions"`
				} `json:"fix"`
			} `json:"vulnerability"`
			Artifact struct {
				Name      string `json:"name"`
				Version   string `json:"version"`
				Locations []struct {
					Path string `json:"path"`
				} `json:"locations"`
			} `json:"artifact"`
		} `json:"matches"`
	}
	if err := json.Unmarshal(data, &payload); err != nil {
		return nil
	}
	out := make([]NormalizedFinding, 0, len(payload.Matches))
	for _, m := range payload.Matches {
		fix := ""
		if len(m.Vulnerability.Fix.Versions) > 0 {
			fix = strings.Join(m.Vulnerability.Fix.Versions, ", ")
		}
		filePath := ""
		if len(m.Artifact.Locations) > 0 {
			filePath = normalizeRepoRelativePath(m.Artifact.Locations[0].Path)
		}
		if filePath == "" {
			filePath = strings.Trim(strings.TrimSpace(m.Artifact.Name)+"@"+strings.TrimSpace(m.Artifact.Version), "@")
		}
		f := NormalizedFinding{
			Kind:     "sca",
			Scanner:  "grype",
			Severity: strings.ToUpper(strings.TrimSpace(m.Vulnerability.Severity)),
			Title:    strings.TrimSpace(m.Vulnerability.ID),
			FilePath: filePath,
			Package:  strings.TrimSpace(m.Artifact.Name),
			Version:  strings.TrimSpace(m.Artifact.Version),
			Fix:      strings.TrimSpace(fix),
			Message:  strings.TrimSpace(m.Vulnerability.Description),
			Status:   "open",
		}
		f.Fingerprint = fingerprintForFinding(f)
		out = append(out, f)
	}
	return out
}

func parseTrivyRawFindings(data []byte) []NormalizedFinding {
	var payload struct {
		Results []struct {
			Target            string `json:"Target"`
			Misconfigurations []struct {
				ID          string `json:"ID"`
				Title       string `json:"Title"`
				Description string `json:"Description"`
				Severity    string `json:"Severity"`
				IacMetadata struct {
					StartLine int `json:"StartLine"`
				} `json:"IacMetadata"`
			} `json:"Misconfigurations"`
		} `json:"Results"`
	}
	if err := json.Unmarshal(data, &payload); err != nil {
		return nil
	}
	var out []NormalizedFinding
	for _, r := range payload.Results {
		for _, m := range r.Misconfigurations {
			title := firstNonEmpty(strings.TrimSpace(m.ID), strings.TrimSpace(m.Title))
			if title == "" {
				title = "trivy-misconfig"
			}
			f := NormalizedFinding{
				Kind:     "iac",
				Scanner:  "trivy",
				Severity: strings.ToUpper(strings.TrimSpace(m.Severity)),
				Title:    title,
				FilePath: normalizeRepoRelativePath(r.Target),
				Line:     m.IacMetadata.StartLine,
				Message:  strings.TrimSpace(m.Description),
				Status:   "open",
			}
			f.Fingerprint = fingerprintForFinding(f)
			out = append(out, f)
		}
	}
	return out
}

func parseTrufflehogRawFindings(data []byte) []NormalizedFinding {
	var out []NormalizedFinding
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var rec struct {
			DetectorName   string         `json:"DetectorName"`
			Verified       bool           `json:"Verified"`
			SourceMetadata map[string]any `json:"SourceMetadata"`
		}
		if err := json.Unmarshal(line, &rec); err != nil {
			continue
		}
		file, lineNo := extractTrufflehogPathLine(rec.SourceMetadata)
		sev := "MEDIUM"
		msg := "Unverified secret candidate"
		if rec.Verified {
			sev = "HIGH"
			msg = "Verified secret detected"
		}
		title := strings.TrimSpace(rec.DetectorName)
		if title == "" {
			title = "Secret"
		}
		f := NormalizedFinding{
			Kind:     "secrets",
			Scanner:  "trufflehog",
			Severity: sev,
			Title:    title,
			FilePath: normalizeRepoRelativePath(file),
			Line:     lineNo,
			Message:  msg,
			Status:   "open",
		}
		f.Fingerprint = fingerprintForFinding(f)
		out = append(out, f)
	}
	return out
}

func fingerprintForFinding(f NormalizedFinding) string {
	// Prefer durable identity features and avoid volatile fields like exact line
	// numbers for code findings to reduce churn across nearby edits.
	parts := []string{
		strings.ToLower(strings.TrimSpace(f.Kind)),
		strings.ToLower(strings.TrimSpace(f.Scanner)),
		strings.ToLower(collapseSpace(f.Title)),
		strings.ToLower(strings.TrimSpace(f.Package)),
		strings.ToLower(strings.TrimSpace(f.Version)),
		strings.ToLower(strings.TrimSpace(f.FilePath)),
	}
	switch strings.ToLower(strings.TrimSpace(f.Kind)) {
	case "secrets":
		// Secret location line is often the best identifier available in raw fallback data.
		parts = append(parts, strconv.Itoa(f.Line))
	case "sast", "iac":
		parts = append(parts, strings.ToLower(collapseSpace(f.Message)))
	case "sca":
		// SCA matches are primarily package+version+vuln; line/message may vary by tool output.
	}
	sum := sha256.Sum256([]byte(strings.Join(parts, "|")))
	return hex.EncodeToString(sum[:])
}

func collapseSpace(s string) string {
	return strings.Join(strings.Fields(strings.TrimSpace(s)), " ")
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func normalizeRepoRelativePath(path string) string {
	p := strings.TrimSpace(path)
	if p == "" {
		return ""
	}
	p = strings.ReplaceAll(p, "\\", "/")
	if idx := strings.Index(p, "/ctrlscan-clone-"); idx >= 0 {
		rest := p[idx+1:]
		if slash := strings.Index(rest, "/"); slash >= 0 {
			return strings.TrimPrefix(rest[slash+1:], "/")
		}
	}
	return p
}

func extractTrufflehogPathLine(source map[string]any) (string, int) {
	if len(source) == 0 {
		return "", 0
	}
	if data, ok := source["Data"].(map[string]any); ok {
		if p, l := findPathLineInMap(data); p != "" || l != 0 {
			return p, l
		}
	}
	return findPathLineInMap(source)
}

func findPathLineInMap(m map[string]any) (string, int) {
	type node struct{ v any }
	q := []node{{v: m}}
	var firstPath string
	var firstLine int
	for len(q) > 0 {
		cur := q[0]
		q = q[1:]
		switch x := cur.v.(type) {
		case map[string]any:
			for k, v := range x {
				switch strings.ToLower(strings.TrimSpace(k)) {
				case "file", "filepath", "path":
					if firstPath == "" {
						if s, ok := v.(string); ok && strings.TrimSpace(s) != "" {
							firstPath = s
						}
					}
				case "line", "linenumber", "line_number":
					if firstLine == 0 {
						firstLine = anyToInt(v)
					}
				}
				switch vv := v.(type) {
				case map[string]any:
					q = append(q, node{v: vv})
				case []any:
					for _, item := range vv {
						q = append(q, node{v: item})
					}
				}
			}
		case []any:
			for _, item := range x {
				q = append(q, node{v: item})
			}
		}
		if firstPath != "" && firstLine != 0 {
			break
		}
	}
	return firstPath, firstLine
}

func anyToInt(v any) int {
	switch n := v.(type) {
	case float64:
		return int(n)
	case float32:
		return int(n)
	case int:
		return n
	case int64:
		return int(n)
	case int32:
		return int(n)
	case json.Number:
		i, _ := n.Int64()
		return int(i)
	case string:
		i, _ := strconv.Atoi(strings.TrimSpace(n))
		return i
	default:
		return 0
	}
}

func keyFor(kind, fp string) string {
	return strings.ToLower(strings.TrimSpace(kind)) + "|" + strings.ToLower(strings.TrimSpace(fp))
}

// Dedup keeps the first occurrence for each kind+fingerprint key.
func Dedup(in []NormalizedFinding) []NormalizedFinding {
	if len(in) == 0 {
		return nil
	}
	out := make([]NormalizedFinding, 0, len(in))
	seen := map[string]struct{}{}
	for _, f := range in {
		if strings.TrimSpace(f.Kind) == "" || strings.TrimSpace(f.Fingerprint) == "" {
			continue
		}
		k := keyFor(f.Kind, f.Fingerprint)
		if _, ok := seen[k]; ok {
			continue
		}
		seen[k] = struct{}{}
		out = append(out, f)
	}
	return out
}

func mustRFC3339(s string) string {
	if strings.TrimSpace(s) == "" {
		return ""
	}
	return s
}

func debugFindingLabel(f NormalizedFinding) string {
	return fmt.Sprintf("%s:%s:%s", f.Kind, f.Scanner, firstNonEmpty(f.Title, f.Package, f.FilePath))
}
