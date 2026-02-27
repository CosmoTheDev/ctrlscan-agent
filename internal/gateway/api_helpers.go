package gateway

import (
	"encoding/json"
	"fmt"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
)

// --- HTTP response helpers ---

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// pathID extracts a numeric path parameter by name from the request.
func pathID(r *http.Request, name string) (int64, error) {
	raw := r.PathValue(name)
	if raw == "" {
		return 0, fmt.Errorf("missing path parameter %q", name)
	}
	id, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid id %q", raw)
	}
	return id, nil
}

// --- Pagination ---

type paginationResult[T any] struct {
	Items      []T `json:"items"`
	Page       int `json:"page"`
	PageSize   int `json:"page_size"`
	Total      int `json:"total"`
	TotalPages int `json:"total_pages"`
}

type paginationParams struct {
	Page     int
	PageSize int
	Offset   int
}

func parsePaginationParams(r *http.Request, defaultPageSize, maxPageSize int) paginationParams {
	q := r.URL.Query()
	page := 1
	pageSize := defaultPageSize

	if v := strings.TrimSpace(q.Get("page")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			page = n
		}
	}
	if v := strings.TrimSpace(q.Get("page_size")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			pageSize = n
		}
	} else if v := strings.TrimSpace(q.Get("limit")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			pageSize = n
		}
	}
	if maxPageSize > 0 && pageSize > maxPageSize {
		pageSize = maxPageSize
	}
	if pageSize <= 0 {
		pageSize = defaultPageSize
	}

	if v := strings.TrimSpace(q.Get("offset")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			return paginationParams{
				Page:     (n / pageSize) + 1,
				PageSize: pageSize,
				Offset:   n,
			}
		}
	}

	return paginationParams{
		Page:     page,
		PageSize: pageSize,
		Offset:   (page - 1) * pageSize,
	}
}

// --- Slice utilities ---

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func normalizeDeleteIDs(ids []int64) ([]int64, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	seen := make(map[int64]struct{}, len(ids))
	out := make([]int64, 0, len(ids))
	for _, id := range ids {
		if id <= 0 {
			return nil, fmt.Errorf("ids must contain positive integers")
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, id)
	}
	return out, nil
}

func diffInt64(requested, existing []int64) []int64 {
	if len(requested) == 0 {
		return []int64{}
	}
	have := make(map[int64]struct{}, len(existing))
	for _, id := range existing {
		have[id] = struct{}{}
	}
	out := make([]int64, 0)
	for _, id := range requested {
		if _, ok := have[id]; !ok {
			out = append(out, id)
		}
	}
	return out
}

func placeholders(n int) string {
	if n <= 0 {
		return ""
	}
	parts := make([]string, n)
	for i := range parts {
		parts[i] = "?"
	}
	return strings.Join(parts, ",")
}

func toAnyArgs(ids []int64) []any {
	args := make([]any, len(ids))
	for i, id := range ids {
		args[i] = id
	}
	return args
}

// --- Path security utilities ---

// validateSafePath ensures that the resolved destination path stays within the allowed base directory.
// It returns an error if the path validation fails, preventing directory traversal attacks.
func validateSafePath(baseDir, filename string) (string, error) {
	// Resolve both the base directory and the destination file path to absolute paths
	absBaseDir, err := filepath.Abs(baseDir)
	if err != nil {
		return "", fmt.Errorf("failed to resolve base directory: %w", err)
	}

	destPath := filepath.Join(baseDir, filename)
	absDestPath, err := filepath.Abs(destPath)
	if err != nil {
		return "", fmt.Errorf("invalid filename: %w", err)
	}

	// Verify the absolute destination path is within the base directory
	if !strings.HasPrefix(absDestPath, absBaseDir+string(filepath.Separator)) {
		return "", fmt.Errorf("filename would escape allowed directory")
	}

	return absDestPath, nil
}
