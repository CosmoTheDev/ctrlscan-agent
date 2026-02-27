package osv

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

const baseURL = "https://api.osv.dev/v1"

// Client is an HTTP client for the OSV.dev API.
// OSV is free, unauthenticated, and allows ~100 req/s.
type Client struct {
	http *http.Client
}

// New returns a Client with a 15-second timeout.
func New() *Client {
	return &Client{
		http: &http.Client{Timeout: 15 * time.Second},
	}
}

// BatchQuery queries OSV for multiple packages at once (POST /v1/querybatch).
// Up to 1000 entries per request; callers are responsible for chunking larger sets.
// Results are returned in the same order as queries.
func (c *Client) BatchQuery(ctx context.Context, queries []PackageQuery) ([]QueryResult, error) {
	if len(queries) == 0 {
		return nil, nil
	}

	entries := make([]batchQueryEntry, len(queries))
	for i, q := range queries {
		entries[i] = batchQueryEntry{Package: q.Package, Version: q.Version}
	}

	body, err := json.Marshal(BatchQueryRequest{Queries: entries})
	if err != nil {
		return nil, fmt.Errorf("osv: marshal batch request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+"/querybatch", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("osv: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("osv: batch query: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("osv: batch query HTTP %d: %s", resp.StatusCode, string(b))
	}

	var result BatchQueryResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("osv: decode batch response: %w", err)
	}
	return result.Results, nil
}

// ListModifiedSince fetches all vulnerabilities modified after the given RFC3339 timestamp.
// Pass an empty string to fetch from the beginning. Handles pagination automatically.
func (c *Client) ListModifiedSince(ctx context.Context, since string) ([]Vuln, error) {
	var all []Vuln
	pageToken := ""

	for {
		params := url.Values{}
		if since != "" {
			params.Set("modified_since", since)
		}
		if pageToken != "" {
			params.Set("page_token", pageToken)
		}

		reqURL := baseURL + "/vulns"
		if len(params) > 0 {
			reqURL += "?" + params.Encode()
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
		if err != nil {
			return nil, fmt.Errorf("osv: build list request: %w", err)
		}

		resp, err := c.http.Do(req)
		if err != nil {
			return nil, fmt.Errorf("osv: list vulns: %w", err)
		}

		if resp.StatusCode != http.StatusOK {
			b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
			resp.Body.Close()
			return nil, fmt.Errorf("osv: list vulns HTTP %d: %s", resp.StatusCode, string(b))
		}

		var page ListResult
		if err := json.NewDecoder(resp.Body).Decode(&page); err != nil {
			resp.Body.Close()
			return nil, fmt.Errorf("osv: decode list response: %w", err)
		}
		resp.Body.Close()

		all = append(all, page.Vulns...)

		if page.NextPageToken == "" {
			break
		}
		pageToken = page.NextPageToken

		// Respect context cancellation between pages.
		if ctx.Err() != nil {
			return all, ctx.Err()
		}
	}

	return all, nil
}
