package gateway

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	cfgpkg "github.com/CosmoTheDev/ctrlscan-agent/internal/config"
	"github.com/CosmoTheDev/ctrlscan-agent/internal/notify"
)

// --- Config handlers ---

func (gw *Gateway) handleGetConfig(w http.ResponseWriter, r *http.Request) {
	gw.mu.RLock()
	cfgCopy := *gw.cfg
	cfgCopy.AI.OpenAIKey = redactSecret(cfgCopy.AI.OpenAIKey)
	cfgCopy.Git.GitHub = cloneGitHubConfigRedacted(cfgCopy.Git.GitHub)
	cfgCopy.Git.GitLab = cloneGitLabConfigRedacted(cfgCopy.Git.GitLab)
	cfgCopy.Git.Azure = cloneAzureConfigRedacted(cfgCopy.Git.Azure)
	cfgPath := gw.configPath
	gw.mu.RUnlock()
	writeJSON(w, http.StatusOK, map[string]any{
		"path":   cfgPath,
		"config": cfgCopy,
	})
}

func (gw *Gateway) handlePutConfig(w http.ResponseWriter, r *http.Request) {
	var req cfgpkg.Config
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Agent.Workers <= 0 {
		req.Agent.Workers = 3
	}
	if req.Agent.Mode == "" {
		req.Agent.Mode = "triage"
	}
	switch req.Agent.Mode {
	case "triage", "semi", "auto":
	default:
		writeError(w, http.StatusBadRequest, "invalid agent.mode")
		return
	}
	if req.Gateway.Port == 0 {
		req.Gateway.Port = gw.cfg.Gateway.Port
	}
	mergeMaskedSecrets(&req, gw.cfg)

	gw.mu.Lock()
	*gw.cfg = req
	cfgPath := gw.configPath
	gw.mu.Unlock()
	if err := cfgpkg.Save(&req, cfgPath); err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("saving config: %v", err))
		return
	}
	gw.broadcaster.send(SSEEvent{Type: "config.updated"})
	writeJSON(w, http.StatusOK, map[string]string{"status": "saved"})
}

func mergeMaskedSecrets(dst *cfgpkg.Config, current *cfgpkg.Config) {
	if dst == nil || current == nil {
		return
	}
	if strings.Contains(dst.AI.OpenAIKey, "*") {
		dst.AI.OpenAIKey = current.AI.OpenAIKey
	}

	for i := range dst.Git.GitHub {
		if i < len(current.Git.GitHub) && strings.Contains(dst.Git.GitHub[i].Token, "*") {
			dst.Git.GitHub[i].Token = current.Git.GitHub[i].Token
		}
	}
	for i := range dst.Git.GitLab {
		if i < len(current.Git.GitLab) && strings.Contains(dst.Git.GitLab[i].Token, "*") {
			dst.Git.GitLab[i].Token = current.Git.GitLab[i].Token
		}
	}
	for i := range dst.Git.Azure {
		if i < len(current.Git.Azure) && strings.Contains(dst.Git.Azure[i].Token, "*") {
			dst.Git.Azure[i].Token = current.Git.Azure[i].Token
		}
	}
}

func redactSecret(v string) string {
	if v == "" {
		return ""
	}
	if len(v) <= 8 {
		return "********"
	}
	return v[:4] + strings.Repeat("*", len(v)-8) + v[len(v)-4:]
}

func cloneGitHubConfigRedacted(in []cfgpkg.GitHubConfig) []cfgpkg.GitHubConfig {
	out := make([]cfgpkg.GitHubConfig, len(in))
	for i, v := range in {
		out[i] = v
		out[i].Token = redactSecret(v.Token)
	}
	return out
}

func cloneGitLabConfigRedacted(in []cfgpkg.GitLabConfig) []cfgpkg.GitLabConfig {
	out := make([]cfgpkg.GitLabConfig, len(in))
	for i, v := range in {
		out[i] = v
		out[i].Token = redactSecret(v.Token)
	}
	return out
}

func cloneAzureConfigRedacted(in []cfgpkg.AzureConfig) []cfgpkg.AzureConfig {
	out := make([]cfgpkg.AzureConfig, len(in))
	for i, v := range in {
		out[i] = v
		out[i].Token = redactSecret(v.Token)
	}
	return out
}

// --- Log handlers ---

type logFileEntry struct {
	Name    string `json:"name"`
	Size    int64  `json:"size"`
	ModTime string `json:"mod_time"`
}

type logsResponse struct {
	LogDir       string         `json:"log_dir"`
	SelectedFile string         `json:"selected_file,omitempty"`
	Tail         int            `json:"tail"`
	Files        []logFileEntry `json:"files"`
	Lines        []string       `json:"lines"`
}

func (gw *Gateway) handleLogs(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	fileName := strings.TrimSpace(q.Get("file"))
	tail := 200
	if raw := strings.TrimSpace(q.Get("tail")); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 {
			writeError(w, http.StatusBadRequest, "tail must be a positive integer")
			return
		}
		if n > 5000 {
			n = 5000
		}
		tail = n
	}

	gw.mu.RLock()
	logDir := gw.logDir
	gw.mu.RUnlock()
	if logDir == "" {
		logDir = "logs"
	}

	files, err := listLogFiles(logDir)
	if err != nil {
		if os.IsNotExist(err) {
			writeJSON(w, http.StatusOK, logsResponse{
				LogDir: logDir, Tail: tail, Files: []logFileEntry{}, Lines: []string{},
			})
			return
		}
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("listing logs: %v", err))
		return
	}

	if fileName == "" {
		for _, f := range files {
			if f.Name == "gateway.log" {
				fileName = f.Name
				break
			}
		}
		if fileName == "" && len(files) > 0 {
			fileName = files[0].Name
		}
	}

	if fileName != "" {
		// Reject any path that is not a bare file name (no directory
		// separators or parent-directory references).
		clean := filepath.Base(fileName)
		if clean != fileName || strings.Contains(fileName, "..") {
			writeError(w, http.StatusBadRequest, "invalid file name")
			return
		}
		fileName = clean
	}

	var lines []string
	if fileName != "" {
		absLogDir, absErr := filepath.Abs(logDir)
		if absErr != nil {
			writeError(w, http.StatusInternalServerError, "resolving log directory")
			return
		}
		lines, err = tailFileLines(absLogDir, fileName, tail)
		if err != nil {
			if os.IsNotExist(err) {
				writeError(w, http.StatusNotFound, "log file not found")
				return
			}
			writeError(w, http.StatusInternalServerError, fmt.Sprintf("reading log file: %v", err))
			return
		}
	}

	writeJSON(w, http.StatusOK, logsResponse{
		LogDir:       logDir,
		SelectedFile: fileName,
		Tail:         tail,
		Files:        files,
		Lines:        lines,
	})
}

func listLogFiles(dir string) ([]logFileEntry, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	type row struct {
		logFileEntry
		mod time.Time
	}
	rows := make([]row, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(name, ".log") {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		rows = append(rows, row{
			logFileEntry: logFileEntry{
				Name:    name,
				Size:    info.Size(),
				ModTime: info.ModTime().UTC().Format(time.RFC3339),
			},
			mod: info.ModTime(),
		})
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Name == "gateway.log" {
			return true
		}
		if rows[j].Name == "gateway.log" {
			return false
		}
		return rows[i].mod.After(rows[j].mod)
	})
	out := make([]logFileEntry, 0, len(rows))
	for _, r := range rows {
		out = append(out, r.logFileEntry)
	}
	return out, nil
}

// tailFileLines reads a file from absLogDir/name, returning up to tail lines.
// absLogDir must be an absolute path; name must be a single file-name component
// (already stripped of directory separators by the caller). The function
// re-validates the final path is within absLogDir before opening it.
func tailFileLines(absLogDir, name string, tail int) ([]string, error) {
	// Reconstruct and verify the path is within the safe directory.
	// This co-locates the guard with the os.Open so CodeQL's taint analysis
	// can see the sanitization at the sink rather than relying on inter-procedural
	// propagation from the caller.
	p := filepath.Join(absLogDir, name)
	abs, err := filepath.Abs(p)
	if err != nil || !strings.HasPrefix(abs, absLogDir+string(filepath.Separator)) {
		return nil, fmt.Errorf("invalid log file path")
	}
	f, err := os.Open(abs) // #nosec G304 -- abs validated above: same-dir prefix check
	if err != nil {
		return nil, err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	var lines []string
	for sc.Scan() {
		lines = append(lines, sc.Text())
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if tail <= 0 || len(lines) <= tail {
		if lines == nil {
			return []string{}, nil
		}
		return lines, nil
	}
	return lines[len(lines)-tail:], nil
}

// --- SSE event stream ---

// handleEvents streams SSE to the client. Each line is a JSON SSEEvent.
// Clients receive a "connected" event immediately, then live updates.
func (gw *Gateway) handleEvents(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeError(w, http.StatusInternalServerError, "streaming not supported")
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no") // disable nginx buffering if behind a proxy

	ch := gw.broadcaster.subscribe()
	defer gw.broadcaster.unsubscribe(ch)

	// Send initial connected event with current status.
	status := gw.currentStatus()
	connected, _ := json.Marshal(SSEEvent{Type: "connected", Payload: status})
	// SSE endpoint writes JSON event frames, not HTML; HTML escaping is not applicable here.
	// nosemgrep: go.lang.security.audit.xss.no-fprintf-to-responsewriter.no-fprintf-to-responsewriter
	fmt.Fprintf(w, "data: %s\n\n", connected)
	flusher.Flush()

	for {
		select {
		case <-r.Context().Done():
			return
		case frame, ok := <-ch:
			if !ok {
				return
			}
			// SSE endpoint streams prebuilt frames (event-stream), not HTML template output.
			// nosemgrep: go.lang.security.audit.xss.no-direct-write-to-responsewriter.no-direct-write-to-responsewriter
			w.Write(frame)
			flusher.Flush()
		}
	}
}

// --- Notification handler ---

// handleNotifyTest sends a test notification through all configured channels.
func (gw *Gateway) handleNotifyTest(w http.ResponseWriter, r *http.Request) {
	if !gw.notifier.IsAnyConfigured() {
		writeError(w, http.StatusBadRequest, "no notification channels configured")
		return
	}
	gw.notifier.Notify(r.Context(), notify.Event{
		Type:     "test",
		Title:    "ctrlscan-agent test notification",
		Body:     "Notification delivery is working correctly.",
		Severity: "low",
	})
	writeJSON(w, http.StatusOK, map[string]string{"status": "sent"})
}

// --- Advisory state handler ---

// handleAdvisoryState returns the current OSV advisory feed poll state.
func (gw *Gateway) handleAdvisoryState(w http.ResponseWriter, r *http.Request) {
	type advisoryStateRow struct {
		ID             int64  `db:"id"              json:"id"`
		Source         string `db:"source"          json:"source"`
		LastPolledAt   string `db:"last_polled_at"  json:"last_polled_at"`
		LastModified   string `db:"last_modified"   json:"last_modified"`
		AdvisoriesSeen int64  `db:"advisories_seen" json:"advisories_seen"`
		ReposQueued    int64  `db:"repos_queued"    json:"repos_queued"`
		CreatedAt      string `db:"created_at"      json:"created_at"`
		UpdatedAt      string `db:"updated_at"      json:"updated_at"`
	}
	var state advisoryStateRow
	err := gw.db.Get(r.Context(), &state,
		`SELECT id, source, last_polled_at, last_modified, advisories_seen, repos_queued, created_at, updated_at
		 FROM advisory_poll_state WHERE source = 'osv' LIMIT 1`)
	if err != nil {
		msg := strings.ToLower(err.Error())
		if strings.Contains(msg, "no such table") {
			writeJSON(w, http.StatusOK, map[string]any{
				"source":  "osv",
				"enabled": false,
				"note":    "advisory_feed migration has not been applied yet",
			})
			return
		}
		if strings.Contains(msg, "no rows") || strings.Contains(msg, "sql: no rows") {
			writeJSON(w, http.StatusOK, map[string]any{
				"source":          "osv",
				"enabled":         false,
				"last_polled_at":  "",
				"advisories_seen": 0,
				"repos_queued":    0,
				"note":            "advisory_feed not yet triggered; add \"advisory_feed\" to agent.scan_targets",
			})
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, state)
}
