package gateway

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/CosmoTheDev/ctrlscan-agent/internal/profiles"
)

type createProfileRequest struct {
	Name    string `json:"name"`
	Content string `json:"content"` // full markdown including frontmatter
}

func (gw *Gateway) profilesDir() string {
	if gw.cfg != nil && gw.cfg.Profiles.Dir != "" {
		return gw.cfg.Profiles.Dir
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".ctrlscan", "profiles")
}

// handleListProfiles returns all available profiles (bundled + user-defined).
func (gw *Gateway) handleListProfiles(w http.ResponseWriter, _ *http.Request) {
	all, err := profiles.List(gw.profilesDir())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	type profileSummary struct {
		Name         string   `json:"name"`
		Description  string   `json:"description"`
		MinSeverity  string   `json:"min_severity"`
		ScannerFocus []string `json:"scanner_focus"`
		Tags         []string `json:"tags"`
		Bundled      bool     `json:"bundled"`
	}
	out := make([]profileSummary, 0, len(all))
	for _, p := range all {
		out = append(out, profileSummary{
			Name:         p.Name,
			Description:  p.Description,
			MinSeverity:  p.MinSeverity,
			ScannerFocus: p.ScannerFocus,
			Tags:         p.Tags,
			Bundled:      p.Bundled,
		})
	}
	writeJSON(w, http.StatusOK, out)
}

// handleGetProfile returns the full content of a single profile.
func (gw *Gateway) handleGetProfile(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if name == "" {
		writeError(w, http.StatusBadRequest, "profile name is required")
		return
	}
	p, err := profiles.Load(name, gw.profilesDir())
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, p)
}

// handleCreateProfile creates or overwrites a user-defined profile.
func (gw *Gateway) handleCreateProfile(w http.ResponseWriter, r *http.Request) {
	var req createProfileRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" || strings.ContainsAny(req.Name, `/\.`) {
		writeError(w, http.StatusBadRequest, "invalid profile name")
		return
	}
	dir := gw.profilesDir()
	if err := os.MkdirAll(dir, 0o750); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create profiles directory")
		return
	}
	dest := filepath.Join(dir, req.Name+".md")
	if err := os.WriteFile(dest, []byte(req.Content), 0o640); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to write profile")
		return
	}
	slog.Info("gateway: profile created/updated", "name", req.Name)
	writeJSON(w, http.StatusOK, map[string]string{"name": req.Name, "status": "saved"})
}

// handleDeleteProfile deletes a user-defined profile. Bundled profiles cannot be deleted.
func (gw *Gateway) handleDeleteProfile(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if name == "" {
		writeError(w, http.StatusBadRequest, "profile name is required")
		return
	}
	path := filepath.Join(gw.profilesDir(), name+".md")
	if err := os.Remove(path); err != nil {
		if os.IsNotExist(err) {
			writeError(w, http.StatusNotFound, "profile not found in user profiles directory (bundled profiles cannot be deleted)")
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	slog.Info("gateway: profile deleted", "name", name)
	writeJSON(w, http.StatusOK, map[string]string{"name": name, "status": "deleted"})
}
