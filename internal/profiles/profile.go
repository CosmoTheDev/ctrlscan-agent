// Package profiles manages scan policy profiles — named sets of AI instructions
// that focus triage on a specific threat model (OWASP, supply chain, etc.).
package profiles

import (
	"bytes"
	"context"
	"embed"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"go.yaml.in/yaml/v3"
)

//go:embed defaults/*.md
var defaultsFS embed.FS

// Profile is a parsed scan policy profile.
type Profile struct {
	// Name is the machine-readable identifier (matches the filename without .md).
	Name string `yaml:"name"`
	// Version is a monotonically increasing integer for future compatibility.
	Version int `yaml:"version"`
	// Description is a one-line human-readable summary.
	Description string `yaml:"description"`
	// MinSeverity is the minimum severity to pass to TriageFindings when this profile is active.
	// Valid values: "critical", "high", "medium", "low", "" (all).
	MinSeverity string `yaml:"min_severity"`
	// ScannerFocus restricts which finding types the AI analyses. Empty = all.
	// Valid values: "sca", "sast", "iac", "secrets".
	ScannerFocus []string `yaml:"scanner_focus"`
	// Tags are searchable labels for the profile.
	Tags []string `yaml:"tags"`
	// Body is the markdown content after the YAML frontmatter.
	// It is injected into the AI system prompt as additional triage context.
	Body string `yaml:"-"`
	// Bundled is true if this profile was loaded from the embedded defaults.
	Bundled bool `yaml:"-"`
}

// contextKey is the unexported key used for context storage.
type contextKey struct{}

// ToContext returns a child context with p stored as the active profile.
func ToContext(ctx context.Context, p *Profile) context.Context {
	return context.WithValue(ctx, contextKey{}, p)
}

// FromContext returns the active profile from ctx, or nil if none is set.
func FromContext(ctx context.Context) *Profile {
	p, _ := ctx.Value(contextKey{}).(*Profile)
	return p
}

// Load reads a profile by name from the user profile directory (falling back
// to bundled defaults). Returns an error if the profile does not exist.
func Load(name, profilesDir string) (*Profile, error) {
	if name == "" {
		return nil, nil
	}

	// Try user profile directory first.
	if profilesDir != "" {
		path := filepath.Join(profilesDir, name+".md")
		if data, err := os.ReadFile(path); err == nil {
			p, err := parse(data)
			if err != nil {
				return nil, fmt.Errorf("profiles: parse %q: %w", path, err)
			}
			if p.Name == "" {
				p.Name = name
			}
			return p, nil
		}
	}

	// Fall back to bundled defaults.
	data, err := defaultsFS.ReadFile("defaults/" + name + ".md")
	if err != nil {
		return nil, fmt.Errorf("profiles: profile %q not found", name)
	}
	p, err := parse(data)
	if err != nil {
		return nil, fmt.Errorf("profiles: parse bundled %q: %w", name, err)
	}
	if p.Name == "" {
		p.Name = name
	}
	p.Bundled = true
	return p, nil
}

// List returns all profiles available — user-defined (from profilesDir) merged
// with bundled defaults. User profiles shadow bundled ones of the same name.
func List(profilesDir string) ([]Profile, error) {
	byName := make(map[string]Profile)

	// Load bundled defaults first.
	entries, err := defaultsFS.ReadDir("defaults")
	if err != nil {
		return nil, fmt.Errorf("profiles: reading embedded defaults: %w", err)
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".md") {
			continue
		}
		data, err := defaultsFS.ReadFile("defaults/" + entry.Name())
		if err != nil {
			continue
		}
		p, err := parse(data)
		if err != nil {
			slog.Warn("profiles: skipping malformed bundled profile", "file", entry.Name(), "error", err)
			continue
		}
		if p.Name == "" {
			p.Name = strings.TrimSuffix(entry.Name(), ".md")
		}
		p.Bundled = true
		byName[p.Name] = *p
	}

	// User-defined profiles shadow bundled ones.
	if profilesDir != "" {
		_ = filepath.WalkDir(profilesDir, func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(d.Name(), ".md") {
				return nil
			}
			data, err := os.ReadFile(path)
			if err != nil {
				return nil
			}
			p, err := parse(data)
			if err != nil {
				slog.Warn("profiles: skipping malformed user profile", "file", path, "error", err)
				return nil
			}
			if p.Name == "" {
				p.Name = strings.TrimSuffix(d.Name(), ".md")
			}
			byName[p.Name] = *p
			return nil
		})
	}

	out := make([]Profile, 0, len(byName))
	for _, p := range byName {
		out = append(out, p)
	}
	return out, nil
}

// DefaultDir returns the default profiles directory: ~/.ctrlscan/profiles/.
func DefaultDir() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".ctrlscan", "profiles")
}

// Init creates the user profiles directory and copies any missing bundled
// profiles into it. Safe to call on every startup — skips files that already exist.
func Init(profilesDir string) error {
	if err := os.MkdirAll(profilesDir, 0o750); err != nil {
		return fmt.Errorf("profiles: create dir %s: %w", profilesDir, err)
	}

	entries, err := defaultsFS.ReadDir("defaults")
	if err != nil {
		return fmt.Errorf("profiles: reading embedded defaults: %w", err)
	}

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".md") {
			continue
		}
		dest := filepath.Join(profilesDir, entry.Name())
		if _, err := os.Stat(dest); err == nil {
			continue // already exists; don't overwrite user edits
		}
		data, err := defaultsFS.ReadFile("defaults/" + entry.Name())
		if err != nil {
			continue
		}
		if err := os.WriteFile(dest, data, 0o640); err != nil {
			slog.Warn("profiles: failed to write default profile", "file", dest, "error", err)
		}
	}
	return nil
}

// parse extracts YAML frontmatter and the markdown body from a profile file.
func parse(data []byte) (*Profile, error) {
	const delim = "---"

	// Strip leading whitespace/newlines.
	data = bytes.TrimLeft(data, " \t\n\r")

	if !bytes.HasPrefix(data, []byte(delim)) {
		// No frontmatter — treat the whole file as the body.
		return &Profile{Body: strings.TrimSpace(string(data))}, nil
	}

	// Remove opening ---.
	rest := bytes.TrimPrefix(data, []byte(delim))
	// Find closing ---.
	idx := bytes.Index(rest, []byte("\n"+delim))
	if idx < 0 {
		return nil, fmt.Errorf("unterminated YAML frontmatter (missing closing ---)")
	}

	frontmatter := rest[:idx]
	body := strings.TrimSpace(string(rest[idx+len("\n"+delim):]))

	var p Profile
	if err := yaml.Unmarshal(frontmatter, &p); err != nil {
		return nil, fmt.Errorf("invalid YAML frontmatter: %w", err)
	}
	p.Body = body
	return &p, nil
}

// FilterFindings filters a slice of finding types by the profile's ScannerFocus.
// If ScannerFocus is empty, all findings are returned unchanged.
// findingType should be one of "sca", "sast", "iac", "secrets".
func (p *Profile) AllowsFindingType(kind string) bool {
	if len(p.ScannerFocus) == 0 {
		return true
	}
	for _, f := range p.ScannerFocus {
		if strings.EqualFold(f, kind) {
			return true
		}
	}
	return false
}
