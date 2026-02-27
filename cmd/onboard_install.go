package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

func scannerInstallSkipReason(scanner, binDir string) string {
	switch scanner {
	case "grype":
		grypePath := findTool("grype", binDir)
		syftPath := findTool("syft", binDir)
		if grypePath != "" && syftPath != "" {
			return fmt.Sprintf("already installed (grype: %s, syft: %s) — skipping", grypePath, syftPath)
		}
	case "opengrep", "trufflehog", "trivy":
		if path := findTool(scanner, binDir); path != "" {
			return fmt.Sprintf("already installed (%s) — skipping", path)
		}
	}
	return ""
}

// installScannerTool downloads a scanner binary to binDir.
func installScannerTool(scanner, binDir string) error {
	goos := runtime.GOOS
	goarch := runtime.GOARCH

	var installCmd *exec.Cmd

	switch scanner {
	case "grype":
		// Install syft first (required by grype for SBOM generation)
		if err := runInstallScript("https://raw.githubusercontent.com/anchore/syft/main/install.sh",
			"-b", binDir); err != nil {
			return fmt.Errorf("syft: %w", err)
		}
		return runInstallScript("https://raw.githubusercontent.com/anchore/grype/main/install.sh",
			"-b", binDir)

	case "trufflehog":
		return runInstallScript("https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh",
			"-b", binDir)

	case "trivy":
		return runInstallScript("https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh",
			"-b", binDir)

	case "opengrep":
		// opengrep distributes releases on GitHub — attempt via curl.
		return installOpengrep(goos, goarch, binDir)

	default:
		installCmd = exec.Command("which", scanner)
		if err := installCmd.Run(); err != nil {
			return fmt.Errorf("%s not found; install manually", scanner)
		}
		return nil
	}
}

// runInstallScript runs a shell install script from a URL.
func runInstallScript(url string, args ...string) error {
	allArgs := append([]string{"-sSfL", url, "|", "sh", "-s", "--"}, args...)
	_ = allArgs

	var lastErr error
	for attempt := 1; attempt <= 3; attempt++ {
		// Use sh -c to allow piped commands.
		cmdStr := fmt.Sprintf("curl -sSfL %s | sh -s -- %s", url, strings.Join(args, " "))
		// nosemgrep: go.lang.security.audit.dangerous-exec-command.dangerous-exec-command
		cmd := exec.Command("sh", "-c", cmdStr)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr

		if err := cmd.Run(); err == nil {
			return nil
		} else {
			lastErr = err
		}

		if attempt < 3 {
			time.Sleep(time.Duration(attempt) * time.Second)
		}
	}

	return lastErr
}

// installOpengrep downloads the opengrep binary from GitHub releases.
func installOpengrep(goos, goarch, binDir string) error {
	ctx := context.Background()
	release, err := fetchOpengrepLatestRelease(ctx)
	if err != nil {
		return fmt.Errorf("fetching opengrep release: %w", err)
	}

	assetName, url, err := selectOpengrepAsset(goos, goarch, release.Assets)
	if err != nil {
		return fmt.Errorf("selecting opengrep asset for %s/%s: %w", goos, goarch, err)
	}

	dest := filepath.Join(binDir, "opengrep")
	tmpDest := dest + ".download"
	// nosemgrep: go.lang.security.audit.dangerous-exec-command.dangerous-exec-command
	cmd := exec.Command("sh", "-c",
		fmt.Sprintf("curl --retry 3 --retry-all-errors -sSfL -o %q %q && mv %q %q && chmod +x %q",
			tmpDest, url, tmpDest, dest, dest))
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("downloading %s from %s: %w", assetName, url, err)
	}
	return nil
}

type opengrepRelease struct {
	TagName string              `json:"tag_name"`
	Assets  []opengrepAssetInfo `json:"assets"`
}

type opengrepAssetInfo struct {
	Name string `json:"name"`
	URL  string `json:"browser_download_url"`
}

func fetchOpengrepLatestRelease(ctx context.Context) (*opengrepRelease, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		"https://api.github.com/repos/opengrep/opengrep/releases/latest", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")

	client := &http.Client{Timeout: 20 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("github api status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var rel opengrepRelease
	if err := json.NewDecoder(resp.Body).Decode(&rel); err != nil {
		return nil, err
	}
	if rel.TagName == "" || len(rel.Assets) == 0 {
		return nil, fmt.Errorf("release metadata missing tag/assets")
	}
	return &rel, nil
}

func selectOpengrepAsset(goos, goarch string, assets []opengrepAssetInfo) (name string, url string, err error) {
	var candidates []string
	switch goos {
	case "darwin":
		switch goarch {
		case "arm64":
			candidates = []string{"opengrep_osx_arm64"}
		case "amd64":
			candidates = []string{"opengrep_osx_x86"}
		}
	case "linux":
		switch goarch {
		case "arm64":
			candidates = []string{"opengrep_manylinux_aarch64", "opengrep_musllinux_aarch64"}
		case "amd64":
			candidates = []string{"opengrep_manylinux_x86", "opengrep_musllinux_x86"}
		}
	case "windows":
		if goarch == "amd64" {
			candidates = []string{"opengrep_windows_x86.exe"}
		}
	}

	if len(candidates) == 0 {
		return "", "", fmt.Errorf("unsupported platform")
	}

	assetMap := make(map[string]string, len(assets))
	for _, a := range assets {
		assetMap[a.Name] = a.URL
	}
	for _, c := range candidates {
		if u := assetMap[c]; u != "" {
			return c, u, nil
		}
	}

	return "", "", fmt.Errorf("no matching asset found (tried: %s)", strings.Join(candidates, ", "))
}
