package scanner

import (
	"context"
	"os/exec"
	"strings"
)

// isDockerAvailable returns true if the Docker daemon is reachable.
func isDockerAvailable(ctx context.Context) bool {
	cmd := exec.CommandContext(ctx, "docker", "info", "--format", "{{.ServerVersion}}")
	return cmd.Run() == nil
}

// dockerRun builds an exec.Cmd that runs the scanner inside a Docker container.
// repoPath is mounted read-only at /scan inside the container.
func dockerRun(ctx context.Context, image, repoPath string, args []string) *exec.Cmd {
	dockerArgs := []string{
		"run", "--rm",
		"--network", "host",
		"-v", repoPath + ":/scan:ro",
	}
	dockerArgs = append(dockerArgs, image)
	dockerArgs = append(dockerArgs, args...)
	return exec.CommandContext(ctx, "docker", dockerArgs...)
}

// isBinaryAvailable checks if name is executable in PATH or binDir.
func isBinaryAvailable(ctx context.Context, name, binDir string) bool {
	// Check binDir first.
	if binDir != "" {
		candidate := binDir + "/" + name
		cmd := exec.CommandContext(ctx, candidate, "--version")
		if cmd.Run() == nil {
			return true
		}
	}
	// Fall back to PATH.
	_, err := exec.LookPath(name)
	if err != nil {
		return false
	}
	// Verify it actually runs.
	cmd := exec.CommandContext(ctx, name, "--version")
	return cmd.Run() == nil
}

// resolveBinary returns the full path of name from binDir or PATH.
func resolveBinary(name, binDir string) string {
	if binDir != "" {
		candidate := binDir + "/" + name
		if p, err := exec.LookPath(candidate); err == nil {
			return p
		}
	}
	if p, err := exec.LookPath(name); err == nil {
		return p
	}
	// Return name and let the OS fail with a clean error.
	if binDir != "" && !strings.Contains(name, "/") {
		return binDir + "/" + name
	}
	return name
}
