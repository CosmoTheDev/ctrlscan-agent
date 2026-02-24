package agent

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// cleanPatch normalises AI-generated patches before validation or application.
// It strips markdown code fences (```diff … ```) that local models sometimes
// embed inside the JSON "patch" field, and normalises CRLF to LF.
func cleanPatch(raw string) string {
	s := strings.ReplaceAll(raw, "\r\n", "\n")
	lines := strings.Split(s, "\n")

	// Find the first markdown fence line.
	start := -1
	for i, l := range lines {
		if strings.HasPrefix(strings.TrimSpace(l), "```") {
			start = i
			break
		}
	}
	if start < 0 {
		return s // no fences found — return as-is (only CRLF normalised)
	}

	// Content starts on the line after the opening fence.
	contentStart := start + 1

	// Find the closing fence (search backwards from the end).
	end := len(lines)
	for i := len(lines) - 1; i > contentStart; i-- {
		if strings.HasPrefix(strings.TrimSpace(lines[i]), "```") {
			end = i
			break
		}
	}

	return strings.Join(lines[contentStart:end], "\n")
}

// repairHunkHeaders reconstructs @@ line-range headers that AI models sometimes
// emit as bare "@@" with no numbers. git apply rejects these with "No valid
// patches in input". We recover by reading the target file and searching for
// the hunk's context/deleted lines to determine the correct offsets.
//
// repoPath is the local clone root used to resolve the target file.
func repairHunkHeaders(patch, repoPath string) string {
	lines := strings.Split(patch, "\n")

	// Check whether any repair is needed.
	needsRepair := false
	for _, l := range lines {
		if isBareHunkHeader(l) {
			needsRepair = true
			break
		}
	}
	if !needsRepair {
		return patch
	}

	// Determine target file from "+++ b/path" (or "+++ path") header.
	targetFile := ""
	for _, l := range lines {
		if strings.HasPrefix(l, "+++ ") {
			p := strings.TrimPrefix(l, "+++ ")
			p = strings.TrimPrefix(p, "b/")
			targetFile = strings.TrimSpace(p)
			break
		}
	}
	if targetFile == "" {
		return patch
	}

	content, err := os.ReadFile(filepath.Join(repoPath, targetFile))
	if err != nil {
		return patch // file not found; let git give the real error
	}
	fileLines := strings.Split(strings.ReplaceAll(string(content), "\r\n", "\n"), "\n")

	var out []string
	i := 0
	for i < len(lines) {
		l := lines[i]
		if isBareHunkHeader(l) {
			// Collect the hunk body (lines until next @@ or end of patch).
			bodyStart := i + 1
			bodyEnd := len(lines)
			for j := bodyStart; j < len(lines); j++ {
				if strings.HasPrefix(lines[j], "@@") {
					bodyEnd = j
					break
				}
			}
			body := lines[bodyStart:bodyEnd]

			// Build the old-side line sequence (context + deleted) for file search.
			var oldSide []string
			oldCount, newCount := 0, 0
			for _, bl := range body {
				switch {
				case strings.HasPrefix(bl, "-"):
					oldSide = append(oldSide, strings.TrimPrefix(bl, "-"))
					oldCount++
				case strings.HasPrefix(bl, "+"):
					newCount++
				default:
					// context line (leading space or empty)
					ctx := bl
					if strings.HasPrefix(bl, " ") {
						ctx = strings.TrimPrefix(bl, " ")
					}
					oldSide = append(oldSide, ctx)
					oldCount++
					newCount++
				}
			}

			// Find old-side lines in the file.
			lineNo := findConsecutiveInFile(fileLines, oldSide)
			if lineNo >= 0 {
				out = append(out, fmt.Sprintf("@@ -%d,%d +%d,%d @@", lineNo+1, oldCount, lineNo+1, newCount))
			} else {
				out = append(out, l) // couldn't repair; keep bare @@ and let git error
			}
			i++
			continue
		}
		out = append(out, l)
		i++
	}
	return strings.Join(out, "\n")
}

// isBareHunkHeader returns true for a @@ line that is missing line numbers,
// e.g. "@@" or "@@ @@" but not "@@ -1,3 +1,4 @@".
func isBareHunkHeader(l string) bool {
	t := strings.TrimSpace(l)
	if !strings.HasPrefix(t, "@@") {
		return false
	}
	// A properly-formed header has at least one "-" digit after the opening @@.
	return !strings.Contains(t, "-")
}

// findConsecutiveInFile returns the 0-based index of the first line in
// fileLines where all needles appear consecutively in order. Returns -1 if not
// found. Trailing whitespace is ignored for comparison.
func findConsecutiveInFile(fileLines, needles []string) int {
	if len(needles) == 0 {
		return -1
	}
	for i := 0; i <= len(fileLines)-len(needles); i++ {
		match := true
		for j, needle := range needles {
			if strings.TrimRight(fileLines[i+j], " \t") != strings.TrimRight(needle, " \t") {
				match = false
				break
			}
		}
		if match {
			return i
		}
	}
	return -1
}

// looksLikeUnifiedDiffPatch performs a lightweight structural check before we
// queue/apply an AI-generated patch.
func looksLikeUnifiedDiffPatch(patch string) bool {
	p := strings.TrimSpace(patch)
	if p == "" {
		return false
	}
	hasOld := false
	hasNew := false
	hasHunk := false
	hasChange := false
	for _, line := range strings.Split(p, "\n") {
		switch {
		case strings.HasPrefix(line, "--- "):
			hasOld = true
		case strings.HasPrefix(line, "+++ "):
			hasNew = true
		case strings.HasPrefix(line, "@@"):
			hasHunk = true
		case strings.HasPrefix(line, "+") || strings.HasPrefix(line, "-"):
			if !strings.HasPrefix(line, "+++ ") && !strings.HasPrefix(line, "--- ") {
				hasChange = true
			}
		}
	}
	return hasOld && hasNew && hasHunk && hasChange
}
