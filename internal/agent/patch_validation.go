package agent

import "strings"

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
