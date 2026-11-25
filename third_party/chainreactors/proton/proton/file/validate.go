package file

import (
	"regexp"
	"strings"
)

var placeholderPattern = regexp.MustCompile(`(?i)^(test|example|dummy|sample|placeholder|changeme|your.?api.?key|insert.?here|xxx+|todo|fixme|replace.?me)$`)

// isLikelySecret returns false for extracted values that are clearly not real secrets.
func isLikelySecret(value string) bool {
	if len(value) < 4 {
		return false
	}

	if isAllSameChar(value) {
		return false
	}

	if placeholderPattern.MatchString(strings.TrimSpace(value)) {
		return false
	}

	if len(value) > 16 && countDistinctChars(value) < 4 {
		return false
	}

	return true
}

func isAllSameChar(s string) bool {
	if len(s) == 0 {
		return true
	}
	c := s[0]
	for i := 1; i < len(s); i++ {
		if s[i] != c {
			return false
		}
	}
	return true
}

func countDistinctChars(s string) int {
	seen := make(map[byte]struct{}, 16)
	for i := 0; i < len(s); i++ {
		seen[s[i]] = struct{}{}
	}
	return len(seen)
}
