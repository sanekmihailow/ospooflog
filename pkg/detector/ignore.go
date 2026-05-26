package detector

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"strings"
)

// IgnoreList is a user-supplied allowlist applied to captured Match
// values: literals checked by equality, patterns by regex match. A
// hit drops the Match without claiming any byte range, identical in
// spirit to isProtectedValue but populated at runtime from a file.
//
// Layering relative to other filters (lowest to highest priority):
//
//	regular detection            → captures value
//	  ↓
//	protectedValues (static)     → drops well-known non-PII
//	  ↓
//	IgnoreList (user-supplied)   → drops user-listed values
//	  ↓
//	overrides (--overrides)      → pre-pass: forces a specific replace,
//	                               sidesteps the detector entirely
type IgnoreList struct {
	literals map[string]bool
	patterns []*regexp.Regexp
}

// LoadIgnoreList parses path in the flat format documented in --help:
//   - blank lines and lines whose first non-space char is '#' are skipped
//   - lines starting with "re:" compile the remainder as a Go regexp
//   - everything else is a case-sensitive literal compared via equality
//
// Returns a wrapped parse error (with file:line) on bad regex so the
// user can find the offending line without reading a stack.
func LoadIgnoreList(path string) (*IgnoreList, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	il := &IgnoreList{literals: make(map[string]bool)}
	scanner := bufio.NewScanner(f)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if rest, ok := strings.CutPrefix(line, "re:"); ok {
			re, err := regexp.Compile(rest)
			if err != nil {
				return nil, fmt.Errorf("%s:%d: bad regex %q: %w", path, lineNo, rest, err)
			}
			il.patterns = append(il.patterns, re)
			continue
		}
		il.literals[line] = true
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return il, nil
}

// Match returns true when value is in the literal set or matches any
// of the loaded regex patterns.
func (l *IgnoreList) Match(value string) bool {
	if l == nil {
		return false
	}
	if l.literals[value] {
		return true
	}
	for _, re := range l.patterns {
		if re.MatchString(value) {
			return true
		}
	}
	return false
}
