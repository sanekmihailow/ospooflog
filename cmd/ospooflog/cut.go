package main

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
)

// cutList is a pre-detection line filter: any line a literal substring or a
// regexp touches is removed from the input entirely, so it reaches neither the
// detector nor the output (and is not reversible — there's nothing to restore).
// Unlike IgnoreList, which keeps a captured value visible but unmasked, cut
// deletes whole lines — meant for prompt/banner noise pasted into a log.
type cutList struct {
	literals []string
	patterns []*regexp.Regexp
}

// loadCutList parses path in the same flat format as --ignore: blank lines and
// '#' comments are skipped, "re:" prefixes a Go regexp, everything else is a
// literal substring. A regexp may span lines (use "(?s)") to drop a multi-line
// block. Leading/trailing whitespace on an entry is trimmed — use a regexp when
// exact whitespace matters.
func loadCutList(path string) (*cutList, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	c := &cutList{}
	scanner := bufio.NewScanner(f)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if pat, ok := strings.CutPrefix(line, "re:"); ok {
			re, err := regexp.Compile(pat)
			if err != nil {
				return nil, ruleErr(fmt.Errorf("%s:%d: bad regex %q: %w", path, lineNo, pat, err))
			}
			// An empty-matching pattern would mark every line for deletion.
			if re.MatchString("") {
				return nil, ruleErr(fmt.Errorf("%s:%d: regex %q matches the empty string — use a more specific pattern", path, lineNo, pat))
			}
			c.patterns = append(c.patterns, re)
			continue
		}
		c.literals = append(c.literals, line)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return c, nil
}

// Apply removes every line that any literal or pattern touches. A match span is
// widened to the full line(s) it covers (including the trailing newline), so a
// multi-line regexp drops the whole block. Returns text unchanged when nothing
// is configured or matched.
func (c *cutList) Apply(text string) string {
	if c == nil || (len(c.literals) == 0 && len(c.patterns) == 0) {
		return text
	}

	type span struct{ start, end int }
	var spans []span
	add := func(s, e int) {
		// Widen to whole lines: back to the char after the previous newline,
		// forward past the next newline.
		start := strings.LastIndexByte(text[:s], '\n') + 1
		end := e
		if nl := strings.IndexByte(text[e:], '\n'); nl < 0 {
			end = len(text)
		} else {
			end = e + nl + 1
		}
		spans = append(spans, span{start, end})
	}

	for _, lit := range c.literals {
		for off := 0; ; {
			i := strings.Index(text[off:], lit)
			if i < 0 {
				break
			}
			add(off+i, off+i+len(lit))
			off += i + len(lit)
		}
	}
	for _, re := range c.patterns {
		for _, loc := range re.FindAllStringIndex(text, -1) {
			add(loc[0], loc[1])
		}
	}
	if len(spans) == 0 {
		return text
	}

	sort.Slice(spans, func(i, j int) bool { return spans[i].start < spans[j].start })
	var b strings.Builder
	b.Grow(len(text))
	pos := 0
	for _, s := range spans {
		if s.start > pos {
			b.WriteString(text[pos:s.start])
		}
		if s.end > pos {
			pos = s.end
		}
	}
	b.WriteString(text[pos:])
	return b.String()
}
