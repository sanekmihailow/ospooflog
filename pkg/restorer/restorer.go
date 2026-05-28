// Package restorer turns an AI response built on the obfuscated text back
// into one with the user's real values.
//
// Two modes:
//
//   - Fast (default): strings.NewReplacer with replacements ordered by
//     length descending. Runs in linear time. Fails on the rare case where
//     a registered replace value is a prefix of an unrelated string the AI
//     produces (e.g. "192.168.1.1" inside "192.168.1.10").
//
//   - Strict: regex-free manual scan with word-boundary checks before each
//     substitution. Slightly more expensive, immune to the substring trap.
//     Enabled with --strict-restore.
package restorer

import (
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/sanekmihailow/ospooflog/pkg/mapper"
)

type Restorer struct {
	mapper *mapper.Mapper
	strict bool
}

func New(m *mapper.Mapper, strict bool) *Restorer {
	return &Restorer{mapper: m, strict: strict}
}

func (r *Restorer) Restore(text string) string {
	entries := r.mapper.Entries()
	if len(entries) == 0 || text == "" {
		return text
	}
	sort.Slice(entries, func(i, j int) bool {
		return len(entries[i].Replace) > len(entries[j].Replace)
	})
	if r.strict {
		return restoreStrict(text, entries)
	}
	return restoreFast(text, entries)
}

func restoreFast(text string, entries []mapper.Entry) string {
	pairs := make([]string, 0, len(entries)*2)
	for _, e := range entries {
		if e.Replace == "" {
			continue
		}
		pairs = append(pairs, e.Replace, e.Origin)
	}
	if len(pairs) == 0 {
		return text
	}
	return strings.NewReplacer(pairs...).Replace(text)
}

type span struct {
	start, end int
	origin     string
}

func restoreStrict(text string, entries []mapper.Entry) string {
	var spans []span
	for _, e := range entries {
		if e.Replace == "" {
			continue
		}
		idx := 0
		for idx < len(text) {
			i := strings.Index(text[idx:], e.Replace)
			if i < 0 {
				break
			}
			start := idx + i
			end := start + len(e.Replace)
			if isWordBoundary(text, start, end) && !overlapsSpans(spans, start, end) {
				spans = append(spans, span{start, end, e.Origin})
			}
			idx = start + 1
		}
	}
	sort.Slice(spans, func(i, j int) bool { return spans[i].start < spans[j].start })

	var b strings.Builder
	b.Grow(len(text))
	pos := 0
	for _, s := range spans {
		if s.start < pos {
			continue
		}
		b.WriteString(text[pos:s.start])
		b.WriteString(s.origin)
		pos = s.end
	}
	b.WriteString(text[pos:])
	return b.String()
}

func overlapsSpans(spans []span, start, end int) bool {
	for _, s := range spans {
		if start < s.end && end > s.start {
			return true
		}
	}
	return false
}

func isWordChar(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9') || b == '_'
}

// isWordRune is the Unicode-aware counterpart used for the *neighbours* of the
// substring being checked. Fake tokens themselves are always ASCII so the
// inside bytes are still byte-checked, but neighbours may be any UTF-8 rune
// (cyrillic, CJK, …) and must be decoded as runes — checking a single
// continuation byte falsely reports "not a word char" and lets the restore
// splice through a non-ASCII word.
func isWordRune(r rune) bool {
	return unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_'
}

// isWordBoundary returns true if the substring [start:end] is not glued to
// adjacent word characters on the side where it itself ends in a word
// character. The asymmetric check is what lets ":8080" match cleanly even
// when its leading colon sits next to a space (the ":" half is not a word
// char so the left side doesn't need to be either).
func isWordBoundary(text string, start, end int) bool {
	if end <= start {
		return true
	}
	first := text[start]
	last := text[end-1]
	if start > 0 && isWordChar(first) {
		prev, _ := utf8.DecodeLastRuneInString(text[:start])
		if isWordRune(prev) {
			return false
		}
	}
	if end < len(text) && isWordChar(last) {
		next, _ := utf8.DecodeRuneInString(text[end:])
		if isWordRune(next) {
			return false
		}
	}
	return true
}
