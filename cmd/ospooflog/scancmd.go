package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strings"
	"text/tabwriter"
	"unicode"

	"github.com/sanekmihailow/ospooflog/pkg/detector"
	"github.com/sanekmihailow/ospooflog/pkg/mapper"
	"github.com/sanekmihailow/ospooflog/pkg/replacer"
	"gopkg.in/yaml.v3"
)

// runScan reports detection coverage: it runs the detector (respecting --mode,
// --ignore and --cut) over the input and prints a per-kind count summary. No
// obfuscation, no session — a read-only "what would be masked here" report.
func runScan(o opts) error {
	rules, err := rulesForMode(o.Mode, o.Aggressive)
	if err != nil {
		return err
	}
	chain := detector.New(rules)
	if o.Ignore != "" {
		il, err := detector.LoadIgnoreList(o.Ignore)
		if err != nil {
			return fmt.Errorf("ignore: %w", err)
		}
		chain.SetIgnore(il)
	}

	text, err := readInput(o.Input)
	if err != nil {
		return err
	}
	if o.Cut != "" {
		cl, err := loadCutList(o.Cut)
		if err != nil {
			return fmt.Errorf("cut: %w", err)
		}
		text = cl.Apply(text)
	}

	matches := chain.Find(text)
	if o.OutRules != "" {
		if o.Regexp && o.Simple {
			return errors.New("--regexp and --simple are mutually exclusive")
		}
		return writeRules(o.OutRules, matches, o.Simple)
	}
	return printScan(os.Stdout, matches, o.Mode)
}

// writeRules turns scan matches into a starter --overrides file. It is NOT
// applied — just a future overrides file to edit, then pass with --overrides. A
// throwaway mapper supplies plausible fakes for the replace: side; nothing is
// persisted. Entries are ordered by coverage (most matches first). Regex mode
// (the default) emits one re: pattern per kind, generated from the kind's
// values; --simple emits every distinct value verbatim.
func writeRules(path string, matches []detector.Match, simple bool) error {
	m := mapper.New(replacer.New())

	type valInfo struct {
		count int
		fake  string
	}
	vals := map[string]*valInfo{}
	var valOrder []string

	kindCount := map[detector.EntityKind]int{}
	kindDistinct := map[detector.EntityKind][]string{}
	kindFake := map[detector.EntityKind]string{}
	var kindOrder []detector.EntityKind

	for _, mt := range matches {
		_, replace := m.Obfuscate(mt.Value, mt.Kind, mt.Extra)
		if _, ok := kindCount[mt.Kind]; !ok {
			kindOrder = append(kindOrder, mt.Kind)
		}
		kindCount[mt.Kind]++
		vi := vals[mt.Value]
		if vi == nil {
			vi = &valInfo{fake: replace}
			vals[mt.Value] = vi
			valOrder = append(valOrder, mt.Value)
			kindDistinct[mt.Kind] = append(kindDistinct[mt.Kind], mt.Value)
			if kindFake[mt.Kind] == "" {
				kindFake[mt.Kind] = replace
			}
		}
		vi.count++
	}

	type weighted struct {
		pair   overridePair
		weight int
	}
	var ws []weighted
	if simple {
		for _, v := range valOrder {
			ws = append(ws, weighted{overridePair{Origin: v, Replace: vals[v].fake}, vals[v].count})
		}
	} else {
		for _, k := range kindOrder {
			pat := generatePattern(kindDistinct[k])
			if pat == "" {
				continue
			}
			ws = append(ws, weighted{overridePair{Origin: "re:" + pat, Replace: kindFake[k]}, kindCount[k]})
		}
	}
	// Most-covering rules first; stable on equal weight keeps first-seen order.
	sort.SliceStable(ws, func(i, j int) bool { return ws[i].weight > ws[j].weight })

	var of overridesFile
	for _, w := range ws {
		of.Overrides = append(of.Overrides, w.pair)
	}
	data, err := yaml.Marshal(of)
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "wrote %d rule(s) to %s — edit, then pass with --overrides\n", len(of.Overrides), path)
	return nil
}

// generatePattern returns a regex matching values: grex if the binary is
// available and succeeds, otherwise the built-in generalizer.
func generatePattern(values []string) string {
	if p, ok := grexPattern(values); ok {
		return p
	}
	return generalizePattern(values)
}

// grexPattern shells out to the optional `grex` binary (not a build dependency)
// to induce a regex from the values. Flags: -e (escape non-ASCII), -d (digits →
// \d), -r (collapse repeats into quantifiers), -i (case-insensitive),
// --no-anchors (match a span, not a whole line), --with-surrogates. Returns
// ok=false when grex is absent or fails, so the caller falls back to the
// built-in generalizer.
func grexPattern(values []string) (string, bool) {
	if len(values) == 0 {
		return "", false
	}
	if _, err := exec.LookPath("grex"); err != nil {
		return "", false
	}
	if len(values) > 200 { // keep the arg list bounded
		values = values[:200]
	}
	out, err := exec.Command("grex", append([]string{"-edri", "--no-anchors", "--with-surrogates"}, values...)...).Output()
	if err != nil {
		return "", false
	}
	pat := strings.TrimSpace(string(out)) // --no-anchors already drops ^ / $
	if pat == "" {
		return "", false
	}
	return pat, true
}

// generalizePattern builds one regex for all values by collecting the distinct
// segment atoms across them (a digit run → \d+, a letter run → [A-Za-z]+, any
// other rune → its escaped literal) and quantifying their alternation:
// (?:atom|atom|…)+. Collapsing to a repetition of atoms keeps structurally
// varied values (hostnames, paths) as one compact pattern instead of
// enumerating every per-value shape.
func generalizePattern(values []string) string {
	seen := map[string]bool{}
	var atoms []string
	for _, v := range values {
		for _, a := range valueAtoms(v) {
			if !seen[a] {
				seen[a] = true
				atoms = append(atoms, a)
			}
		}
	}
	switch len(atoms) {
	case 0:
		return ""
	case 1:
		return atoms[0] // already quantified (\d+ / [A-Za-z]+) or a lone literal
	default:
		return "(?:" + strings.Join(atoms, "|") + ")+"
	}
}

// valueAtoms splits s into regex atoms: maximal digit runs → \d+, letter runs →
// [A-Za-z]+, any other rune → its escaped literal.
func valueAtoms(s string) []string {
	var out []string
	rs := []rune(s)
	for i := 0; i < len(rs); {
		switch r := rs[i]; {
		case unicode.IsDigit(r):
			for i < len(rs) && unicode.IsDigit(rs[i]) {
				i++
			}
			out = append(out, `\d+`)
		case unicode.IsLetter(r):
			for i < len(rs) && unicode.IsLetter(rs[i]) {
				i++
			}
			out = append(out, `[A-Za-z]+`)
		default:
			out = append(out, regexp.QuoteMeta(string(rs[i])))
			i++
		}
	}
	return out
}

func printScan(w io.Writer, matches []detector.Match, mode string) error {
	type stat struct {
		count   int
		example string
	}
	stats := map[detector.EntityKind]*stat{}
	var kinds []detector.EntityKind
	for _, m := range matches {
		s := stats[m.Kind]
		if s == nil {
			s = &stat{}
			stats[m.Kind] = s
			kinds = append(kinds, m.Kind)
		}
		s.count++
		if s.example == "" {
			s.example = m.Value
		}
	}

	if len(matches) == 0 {
		_, err := fmt.Fprintf(w, "no sensitive values detected (mode: %s)\n", mode)
		return err
	}

	// Highest count first; kind name as a stable tiebreaker.
	sort.Slice(kinds, func(i, j int) bool {
		if stats[kinds[i]].count != stats[kinds[j]].count {
			return stats[kinds[i]].count > stats[kinds[j]].count
		}
		return kinds[i] < kinds[j]
	})

	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "COUNT\tKIND\tEXAMPLE")
	for _, k := range kinds {
		fmt.Fprintf(tw, "%d\t%s\t%s\n", stats[k].count, k, truncateRunes(stats[k].example, 40))
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	_, err := fmt.Fprintf(w, "\n%d matches across %d kinds (mode: %s)\n", len(matches), len(kinds), mode)
	return err
}

// truncateRunes shortens s to at most n runes, appending an ellipsis when cut.
func truncateRunes(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}
