package main

import (
	"fmt"
	"io"
	"os"
	"sort"
	"text/tabwriter"

	"github.com/sanekmihailow/ospooflog/pkg/detector"
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

	return printScan(os.Stdout, chain.Find(text), o.Mode)
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
