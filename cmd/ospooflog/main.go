// Command ospooflog is the CLI entry point. It wires the packages together
// for three pipe-friendly verbs: obfuscate (raw log -> AI-safe text),
// restore (AI response -> real instructions) and show (inspect mapping).
// All logic lives in pkg/.
package main

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"regexp"
	"regexp/syntax"
	rtdebug "runtime/debug"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	flags "github.com/jessevdk/go-flags"
	"gopkg.in/yaml.v3"

	"github.com/sanekmihailow/ospooflog/pkg/audithex"
	"github.com/sanekmihailow/ospooflog/pkg/detector"
	"github.com/sanekmihailow/ospooflog/pkg/jsonproc"
	"github.com/sanekmihailow/ospooflog/pkg/mapper"
	"github.com/sanekmihailow/ospooflog/pkg/obfuscator"
	"github.com/sanekmihailow/ospooflog/pkg/replacer"
	"github.com/sanekmihailow/ospooflog/pkg/restorer"
	"github.com/sanekmihailow/ospooflog/pkg/session"
)

// defaultSessionPath is used when -s is omitted. /tmp keeps throwaway
// obfuscate→restore sessions out of the working tree.
const defaultSessionPath = "/tmp/ospooflog_session.json"

// sessionPath resolves the session file: the -s flag wins, otherwise the
// built-in default. Kept as a seam so a future config file can slot a value
// between the flag and the default.
func sessionPath(flag string) string {
	if flag == "" {
		return defaultSessionPath
	}
	return flag
}

type opts struct {
	Input         string   `short:"i" long:"input" description:"input file (default: stdin)"`
	Output        string   `short:"o" long:"output" description:"output file (default: stdout)"`
	Session       string   `short:"s" long:"session" description:"session file (default: /tmp/ospooflog_session.json)"`
	Mode          string   `long:"mode" description:"detection breadth — safe (default): strict context only | balanced: + 'as alice' / abs paths / bare ports | aggressive: + single-label HOST / base64 decode-verify"`
	Aggressive    bool     `long:"aggressive" description:"deprecated alias for --mode aggressive"`
	FastRestore   bool     `long:"fast-restore" description:"opt out of word-boundary aware restore — faster, but a registered fake that's a prefix of an unrelated string in the AI response will be wrongly replaced"`
	StrictRestore bool     `long:"strict-restore" description:"deprecated — strict restore is now the default; pass --fast-restore to opt out"`
	DryRun        bool     `long:"dry-run" description:"obfuscate: print detected matches without modifying text or persisting the session"`
	Diff          bool     `long:"diff" description:"obfuscate: print a per-line diff of original vs obfuscated text instead of the obfuscated text; does not persist the session (mutually exclusive with --dry-run)"`
	Explain       bool     `long:"explain" description:"obfuscate: print per-value detector decisions to stderr (MASK / drop + reason) to analyze why values are or aren't masked"`
	Valid         bool     `long:"valid" description:"parse-check the config and the --overrides / --ignore / --cut files and --mode for syntax errors, then exit (no command needed, no obfuscation)"`
	Overrides     string   `long:"overrides" description:"YAML file with origin → replace pairs that win over the built-in templates; a literal origin matches verbatim, an 'origin: re:<pattern>' value matches a class by Go regexp; plain-text mode only (NUL placeholders collide with JSON)"`
	Ignore        string   `long:"ignore" description:"obfuscate: plain-text file of values to leave untouched — one per line, '#' for comments, 're:<pattern>' for a Go regexp matched against captured values"`
	Cut           string   `long:"cut" description:"obfuscate: plain-text file of literal substrings / 're:<pattern>' regexps; any line a match touches is removed entirely before detection (a multi-line (?s) regex drops the whole spanned block). Not reversible — cut content never reaches the session"`
	KeepTLD       bool     `long:"keep-tld" description:"obfuscate: keep the real top-level label of FQDN/HOST/EMAIL domains; the registrable domain becomes exampleN (stable per real domain), subdomain serviceN — e.g. messenger.max.ru → service1.example1.ru"`
	JSON          bool     `long:"json" description:"obfuscate: parse each line as JSON (NDJSON) and obfuscate string leaves while preserving structure"`
	AllowKeys     string   `long:"allow-keys" description:"--json: skip these JSON keys (e.g. level,timestamp,msg) — values pass through unchanged"`
	Debug         int      `long:"debug" description:"debug trace verbosity on stderr, 1-10 (cumulative: 1 config/options, 4 session, 6 stages, 7 timings, 8 detector internals, 9 +caller/stack, 10 +runtime stats); off when omitted"`
	DebugOut      string   `long:"debug-out" description:"directory for binary Go artifacts at high verbosity: runtime/trace + CPU/heap pprof (read with go tool trace / pprof)"`
	Obfuscate     struct{} `command:"obfuscate" description:"sanitize log text — replace sensitive values with plausible fakes, persist the mapping to the session file"`
	Restore       struct{} `command:"restore" description:"reverse pass — restore originals in an AI response using the session file"`
	Show          struct{} `command:"show" description:"print the current session mapping as a TOKEN/KIND/ORIGIN/REPLACE table"`
	Config        struct {
		Show struct{} `command:"show" description:"print the effective merged config as YAML"`
		Edit struct{} `command:"edit" description:"open the config file in $EDITOR"`
		Path struct{} `command:"path" description:"print the config file paths and which are loaded"`
	} `command:"config" description:"inspect or edit the config file: show | edit | path"`
}

func main() {
	defer func() {
		if r := recover(); r != nil {
			fmt.Fprintf(os.Stderr, "panic: %v\n%s", r, rtdebug.Stack())
			os.Exit(1)
		}
	}()
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		// Cheap stack on error at high verbosity (shallow — main's goroutine,
		// not the error's origin; the accepted trade-off for not wrapping every
		// error site). Panics get a real stack via the recover above.
		if dbg.on(dbgCaller) {
			fmt.Fprintf(os.Stderr, "%s", rtdebug.Stack())
		}
		os.Exit(exitCode(err))
	}
}

// exitError tags an error with an explicit process exit code, for the cases the
// standard error types below can't classify (e.g. an override pattern rejected
// at load — not a compile error, so not a *syntax.Error).
type exitError struct {
	code int
	err  error
}

func (e *exitError) Error() string { return e.err.Error() }
func (e *exitError) Unwrap() error { return e.err }

// ruleErr marks err as a detection-rule problem (exit code 3).
func ruleErr(err error) error { return &exitError{code: 3, err: err} }

// exitCode maps a run() error to a documented process code so scripts/CI can
// branch on the failure class:
//
//	1 — bad arguments / config (the default: flag parse, --mode, malformed YAML)
//	2 — I/O failure: os file ops return *fs.PathError on open/read/write/create
//	3 — bad detection rule: a user-supplied regex that won't compile
//	    (--overrides re:, --ignore re:) is a *regexp/syntax.Error; a pattern
//	    rejected at load is wrapped via ruleErr
func exitCode(err error) int {
	var ee *exitError
	if errors.As(err, &ee) {
		return ee.code
	}
	var se *syntax.Error
	if errors.As(err, &se) {
		return 3
	}
	var pe *fs.PathError
	if errors.As(err, &pe) {
		return 2
	}
	return 1
}

func run(args []string) error {
	var o opts
	parser := flags.NewParser(&o, flags.Default)
	// Allow no subcommand at parse time so --valid (a standalone check) works;
	// the "command required" case is still enforced manually below.
	parser.SubcommandsOptional = true
	if _, err := parser.ParseArgs(args); err != nil {
		var fe *flags.Error
		if errors.As(err, &fe) && fe.Type == flags.ErrHelp {
			return nil
		}
		return errors.New("invalid arguments")
	}
	// Tracer at the flag level first so config discovery itself can be traced;
	// the effective level (config may raise it) is set right after the merge.
	dbg = &debugLog{level: o.Debug, w: os.Stderr}

	// Config file fills options the flags left unset (flag > config > default),
	// then the built-in fallbacks for what neither set.
	cfg, err := loadConfig()
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}
	cfg.applyTo(&o)
	o.Session = sessionPath(o.Session)
	if o.Mode == "" {
		o.Mode = "safe"
	}
	dbg.level = o.Debug

	dbg.at(1, "effective: mode=%s session=%s", o.Mode, o.Session)
	dbg.at(2, "effective: json=%v fast_restore=%v allow_keys=%q ignore=%q overrides=%q cut=%q debug_out=%q",
		o.JSON, o.FastRestore, o.AllowKeys, o.Ignore, o.Overrides, o.Cut, o.DebugOut)

	// --valid: parse-check config + the --overrides / --ignore / --cut files
	// and --mode, then stop (no command required, no obfuscation).
	if o.Valid {
		return validate(o)
	}

	if parser.Active == nil {
		return errors.New("command required: obfuscate | restore | show | config")
	}

	// config subcommands operate only on the config files — no session needed.
	if parser.Active.Name == "config" {
		return runConfig(parser.Active, cfg)
	}

	if o.StrictRestore {
		fmt.Fprintln(os.Stderr, "warning: --strict-restore is deprecated — strict restore is now the default; pass --fast-restore to opt out")
	}

	rep := replacer.New()
	rep.SetKeepTLD(o.KeepTLD)
	m := mapper.New(rep)
	if err := session.Load(o.Session, m); err != nil {
		return fmt.Errorf("session load: %w", err)
	}
	dbg.at(4, "session: loaded %d entries from %s", len(m.Entries()), o.Session)

	var ov []overrideRule
	if o.Overrides != "" {
		var err error
		ov, err = loadOverrides(o.Overrides)
		if err != nil {
			return fmt.Errorf("overrides: %w", err)
		}
		m.SetOverrides(overrideLiterals(ov))
		dbg.at(5, "overrides: %d rules from %s", len(ov), o.Overrides)
	}

	switch parser.Active.Name {
	case "obfuscate":
		return runObfuscate(o, m, ov)
	case "restore":
		return runRestore(o, m)
	case "show":
		return runShow(o, m)
	default:
		return fmt.Errorf("unknown command: %s", parser.Active.Name)
	}
}

// validate parse-checks the configured inputs for --valid: the --overrides /
// --ignore / --cut files and --mode. Config-file syntax was already verified by
// loadConfig in run(). Returns the first error (carrying its exit code); on
// success prints what was checked and returns nil (exit 0).
func validate(o opts) error {
	checked := []string{"config"}
	if o.Overrides != "" {
		if _, err := loadOverrides(o.Overrides); err != nil {
			return fmt.Errorf("overrides: %w", err)
		}
		checked = append(checked, "overrides")
	}
	if o.Ignore != "" {
		if _, err := detector.LoadIgnoreList(o.Ignore); err != nil {
			return fmt.Errorf("ignore: %w", err)
		}
		checked = append(checked, "ignore")
	}
	if o.Cut != "" {
		if _, err := loadCutList(o.Cut); err != nil {
			return fmt.Errorf("cut: %w", err)
		}
		checked = append(checked, "cut")
	}
	if _, err := rulesForMode(o.Mode, o.Aggressive); err != nil {
		return err
	}
	fmt.Printf("valid: %s, mode=%s\n", strings.Join(checked, ", "), o.Mode)
	return nil
}

// rulesForMode picks the detector ruleset for the requested mode.
// --aggressive is honoured as a deprecated alias for --mode aggressive
// (with a stderr warning) so older invocations don't break.
func rulesForMode(mode string, deprecatedAggressive bool) ([]detector.Rule, error) {
	if deprecatedAggressive {
		fmt.Fprintln(os.Stderr, "warning: --aggressive is deprecated, use --mode aggressive instead")
		mode = "aggressive"
	}
	switch mode {
	case "", "safe":
		return detector.DefaultRules(), nil
	case "balanced":
		return detector.BalancedRules(), nil
	case "aggressive":
		return detector.AggressiveRules(), nil
	default:
		return nil, fmt.Errorf("unknown --mode value: %q (want safe|balanced|aggressive)", mode)
	}
}

func runObfuscate(o opts, m *mapper.Mapper, ov []overrideRule) error {
	if o.DryRun && o.Diff {
		return errors.New("--diff and --dry-run are mutually exclusive")
	}
	defer dbg.runtimeStats()
	if o.DebugOut != "" {
		stop, err := startProfiling(o.DebugOut)
		if err != nil {
			return fmt.Errorf("debug-out: %w", err)
		}
		defer stop()
	}
	rules, err := rulesForMode(o.Mode, o.Aggressive)
	if err != nil {
		return err
	}
	dbg.at(3, "ruleset: mode=%s → %d rules", o.Mode, len(rules))
	chain := detector.New(rules)
	var stats detector.FindStats
	if dbg.on(8) {
		chain.SetStats(&stats)
	}
	if o.Explain {
		chain.SetExplain(func(d detector.Decision) {
			if d.Masked {
				fmt.Fprintf(os.Stderr, "explain: MASK [%s] @%d %q\n", d.Kind, d.Start, d.Value)
				return
			}
			fmt.Fprintf(os.Stderr, "explain: drop [%s] @%d %q — %s\n", d.Kind, d.Start, d.Value, d.Reason)
		})
	}
	if o.Ignore != "" {
		il, err := detector.LoadIgnoreList(o.Ignore)
		if err != nil {
			return fmt.Errorf("ignore: %w", err)
		}
		chain.SetIgnore(il)
		dbg.at(5, "ignore: loaded from %s", o.Ignore)
	}

	text, err := readInput(o.Input)
	if err != nil {
		return err
	}
	// Cut first: drop whole lines a pattern touches so they reach neither the
	// detector nor the --diff baseline (originalText) below.
	if o.Cut != "" {
		cl, err := loadCutList(o.Cut)
		if err != nil {
			return fmt.Errorf("cut: %w", err)
		}
		text = cl.Apply(text)
		dbg.at(5, "cut: applied from %s", o.Cut)
	}
	originalText := text

	// Sed-style overrides: replace each origin with a NUL-bracketed placeholder
	// before detection so (a) the detector cannot re-tokenize the replace value
	// and (b) the substitution wins even when no rule would have matched origin.
	// NUL is illegal inside JSON strings, so this pass only runs in plain-text
	// mode; --json keeps the old SetOverrides behavior for literals.
	var ovSlots []struct{ replace string }
	if !o.JSON && len(ov) > 0 {
		var literals, regexes []overrideRule
		for _, r := range ov {
			if r.re != nil {
				regexes = append(regexes, r)
			} else {
				literals = append(literals, r)
			}
		}
		// Literals first (longest origin first so a shorter one doesn't clobber
		// an overlapping prefix) — unchanged one-to-one behavior. Regexes after,
		// so an explicit literal wins over a pattern covering the same span.
		sort.Slice(literals, func(i, j int) bool { return len(literals[i].literal) > len(literals[j].literal) })
		for _, r := range literals {
			if !strings.Contains(text, r.literal) {
				continue
			}
			ph := fmt.Sprintf("\x00OVR%d\x00", len(ovSlots))
			text = strings.ReplaceAll(text, r.literal, ph)
			ovSlots = append(ovSlots, struct{ replace string }{r.replace})
			m.RegisterOverride(r.literal, r.replace)
		}
		// Regex: every match collapses to one replace in the output, but each
		// distinct matched value is registered separately so restore reverses
		// the shared fake back to a real value.
		for _, r := range regexes {
			ph := fmt.Sprintf("\x00OVR%d\x00", len(ovSlots))
			next, matched := replaceOutsidePlaceholders(text, r.re, ph)
			if len(matched) == 0 {
				continue
			}
			text = next
			for _, v := range matched {
				m.RegisterOverride(v, r.replace)
			}
			ovSlots = append(ovSlots, struct{ replace string }{r.replace})
		}
	} else if o.JSON {
		n := 0
		for _, r := range ov {
			if r.re != nil {
				n++
			}
		}
		if n > 0 {
			fmt.Fprintf(os.Stderr, "warning: %d regex (re:) override(s) ignored in --json mode\n", n)
		}
	}

	out, closeOut, err := openOutput(o.Output)
	if err != nil {
		return fmt.Errorf("output: %w", err)
	}
	defer closeOut()

	if o.DryRun {
		return printMatches(out, chain.Find(text))
	}

	obf := obfuscator.New(chain, m)
	stage := "plain"
	if o.JSON {
		stage = "json"
	}
	dbg.at(6, "stage: detect+obfuscate (%s)", stage)
	t0 := time.Now()
	var result string
	if o.JSON {
		result = jsonproc.New(obf, m, splitCSV(o.AllowKeys)).Process(text)
	} else {
		text = audithex.Process(text, obf)
		result = obf.Obfuscate(text)
	}
	dbg.at(7, "timing: obfuscate %s", time.Since(t0))
	dbg.at(8, "detector: %d rules evaluated, %d prefilter-skipped, %d candidates, %d emitted",
		stats.RulesEvaluated, stats.PrefilterSkip, stats.Candidates, stats.Emitted)
	for i, s := range ovSlots {
		result = strings.ReplaceAll(result, fmt.Sprintf("\x00OVR%d\x00", i), s.replace)
	}
	if o.Diff {
		return printDiff(out, originalText, result)
	}
	if _, err := out.Write([]byte(result)); err != nil {
		return fmt.Errorf("write output: %w", err)
	}
	if err := session.Save(o.Session, m); err != nil {
		return fmt.Errorf("session save: %w", err)
	}
	dbg.at(4, "session: saved %d entries to %s", len(m.Entries()), o.Session)
	return nil
}

func runRestore(o opts, m *mapper.Mapper) error {
	if len(m.Entries()) == 0 {
		fmt.Fprintln(os.Stderr, "warning: session file is empty — nothing to restore")
	}
	text, err := readInput(o.Input)
	if err != nil {
		return err
	}
	out, closeOut, err := openOutput(o.Output)
	if err != nil {
		return fmt.Errorf("output: %w", err)
	}
	defer closeOut()
	r := restorer.New(m, !o.FastRestore)
	text = audithex.Restore(text, r)
	result := r.Restore(text)
	if _, err := out.Write([]byte(result)); err != nil {
		return fmt.Errorf("write output: %w", err)
	}
	return nil
}

func runShow(o opts, m *mapper.Mapper) error {
	out, closeOut, err := openOutput(o.Output)
	if err != nil {
		return fmt.Errorf("output: %w", err)
	}
	defer closeOut()

	entries := m.Entries()
	if len(entries) == 0 {
		_, err := fmt.Fprintln(out, "(session is empty)")
		return err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Token < entries[j].Token })

	tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "TOKEN\tKIND\tORIGIN\tREPLACE")
	for _, e := range entries {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", e.Token, e.Kind, e.Origin, e.Replace)
	}
	return tw.Flush()
}

// printDiff writes a per-line diff: each line where the obfuscated text
// differs from the original becomes a "- original\n+ obfuscated\n" pair.
// Unchanged lines are skipped. If a single mask replaced a multi-line
// value, the two inputs have different line counts and pairwise alignment
// breaks — fall back to writing the obfuscated text with a stderr note so
// the user still gets the result.
func printDiff(w io.Writer, original, obfuscated string) error {
	o := strings.Split(original, "\n")
	n := strings.Split(obfuscated, "\n")
	if len(o) != len(n) {
		fmt.Fprintf(os.Stderr, "warning: line count changed (%d → %d), per-line diff not possible — printing obfuscated text instead\n", len(o), len(n))
		_, err := w.Write([]byte(obfuscated))
		return err
	}
	var minus, plus, reset string
	if colorEnabled(w) {
		minus, plus, reset = "\x1b[31m", "\x1b[32m", "\x1b[0m"
	}
	changed := false
	for i := range o {
		if o[i] == n[i] {
			continue
		}
		changed = true
		if _, err := fmt.Fprintf(w, "%s- %s%s\n%s+ %s%s\n", minus, o[i], reset, plus, n[i], reset); err != nil {
			return err
		}
	}
	if !changed {
		_, err := fmt.Fprintln(w, "(no changes)")
		return err
	}
	return nil
}

// colorEnabled defaults to on; we only suppress ANSI when it would
// definitely be noise: the user set NO_COLOR (https://no-color.org/)
// or piped output to a file via -o (any *os.File that isn't os.Stdout).
// Shell redirects (> file) keep stdout as os.Stdout and stay colored —
// caller can opt out with NO_COLOR if that bites.
func colorEnabled(w io.Writer) bool {
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	if f, ok := w.(*os.File); ok && f != os.Stdout {
		return false
	}
	return true
}

func printMatches(w io.Writer, matches []detector.Match) error {
	if len(matches) == 0 {
		_, err := fmt.Fprintln(w, "(no matches)")
		return err
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "OFFSET\tKIND\tVALUE")
	for _, m := range matches {
		fmt.Fprintf(tw, "%d\t%s\t%s\n", m.Start, m.Kind, m.Value)
	}
	return tw.Flush()
}

type overridesFile struct {
	Overrides []struct {
		Origin  string `yaml:"origin"`
		Replace string `yaml:"replace"`
	} `yaml:"overrides"`
}

// overrideRule is one origin → replace pair. A literal origin matches verbatim
// (the original one-to-one substitution); an origin prefixed "re:" compiles the
// remainder as a Go regexp so a whole class of values collapses to one replace.
type overrideRule struct {
	re      *regexp.Regexp // non-nil for "re:<pattern>" origins
	literal string         // origin value when re == nil
	replace string
}

func loadOverrides(path string) ([]overrideRule, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var f overridesFile
	if err := yaml.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	out := make([]overrideRule, 0, len(f.Overrides))
	for i, r := range f.Overrides {
		if r.Origin == "" || r.Replace == "" {
			continue
		}
		pat, isRegex := strings.CutPrefix(r.Origin, "re:")
		if !isRegex {
			out = append(out, overrideRule{literal: r.Origin, replace: r.Replace})
			continue
		}
		re, err := regexp.Compile(pat)
		if err != nil {
			return nil, ruleErr(fmt.Errorf("%s: overrides[%d]: bad regex %q: %w", path, i, pat, err))
		}
		// An empty-matching pattern (".*", "a*") would splatter placeholders
		// at every position via ReplaceAllString — reject it with a clear note.
		if re.MatchString("") {
			return nil, ruleErr(fmt.Errorf("%s: overrides[%d]: regex %q matches the empty string — use a more specific pattern", path, i, pat))
		}
		out = append(out, overrideRule{re: re, replace: r.Replace})
	}
	return out, nil
}

// overrideLiterals collects the literal pairs for the JSON-mode SetOverrides
// path, which matches detector-found values by equality and so can't apply
// regex rules (those are skipped, with a warning, in JSON mode).
func overrideLiterals(rules []overrideRule) map[string]string {
	out := make(map[string]string, len(rules))
	for _, r := range rules {
		if r.re == nil {
			out[r.literal] = r.replace
		}
	}
	return out
}

// phPattern matches the NUL-bracketed override placeholders inserted by the
// override pre-pass, so a later regex override never matches inside one.
var phPattern = regexp.MustCompile("\x00OVR\\d+\x00")

// replaceOutsidePlaceholders swaps every match of re for ph in the parts of
// text that are not an existing placeholder, returning the new text and the
// distinct matched substrings (each registered separately so restore can map
// the shared fake back to a real value). Skipping placeholder spans keeps a
// broad pattern (e.g. re:\d+) from corrupting an earlier override's "OVR<n>".
func replaceOutsidePlaceholders(text string, re *regexp.Regexp, ph string) (string, []string) {
	var b strings.Builder
	seen := map[string]bool{}
	var distinct []string
	apply := func(seg string) {
		for _, m := range re.FindAllString(seg, -1) {
			if !seen[m] {
				seen[m] = true
				distinct = append(distinct, m)
			}
		}
		b.WriteString(re.ReplaceAllString(seg, ph))
	}
	last := 0
	for _, loc := range phPattern.FindAllStringIndex(text, -1) {
		apply(text[last:loc[0]])
		b.WriteString(text[loc[0]:loc[1]])
		last = loc[1]
	}
	apply(text[last:])
	return b.String(), distinct
}

func splitCSV(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func readInput(path string) (string, error) {
	in, closeIn, err := openInput(path)
	if err != nil {
		return "", fmt.Errorf("input: %w", err)
	}
	defer closeIn()
	data, err := io.ReadAll(in)
	if err != nil {
		return "", fmt.Errorf("read input: %w", err)
	}
	return string(data), nil
}

func openInput(path string) (io.Reader, func(), error) {
	if path == "" {
		return os.Stdin, func() {}, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	return f, func() { _ = f.Close() }, nil
}

func openOutput(path string) (io.Writer, func(), error) {
	if path == "" {
		return os.Stdout, func() {}, nil
	}
	f, err := os.Create(path)
	if err != nil {
		return nil, nil, err
	}
	return f, func() { _ = f.Close() }, nil
}
