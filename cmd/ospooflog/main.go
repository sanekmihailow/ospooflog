// Command ospooflog is the CLI entry point. It wires the packages together
// for three pipe-friendly verbs: obfuscate (raw log -> AI-safe text),
// restore (AI response -> real instructions) and show (inspect mapping).
// All logic lives in pkg/.
package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"text/tabwriter"

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

type opts struct {
	Input         string `short:"i" long:"input" description:"input file (default: stdin)"`
	Output        string `short:"o" long:"output" description:"output file (default: stdout)"`
	Session       string `short:"s" long:"session" description:"session file (required)" required:"true"`
	Mode          string `long:"mode" description:"detection breadth — safe: strict context only | balanced: + 'as alice' / abs paths / bare ports | aggressive: + single-label HOST / base64 decode-verify" default:"safe"`
	Aggressive    bool   `long:"aggressive" description:"deprecated alias for --mode aggressive"`
	FastRestore   bool   `long:"fast-restore" description:"opt out of word-boundary aware restore — faster, but a registered fake that's a prefix of an unrelated string in the AI response will be wrongly replaced"`
	StrictRestore bool   `long:"strict-restore" description:"deprecated — strict restore is now the default; pass --fast-restore to opt out"`
	DryRun        bool   `long:"dry-run" description:"obfuscate: print detected matches without modifying text or persisting the session"`
	Overrides     string `long:"overrides" description:"YAML file with fixed origin → replace pairs that win over the built-in templates; plain-text mode only (NUL placeholders collide with JSON)"`
	JSON          bool   `long:"json" description:"obfuscate: parse each line as JSON (NDJSON) and obfuscate string leaves while preserving structure"`
	AllowKeys     string `long:"allow-keys" description:"--json: skip these JSON keys (e.g. level,timestamp,msg) — values pass through unchanged"`
	Dbg           bool   `long:"dbg" description:"debug logging on stderr (session load count, match dumps in dry-run)"`

	Obfuscate struct{} `command:"obfuscate" description:"sanitize log text — replace sensitive values with plausible fakes, persist the mapping to the session file"`
	Restore   struct{} `command:"restore" description:"reverse pass — restore originals in an AI response using the session file"`
	Show      struct{} `command:"show" description:"print the current session mapping as a TOKEN/KIND/ORIGIN/REPLACE table"`
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	var o opts
	parser := flags.NewParser(&o, flags.Default)
	if _, err := parser.ParseArgs(args); err != nil {
		var fe *flags.Error
		if errors.As(err, &fe) && fe.Type == flags.ErrHelp {
			return nil
		}
		return errors.New("invalid arguments")
	}
	if parser.Active == nil {
		return errors.New("command required: obfuscate | restore | show")
	}

	if o.StrictRestore {
		fmt.Fprintln(os.Stderr, "warning: --strict-restore is deprecated — strict restore is now the default; pass --fast-restore to opt out")
	}

	m := mapper.New(replacer.New())
	if err := session.Load(o.Session, m); err != nil {
		return fmt.Errorf("session load: %w", err)
	}
	var ov map[string]string
	if o.Overrides != "" {
		var err error
		ov, err = loadOverrides(o.Overrides)
		if err != nil {
			return fmt.Errorf("overrides: %w", err)
		}
		m.SetOverrides(ov)
		if o.Dbg {
			fmt.Fprintf(os.Stderr, "debug: loaded %d overrides from %s\n", len(ov), o.Overrides)
		}
	}
	if o.Dbg {
		fmt.Fprintf(os.Stderr, "debug: loaded %d entries from %s\n", len(m.Entries()), o.Session)
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

func runObfuscate(o opts, m *mapper.Mapper, ov map[string]string) error {
	rules, err := rulesForMode(o.Mode, o.Aggressive)
	if err != nil {
		return err
	}
	chain := detector.New(rules)

	text, err := readInput(o.Input)
	if err != nil {
		return err
	}

	// Literal sed-style overrides: replace every occurrence of origin with a
	// NUL-bracketed placeholder before detection so (a) the detector cannot
	// re-tokenize the replace value and (b) the substitution wins even when
	// no rule would have matched origin. NUL is illegal inside JSON strings,
	// so this path only runs in plain-text mode; --json keeps the old
	// SetOverrides behavior. Longest origins first so shorter ones don't
	// clobber overlapping prefixes.
	var ovSlots []struct{ replace string }
	if !o.JSON && len(ov) > 0 {
		keys := make([]string, 0, len(ov))
		for k := range ov {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool { return len(keys[i]) > len(keys[j]) })
		for _, origin := range keys {
			repl := ov[origin]
			if origin == "" || repl == "" || !strings.Contains(text, origin) {
				continue
			}
			ph := fmt.Sprintf("\x00OVR%d\x00", len(ovSlots))
			text = strings.ReplaceAll(text, origin, ph)
			ovSlots = append(ovSlots, struct{ replace string }{repl})
			m.RegisterOverride(origin, repl)
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
	var result string
	if o.JSON {
		result = jsonproc.New(obf, m, splitCSV(o.AllowKeys)).Process(text)
	} else {
		text = audithex.Process(text, obf)
		result = obf.Obfuscate(text)
	}
	for i, s := range ovSlots {
		result = strings.ReplaceAll(result, fmt.Sprintf("\x00OVR%d\x00", i), s.replace)
	}
	if _, err := out.Write([]byte(result)); err != nil {
		return fmt.Errorf("write output: %w", err)
	}
	if err := session.Save(o.Session, m); err != nil {
		return fmt.Errorf("session save: %w", err)
	}
	if o.Dbg {
		fmt.Fprintf(os.Stderr, "debug: session has %d entries after obfuscate\n", len(m.Entries()))
	}
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

func loadOverrides(path string) (map[string]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var f overridesFile
	if err := yaml.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	out := make(map[string]string, len(f.Overrides))
	for _, r := range f.Overrides {
		if r.Origin == "" || r.Replace == "" {
			continue
		}
		out[r.Origin] = r.Replace
	}
	return out, nil
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
