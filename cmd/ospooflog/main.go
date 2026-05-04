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
	"text/tabwriter"

	flags "github.com/jessevdk/go-flags"
	"gopkg.in/yaml.v3"

	"github.com/sanekmihailow/ospooflog/pkg/detector"
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
	Aggressive    bool   `long:"aggressive" description:"aggressive USER/HOST/PATH/PORT detection (more false positives)"`
	StrictRestore bool   `long:"strict-restore" description:"word-boundary aware restore (slower, immune to substring traps)"`
	DryRun        bool   `long:"dry-run" description:"obfuscate: print detected matches without modifying text or session"`
	Overrides     string `long:"overrides" description:"YAML file with custom origin→replace pairs"`
	Dbg           bool   `long:"dbg" description:"debug logging on stderr"`

	Obfuscate struct{} `command:"obfuscate" description:"sanitize log text — replace sensitive values with plausible fakes"`
	Restore   struct{} `command:"restore" description:"restore originals in an AI response using the session file"`
	Show      struct{} `command:"show" description:"print the current session mapping as a table"`
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

	m := mapper.New(replacer.New())
	if err := session.Load(o.Session, m); err != nil {
		return fmt.Errorf("session load: %w", err)
	}
	if o.Overrides != "" {
		ov, err := loadOverrides(o.Overrides)
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
		return runObfuscate(o, m)
	case "restore":
		return runRestore(o, m)
	case "show":
		return runShow(o, m)
	default:
		return fmt.Errorf("unknown command: %s", parser.Active.Name)
	}
}

func runObfuscate(o opts, m *mapper.Mapper) error {
	rules := detector.DefaultRules()
	if o.Aggressive {
		rules = detector.AggressiveRules()
	}
	chain := detector.New(rules)

	text, err := readInput(o.Input)
	if err != nil {
		return err
	}

	out, closeOut, err := openOutput(o.Output)
	if err != nil {
		return fmt.Errorf("output: %w", err)
	}
	defer closeOut()

	if o.DryRun {
		return printMatches(out, chain.Find(text))
	}

	result := obfuscator.New(chain, m).Obfuscate(text)
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
	result := restorer.New(m, o.StrictRestore).Restore(text)
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
