// Command ospooflog is the CLI entry point. It wires the packages together
// for two pipe-friendly verbs: obfuscate (raw log -> AI-safe text) and
// restore (AI response -> real instructions). All logic lives in pkg/.
package main

import (
	"errors"
	"fmt"
	"io"
	"os"

	flags "github.com/jessevdk/go-flags"

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
	Dbg           bool   `long:"dbg" description:"debug logging on stderr"`

	Obfuscate struct{} `command:"obfuscate" description:"sanitize log text — replace sensitive values with plausible fakes"`
	Restore   struct{} `command:"restore" description:"restore originals in an AI response using the session file"`
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
		// go-flags already printed a useful message on stderr.
		return errors.New("invalid arguments")
	}
	if parser.Active == nil {
		return errors.New("command required: obfuscate or restore")
	}

	rep := replacer.New()
	m := mapper.New(rep)
	if err := session.Load(o.Session, m); err != nil {
		return fmt.Errorf("session load: %w", err)
	}
	if o.Dbg {
		fmt.Fprintf(os.Stderr, "debug: loaded %d entries from %s\n", len(m.Entries()), o.Session)
	}

	in, closeIn, err := openInput(o.Input)
	if err != nil {
		return fmt.Errorf("input: %w", err)
	}
	defer closeIn()

	out, closeOut, err := openOutput(o.Output)
	if err != nil {
		return fmt.Errorf("output: %w", err)
	}
	defer closeOut()

	text, err := io.ReadAll(in)
	if err != nil {
		return fmt.Errorf("read input: %w", err)
	}

	var result string
	switch parser.Active.Name {
	case "obfuscate":
		rules := detector.DefaultRules()
		if o.Aggressive {
			rules = detector.AggressiveRules()
		}
		result = obfuscator.New(detector.New(rules), m).Obfuscate(string(text))
		if err := session.Save(o.Session, m); err != nil {
			return fmt.Errorf("session save: %w", err)
		}
		if o.Dbg {
			fmt.Fprintf(os.Stderr, "debug: session has %d entries after obfuscate\n", len(m.Entries()))
		}
	case "restore":
		if len(m.Entries()) == 0 {
			fmt.Fprintln(os.Stderr, "warning: session file is empty — nothing to restore")
		}
		result = restorer.New(m, o.StrictRestore).Restore(string(text))
	default:
		return fmt.Errorf("unknown command: %s", parser.Active.Name)
	}

	if _, err := out.Write([]byte(result)); err != nil {
		return fmt.Errorf("write output: %w", err)
	}
	return nil
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
