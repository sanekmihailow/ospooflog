package main

import (
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
)

// helpExample is one annotated command line shown by `--help <topic>`.
type helpExample struct {
	cmd  string
	desc string
}

// helpTopic groups examples for one command or flag: standalone uses first,
// then uses combined with other flags.
type helpTopic struct {
	title      string
	standalone []helpExample
	combos     []helpExample
	notes      []string // free-form lines (e.g. file format) printed below the examples
}

// helpTopics maps a command or long-flag name (without the leading --) to its
// examples. `ospooflog --help <topic>` prints them.
var helpTopics = map[string]helpTopic{
	"obfuscate": {
		title: "obfuscate — mask sensitive values before sending a log to an AI",
		standalone: []helpExample{
			{"ospooflog -s s.json obfuscate -i app.log -o safe.log", "file in, file out; mapping saved to s.json"},
			{"cat app.log | ospooflog -s s.json obfuscate | some-ai-tool", "stdin → stdout, straight into a pipeline"},
			{"ospooflog -s s.json --mode aggressive obfuscate -i app.log", "wider detection (more catches, more false positives)"},
			{"ospooflog -s s.json --dry-run obfuscate -i app.log", "preview detected matches without writing or persisting"},
		},
		combos: []helpExample{
			{"ospooflog -s s.json --ignore allow.txt --cut noise.txt obfuscate -i app.log", "skip all-listed values, drop noise lines first"},
			{"ospooflog -s s.json --overrides ovr.yaml --keep-tld obfuscate -i app.log", "custom replacements + keep real TLDs"},
		},
	},
	"restore": {
		title: "restore — turn an AI reply built on obfuscated text back into real values",
		standalone: []helpExample{
			{"cat ai_reply.txt | ospooflog -s s.json restore", "pipe the AI reply back through the same session"},
			{"ospooflog -s s.json restore -i ai_reply.txt -o real.txt", "file in, file out"},
			{"ospooflog -s s.json --fast-restore restore -i ai_reply.txt", "faster, but vulnerable to substring traps"},
		},
	},
	"show": {
		title: "show — print the current session mapping",
		standalone: []helpExample{
			{"ospooflog -s s.json show", "TOKEN / KIND / ORIGIN / REPLACE table"},
		},
	},
	"scan": {
		title: "scan — report what would be masked, without obfuscating",
		standalone: []helpExample{
			{"ospooflog -i app.log scan", "per-value coverage table + metrics"},
			{"cat app.log | ospooflog scan", "stdin"},
			{"ospooflog -i app.log scan --format json", "machine-readable metrics for dashboards"},
			{"ospooflog -i app.log scan --out-rules rules.yaml", "generate a starter --overrides file"},
		},
		combos: []helpExample{
			{"ospooflog -i app.log --mode aggressive --ignore allow.txt scan", "coverage under a wider mode minus allow-listed values"},
		},
	},
	"config": {
		title: "config — inspect or edit the YAML config",
		standalone: []helpExample{
			{"ospooflog config show", "effective merged config (only set keys)"},
			{"ospooflog config path", "config file locations and which are loaded"},
			{"ospooflog config edit", "open the active config in $EDITOR"},
		},
	},
	"overrides": {
		title: "--overrides FILE — fixed origin → replace pairs that win over the built-in templates",
		standalone: []helpExample{
			{"ospooflog -s s.json --overrides ovr.yaml obfuscate -i app.log", "apply the pairs (literal origins match verbatim)"},
			{"ospooflog --valid --overrides ovr.yaml", "syntax-check the file without running"},
		},
		combos: []helpExample{
			{"ospooflog -s s.json --overrides ovr.yaml --ignore allow.txt obfuscate -i app.log", "custom replacements + an allowlist"},
		},
		notes: []string{"$ cat ovr.yaml\noverrides:\n  - {origin: alice, replace: bob}\n  - {origin: \"re:user[0-9]+\", replace: USER}   # an \"re:\" origin is a regexp"},
	},
	"ignore": {
		title: "--ignore FILE — values to never mask (allowlist)",
		standalone: []helpExample{
			{"ospooflog -s s.json --ignore allow.txt obfuscate -i app.log", "leave listed values untouched"},
		},
		notes: []string{"$ cat allow.txt\n10.0.0.1\n# lines starting with # are comments\nre:^svc-[a-z]+$   # an \"re:\" line is a regexp"},
	},
	"cut": {
		title: "--cut FILE — drop whole lines a pattern touches, before detection",
		standalone: []helpExample{
			{"ospooflog -s s.json --cut noise.txt obfuscate -i app.log", "remove prompt/banner noise lines entirely"},
		},
		notes: []string{"$ cat noise.txt\nWELCOME BANNER\nre:(?s)-----BEGIN.*?-----END[^-]*-----   # drop a multi-line block"},
	},
	"keep-tld": {
		title: "--keep-tld — keep the real top-level label in domain fakes",
		standalone: []helpExample{
			{"ospooflog -s s.json --keep-tld obfuscate -i app.log", "messenger.max.ru → service1.example1.ru (real .ru kept)"},
		},
	},
	"fields": {
		title: "--fields FILE — per-field rules for --json logs (keep | mask | mask-as:KIND | remove)",
		standalone: []helpExample{
			{"ospooflog -s s.json --json --fields f.yaml obfuscate -i app.log", "apply the field rules while obfuscating NDJSON"},
			{"ospooflog --valid --fields f.yaml", "syntax-check the rules without running"},
		},
		notes: []string{"$ cat f.yaml\nfields:\n  user.id:                mask            # mask the whole value\n  user.token:             mask-as:APIKEY  # mask as a specific kind\n  headers.Authorization:  remove          # drop the field entirely\n  msg:                    keep            # never touch\n# dotted paths; arrays are transparent (items.email matches every element)"},
	},
	"mask": {
		title: "--mask GROUPS — which categories to mask (detection is unchanged; default 'all')",
		standalone: []helpExample{
			{"ospooflog -s s.json --mask secrets obfuscate -i app.log", "mask only credentials; leave IP/email/etc. visible"},
			{"ospooflog -s s.json --mask secrets,pii obfuscate -i app.log", "credentials + personal data"},
			{"ospooflog -s s.json --mask secrets,EMAIL obfuscate -i app.log", "a group plus one bare kind (power-user)"},
		},
		notes: []string{"groups: secrets (PWD/APIKEY/TOKEN/DSN/PRIVKEY) · pii (EMAIL/USER/PHONE/CARD/IP/IP6/MAC/ADDR/SID) · infra (HOST/FQDN/PORT/PATH/ARN) · ids (UUID/PUBKEY/FP)"},
	},
	"mode": {
		title: "--mode safe|balanced|aggressive — detection breadth",
		standalone: []helpExample{
			{"ospooflog -s s.json --mode balanced obfuscate -i app.log", "adds 'as alice' / abs paths / bare ports"},
			{"ospooflog -s s.json --mode aggressive obfuscate -i app.log", "adds single-label hosts + base64 decode-verify"},
		},
	},
	"json": {
		title: "--json — NDJSON mode: obfuscate string leaves, keep JSON structure",
		standalone: []helpExample{
			{"cat k8s.log | ospooflog -s s.json --json --allow-keys level,time,msg obfuscate", "mask values, skip the listed keys"},
		},
	},
	"debug": {
		title: "--debug=N (1-10) / --debug-out DIR — leveled stderr trace + Go profiling",
		standalone: []helpExample{
			{"ospooflog --debug=2 -s s.json obfuscate -i app.log", "level 2: effective options + session counts"},
			{"ospooflog --debug=10 --debug-out ./prof -s s.json obfuscate -i app.log", "full trace + runtime/trace & pprof in ./prof"},
		},
	},
	"explain": {
		title: "--explain — per-value detector decisions (why a value is or isn't masked)",
		standalone: []helpExample{
			{"ospooflog --explain -s s.json obfuscate -i app.log >/dev/null", "MASK / drop + reason on stderr; result discarded"},
		},
	},
	"valid": {
		title: "--valid — syntax-check the config and --overrides/--ignore/--cut files, then exit",
		standalone: []helpExample{
			{"ospooflog --valid --overrides ovr.yaml --ignore allow.txt --cut noise.txt", "exit 0 = all valid; 3 = bad regex"},
		},
	},
}

// helpExamplesTopic returns the topic to show examples for: only when --help/-h
// is present together with a known command or --flag among the args.
func helpExamplesTopic(args []string) (string, bool) {
	hasHelp := false
	for _, a := range args {
		if a == "--help" || a == "-h" {
			hasHelp = true
			break
		}
	}
	if !hasHelp {
		return "", false
	}
	for _, a := range args {
		name := strings.TrimPrefix(a, "--")
		if _, ok := helpTopics[name]; ok {
			return name, true
		}
	}
	return "", false
}

// printHelpExamples writes the standalone (and combined) examples for a topic.
func printHelpExamples(w io.Writer, name string) error {
	t := helpTopics[name]
	fmt.Fprintf(w, "%s\n\nExamples:\n", t.title)
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	for _, e := range t.standalone {
		fmt.Fprintf(tw, "  %s\t# %s\n", e.cmd, e.desc)
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	if len(t.combos) > 0 {
		fmt.Fprintf(w, "\nCombined with other flags:\n")
		tw = tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
		for _, e := range t.combos {
			fmt.Fprintf(tw, "  %s\t# %s\n", e.cmd, e.desc)
		}
		if err := tw.Flush(); err != nil {
			return err
		}
	}
	for _, n := range t.notes {
		fmt.Fprintf(w, "\n%s\n", n)
	}
	return nil
}
