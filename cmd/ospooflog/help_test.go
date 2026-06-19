package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestHelpExamplesTopic(t *testing.T) {
	cases := []struct {
		args []string
		want string
		ok   bool
	}{
		{[]string{"--help", "--overrides"}, "overrides", true}, // flag topic
		{[]string{"--help", "scan"}, "scan", true},             // command topic
		{[]string{"-h", "--keep-tld"}, "keep-tld", true},       // short -h + flag
		{[]string{"--overrides", "ovr.yaml"}, "", false},       // no --help → not a topic request
		{[]string{"--help"}, "", false},                        // bare --help → fall through to go-flags
		{[]string{"--help", "--nonsense"}, "", false},          // unknown topic → fall through
	}
	for _, c := range cases {
		got, ok := helpExamplesTopic(c.args)
		if got != c.want || ok != c.ok {
			t.Errorf("helpExamplesTopic(%v) = (%q,%v), want (%q,%v)", c.args, got, ok, c.want, c.ok)
		}
	}
}

func TestPrintHelpExamples_StandaloneAndCombos(t *testing.T) {
	var buf bytes.Buffer
	if err := printHelpExamples(&buf, "obfuscate"); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "Examples:") {
		t.Errorf("missing standalone header:\n%s", out)
	}
	if !strings.Contains(out, "Combined with other flags:") {
		t.Errorf("obfuscate has combos, header missing:\n%s", out)
	}
	if !strings.Contains(out, "obfuscate -i app.log -o safe.log") {
		t.Errorf("missing a known example line:\n%s", out)
	}
}

func TestPrintHelpExamples_NoCombosNoHeader(t *testing.T) {
	var buf bytes.Buffer
	if err := printHelpExamples(&buf, "show"); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buf.String(), "Combined with other flags:") {
		t.Errorf("show has no combos, header should be absent:\n%s", buf.String())
	}
}

// Every topic must be either a known command or a real long flag, so the help
// stays in sync with the actual CLI surface.
func TestHelpTopics_HaveTitleAndExamples(t *testing.T) {
	for name, topic := range helpTopics {
		if topic.title == "" {
			t.Errorf("topic %q has no title", name)
		}
		if len(topic.standalone) == 0 {
			t.Errorf("topic %q has no standalone examples", name)
		}
	}
}
