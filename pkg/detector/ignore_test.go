package detector

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestIgnoreList_ParseAndMatch(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "ignore.txt")
	body := `# top-level comment
   # leading-whitespace comment

alice
10.0.0.5
/opt/myapp/secret-path
   trimmed-literal

re:^test-[a-z0-9]+$
re:\.staging\.corp\.com$
`
	if err := os.WriteFile(f, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	il, err := LoadIgnoreList(f)
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	hits := []string{
		"alice",
		"10.0.0.5",
		"/opt/myapp/secret-path",
		"trimmed-literal",
		"test-foo",
		"test-abc123",
		"api.staging.corp.com",
	}
	for _, v := range hits {
		if !il.Match(v) {
			t.Errorf("expected %q to be ignored", v)
		}
	}

	misses := []string{
		"",
		"Alice",            // literals are case-sensitive
		"10.0.0.6",
		"/opt/myapp",       // shorter than the literal
		"test-FOO",         // regex is [a-z0-9]+, uppercase doesn't match
		"corp.com",         // suffix regex requires the .staging. infix
	}
	for _, v := range misses {
		if il.Match(v) {
			t.Errorf("expected %q to NOT be ignored", v)
		}
	}
}

func TestIgnoreList_BadRegexReportsLine(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "ignore.txt")
	body := "good\nre:[unterminated\n"
	if err := os.WriteFile(f, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := LoadIgnoreList(f)
	if err == nil {
		t.Fatal("expected error for malformed regex")
	}
	if !strings.Contains(err.Error(), ":2:") {
		t.Errorf("error should pinpoint line 2, got: %v", err)
	}
}

func TestIgnoreList_NilSafe(t *testing.T) {
	var il *IgnoreList
	if il.Match("anything") {
		t.Errorf("nil IgnoreList must not match anything")
	}
}

func TestIgnoreList_DropsCapturedMatch(t *testing.T) {
	// End-to-end through the chain: IgnoreList hit removes the Match
	// without claiming the byte range, so a neighbouring rule whose
	// match span overlaps is unaffected.
	il := &IgnoreList{
		literals: map[string]bool{"alice": true},
	}
	chain := New(DefaultRules())
	chain.SetIgnore(il)

	matches := chain.Find("user=alice from 10.1.2.3")
	for _, m := range matches {
		if m.Value == "alice" {
			t.Errorf("alice should have been ignored: %+v", m)
		}
	}
	// 10.1.2.3 must still be captured — proves the ignore filter is
	// per-value and doesn't poison neighbouring spans.
	var hitIP bool
	for _, m := range matches {
		if m.Kind == KindIP && m.Value == "10.1.2.3" {
			hitIP = true
		}
	}
	if !hitIP {
		t.Errorf("10.1.2.3 should still be captured alongside ignored alice: %+v", matches)
	}
}
