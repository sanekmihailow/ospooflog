//go:build failtests

// Intentionally-red canaries. Each test asserts the OPPOSITE of a real
// guarantee, so a failure here is the expected, healthy state — it proves the
// underlying machinery still bites. A green test in this file means a guarantee
// silently stopped holding. Excluded from normal builds by the failtests tag;
// run with `make test-fail`.
package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sanekmihailow/ospooflog/pkg/detector"
	"github.com/sanekmihailow/ospooflog/pkg/jsonproc"
	"github.com/sanekmihailow/ospooflog/pkg/mapper"
	"github.com/sanekmihailow/ospooflog/pkg/obfuscator"
	"github.com/sanekmihailow/ospooflog/pkg/replacer"
)

// Detector still masks obviously sensitive values. RED = detection alive.
func TestFail_SensitiveValueMustLeak(t *testing.T) {
	matches := detector.New(detector.DefaultRules()).Find("mail alice@corp.com from 10.0.0.1")
	if len(matches) != 0 {
		t.Fatalf("RED as designed: detector masked %d value(s); GREEN would mean detection broke", len(matches))
	}
}

// A bad re: pattern is rejected with exit 3. RED = the validator catches it.
func TestFail_BadRegexMustExitZero(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(t.TempDir(), "empty"))
	ovr := filepath.Join(t.TempDir(), "ovr.yaml")
	if err := os.WriteFile(ovr, []byte("overrides:\n  - {origin: \"re:[\", replace: X}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code := exitCode(run([]string{"--valid", "--overrides", ovr})); code != 0 {
		t.Fatalf("RED as designed: bad regex exited %d; GREEN would mean --valid stopped catching broken patterns", code)
	}
}

// A missing input file is an I/O error (exit 2). RED = the error path works.
func TestFail_MissingInputMustExitZero(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(t.TempDir(), "empty"))
	missing := filepath.Join(t.TempDir(), "does-not-exist.log")
	if code := exitCode(run([]string{"-i", missing, "scan"})); code != 0 {
		t.Fatalf("RED as designed: missing input exited %d; GREEN would mean I/O errors are swallowed", code)
	}
}

// obfuscate → restore is a lossless roundtrip. RED = the session round-trips.
func TestFail_RoundtripMustCorrupt(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(t.TempDir(), "empty"))
	dir := t.TempDir()
	orig := "user=alice from 10.0.0.1\n"
	in := filepath.Join(dir, "in.log")
	sess := filepath.Join(dir, "s.json")
	obf := filepath.Join(dir, "obf.log")
	out := filepath.Join(dir, "out.log")
	if err := os.WriteFile(in, []byte(orig), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"-s", sess, "-i", in, "-o", obf, "obfuscate"}); err != nil {
		t.Fatalf("obfuscate failed (not the point of this test): %v", err)
	}
	if err := run([]string{"-s", sess, "-i", obf, "-o", out, "restore"}); err != nil {
		t.Fatalf("restore failed (not the point of this test): %v", err)
	}
	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) == orig {
		t.Fatalf("RED as designed: roundtrip restored the original exactly; GREEN would mean it corrupts data")
	}
}

// Every help topic carries examples. RED = the registry is populated.
func TestFail_HelpTopicsMustBeEmpty(t *testing.T) {
	if len(helpTopics["scan"].standalone) != 0 {
		t.Fatalf("RED as designed: the scan topic has examples; GREEN would mean the help registry emptied out")
	}
}

// --mask drops kinds outside the selected set. RED = the kind filter still bites.
func TestFail_MaskMustIgnoreFilter(t *testing.T) {
	c := detector.New(detector.DefaultRules())
	c.SetMask(map[detector.EntityKind]bool{detector.KindIP: true})
	hasEmail := false
	for _, m := range c.Find("mail a@b.com from 10.0.0.1") {
		if m.Kind == detector.KindEmail {
			hasEmail = true
		}
	}
	if !hasEmail {
		t.Fatalf("RED as designed: --mask dropped the unselected EMAIL; GREEN would mean the kind filter stopped working")
	}
}

// --fields remove drops the field. RED = the remove action still bites.
func TestFail_JSONRemoveMustKeepField(t *testing.T) {
	d := detector.New(detector.DefaultRules())
	m := mapper.New(replacer.New())
	p := jsonproc.New(obfuscator.New(d, m), m, nil, jsonproc.FieldRules{
		"secret": {Action: jsonproc.ActionRemove},
	})
	if !strings.Contains(p.Process(`{"secret":"x","keep":"y"}`), "secret") {
		t.Fatalf("RED as designed: --fields remove dropped the field; GREEN would mean remove stopped working")
	}
}

// --in-place backs the original up to FILE.bak. RED = the backup is written.
func TestFail_InPlaceMustNotBackup(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(t.TempDir(), "empty"))
	dir := t.TempDir()
	f := filepath.Join(dir, "a.log")
	if err := os.WriteFile(f, []byte("user=alice\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"-s", filepath.Join(dir, "s.json"), "--in-place", "obfuscate", f}); err != nil {
		t.Fatalf("in-place failed (not the point of this test): %v", err)
	}
	if _, err := os.Stat(f + ".bak"); err == nil {
		t.Fatalf("RED as designed: --in-place wrote the .bak backup; GREEN would mean the backup was skipped")
	}
}
