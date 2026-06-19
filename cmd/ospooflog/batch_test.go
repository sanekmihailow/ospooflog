package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExpandInputs(t *testing.T) {
	dir := t.TempDir()
	for _, n := range []string{"b.log", "a.log", "note.txt"} {
		if err := os.WriteFile(filepath.Join(dir, n), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	got, err := expandInputs([]string{filepath.Join(dir, "*.log")})
	if err != nil {
		t.Fatal(err)
	}
	// Glob expands to the two .log files, sorted (a before b), .txt excluded.
	if len(got) != 2 || !strings.HasSuffix(got[0], "a.log") || !strings.HasSuffix(got[1], "b.log") {
		t.Errorf("glob expand wrong: %v", got)
	}

	// A literal path that matches nothing is kept verbatim (so the missing
	// file surfaces as a read error later, not a silent skip).
	missing := filepath.Join(dir, "nope.log")
	lit, err := expandInputs([]string{missing})
	if err != nil {
		t.Fatal(err)
	}
	if len(lit) != 1 || lit[0] != missing {
		t.Errorf("literal fallback wrong: %v", lit)
	}
}

func TestObfuscate_InPlace(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(t.TempDir(), "empty"))
	dir := t.TempDir()
	sess := filepath.Join(dir, "s.json")
	a := filepath.Join(dir, "a.log")
	b := filepath.Join(dir, "b.log")
	if err := os.WriteFile(a, []byte("user=alice\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(b, []byte("login user=alice done\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"-s", sess, "--in-place", "obfuscate", a, b}); err != nil {
		t.Fatalf("in-place batch: %v", err)
	}

	ga, _ := os.ReadFile(a)
	gb, _ := os.ReadFile(b)
	if strings.Contains(string(ga), "alice") || strings.Contains(string(gb), "alice") {
		t.Errorf("in-place files still contain the original: %q %q", ga, gb)
	}
	// One shared session → alice maps to the same fake in both files.
	fake := strings.TrimSpace(strings.TrimPrefix(string(ga), "user="))
	if fake == "" || !strings.Contains(string(gb), fake) {
		t.Errorf("fake %q not shared across files: %q", fake, gb)
	}
	// The originals are preserved in the .bak backups.
	if bak, _ := os.ReadFile(a + ".bak"); string(bak) != "user=alice\n" {
		t.Errorf("backup missing or wrong: %q", bak)
	}
}

func TestObfuscate_InPlaceRequiresFiles(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(t.TempDir(), "empty"))
	if err := run([]string{"-s", filepath.Join(t.TempDir(), "s.json"), "--in-place", "obfuscate"}); err == nil {
		t.Error("expected error: --in-place without FILE args")
	}
}
