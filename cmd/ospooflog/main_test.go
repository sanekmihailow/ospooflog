package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestRoundTrip_FullCLI runs the obfuscate→restore loop the same way a user
// would: through the run() entry point, with file inputs and outputs and a
// shared session file. Catches regressions in CLI wiring, session
// persistence and the substring-vs-strict tradeoff.
func TestRoundTrip_FullCLI(t *testing.T) {
	dir := t.TempDir()
	logFile := filepath.Join(dir, "error.log")
	safeFile := filepath.Join(dir, "safe.txt")
	aiFile := filepath.Join(dir, "ai.txt")
	resultFile := filepath.Join(dir, "result.txt")
	sessionFile := filepath.Join(dir, "session.json")

	rawLog := `2026-05-03 19:00:01 ERROR dial tcp 10.23.41.5:5432 → db-prod.internal
2026-05-03 19:00:02 ERROR user=alice has no CONNECT privilege on appdb
2026-05-03 19:00:03 INFO trace 550e8400-e29b-41d4-a716-446655440000 done
2026-05-03 19:00:04 INFO mail to alice@corp.com
2026-05-03 19:00:05 INFO config at /var/lib/postgresql/data
`
	if err := os.WriteFile(logFile, []byte(rawLog), 0o600); err != nil {
		t.Fatal(err)
	}

	// Step 1 — obfuscate.
	if err := run([]string{"-i", logFile, "-o", safeFile, "-s", sessionFile, "obfuscate"}); err != nil {
		t.Fatalf("obfuscate failed: %v", err)
	}

	safe, err := os.ReadFile(safeFile)
	if err != nil {
		t.Fatal(err)
	}
	safeStr := string(safe)

	// Originals must not leak.
	for _, leaked := range []string{
		"10.23.41.5", "db-prod.internal", "alice", "corp.com",
		"550e8400-e29b-41d4-a716-446655440000", "/var/lib/postgresql",
	} {
		if strings.Contains(safeStr, leaked) {
			t.Errorf("origin %q leaked into safe output:\n%s", leaked, safeStr)
		}
	}

	// Step 2 — synthesise an AI response that uses the replace values.
	// Pull a couple out of the safe text by grepping known templates.
	if !strings.Contains(safeStr, "192.168.1.") {
		t.Fatalf("safe output missing IP-shaped replacement:\n%s", safeStr)
	}

	aiResponse := safeStr + `
Recommended steps:
- check the connection to the IP from the first error
- grant user1 CONNECT privilege
- review the trace UUID for context
`
	if err := os.WriteFile(aiFile, []byte(aiResponse), 0o600); err != nil {
		t.Fatal(err)
	}

	// Step 3 — restore with default (fast) mode.
	if err := run([]string{"-i", aiFile, "-o", resultFile, "-s", sessionFile, "restore"}); err != nil {
		t.Fatalf("restore failed: %v", err)
	}
	result, err := os.ReadFile(resultFile)
	if err != nil {
		t.Fatal(err)
	}
	resultStr := string(result)

	// Originals must come back.
	for _, want := range []string{
		"10.23.41.5", "db-prod.internal", "alice", "alice@corp.com",
		"550e8400-e29b-41d4-a716-446655440000", "/var/lib/postgresql/data",
	} {
		if !strings.Contains(resultStr, want) {
			t.Errorf("origin %q missing from restore output:\n%s", want, resultStr)
		}
	}

	// And the leading prefix of the original log (everything pre-first-match)
	// is preserved verbatim.
	if !strings.HasPrefix(resultStr, "2026-05-03 19:00:01 ERROR dial tcp 10.23.41.5:5432") {
		t.Errorf("prefix not preserved through round-trip:\n%s", resultStr)
	}
}

func TestRoundTrip_StrictMode(t *testing.T) {
	dir := t.TempDir()
	logFile := filepath.Join(dir, "log.txt")
	safeFile := filepath.Join(dir, "safe.txt")
	aiFile := filepath.Join(dir, "ai.txt")
	resultFile := filepath.Join(dir, "result.txt")
	sessionFile := filepath.Join(dir, "session.json")

	if err := os.WriteFile(logFile, []byte("connect 10.23.41.5 done"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"-i", logFile, "-o", safeFile, "-s", sessionFile, "obfuscate"}); err != nil {
		t.Fatal(err)
	}

	// AI invents an unrelated IP that happens to start with our replace value.
	aiText := "to fix, also check 192.168.1.10 for context\nour mapped one stays at 192.168.1.1"
	if err := os.WriteFile(aiFile, []byte(aiText), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := run([]string{"-i", aiFile, "-o", resultFile, "-s", sessionFile, "--strict-restore", "restore"}); err != nil {
		t.Fatal(err)
	}
	result, err := os.ReadFile(resultFile)
	if err != nil {
		t.Fatal(err)
	}
	got := string(result)

	if !strings.Contains(got, "192.168.1.10") {
		t.Errorf("strict mode should preserve the AI's unrelated 192.168.1.10:\n%s", got)
	}
	if !strings.Contains(got, "10.23.41.5") {
		t.Errorf("strict mode should still restore real mapping:\n%s", got)
	}
}

func TestObfuscate_AppendsToExistingSession(t *testing.T) {
	dir := t.TempDir()
	sessionFile := filepath.Join(dir, "s.json")

	logA := filepath.Join(dir, "a.log")
	if err := os.WriteFile(logA, []byte("ip=10.1.2.3"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"-i", logA, "-o", filepath.Join(dir, "a.safe"), "-s", sessionFile, "obfuscate"}); err != nil {
		t.Fatal(err)
	}

	logB := filepath.Join(dir, "b.log")
	if err := os.WriteFile(logB, []byte("ip=10.4.5.6 and again ip=10.1.2.3"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"-i", logB, "-o", filepath.Join(dir, "b.safe"), "-s", sessionFile, "obfuscate"}); err != nil {
		t.Fatal(err)
	}

	// 10.1.2.3 from run #1 must be remembered as the same replace value in run #2.
	bSafe, err := os.ReadFile(filepath.Join(dir, "b.safe"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(bSafe), "192.168.1.1") {
		t.Errorf("expected 192.168.1.1 (stable mapping for 10.1.2.3): %s", bSafe)
	}
	if !strings.Contains(string(bSafe), "192.168.1.2") {
		t.Errorf("expected 192.168.1.2 (new mapping for 10.4.5.6): %s", bSafe)
	}
}
