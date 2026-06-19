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

	// Originals must not leak. /var/lib/postgresql/data (4 segments)
	// is intentionally preserved by the shallow-path policy — it's
	// FHS-level structure, not PII — so it's NOT in this list and
	// the assertion below confirms it remains in the output.
	for _, leaked := range []string{
		"10.23.41.5", "db-prod.internal", "alice", "corp.com",
		"550e8400-e29b-41d4-a716-446655440000",
	} {
		if strings.Contains(safeStr, leaked) {
			t.Errorf("origin %q leaked into safe output:\n%s", leaked, safeStr)
		}
	}
	if !strings.Contains(safeStr, "/var/lib/postgresql/data") {
		t.Errorf("shallow path /var/lib/postgresql/data should pass through unchanged:\n%s", safeStr)
	}

	// Step 2 — synthesise an AI response that uses the replace values.
	// Pull a couple out of the safe text by grepping known templates.
	if !strings.Contains(safeStr, "192.168.0.") {
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

// TestRoundTrip_PEMAndIPScope locks in two things the format sweep
// verified by hand: a multi-line PEM private-key block round-trips
// byte-for-byte (the body spans newlines, the trickiest replace shape),
// and the public/private IP scope split plus well-known-resolver
// preservation survive a full CLI obfuscate→restore.
func TestRoundTrip_PEMAndIPScope(t *testing.T) {
	dir := t.TempDir()
	logFile := filepath.Join(dir, "in.log")
	safeFile := filepath.Join(dir, "safe.txt")
	resultFile := filepath.Join(dir, "out.txt")
	sessionFile := filepath.Join(dir, "s.json")

	raw := `internal 10.0.0.8 external 203.0.113.5 resolver 8.8.8.8
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtz
c2gtZWQyNTUxOQAAACDvuMQ3pAaKw9P7eq7Dn5Hd5e6Z4mZ5Z4mZ5Z4mZ5Z4g
-----END OPENSSH PRIVATE KEY-----
done
`
	if err := os.WriteFile(logFile, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"-i", logFile, "-o", safeFile, "-s", sessionFile, "obfuscate"}); err != nil {
		t.Fatalf("obfuscate failed: %v", err)
	}
	safe, err := os.ReadFile(safeFile)
	if err != nil {
		t.Fatal(err)
	}
	safeStr := string(safe)

	// PEM body masked to a single token; private → 192.168/16, public →
	// 77/8; well-known resolver 8.8.8.8 preserved.
	for _, want := range []string{"FAKE_PRIVATE_KEY_", "192.168.0.", "77.0.0.", "8.8.8.8"} {
		if !strings.Contains(safeStr, want) {
			t.Errorf("safe output missing %q:\n%s", want, safeStr)
		}
	}
	// The BEGIN/END markers are not secret and stay; the base64 key body
	// is what must be gone.
	for _, leaked := range []string{"10.0.0.8", "203.0.113.5", "b3BlbnNzaC1rZXktdjEA"} {
		if strings.Contains(safeStr, leaked) {
			t.Errorf("origin %q leaked:\n%s", leaked, safeStr)
		}
	}

	// Round-trip restores the original byte-for-byte, multi-line key included.
	if err := run([]string{"-i", safeFile, "-o", resultFile, "-s", sessionFile, "restore"}); err != nil {
		t.Fatalf("restore failed: %v", err)
	}
	result, err := os.ReadFile(resultFile)
	if err != nil {
		t.Fatal(err)
	}
	if string(result) != raw {
		t.Errorf("round-trip not byte-exact:\n--- want ---\n%s\n--- got ---\n%s", raw, result)
	}
}

func TestMode_BalancedEnablesAsAliceButNotSingleLabelHost(t *testing.T) {
	dir := t.TempDir()
	logFile := filepath.Join(dir, "log.txt")
	safeFile := filepath.Join(dir, "safe.txt")
	sessionFile := filepath.Join(dir, "session.json")

	// "as alice" only fires under balanced+ ; "host=db-prod" only under aggressive.
	if err := os.WriteFile(logFile, []byte("running as alice host=db-prod start"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"-i", logFile, "-o", safeFile, "-s", sessionFile, "--mode", "balanced", "obfuscate"}); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(safeFile)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(got), "alice") {
		t.Errorf("balanced should mask 'alice' from 'as alice':\n%s", got)
	}
	if !strings.Contains(string(got), "db-prod") {
		t.Errorf("balanced should NOT mask single-label HOST 'db-prod':\n%s", got)
	}
}

func TestMode_UnknownValueErrors(t *testing.T) {
	dir := t.TempDir()
	logFile := filepath.Join(dir, "log.txt")
	if err := os.WriteFile(logFile, []byte("foo"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := run([]string{"-i", logFile, "-o", filepath.Join(dir, "out"), "-s", filepath.Join(dir, "s.json"), "--mode", "yolo", "obfuscate"})
	if err == nil {
		t.Fatal("expected error for unknown --mode value")
	}
	if !strings.Contains(err.Error(), "unknown --mode") {
		t.Errorf("error should mention unknown --mode, got: %v", err)
	}
}

func TestFastRestore_FallsForSubstringTrap(t *testing.T) {
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
	aiText := "see 192.168.0.10 for context"
	if err := os.WriteFile(aiFile, []byte(aiText), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"-i", aiFile, "-o", resultFile, "-s", sessionFile, "--fast-restore", "restore"}); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(resultFile)
	// Fast mode falls for the trap: replaces "192.168.0.1" inside "192.168.0.10".
	if !strings.Contains(string(got), "10.23.41.50") {
		t.Errorf("expected fast-restore substring trap to produce '10.23.41.50' in: %s", got)
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
	aiText := "to fix, also check 192.168.0.10 for context\nour mapped one stays at 192.168.0.1"
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

	if !strings.Contains(got, "192.168.0.10") {
		t.Errorf("strict mode should preserve the AI's unrelated 192.168.0.10:\n%s", got)
	}
	if !strings.Contains(got, "10.23.41.5") {
		t.Errorf("strict mode should still restore real mapping:\n%s", got)
	}
}

func TestShow_PrintsMapping(t *testing.T) {
	dir := t.TempDir()
	logFile := filepath.Join(dir, "log.txt")
	safeFile := filepath.Join(dir, "safe.txt")
	showFile := filepath.Join(dir, "show.txt")
	sessionFile := filepath.Join(dir, "s.json")

	if err := os.WriteFile(logFile, []byte("user=alice from 10.1.2.3"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"-i", logFile, "-o", safeFile, "-s", sessionFile, "obfuscate"}); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"-o", showFile, "-s", sessionFile, "show"}); err != nil {
		t.Fatal(err)
	}
	out, err := os.ReadFile(showFile)
	if err != nil {
		t.Fatal(err)
	}
	got := string(out)
	for _, want := range []string{"TOKEN", "KIND", "ORIGIN", "REPLACE", "alice", "user1", "10.1.2.3", "192.168.0.1"} {
		if !strings.Contains(got, want) {
			t.Errorf("show output missing %q:\n%s", want, got)
		}
	}
}

func TestShow_EmptySession(t *testing.T) {
	dir := t.TempDir()
	showFile := filepath.Join(dir, "show.txt")
	sessionFile := filepath.Join(dir, "s.json")

	if err := run([]string{"-o", showFile, "-s", sessionFile, "show"}); err != nil {
		t.Fatal(err)
	}
	out, err := os.ReadFile(showFile)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), "(session is empty)") {
		t.Errorf("expected empty marker: %s", out)
	}
}

func TestDryRun_PrintsMatchesAndDoesNotMutate(t *testing.T) {
	dir := t.TempDir()
	logFile := filepath.Join(dir, "log.txt")
	dryFile := filepath.Join(dir, "dry.txt")
	sessionFile := filepath.Join(dir, "s.json")

	if err := os.WriteFile(logFile, []byte("user=alice from 10.1.2.3"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"-i", logFile, "-o", dryFile, "-s", sessionFile, "--dry-run", "obfuscate"}); err != nil {
		t.Fatal(err)
	}

	dry, err := os.ReadFile(dryFile)
	if err != nil {
		t.Fatal(err)
	}
	got := string(dry)
	for _, want := range []string{"OFFSET", "KIND", "VALUE", "USER", "alice", "IP", "10.1.2.3"} {
		if !strings.Contains(got, want) {
			t.Errorf("dry-run output missing %q:\n%s", want, got)
		}
	}

	// Session file must NOT have been written.
	if _, err := os.Stat(sessionFile); !os.IsNotExist(err) {
		t.Errorf("dry-run created a session file (err=%v)", err)
	}
}

func TestDiff_PrintsChangedLinesAndDoesNotMutate(t *testing.T) {
	dir := t.TempDir()
	logFile := filepath.Join(dir, "log.txt")
	diffFile := filepath.Join(dir, "diff.txt")
	sessionFile := filepath.Join(dir, "s.json")

	// Two changed lines (first mask USER, second mask IP) bracketing an
	// untouched line that must NOT appear in the diff output.
	rawLog := "user=alice login\nunchanged middle line with no secrets\nconnect 10.1.2.3 ok\n"
	if err := os.WriteFile(logFile, []byte(rawLog), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"-i", logFile, "-o", diffFile, "-s", sessionFile, "--diff", "obfuscate"}); err != nil {
		t.Fatalf("diff run failed: %v", err)
	}

	got, err := os.ReadFile(diffFile)
	if err != nil {
		t.Fatal(err)
	}
	gotStr := string(got)

	for _, want := range []string{"- user=alice login", "+ user=user1 login", "- connect 10.1.2.3 ok", "+ connect 192.168.0.1 ok"} {
		if !strings.Contains(gotStr, want) {
			t.Errorf("diff output missing %q:\n%s", want, gotStr)
		}
	}
	if strings.Contains(gotStr, "unchanged middle line") {
		t.Errorf("diff output should skip unchanged lines:\n%s", gotStr)
	}

	if _, err := os.Stat(sessionFile); !os.IsNotExist(err) {
		t.Errorf("--diff created a session file (err=%v)", err)
	}
}

func TestDiff_ConflictsWithDryRun(t *testing.T) {
	dir := t.TempDir()
	logFile := filepath.Join(dir, "log.txt")
	if err := os.WriteFile(logFile, []byte("user=alice"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := run([]string{"-i", logFile, "-o", filepath.Join(dir, "out"), "-s", filepath.Join(dir, "s.json"), "--diff", "--dry-run", "obfuscate"})
	if err == nil {
		t.Fatal("expected error when --diff and --dry-run are combined")
	}
	if !strings.Contains(err.Error(), "mutually exclusive") {
		t.Errorf("error should mention mutual exclusion, got: %v", err)
	}
}

func TestDiff_NoChangesMarker(t *testing.T) {
	dir := t.TempDir()
	logFile := filepath.Join(dir, "log.txt")
	diffFile := filepath.Join(dir, "diff.txt")
	sessionFile := filepath.Join(dir, "s.json")

	if err := os.WriteFile(logFile, []byte("nothing sensitive here at all\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"-i", logFile, "-o", diffFile, "-s", sessionFile, "--diff", "obfuscate"}); err != nil {
		t.Fatalf("diff run failed: %v", err)
	}
	got, err := os.ReadFile(diffFile)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(got), "(no changes)") {
		t.Errorf("expected '(no changes)' marker, got:\n%s", got)
	}
}

func TestDiff_JSONMode(t *testing.T) {
	dir := t.TempDir()
	logFile := filepath.Join(dir, "log.json")
	diffFile := filepath.Join(dir, "diff.txt")
	sessionFile := filepath.Join(dir, "s.json")

	rawLog := `{"user":"alice","ip":"10.1.2.3"}` + "\n"
	if err := os.WriteFile(logFile, []byte(rawLog), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"-i", logFile, "-o", diffFile, "-s", sessionFile, "--json", "--diff", "obfuscate"}); err != nil {
		t.Fatalf("diff run failed: %v", err)
	}
	got, err := os.ReadFile(diffFile)
	if err != nil {
		t.Fatal(err)
	}
	gotStr := string(got)
	if !strings.Contains(gotStr, `- {"user":"alice","ip":"10.1.2.3"}`) {
		t.Errorf("missing original line in diff:\n%s", gotStr)
	}
	if !strings.Contains(gotStr, `"user":"user1"`) || !strings.Contains(gotStr, `"ip":"192.168.0.1"`) {
		t.Errorf("missing obfuscated values in diff:\n%s", gotStr)
	}
}

func TestOverrides_CustomReplaceWins(t *testing.T) {
	dir := t.TempDir()
	logFile := filepath.Join(dir, "log.txt")
	safeFile := filepath.Join(dir, "safe.txt")
	resultFile := filepath.Join(dir, "result.txt")
	aiFile := filepath.Join(dir, "ai.txt")
	sessionFile := filepath.Join(dir, "s.json")
	overridesFile := filepath.Join(dir, "overrides.yaml")

	if err := os.WriteFile(overridesFile, []byte(`overrides:
  - origin: alice
    replace: john
  - origin: 10.1.2.3
    replace: 172.16.0.5
`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(logFile, []byte("user=alice from 10.1.2.3 plus 10.4.5.6"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"-i", logFile, "-o", safeFile, "-s", sessionFile, "--overrides", overridesFile, "obfuscate"}); err != nil {
		t.Fatal(err)
	}
	safe, err := os.ReadFile(safeFile)
	if err != nil {
		t.Fatal(err)
	}
	safeStr := string(safe)
	for _, want := range []string{"john", "172.16.0.5"} {
		if !strings.Contains(safeStr, want) {
			t.Errorf("override missing in obfuscate output: want %q in\n%s", want, safeStr)
		}
	}
	// Non-overridden origin still uses template.
	if !strings.Contains(safeStr, "192.168.0.") {
		t.Errorf("template-derived replacement missing for non-overridden IP:\n%s", safeStr)
	}

	// Round-trip with overrides — restore must map "john" back to "alice".
	if err := os.WriteFile(aiFile, []byte("Tell john at 172.16.0.5 to retry"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"-i", aiFile, "-o", resultFile, "-s", sessionFile, "restore"}); err != nil {
		t.Fatal(err)
	}
	result, err := os.ReadFile(resultFile)
	if err != nil {
		t.Fatal(err)
	}
	want := "Tell alice at 10.1.2.3 to retry"
	if string(result) != want {
		t.Errorf("override round-trip:\n got %q\nwant %q", result, want)
	}
}

// TestOverrides_RegexCollapsesClass covers the re: prefix: one pattern masks a
// whole class to a single fake in the output, but each distinct matched value
// is recorded as its own session entry so restore can reverse the shared fake.
func TestOverrides_RegexCollapsesClass(t *testing.T) {
	dir := t.TempDir()
	logFile := filepath.Join(dir, "log.txt")
	safeFile := filepath.Join(dir, "safe.txt")
	showFile := filepath.Join(dir, "show.txt")
	aiFile := filepath.Join(dir, "ai.txt")
	resultFile := filepath.Join(dir, "result.txt")
	sessionFile := filepath.Join(dir, "s.json")
	overridesFile := filepath.Join(dir, "overrides.yaml")

	if err := os.WriteFile(overridesFile, []byte(`overrides:
  - origin: "re:user[0-9]+"
    replace: MASKED_USER
`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(logFile, []byte("login user1\nlogin user42\nlogin user99\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"-i", logFile, "-o", safeFile, "-s", sessionFile, "--overrides", overridesFile, "obfuscate"}); err != nil {
		t.Fatal(err)
	}
	safe, err := os.ReadFile(safeFile)
	if err != nil {
		t.Fatal(err)
	}
	// All three distinct values collapse to the one replace; none leak.
	if got := strings.Count(string(safe), "MASKED_USER"); got != 3 {
		t.Errorf("expected 3 MASKED_USER in output, got %d:\n%s", got, safe)
	}
	for _, leaked := range []string{"user1", "user42", "user99"} {
		if strings.Contains(string(safe), leaked) {
			t.Errorf("origin %q leaked into output:\n%s", leaked, safe)
		}
	}

	// Each distinct match is its own session entry, not merged into one.
	if err := run([]string{"-s", sessionFile, "-o", showFile, "show"}); err != nil {
		t.Fatal(err)
	}
	show, err := os.ReadFile(showFile)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"user1", "user42", "user99"} {
		if !strings.Contains(string(show), want) {
			t.Errorf("session missing per-value entry for %q:\n%s", want, show)
		}
	}

	// Restore maps the shared fake back to a real value (collapse is lossy by
	// design — any one original is acceptable, but the fake must be gone).
	if err := os.WriteFile(aiFile, []byte("check MASKED_USER now"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"-i", aiFile, "-o", resultFile, "-s", sessionFile, "restore"}); err != nil {
		t.Fatal(err)
	}
	result, err := os.ReadFile(resultFile)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(result), "MASKED_USER") {
		t.Errorf("restore left the fake in place:\n%s", result)
	}
	if !strings.Contains(string(result), "user1") &&
		!strings.Contains(string(result), "user42") &&
		!strings.Contains(string(result), "user99") {
		t.Errorf("restore did not map the fake back to an original:\n%s", result)
	}
}

// TestOverrides_LiteralWinsOverRegex confirms precedence: an explicit literal
// claims its value before a regex pattern covering the same span runs.
func TestOverrides_LiteralWinsOverRegex(t *testing.T) {
	dir := t.TempDir()
	logFile := filepath.Join(dir, "log.txt")
	safeFile := filepath.Join(dir, "safe.txt")
	sessionFile := filepath.Join(dir, "s.json")
	overridesFile := filepath.Join(dir, "overrides.yaml")

	if err := os.WriteFile(overridesFile, []byte(`overrides:
  - origin: "re:user[0-9]+"
    replace: GENERIC
  - origin: user42
    replace: SPECIAL
`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(logFile, []byte("user1 user42 user99"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"-i", logFile, "-o", safeFile, "-s", sessionFile, "--overrides", overridesFile, "obfuscate"}); err != nil {
		t.Fatal(err)
	}
	safe, err := os.ReadFile(safeFile)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(safe), "SPECIAL") {
		t.Errorf("literal override should win for user42:\n%s", safe)
	}
	if got := strings.Count(string(safe), "GENERIC"); got != 2 {
		t.Errorf("regex should still mask the other two as GENERIC, got %d:\n%s", got, safe)
	}
}

func TestOverrides_RegexBadRegexErrors(t *testing.T) {
	dir := t.TempDir()
	logFile := filepath.Join(dir, "log.txt")
	overridesFile := filepath.Join(dir, "overrides.yaml")
	if err := os.WriteFile(logFile, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(overridesFile, []byte("overrides:\n  - origin: \"re:[unterminated\"\n    replace: X\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := run([]string{"-i", logFile, "-o", filepath.Join(dir, "out"), "-s", filepath.Join(dir, "s.json"), "--overrides", overridesFile, "obfuscate"})
	if err == nil {
		t.Fatal("expected error for bad regex override")
	}
	if !strings.Contains(err.Error(), "bad regex") {
		t.Errorf("error should mention bad regex, got: %v", err)
	}
}

func TestOverrides_RegexEmptyMatchRejected(t *testing.T) {
	dir := t.TempDir()
	logFile := filepath.Join(dir, "log.txt")
	overridesFile := filepath.Join(dir, "overrides.yaml")
	if err := os.WriteFile(logFile, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(overridesFile, []byte("overrides:\n  - origin: \"re:.*\"\n    replace: X\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := run([]string{"-i", logFile, "-o", filepath.Join(dir, "out"), "-s", filepath.Join(dir, "s.json"), "--overrides", overridesFile, "obfuscate"})
	if err == nil {
		t.Fatal("expected error for empty-matching regex override")
	}
	if !strings.Contains(err.Error(), "empty string") {
		t.Errorf("error should mention empty string, got: %v", err)
	}
}

// TestExitCodes drives run() to a failure and checks the documented code class:
// 1 argument/config, 2 I/O, 3 bad detection rule (regex).
func TestValid_PassAndFail(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(dir, "empty")) // isolate from real ~/.config
	good := filepath.Join(dir, "good.yaml")
	bad := filepath.Join(dir, "bad.yaml")
	if err := os.WriteFile(good, []byte("overrides:\n  - origin: alice\n    replace: bob\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bad, []byte("overrides:\n  - origin: \"re:[bad\"\n    replace: X\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Valid inputs: no error, and no command is required.
	if err := run([]string{"--valid", "--overrides", good}); err != nil {
		t.Errorf("--valid on good overrides should pass: %v", err)
	}
	// Bad regex: error classified as a rule problem (exit 3).
	err := run([]string{"--valid", "--overrides", bad})
	if err == nil {
		t.Fatal("--valid on bad overrides should error")
	}
	if got := exitCode(err); got != 3 {
		t.Errorf("bad regex via --valid should be exit 3, got %d (%v)", got, err)
	}
}

func TestExitCodes(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	goodLog := write("log.txt", "user1 user42")
	badOverrides := write("bad-re.yaml", "overrides:\n  - origin: \"re:[bad\"\n    replace: X\n")
	emptyOverrides := write("empty-re.yaml", "overrides:\n  - origin: \"re:.*\"\n    replace: X\n")
	badIgnore := write("bad-ignore.txt", "re:[bad\n")
	badCut := write("bad-cut.txt", "re:[bad\n")
	out := filepath.Join(dir, "out")
	sess := filepath.Join(dir, "s.json")

	cases := []struct {
		name string
		args []string
		want int
	}{
		{"unknown-mode", []string{"-i", goodLog, "-o", out, "-s", sess, "--mode", "yolo", "obfuscate"}, 1},
		{"missing-input", []string{"-i", filepath.Join(dir, "nope.txt"), "-o", out, "-s", sess, "obfuscate"}, 2},
		{"bad-overrides-regex", []string{"-i", goodLog, "-o", out, "-s", sess, "--overrides", badOverrides, "obfuscate"}, 3},
		{"empty-overrides-regex", []string{"-i", goodLog, "-o", out, "-s", sess, "--overrides", emptyOverrides, "obfuscate"}, 3},
		{"bad-ignore-regex", []string{"-i", goodLog, "-o", out, "-s", sess, "--ignore", badIgnore, "obfuscate"}, 3},
		{"bad-cut-regex", []string{"-i", goodLog, "-o", out, "-s", sess, "--cut", badCut, "obfuscate"}, 3},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := run(tc.args)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if got := exitCode(err); got != tc.want {
				t.Errorf("exitCode = %d, want %d (err: %v)", got, tc.want, err)
			}
		})
	}
}

// TestCut_RemovesWholeLines covers --cut: a literal substring drops the whole
// line it touches, before detection, and the surrounding lines still obfuscate.
func TestCut_RemovesWholeLines(t *testing.T) {
	dir := t.TempDir()
	logFile := filepath.Join(dir, "log.txt")
	safeFile := filepath.Join(dir, "safe.txt")
	cutFile := filepath.Join(dir, "cut.txt")
	sessionFile := filepath.Join(dir, "s.json")

	raw := "real line user=alice\n#----------------(HOME-WIN) 7-[Sat Jun 06] [10.0.0.1]\nkeep this user=bob\n"
	if err := os.WriteFile(logFile, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cutFile, []byte("# drop the shell prompt\n(HOME-WIN)\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"-i", logFile, "-o", safeFile, "-s", sessionFile, "--cut", cutFile, "obfuscate"}); err != nil {
		t.Fatal(err)
	}
	safe, err := os.ReadFile(safeFile)
	if err != nil {
		t.Fatal(err)
	}
	// The cut line (and the IP inside it) is gone entirely — not masked, removed.
	for _, gone := range []string{"HOME-WIN", "10.0.0.1", "Sat Jun"} {
		if strings.Contains(string(safe), gone) {
			t.Errorf("cut content %q should be removed:\n%s", gone, safe)
		}
	}
	// Surrounding lines survive and are still obfuscated.
	for _, want := range []string{"user1", "user2"} {
		if !strings.Contains(string(safe), want) {
			t.Errorf("kept line missing masked value %q:\n%s", want, safe)
		}
	}
}

// TestCut_MultilineBlock covers a (?s) regexp dropping a whole multi-line block
// (a 3-line shell prompt pasted into the log), keeping the lines around it.
func TestCut_MultilineBlock(t *testing.T) {
	dir := t.TempDir()
	logFile := filepath.Join(dir, "log.txt")
	safeFile := filepath.Join(dir, "safe.txt")
	cutFile := filepath.Join(dir, "cut.txt")
	sessionFile := filepath.Join(dir, "s.json")

	raw := "before user=alice\n" +
		"                    ✅\n" +
		"#----------------(HOME-WIN) 7-[Sat Jun 06] [10.0.0.1] (test)080d344\n" +
		" 00:40:14j=0 sanekM@HOME-WIN: ~/DOWNLOAD\n" +
		"\n" +
		" $\n" +
		"after user=bob\n"
	if err := os.WriteFile(logFile, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	// One pattern spans the whole prompt: from the status line through the "$".
	if err := os.WriteFile(cutFile, []byte("re:(?s)✅.*?\\$\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"-i", logFile, "-o", safeFile, "-s", sessionFile, "--cut", cutFile, "obfuscate"}); err != nil {
		t.Fatal(err)
	}
	safe, err := os.ReadFile(safeFile)
	if err != nil {
		t.Fatal(err)
	}
	for _, gone := range []string{"✅", "HOME-WIN", "sanekM", "080d344"} {
		if strings.Contains(string(safe), gone) {
			t.Errorf("multi-line block content %q should be gone:\n%s", gone, safe)
		}
	}
	for _, want := range []string{"user1", "user2"} {
		if !strings.Contains(string(safe), want) {
			t.Errorf("line outside the block missing masked value %q:\n%s", want, safe)
		}
	}
}

func TestSessionPath_DefaultWhenOmitted(t *testing.T) {
	if got := sessionPath(""); got != defaultSessionPath {
		t.Errorf("omitted -s: got %q, want %q", got, defaultSessionPath)
	}
	if got := sessionPath("/custom/s.json"); got != "/custom/s.json" {
		t.Errorf("explicit -s should win: got %q", got)
	}
}

func TestIgnore_LiteralAndRegexBothApplied(t *testing.T) {
	dir := t.TempDir()
	logFile := filepath.Join(dir, "log.txt")
	safeFile := filepath.Join(dir, "safe.txt")
	sessionFile := filepath.Join(dir, "s.json")
	ignoreFile := filepath.Join(dir, "ignore.txt")

	if err := os.WriteFile(ignoreFile, []byte(`# leave alice and the test- hosts alone
alice
re:^192\.168\.99\.\d+$
`), 0o600); err != nil {
		t.Fatal(err)
	}
	rawLog := "user=alice from 192.168.99.42 and user=bob from 10.4.5.6"
	if err := os.WriteFile(logFile, []byte(rawLog), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"-i", logFile, "-o", safeFile, "-s", sessionFile, "--ignore", ignoreFile, "obfuscate"}); err != nil {
		t.Fatalf("obfuscate failed: %v", err)
	}
	got, err := os.ReadFile(safeFile)
	if err != nil {
		t.Fatal(err)
	}
	gotStr := string(got)

	for _, preserved := range []string{"alice", "192.168.99.42"} {
		if !strings.Contains(gotStr, preserved) {
			t.Errorf("ignored value %q should remain in output:\n%s", preserved, gotStr)
		}
	}
	for _, leaked := range []string{"bob", "10.4.5.6"} {
		if strings.Contains(gotStr, leaked) {
			t.Errorf("non-ignored value %q should have been masked:\n%s", leaked, gotStr)
		}
	}
}

func TestIgnore_BadFileErrors(t *testing.T) {
	dir := t.TempDir()
	logFile := filepath.Join(dir, "log.txt")
	if err := os.WriteFile(logFile, []byte("user=alice"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := run([]string{"-i", logFile, "-o", filepath.Join(dir, "out"), "-s", filepath.Join(dir, "s.json"), "--ignore", "/nonexistent/path/ignore.txt", "obfuscate"})
	if err == nil {
		t.Fatal("expected error for missing ignore file")
	}
	if !strings.Contains(err.Error(), "ignore") {
		t.Errorf("error should mention 'ignore', got: %v", err)
	}
}

func TestJSON_NDJSONRoundTrip(t *testing.T) {
	dir := t.TempDir()
	logFile := filepath.Join(dir, "log.json")
	safeFile := filepath.Join(dir, "safe.json")
	aiFile := filepath.Join(dir, "ai.txt")
	resultFile := filepath.Join(dir, "result.txt")
	sessionFile := filepath.Join(dir, "s.json")

	rawLog := `{"level":"error","time":"2026-05-03T19:00:01Z","user":"alice","ip":"10.1.2.3","msg":"connect from 10.1.2.3"}
{"level":"info","time":"2026-05-03T19:00:02Z","user":"bob","ip":"10.4.5.6","msg":"login ok"}
`
	if err := os.WriteFile(logFile, []byte(rawLog), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"-i", logFile, "-o", safeFile, "-s", sessionFile, "--json", "--allow-keys", "level,time", "obfuscate"}); err != nil {
		t.Fatal(err)
	}

	safe, err := os.ReadFile(safeFile)
	if err != nil {
		t.Fatal(err)
	}
	safeStr := string(safe)

	// allow-keys preserved verbatim.
	if !strings.Contains(safeStr, `"level":"error"`) {
		t.Errorf("allow-key level changed: %s", safeStr)
	}
	if !strings.Contains(safeStr, `"time":"2026-05-03T19:00:01Z"`) {
		t.Errorf("allow-key time changed: %s", safeStr)
	}

	// Sensitive fields obfuscated.
	for _, leaked := range []string{"alice", "bob", "10.1.2.3", "10.4.5.6"} {
		if strings.Contains(safeStr, leaked) {
			t.Errorf("origin %q leaked: %s", leaked, safeStr)
		}
	}
	for _, want := range []string{`"user":"user1"`, `"user":"user2"`, `"ip":"192.168.0.1"`, `"ip":"192.168.0.2"`} {
		if !strings.Contains(safeStr, want) {
			t.Errorf("missing %q in safe output: %s", want, safeStr)
		}
	}

	// Restore round-trip — AI response references the fakes, restore yields originals.
	aiText := "Action items: ask user1 (192.168.0.1) and user2 (192.168.0.2) to retry."
	if err := os.WriteFile(aiFile, []byte(aiText), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"-i", aiFile, "-o", resultFile, "-s", sessionFile, "restore"}); err != nil {
		t.Fatal(err)
	}
	result, err := os.ReadFile(resultFile)
	if err != nil {
		t.Fatal(err)
	}
	want := "Action items: ask alice (10.1.2.3) and bob (10.4.5.6) to retry."
	if string(result) != want {
		t.Errorf("round-trip:\n got %q\nwant %q", result, want)
	}
}

func TestJSON_KubernetesPrefixFallsBackToPlain(t *testing.T) {
	dir := t.TempDir()
	logFile := filepath.Join(dir, "log.txt")
	safeFile := filepath.Join(dir, "safe.txt")
	sessionFile := filepath.Join(dir, "s.json")

	// k8s CRI prefix — line is not pure JSON, falls back to plain obfuscation.
	rawLog := `2026-05-03T19:00:01Z stdout F connection from 10.1.2.3 user=alice` + "\n"
	if err := os.WriteFile(logFile, []byte(rawLog), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"-i", logFile, "-o", safeFile, "-s", sessionFile, "--json", "obfuscate"}); err != nil {
		t.Fatal(err)
	}
	safe, err := os.ReadFile(safeFile)
	if err != nil {
		t.Fatal(err)
	}
	got := string(safe)
	if strings.Contains(got, "10.1.2.3") || strings.Contains(got, "alice") {
		t.Errorf("k8s-prefix fallback didn't obfuscate: %s", got)
	}
	if !strings.Contains(got, "192.168.0.1") || !strings.Contains(got, "user1") {
		t.Errorf("k8s-prefix fallback missing replacements: %s", got)
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
	if !strings.Contains(string(bSafe), "192.168.0.1") {
		t.Errorf("expected 192.168.0.1 (stable mapping for 10.1.2.3): %s", bSafe)
	}
	if !strings.Contains(string(bSafe), "192.168.0.2") {
		t.Errorf("expected 192.168.0.2 (new mapping for 10.4.5.6): %s", bSafe)
	}
}
