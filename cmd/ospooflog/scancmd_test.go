package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sanekmihailow/ospooflog/pkg/detector"
)

func TestPrintScan_CountsAndSorts(t *testing.T) {
	matches := []detector.Match{
		{Kind: detector.KindIP, Value: "10.0.0.1"},
		{Kind: detector.KindEmail, Value: "a@b.com"},
		{Kind: detector.KindIP, Value: "10.0.0.2"},
		{Kind: detector.KindIP, Value: "10.0.0.3"},
	}
	var buf bytes.Buffer
	if err := printScan(&buf, matches, "safe"); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	// IP (3) must sort ahead of EMAIL (1).
	if ip, email := strings.Index(out, "IP"), strings.Index(out, "EMAIL"); ip < 0 || email < 0 || ip > email {
		t.Errorf("IP (3) should sort before EMAIL (1):\n%s", out)
	}
	if !strings.Contains(out, "4 matches across 2 kinds") {
		t.Errorf("missing/incorrect total:\n%s", out)
	}
}

func TestPrintScan_Empty(t *testing.T) {
	var buf bytes.Buffer
	if err := printScan(&buf, nil, "safe"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "no sensitive values detected") {
		t.Errorf("expected the empty marker, got:\n%s", buf.String())
	}
}

func TestScan_EndToEnd(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(dir, "empty")) // isolate from real config
	logFile := filepath.Join(dir, "app.log")
	if err := os.WriteFile(logFile, []byte("user=alice from 10.0.0.1"), 0o600); err != nil {
		t.Fatal(err)
	}
	// scan dispatches early, detects, prints to stdout, persists nothing.
	if err := run([]string{"-i", logFile, "scan"}); err != nil {
		t.Fatalf("scan: %v", err)
	}
}

func TestTruncateRunes(t *testing.T) {
	if got := truncateRunes("abc", 5); got != "abc" {
		t.Errorf("short string unchanged: %q", got)
	}
	if got := truncateRunes("abcdef", 3); got != "abc…" {
		t.Errorf("long string truncated with ellipsis: %q", got)
	}
}
