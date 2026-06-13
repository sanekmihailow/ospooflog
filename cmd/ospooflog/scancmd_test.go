package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sanekmihailow/ospooflog/pkg/detector"
)

func TestComputeScanStats_PerValueAndMetrics(t *testing.T) {
	text := "a@b.com here\n10.0.0.1 and 10.0.0.1\nclean line\n"
	matches := []detector.Match{
		{Kind: detector.KindEmail, Value: "a@b.com", Start: 0},
		{Kind: detector.KindIP, Value: "10.0.0.1", Start: 13},
		{Kind: detector.KindIP, Value: "10.0.0.1", Start: 26}, // same line as the first IP
	}
	s := computeScanStats(matches, text, "safe")
	if s.Matches != 3 || s.DistinctValues != 2 {
		t.Errorf("totals wrong: %+v", s)
	}
	// "a@b.com"(7) + "10.0.0.1"(8) ×2 = 23 masked of 46 total characters.
	if s.CharsTotal != 46 || s.CharsMasked != 23 {
		t.Errorf("char metrics wrong: total=%d masked=%d (want 46/23)", s.CharsTotal, s.CharsMasked)
	}
	if len(s.ByKind) != 2 || s.ByKind[0].Kind != "IP" || s.ByKind[0].Count != 2 {
		t.Errorf("by_kind should lead with IP×2: %+v", s.ByKind)
	}
	if s.Values[0].Value != "10.0.0.1" || s.Values[0].Count != 2 {
		t.Errorf("values should lead with 10.0.0.1×2: %+v", s.Values[0])
	}
}

func TestPrintScanText_Empty(t *testing.T) {
	var buf bytes.Buffer
	if err := printScanText(&buf, computeScanStats(nil, "a\nb\n", "safe")); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "no sensitive values detected in 4 characters") {
		t.Errorf("expected the empty marker with char count, got:\n%s", buf.String())
	}
}

func TestPrintScanJSON_Valid(t *testing.T) {
	matches := []detector.Match{
		{Kind: detector.KindIP, Value: "10.0.0.1", Start: 0},
		{Kind: detector.KindIP, Value: "10.0.0.1", Start: 9},
	}
	var buf bytes.Buffer
	if err := printScanJSON(&buf, computeScanStats(matches, "10.0.0.1 10.0.0.1\n", "safe")); err != nil {
		t.Fatal(err)
	}
	var got scanStats
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, buf.String())
	}
	if got.Matches != 2 || got.DistinctValues != 1 || got.Mode != "safe" {
		t.Errorf("decoded stats wrong: %+v", got)
	}
	if len(got.ByKind) != 1 || got.ByKind[0].Kind != "IP" || got.ByKind[0].Count != 2 {
		t.Errorf("by_kind wrong: %+v", got.ByKind)
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

func TestGeneralizePattern_AtomUnion(t *testing.T) {
	cases := []struct {
		values []string
		want   string
	}{
		{[]string{"10.0.0.1", "192.168.0.5"}, `(?:\d+|\.)+`},          // digits + dot
		{[]string{"alice", "bob"}, `[A-Za-z]+`},                       // single atom
		{[]string{"k3s-node01", "web2-prod"}, `(?:[A-Za-z]+|\d+|-)+`}, // varied hosts → one pattern
	}
	for _, c := range cases {
		if got := generalizePattern(c.values); got != c.want {
			t.Errorf("generalizePattern(%v) = %q, want %q", c.values, got, c.want)
		}
	}
}

func TestWriteRules_SimpleExactAndOrdered(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "rules.yaml")
	matches := []detector.Match{
		{Kind: detector.KindEmail, Value: "a@b.com"},
		{Kind: detector.KindIP, Value: "10.0.0.1"},
		{Kind: detector.KindIP, Value: "10.0.0.1"}, // count 2 → higher coverage
	}
	if err := writeRules(out, matches, true); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	s := string(data)
	if !strings.Contains(s, "origin: 10.0.0.1") || !strings.Contains(s, "origin: a@b.com") {
		t.Errorf("simple mode should list exact values:\n%s", s)
	}
	if strings.Index(s, "10.0.0.1") > strings.Index(s, "a@b.com") {
		t.Errorf("higher-coverage value should come first:\n%s", s)
	}
}

func TestWriteRules_RegexEmitsPatterns(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "rules.yaml")
	matches := []detector.Match{{Kind: detector.KindIP, Value: "10.0.0.1"}}
	if err := writeRules(out, matches, false); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	// grex or the built-in generalizer both yield an "re:" pattern entry.
	if !strings.Contains(string(data), "origin: re:") {
		t.Errorf("regex mode should emit an re: pattern:\n%s", data)
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
