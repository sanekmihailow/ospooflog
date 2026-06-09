package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sanekmihailow/ospooflog/pkg/detector"
)

func TestDebugLog_LevelGating(t *testing.T) {
	var buf bytes.Buffer
	d := &debugLog{level: 5, w: &buf}
	d.at(3, "shown-low")
	d.at(5, "shown-edge")
	d.at(6, "hidden-high")
	out := buf.String()
	if !strings.Contains(out, "shown-low") || !strings.Contains(out, "shown-edge") {
		t.Errorf("levels <= 5 should print:\n%s", out)
	}
	if strings.Contains(out, "hidden-high") {
		t.Errorf("level 6 must not print at verbosity 5:\n%s", out)
	}
	if strings.Contains(out, ".go:") {
		t.Errorf("no caller prefix expected below level 9:\n%s", out)
	}
}

func TestDebugLog_CallerPrefixAtHighLevel(t *testing.T) {
	var buf bytes.Buffer
	d := &debugLog{level: dbgCaller, w: &buf}
	d.at(1, "x")
	if !strings.Contains(buf.String(), "debug_test.go:") {
		t.Errorf("expected caller file:line prefix at level %d:\n%s", dbgCaller, buf.String())
	}
}

func TestDebugLog_NilSafe(t *testing.T) {
	var d *debugLog
	d.at(1, "must not panic") // nil receiver
	if d.on(1) {
		t.Error("nil tracer should report off")
	}
}

func TestFindStats_Counts(t *testing.T) {
	chain := detector.New(detector.DefaultRules())
	var stats detector.FindStats
	chain.SetStats(&stats)
	chain.Find("user=alice connect 10.0.0.1")
	if stats.Emitted < 2 {
		t.Errorf("expected >=2 emitted (user, ip), got %d (%+v)", stats.Emitted, stats)
	}
	if stats.RulesEvaluated == 0 {
		t.Errorf("expected some rules evaluated: %+v", stats)
	}
	if stats.Candidates < stats.Emitted {
		t.Errorf("candidates (%d) must be >= emitted (%d)", stats.Candidates, stats.Emitted)
	}
}

// TestDebugOut_WritesArtifacts drives --debug-out and checks the binary Go
// artifacts land in the directory, non-empty.
func TestDebugOut_WritesArtifacts(t *testing.T) {
	dir := t.TempDir()
	logFile := filepath.Join(dir, "log.txt")
	if err := os.WriteFile(logFile, []byte("user=alice connect 10.0.0.1"), 0o600); err != nil {
		t.Fatal(err)
	}
	outDir := filepath.Join(dir, "prof")
	err := run([]string{"-i", logFile, "-o", filepath.Join(dir, "safe"), "-s", filepath.Join(dir, "s.json"), "--debug-out", outDir, "obfuscate"})
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"ospooflog.trace", "ospooflog.cpu.pprof", "ospooflog.mem.pprof"} {
		fi, err := os.Stat(filepath.Join(outDir, name))
		if err != nil {
			t.Errorf("missing artifact %s: %v", name, err)
			continue
		}
		if fi.Size() == 0 {
			t.Errorf("artifact %s is empty", name)
		}
	}
}
