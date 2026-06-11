package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestConfigShow_RendersOnlySetKeys(t *testing.T) {
	tru := true
	cfg := config{Mode: "balanced", KeepTLD: &tru}
	var buf bytes.Buffer
	if err := configShow(&buf, cfg); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "mode: balanced") {
		t.Errorf("missing mode:\n%s", out)
	}
	if !strings.Contains(out, "keep_tld: true") {
		t.Errorf("missing keep_tld:\n%s", out)
	}
	if strings.Contains(out, "session:") || strings.Contains(out, "debug:") {
		t.Errorf("unset keys should be omitted:\n%s", out)
	}
}

func TestConfigShow_Empty(t *testing.T) {
	var buf bytes.Buffer
	if err := configShow(&buf, config{}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "no config set") {
		t.Errorf("expected the empty marker, got:\n%s", buf.String())
	}
}

func TestConfigPath_ListsLoadedStatus(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	cfgDir := filepath.Join(dir, "ospooflog")
	if err := os.MkdirAll(cfgDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cfgDir, "config.yaml"), []byte("mode: safe\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := configPath(&buf); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "config.yaml (loaded)") {
		t.Errorf("user config should report loaded:\n%s", out)
	}
	if !strings.Contains(out, ".ospooflog.yaml (not found)") {
		t.Errorf("absent project config should report not found:\n%s", out)
	}
}

func TestConfigEdit_BootstrapsUserConfig(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	t.Setenv("EDITOR", "true") // no-op "editor" that just exits 0

	// Run from a directory with no project config so edit bootstraps the user one.
	orig, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(orig)
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}

	if err := configEdit(); err != nil {
		t.Fatalf("config edit: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "ospooflog", "config.yaml")); err != nil {
		t.Errorf("user config should have been created: %v", err)
	}
}
