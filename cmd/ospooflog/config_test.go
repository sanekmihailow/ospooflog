package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestConfig_ProjectOverridesHome(t *testing.T) {
	dir := t.TempDir()
	home := filepath.Join(dir, "home.yaml")
	proj := filepath.Join(dir, "proj.yaml")
	if err := os.WriteFile(home, []byte("mode: safe\nsession: /home/s.json\ndebug: true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(proj, []byte("mode: balanced\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// configPaths() order is [home, project]; project wins per key.
	cfg, err := loadConfigFrom([]string{home, proj})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Mode != "balanced" {
		t.Errorf("project should override mode: got %q", cfg.Mode)
	}
	if cfg.Session != "/home/s.json" {
		t.Errorf("home session should survive: got %q", cfg.Session)
	}
	if cfg.Debug == nil || !*cfg.Debug {
		t.Errorf("home debug=true should survive: %v", cfg.Debug)
	}
}

func TestConfig_ApplyToPrecedence(t *testing.T) {
	tru := true
	cfg := config{Mode: "balanced", Session: "/cfg/s.json", JSON: &tru}

	o := opts{Mode: "aggressive"} // flag set
	cfg.applyTo(&o)
	if o.Mode != "aggressive" {
		t.Errorf("flag mode should win over config: got %q", o.Mode)
	}
	if o.Session != "/cfg/s.json" {
		t.Errorf("config session should fill unset flag: got %q", o.Session)
	}
	if !o.JSON {
		t.Errorf("config json=true should fill unset flag: got %v", o.JSON)
	}
}

func TestConfig_MissingFilesNotAnError(t *testing.T) {
	cfg, err := loadConfigFrom([]string{"/no/such/a.yaml", "/no/such/b.yaml"})
	if err != nil {
		t.Fatalf("missing config files should not error: %v", err)
	}
	if cfg.Mode != "" {
		t.Errorf("expected empty config, got %+v", cfg)
	}
}

func TestConfig_MalformedErrors(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.yaml")
	if err := os.WriteFile(bad, []byte("mode: [unterminated\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadConfigFrom([]string{bad}); err == nil {
		t.Fatal("expected error for malformed config")
	}
}

// TestConfig_ProjectFileAppliedEndToEnd drives run() from a directory holding a
// .ospooflog.yaml and confirms the config's mode takes effect without --mode.
func TestConfig_ProjectFileAppliedEndToEnd(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(dir, "empty")) // isolate from real ~/.config
	orig, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(orig)
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(".ospooflog.yaml", []byte("mode: balanced\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile("log.txt", []byte("running as alice"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"-i", "log.txt", "-o", "safe.txt", "-s", "s.json", "obfuscate"}); err != nil {
		t.Fatal(err)
	}
	safe, err := os.ReadFile("safe.txt")
	if err != nil {
		t.Fatal(err)
	}
	// "as alice" only masks under balanced+, so config mode took effect.
	if strings.Contains(string(safe), "alice") {
		t.Errorf("config mode=balanced should mask 'as alice':\n%s", safe)
	}
}
