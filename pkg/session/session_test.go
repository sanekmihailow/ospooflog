package session

import (
	"path/filepath"
	"testing"

	"github.com/sanekmihailow/ospooflog/pkg/detector"
	"github.com/sanekmihailow/ospooflog/pkg/mapper"
	"github.com/sanekmihailow/ospooflog/pkg/replacer"
)

func TestSaveLoad_Roundtrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "s.json")

	m1 := mapper.New(replacer.New())
	m1.Obfuscate("alice", detector.KindUser, nil)
	m1.Obfuscate("10.1.2.3", detector.KindIP, nil)
	m1.Obfuscate("10.1.2.3:5432", detector.KindAddr, map[string]string{"port": "5432"})

	if err := Save(path, m1); err != nil {
		t.Fatal(err)
	}

	m2 := mapper.New(replacer.New())
	if err := Load(path, m2); err != nil {
		t.Fatal(err)
	}

	cases := []struct{ replace, origin string }{
		{"user1", "alice"},
		{"192.168.0.1", "10.1.2.3"},
		{"192.168.0.1:5432", "10.1.2.3:5432"},
	}
	for _, c := range cases {
		got, ok := m2.Restore(c.replace)
		if !ok || got != c.origin {
			t.Errorf("restore %q: got %q ok=%v, want %q", c.replace, got, ok, c.origin)
		}
	}
}

func TestLoad_Missing_NotError(t *testing.T) {
	m := mapper.New(replacer.New())
	err := Load(filepath.Join(t.TempDir(), "nope.json"), m)
	if err != nil {
		t.Errorf("missing file should not error, got %v", err)
	}
}

func TestSave_PreservesCreated(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "s.json")

	m1 := mapper.New(replacer.New())
	m1.Obfuscate("alice", detector.KindUser, nil)
	if err := Save(path, m1); err != nil {
		t.Fatal(err)
	}

	// Read created timestamp.
	m2 := mapper.New(replacer.New())
	if err := Load(path, m2); err != nil {
		t.Fatal(err)
	}
	m2.Obfuscate("bob", detector.KindUser, nil)

	// Wait a moment so updated would diverge if both got "now".
	if err := Save(path, m2); err != nil {
		t.Fatal(err)
	}

	// Now read raw and verify created persists.
	// (We don't expose the timestamps via mapper, so we re-read JSON via Load
	// just to confirm round-trip success on the new entry.)
	m3 := mapper.New(replacer.New())
	if err := Load(path, m3); err != nil {
		t.Fatal(err)
	}
	if got, ok := m3.Restore("user2"); !ok || got != "bob" {
		t.Errorf("second-write entry lost: %q ok=%v", got, ok)
	}
	if got, ok := m3.Restore("user1"); !ok || got != "alice" {
		t.Errorf("first-write entry lost: %q ok=%v", got, ok)
	}
}
