package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/sanekmihailow/ospooflog/pkg/detector"
	"github.com/sanekmihailow/ospooflog/pkg/jsonproc"
)

func TestParseFieldAction(t *testing.T) {
	cases := []struct {
		in   string
		want jsonproc.FieldRule
		err  bool
	}{
		{"keep", jsonproc.FieldRule{Action: jsonproc.ActionKeep}, false},
		{" MASK ", jsonproc.FieldRule{Action: jsonproc.ActionMask}, false}, // case + spaces
		{"remove", jsonproc.FieldRule{Action: jsonproc.ActionRemove}, false},
		{"mask-as:email", jsonproc.FieldRule{Action: jsonproc.ActionMaskAs, Kind: detector.KindEmail}, false},
		{"mask-as:BOGUS", jsonproc.FieldRule{}, true}, // unknown kind
		{"nuke", jsonproc.FieldRule{}, true},          // unknown action
	}
	for _, c := range cases {
		got, err := parseFieldAction(c.in)
		if (err != nil) != c.err {
			t.Errorf("parseFieldAction(%q) err = %v, want err=%v", c.in, err, c.err)
			continue
		}
		if !c.err && got != c.want {
			t.Errorf("parseFieldAction(%q) = %+v, want %+v", c.in, got, c.want)
		}
	}
}

func TestLoadFieldRules(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "fields.yaml")
	if err := os.WriteFile(path, []byte("fields:\n  user.id: mask\n  headers.Authorization: remove\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	rules, err := loadFieldRules(path)
	if err != nil {
		t.Fatal(err)
	}
	if rules["user.id"].Action != jsonproc.ActionMask || rules["headers.Authorization"].Action != jsonproc.ActionRemove {
		t.Errorf("rules parsed wrong: %+v", rules)
	}

	bad := filepath.Join(dir, "bad.yaml")
	if err := os.WriteFile(bad, []byte("fields:\n  x: nuke\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadFieldRules(bad); err == nil {
		t.Error("expected error on unknown action")
	}
}
