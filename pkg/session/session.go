// Package session persists the mapper registry to a JSON file between
// obfuscate and restore CLI invocations. The file is the contract that
// makes the round-trip work — without it, restore has nothing to look up.
package session

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"time"

	"github.com/sanekmihailow/ospooflog/pkg/detector"
	"github.com/sanekmihailow/ospooflog/pkg/mapper"
)

// Version is the current session-file schema version. Bumped when the JSON
// shape changes incompatibly.
const Version = 2

type sessionFile struct {
	Version int                  `json:"version"`
	Created time.Time            `json:"created"`
	Updated time.Time            `json:"updated"`
	Mapping map[string]entryJSON `json:"mapping"`
}

type entryJSON struct {
	Kind    string            `json:"kind"`
	Origin  string            `json:"origin"`
	Replace string            `json:"replace"`
	Extra   map[string]string `json:"extra,omitempty"`
}

// Load reads path into m. Missing file is not an error — the first
// obfuscate run starts from an empty registry.
func Load(path string, m *mapper.Mapper) error {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("read %s: %w", path, err)
	}
	var f sessionFile
	if err := json.Unmarshal(data, &f); err != nil {
		return fmt.Errorf("parse %s: %w", path, err)
	}
	entries := make([]mapper.Entry, 0, len(f.Mapping))
	for token, e := range f.Mapping {
		entries = append(entries, mapper.Entry{
			Token:   token,
			Kind:    detector.EntityKind(e.Kind),
			Origin:  e.Origin,
			Replace: e.Replace,
			Extra:   e.Extra,
		})
	}
	m.Load(entries)
	return nil
}

// Save writes m to path. Created timestamp is preserved across saves so
// you can see when the session was first started.
func Save(path string, m *mapper.Mapper) error {
	now := time.Now().UTC()
	created := now
	if data, err := os.ReadFile(path); err == nil {
		var prev sessionFile
		if json.Unmarshal(data, &prev) == nil && !prev.Created.IsZero() {
			created = prev.Created
		}
	}

	f := sessionFile{
		Version: Version,
		Created: created,
		Updated: now,
		Mapping: make(map[string]entryJSON),
	}
	for _, e := range m.Entries() {
		f.Mapping[e.Token] = entryJSON{
			Kind:    string(e.Kind),
			Origin:  e.Origin,
			Replace: e.Replace,
			Extra:   e.Extra,
		}
	}
	data, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}
