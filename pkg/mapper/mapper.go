// Package mapper holds the bidirectional registry that ties together every
// origin value, its internal token (e.g. IP_001) and its replace value.
// All access is mutex-guarded so the same Mapper can be shared across
// goroutines if we ever process input concurrently.
package mapper

import (
	"fmt"
	"sync"

	"github.com/sanekmihailow/ospooflog/pkg/detector"
	"github.com/sanekmihailow/ospooflog/pkg/replacer"
)

// Entry is one row in the registry.
type Entry struct {
	Token   string
	Kind    detector.EntityKind
	Origin  string
	Replace string
	Extra   map[string]string
}

type Mapper struct {
	mu        sync.RWMutex
	byOrigin  map[string]*Entry
	byToken   map[string]*Entry
	byReplace map[string]*Entry
	counters  map[detector.EntityKind]int
	replacer  *replacer.Replacer
	overrides map[string]string
}

func New(r *replacer.Replacer) *Mapper {
	return &Mapper{
		byOrigin:  make(map[string]*Entry),
		byToken:   make(map[string]*Entry),
		byReplace: make(map[string]*Entry),
		counters:  make(map[detector.EntityKind]int),
		replacer:  r,
	}
}

// Obfuscate returns the (token, replace) pair for origin. On first sight of
// origin a new entry is created using the per-kind counter; on subsequent
// calls the cached pair is returned, guaranteeing stability across the run.
// If a user-supplied override exists for origin, the override's replace
// value wins over the built-in template.
func (m *Mapper) Obfuscate(origin string, kind detector.EntityKind, extra map[string]string) (token, replace string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if e, ok := m.byOrigin[origin]; ok {
		return e.Token, e.Replace
	}
	m.counters[kind]++
	n := m.counters[kind]
	token = fmt.Sprintf("%s_%03d", kind, n)
	if r, ok := m.overrides[origin]; ok && r != "" {
		replace = r
	} else {
		replace = m.replacer.Generate(kind, n, extra)
	}
	e := &Entry{
		Token:   token,
		Kind:    kind,
		Origin:  origin,
		Replace: replace,
		Extra:   extra,
	}
	m.byOrigin[origin] = e
	m.byToken[token] = e
	m.byReplace[replace] = e
	return token, replace
}

// SetOverrides installs a fixed origin→replace map. Overrides only apply
// on first sighting of an origin; entries already in the registry (e.g.
// loaded from a prior session) keep their existing replace value.
func (m *Mapper) SetOverrides(o map[string]string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.overrides = o
}

// RegisterOverride records a literal (origin, replace) pair as an OVR_NNN
// entry so Restore can round-trip the replace value back to origin. No-op
// if origin is already registered. Used by the sed-style override path,
// which bypasses the detector entirely.
func (m *Mapper) RegisterOverride(origin, replace string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.byOrigin[origin]; ok {
		return
	}
	m.counters[detector.KindOverride]++
	n := m.counters[detector.KindOverride]
	e := &Entry{
		Token:   fmt.Sprintf("%s_%03d", detector.KindOverride, n),
		Kind:    detector.KindOverride,
		Origin:  origin,
		Replace: replace,
	}
	m.byOrigin[origin] = e
	m.byToken[e.Token] = e
	m.byReplace[replace] = e
}

// Restore looks up the original value by replace value. ok=false if the
// replace value is unknown (e.g. the AI fabricated it).
func (m *Mapper) Restore(replace string) (string, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if e, ok := m.byReplace[replace]; ok {
		return e.Origin, true
	}
	return "", false
}

// Entries returns a snapshot of all registered entries.
func (m *Mapper) Entries() []Entry {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]Entry, 0, len(m.byToken))
	for _, e := range m.byToken {
		out = append(out, *e)
	}
	return out
}

// Load installs entries from a session file and resumes counters at the
// highest seen index per kind, so freshly minted tokens never collide.
func (m *Mapper) Load(entries []Entry) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, e := range entries {
		ec := e
		m.byOrigin[ec.Origin] = &ec
		m.byToken[ec.Token] = &ec
		m.byReplace[ec.Replace] = &ec
		var n int
		if _, err := fmt.Sscanf(ec.Token, string(ec.Kind)+"_%d", &n); err == nil {
			if n > m.counters[ec.Kind] {
				m.counters[ec.Kind] = n
			}
		}
	}
}
