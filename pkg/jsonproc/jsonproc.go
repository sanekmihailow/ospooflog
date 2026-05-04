// Package jsonproc obfuscates structured (NDJSON) logs while preserving
// their JSON shape. Each input line is tried as JSON; on a successful
// parse, every string leaf is run through the obfuscator, optionally
// skipping configured allow-listed keys (e.g. "level", "timestamp",
// "message" — fields that are noise, not signal). Lines that don't parse
// (e.g. k8s CRI prefixes like "2026-05-03T... stdout F {...}") fall back
// to plain-text obfuscation.
package jsonproc

import (
	"bytes"
	"encoding/json"
	"strings"

	"github.com/sanekmihailow/ospooflog/pkg/detector"
	"github.com/sanekmihailow/ospooflog/pkg/mapper"
	"github.com/sanekmihailow/ospooflog/pkg/obfuscator"
)

// keyKindHints lets us obfuscate JSON leaf values whose own content carries
// no context (e.g. a bare "alice" under the "user" key). The detector chain
// runs first; if it finds nothing AND the parent key is in this list, we
// force-map the value as the hinted kind via the mapper directly.
var keyKindHints = map[string]detector.EntityKind{
	"user":      detector.KindUser,
	"username":  detector.KindUser,
	"login":     detector.KindUser,
	"actor":     detector.KindUser,
	"owner":     detector.KindUser,
	"account":   detector.KindUser,
	"host":      detector.KindHost,
	"hostname":  detector.KindHost,
	"server":    detector.KindHost,
	"node":      detector.KindHost,
	"domain":    detector.KindFQDN,
	"fqdn":      detector.KindFQDN,
	"ip":        detector.KindIP,
	"addr":      detector.KindIP,
	"address":   detector.KindIP,
	"client_ip": detector.KindIP,
	"remote_ip": detector.KindIP,
	"email":     detector.KindEmail,
	"mail":      detector.KindEmail,
	"path":      detector.KindPath,
	"file":      detector.KindPath,
	"trace_id":  detector.KindUUID,
	"request_id": detector.KindUUID,
	"uuid":      detector.KindUUID,
}

type Processor struct {
	obf       *obfuscator.Obfuscator
	mapper    *mapper.Mapper
	allowKeys map[string]bool
}

func New(obf *obfuscator.Obfuscator, m *mapper.Mapper, allowKeys []string) *Processor {
	keys := make(map[string]bool, len(allowKeys))
	for _, k := range allowKeys {
		if k = strings.TrimSpace(k); k != "" {
			keys[k] = true
		}
	}
	return &Processor{obf: obf, mapper: m, allowKeys: keys}
}

// Process splits text on \n and obfuscates each line independently.
// Newlines and the relative ordering of records are preserved verbatim.
func (p *Processor) Process(text string) string {
	lines := strings.Split(text, "\n")
	for i, line := range lines {
		lines[i] = p.processLine(line)
	}
	return strings.Join(lines, "\n")
}

func (p *Processor) processLine(line string) string {
	trimmed := strings.TrimSpace(line)
	if len(trimmed) == 0 || (trimmed[0] != '{' && trimmed[0] != '[') {
		return p.obf.Obfuscate(line)
	}
	var v any
	if err := json.Unmarshal([]byte(trimmed), &v); err != nil {
		return p.obf.Obfuscate(line)
	}
	p.walk("", &v)

	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return p.obf.Obfuscate(line)
	}
	encoded := strings.TrimRight(buf.String(), "\n")

	leading := line[:len(line)-len(strings.TrimLeft(line, " \t"))]
	return leading + encoded
}

// walk recurses into the decoded structure, replacing string leaves with
// their obfuscated form. parentKey is the map key the current value sits
// under (empty for the root); array elements inherit their container's
// key so allow-listing "messages" skips strings inside that array too.
func (p *Processor) walk(parentKey string, v *any) {
	switch t := (*v).(type) {
	case string:
		if p.allowKeys[parentKey] {
			return
		}
		obfuscated := p.obf.Obfuscate(t)
		if obfuscated != t {
			*v = obfuscated
			return
		}
		if hint, ok := keyKindHints[strings.ToLower(parentKey)]; ok && t != "" {
			_, replace := p.mapper.Obfuscate(t, hint, nil)
			*v = replace
		}
	case map[string]any:
		for k, vv := range t {
			child := vv
			p.walk(k, &child)
			t[k] = child
		}
	case []any:
		for i := range t {
			child := t[i]
			p.walk(parentKey, &child)
			t[i] = child
		}
	}
}
