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
	"user":        detector.KindUser,
	"username":    detector.KindUser,
	"login":       detector.KindUser,
	"actor":       detector.KindUser,
	"owner":       detector.KindUser,
	"account":     detector.KindUser,
	"remote_user": detector.KindUser, // nginx/apache access-log JSON field
	"principal":   detector.KindUser, // mongo / generic auth logs
	"host":        detector.KindHost,
	"hostname":    detector.KindHost,
	"server":      detector.KindHost,
	"node":        detector.KindHost,
	"domain":      detector.KindFQDN,
	"fqdn":        detector.KindFQDN,
	"ip":          detector.KindIP,
	"addr":        detector.KindIP,
	"address":     detector.KindIP,
	"client_ip":   detector.KindIP,
	"remote_ip":   detector.KindIP,
	"email":       detector.KindEmail,
	"mail":        detector.KindEmail,
	"path":        detector.KindPath,
	"file":        detector.KindPath,
	"trace_id":    detector.KindUUID,
	"request_id":  detector.KindUUID,
	"uuid":        detector.KindUUID,
}

// Action is what a field rule does to a matched JSON field. The zero value
// ActionAuto means "no rule" — the default detector pass applies.
type Action uint8

const (
	ActionAuto   Action = iota // run the detector over the value (default)
	ActionKeep                 // leave the value verbatim, skip detection
	ActionMask                 // replace the whole value with one fake
	ActionMaskAs               // replace the whole value with a fake of Kind
	ActionRemove               // drop the field entirely
)

// FieldRule overrides the default handling for one field, addressed by its
// dotted path (e.g. "user.email", "headers.Authorization").
type FieldRule struct {
	Action Action
	Kind   detector.EntityKind // only for ActionMaskAs
}

// FieldRules maps a dotted field path to its rule. Array indices are
// transparent: "items.email" matches email inside any element of items.
type FieldRules map[string]FieldRule

// maskFieldKind is the kind used by a bare "mask" action — no template, so the
// replacer falls back to FAKE_FIELD_<N>.
const maskFieldKind = detector.EntityKind("FIELD")

type Processor struct {
	obf        *obfuscator.Obfuscator
	mapper     *mapper.Mapper
	allowKeys  map[string]bool
	fieldRules FieldRules
}

func New(obf *obfuscator.Obfuscator, m *mapper.Mapper, allowKeys []string, fieldRules FieldRules) *Processor {
	keys := make(map[string]bool, len(allowKeys))
	for _, k := range allowKeys {
		if k = strings.TrimSpace(k); k != "" {
			keys[k] = true
		}
	}
	return &Processor{obf: obf, mapper: m, allowKeys: keys, fieldRules: fieldRules}
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
	p.walk("", "", &v)

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
// their obfuscated form. path is the dotted field path of the current value
// (array indices are transparent, so an array inherits its container's path);
// parentKey is the immediate map key, used by the key-name allowKeys and
// keyKindHints. Explicit --fields rules are applied at the map-key level
// (below) so remove/mask can act on a whole field of any type.
func (p *Processor) walk(path, parentKey string, v *any) {
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
			childPath := joinPath(path, k)
			if rule, ok := p.fieldRules[childPath]; ok {
				switch rule.Action {
				case ActionRemove:
					delete(t, k)
					continue
				case ActionKeep:
					continue
				case ActionMask:
					t[k] = p.fake(vv, maskFieldKind)
					continue
				case ActionMaskAs:
					t[k] = p.fake(vv, rule.Kind)
					continue
				}
			}
			child := vv
			p.walk(childPath, k, &child)
			t[k] = child
		}
	case []any:
		for i := range t {
			child := t[i]
			p.walk(path, parentKey, &child)
			t[i] = child
		}
	}
}

// fake replaces a whole leaf of any JSON type with a single registered fake so
// restore can reverse it. Non-string scalars are stringified first (a forced
// mask of a number/bool comes back as a string on restore — the type is lost).
func (p *Processor) fake(v any, kind detector.EntityKind) string {
	var origin string
	if s, ok := v.(string); ok {
		origin = s
	} else {
		b, _ := json.Marshal(v)
		origin = string(b)
	}
	_, replace := p.mapper.Obfuscate(origin, kind, nil)
	return replace
}

func joinPath(base, key string) string {
	if base == "" {
		return key
	}
	return base + "." + key
}
