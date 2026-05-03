// Package replacer turns a (kind, counter, extras) triple into a plausible
// fake value to send to an AI. The "plausible" part is the whole point —
// real-looking inputs make the AI produce real-looking instructions.
package replacer

import (
	"fmt"

	"github.com/sanekmihailow/ospooflog/pkg/detector"
)

type Replacer struct{}

func New() *Replacer { return &Replacer{} }

// Generate returns the replace value for the given kind and 1-based counter.
// extra carries optional context from the original match (port for ADDR,
// scheme/user/host/db for DSN). Stable across calls — same (kind, n, extra)
// always yields the same string.
func (r *Replacer) Generate(kind detector.EntityKind, n int, extra map[string]string) string {
	if fn, ok := templates[kind]; ok {
		return fn(n, extra)
	}
	return fmt.Sprintf("FAKE_%s_%d", kind, n)
}
