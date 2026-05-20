// Package obfuscator combines a detector chain with the mapper registry to
// turn raw text into AI-safe text. It walks the matches in order and
// splices replace values into the gaps.
package obfuscator

import (
	"strings"

	"github.com/sanekmihailow/ospooflog/pkg/detector"
	"github.com/sanekmihailow/ospooflog/pkg/mapper"
)

type Obfuscator struct {
	detector *detector.Chain
	mapper   *mapper.Mapper
}

func New(d *detector.Chain, m *mapper.Mapper) *Obfuscator {
	return &Obfuscator{detector: d, mapper: m}
}

// Obfuscate scans text and returns it with every detected sensitive span
// replaced by its plausible-but-fake counterpart. New origins are
// registered in the mapper as a side effect.
func (o *Obfuscator) Obfuscate(text string) string {
	matches := o.detector.Find(text)
	if len(matches) == 0 {
		return text
	}
	var b strings.Builder
	b.Grow(len(text))
	pos := 0
	for _, m := range matches {
		if m.Start < pos {
			// Defensive: detector must hand back non-overlapping matches.
			continue
		}
		// Pre-register any "claim:<KIND>" Extra values (set by jwtExtra)
		// so identical values appearing bare elsewhere in this run map
		// to the same fake. mapper.Obfuscate is idempotent on origin.
		for k, v := range m.Extra {
			if kindStr, ok := strings.CutPrefix(k, "claim:"); ok {
				o.mapper.Obfuscate(v, detector.EntityKind(kindStr), nil)
			}
		}
		b.WriteString(text[pos:m.Start])
		_, replace := o.mapper.Obfuscate(m.Value, m.Kind, m.Extra)
		b.WriteString(replace)
		pos = m.End
	}
	b.WriteString(text[pos:])
	return b.String()
}
