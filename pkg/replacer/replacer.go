// Package replacer turns a (kind, counter, extras) triple into a plausible
// fake value to send to an AI. The "plausible" part is the whole point —
// real-looking inputs make the AI produce real-looking instructions.
package replacer

import (
	"fmt"
	"strings"
	"sync"

	"github.com/sanekmihailow/ospooflog/pkg/detector"
)

type Replacer struct {
	// keepTLD makes domain fakes (FQDN/HOST/EMAIL) preserve the real
	// top-level label instead of the fixed "example.com".
	keepTLD bool
	// domainIdx assigns a stable exampleN per real registrable domain
	// (e.g. max.ru → example1, vk.ru → example2) so different hosts under
	// one domain share their fake domain. Guarded by mu — Generate may be
	// called under the mapper lock, but the inner map mutation is its own.
	mu         sync.Mutex
	domainIdx  map[string]int
	domainNext int
}

func New() *Replacer { return &Replacer{domainIdx: map[string]int{}} }

// SetKeepTLD toggles real-TLD-preserving domain fakes.
func (r *Replacer) SetKeepTLD(on bool) { r.keepTLD = on }

// Generate returns the replace value for the given kind and 1-based counter.
// extra carries optional context from the original match (port for ADDR,
// scheme/user/host/db for DSN). Stable across calls — same (kind, n, extra)
// always yields the same string.
func (r *Replacer) Generate(kind detector.EntityKind, n int, extra map[string]string) string {
	if r.keepTLD {
		switch kind {
		case detector.KindFQDN, detector.KindHost:
			if s := r.maskHost(extra["_origin"], n); s != "" {
				return s
			}
		case detector.KindEmail:
			if s := r.maskEmail(extra["_origin"], n); s != "" {
				return s
			}
		}
	}
	if fn, ok := templates[kind]; ok {
		return fn(n, extra)
	}
	return fmt.Sprintf("FAKE_%s_%d", kind, n)
}

// maskHost masks a dotted host/FQDN, preserving the real last label (TLD): the
// registrable label becomes a stable exampleN (per real registrable domain),
// and any leading subdomain labels collapse to serviceN. Returns "" for a name
// with no dot (no TLD to preserve) so the caller falls back to its template.
//
// TLD detection is naive (the last label only), so a multi-part suffix like
// "co.uk" keeps just ".uk". Good enough for single-label TLDs; a Public Suffix
// List could refine it later.
func (r *Replacer) maskHost(origin string, n int) string {
	labels := strings.Split(origin, ".")
	if len(labels) < 2 || labels[len(labels)-1] == "" {
		return ""
	}
	tld := labels[len(labels)-1]
	registrable := labels[len(labels)-2] + "." + tld
	k := r.exampleIndex(registrable)
	if len(labels) == 2 {
		return fmt.Sprintf("example%d.%s", k, tld)
	}
	return fmt.Sprintf("service%d.example%d.%s", n, k, tld)
}

// maskEmail masks the local part to userN and the domain via maskHost. Returns
// "" if origin isn't an addr@domain shape so the caller falls back.
func (r *Replacer) maskEmail(origin string, n int) string {
	at := strings.LastIndexByte(origin, '@')
	if at <= 0 || at == len(origin)-1 {
		return ""
	}
	domain := r.maskHost(origin[at+1:], n)
	if domain == "" {
		return ""
	}
	return fmt.Sprintf("user%d@%s", n, domain)
}

// exampleIndex returns a stable 1-based index for a registrable domain.
func (r *Replacer) exampleIndex(domain string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	if idx, ok := r.domainIdx[domain]; ok {
		return idx
	}
	r.domainNext++
	r.domainIdx[domain] = r.domainNext
	return r.domainNext
}
