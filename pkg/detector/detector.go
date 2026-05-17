// Package detector finds sensitive entity spans in arbitrary text using a
// priority-ordered chain of regex rules. Higher-priority rules run first and
// claim text ranges; lower-priority rules skip any range already covered.
// This guarantees, for example, that a full DSN like
// "postgres://alice:pwd@10.1.2.3:5432/db" is captured as a single DSN match
// instead of being shredded by the IP, EMAIL and PATH detectors.
package detector

import (
	"regexp"
	"sort"
)

// EntityKind tags the type of a detected sensitive value. The kind drives
// counter scope, replace template selection and session-file tagging.
type EntityKind string

const (
	KindDSN   EntityKind = "DSN"
	KindToken EntityKind = "TOKEN"
	KindUUID  EntityKind = "UUID"
	KindEmail EntityKind = "EMAIL"
	KindAddr  EntityKind = "ADDR"
	KindIP    EntityKind = "IP"
	KindIP6   EntityKind = "IP6"
	KindHost  EntityKind = "HOST"
	KindFQDN  EntityKind = "FQDN"
	KindPort  EntityKind = "PORT"
	KindUser  EntityKind = "USER"
	KindPath  EntityKind = "PATH"
	// KindFingerprint covers SHA256/MD5 SSH key fingerprints.
	KindFingerprint EntityKind = "FP"
	// KindPubKey covers ssh-rsa / ssh-ed25519 / ecdsa-sha2-* public key bodies.
	KindPubKey EntityKind = "PUBKEY"
	// KindPrivKey covers PEM-armored private key blocks.
	KindPrivKey EntityKind = "PRIVKEY"
	// KindOverride tags pairs from --overrides applied as literal sed-style
	// substitutions, independent of any detector rule.
	KindOverride EntityKind = "OVR"
)

// Match is a single detected span. Start/End refer to the substring that
// will actually be replaced in the output (the capture group, not the whole
// regex match — for rules like "user=alice" we only want to swap "alice").
type Match struct {
	Start int
	End   int
	Value string
	Kind  EntityKind
	Extra map[string]string
}

// Rule is one detection rule. CaptureGroup picks which submatch to treat as
// the value (0 = whole match). ExtraFn pulls structured pieces out of the
// match (port from ADDR, scheme/user/host from DSN) so the replacer can
// preserve format. Validate optionally rejects regex matches that pass the
// pattern but aren't actually the thing they look like — e.g. "19:00:01"
// is shaped like an IPv6 but isn't.
type Rule struct {
	Kind         EntityKind
	Re           *regexp.Regexp
	CaptureGroup int
	ExtraFn      func(submatches []string) map[string]string
	Validate     func(value string) bool
}

// Chain runs Rules in order with a covered-range guard.
type Chain struct {
	rules []Rule
}

func New(rules []Rule) *Chain {
	return &Chain{rules: rules}
}

type interval struct{ start, end int }

// Find returns all non-overlapping matches in text, sorted by start offset.
func (c *Chain) Find(text string) []Match {
	var (
		results []Match
		covered []interval
	)
	for _, rule := range c.rules {
		idxs := rule.Re.FindAllStringSubmatchIndex(text, -1)
		subs := rule.Re.FindAllStringSubmatch(text, -1)
		for i, idx := range idxs {
			cg := rule.CaptureGroup
			startIdx, endIdx := 2*cg, 2*cg+1
			if endIdx >= len(idx) || idx[startIdx] < 0 {
				continue
			}
			start, end := idx[startIdx], idx[endIdx]
			// Block out the entire regex match (idx[0:2]) — not just the capture
			// span — so contextual prefixes like "user=" aren't picked apart by
			// later rules.
			blockStart, blockEnd := idx[0], idx[1]
			if overlapsAny(blockStart, blockEnd, covered) {
				continue
			}

			value := text[start:end]
			if rule.Validate != nil && !rule.Validate(value) {
				continue
			}

			var extra map[string]string
			if rule.ExtraFn != nil {
				extra = rule.ExtraFn(subs[i])
			}

			results = append(results, Match{
				Start: start,
				End:   end,
				Value: value,
				Kind:  rule.Kind,
				Extra: extra,
			})
			covered = append(covered, interval{blockStart, blockEnd})
		}
	}
	sort.Slice(results, func(i, j int) bool { return results[i].Start < results[j].Start })
	return results
}

func overlapsAny(start, end int, covered []interval) bool {
	for _, c := range covered {
		if start < c.end && end > c.start {
			return true
		}
	}
	return false
}
