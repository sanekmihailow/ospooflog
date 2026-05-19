// Package detector finds sensitive entity spans in arbitrary text using a
// priority-ordered chain of regex rules. Higher-priority rules run first and
// claim text ranges; lower-priority rules skip any range already covered.
// This guarantees, for example, that a full DSN like
// "postgres://alice:pwd@10.1.2.3:5432/db" is captured as a single DSN match
// instead of being shredded by the IP, EMAIL and PATH detectors.
package detector

import (
	"math"
	"regexp"
	"sort"
	"strings"
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
	KindMAC   EntityKind = "MAC"
	KindHost  EntityKind = "HOST"
	KindFQDN  EntityKind = "FQDN"
	KindPort  EntityKind = "PORT"
	KindUser  EntityKind = "USER"
	KindPath  EntityKind = "PATH"
	// KindPassword covers plaintext passwords from "IDENTIFIED BY '…'",
	// "password=…", "passwd: …", "pwd=…" patterns.
	KindPassword EntityKind = "PWD"
	// KindAPIKey covers API keys, bearer tokens, and provider-specific
	// credentials (AWS AKIA, GitHub gh*_, etc).
	KindAPIKey EntityKind = "APIKEY"
	// KindFingerprint covers SHA256/MD5 SSH key fingerprints.
	KindFingerprint EntityKind = "FP"
	// KindPubKey covers ssh-rsa / ssh-ed25519 / ecdsa-sha2-* public key bodies.
	KindPubKey EntityKind = "PUBKEY"
	// KindPrivKey covers PEM-armored private key blocks.
	KindPrivKey EntityKind = "PRIVKEY"
	// KindARN covers AWS Amazon Resource Names — "arn:aws:service:region:
	// account-id:resource". Worth its own kind because the format encodes
	// the 12-digit account ID (security-sensitive) plus resource paths.
	KindARN EntityKind = "ARN"
	// KindCard covers credit / payment card numbers that pass a Luhn check.
	KindCard EntityKind = "CARD"
	// KindPhone covers phone numbers in E.164 form and keyword-anchored
	// shapes ("phone: 555-1234").
	KindPhone EntityKind = "PHONE"
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
	// Skip rules mark the matched range as covered (preventing later rules
	// from tokenizing fragments inside it) but emit no Match — used to keep
	// SSH algorithm identifiers like "chacha20-poly1305@openssh.com" intact.
	Skip bool
	// BlockCaptureOnly narrows the covered-range claim to the capture span
	// rather than the full regex match. Use when the rule needs a wide anchor
	// (e.g. a httpd line prefix) to locate the value, but the anchor itself
	// contains other entities that other rules must still be free to detect.
	BlockCaptureOnly bool
	// Keyword is an optional literal substring that must appear in the input
	// before the regex is evaluated. Cheap pre-filter for rules anchored on
	// a fixed token like "AIza", "sk-ant-", "T3BlbkFJ". Match is case-
	// sensitive — set it in the casing the regex actually requires.
	Keyword string
	// MinEntropy rejects captures whose Shannon entropy (bits-per-char over
	// byte alphabet) falls below the threshold. Filters repeating placeholders
	// like "AAAAAAAA" / "xxxxxxxx" and short trivial values like "true"
	// without needing a giant string allowlist. Zero disables the check.
	MinEntropy float64
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
		if rule.Keyword != "" && !strings.Contains(text, rule.Keyword) {
			continue
		}
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
			// later rules. BlockCaptureOnly opts out for rules whose anchor
			// legitimately overlaps other entities (e.g. httpd line prefix).
			blockStart, blockEnd := idx[0], idx[1]
			if rule.BlockCaptureOnly {
				blockStart, blockEnd = start, end
			}
			if overlapsAny(blockStart, blockEnd, covered) {
				continue
			}

			value := text[start:end]
			if rule.Validate != nil && !rule.Validate(value) {
				continue
			}
			if rule.MinEntropy > 0 && shannonEntropy(value) < rule.MinEntropy {
				continue
			}

			if rule.Skip {
				covered = append(covered, interval{blockStart, blockEnd})
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

// shannonEntropy returns bits-per-char over the byte alphabet. Treats input
// as bytes — works for ASCII and UTF-8 alike since the goal is to detect
// low-variety strings ("AAAAA", "xxxxxxxx"), not to characterise language.
func shannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	var freq [256]int
	for i := 0; i < len(s); i++ {
		freq[s[i]]++
	}
	n := float64(len(s))
	h := 0.0
	for _, c := range freq {
		if c == 0 {
			continue
		}
		p := float64(c) / n
		h -= p * math.Log2(p)
	}
	return h
}

func overlapsAny(start, end int, covered []interval) bool {
	for _, c := range covered {
		if start < c.end && end > c.start {
			return true
		}
	}
	return false
}
