// Package audithex unmasks linux audit "proctitle=…" and "aN=…" fields,
// which hex-encode argv. Without this step a command line like
// "mysql -p secret" would leak through as raw hex; the detector chain has
// no way to look inside hex on its own.
//
// We NUL→space the decoded payload before obfuscation so the detector can
// see flag/value context across argv boundaries (e.g. "--password secret").
// The audit parser will see a single joined argv after re-encoding — a
// safety-over-fidelity trade-off.
package audithex

import (
	"encoding/hex"
	"regexp"
	"strings"

	"github.com/sanekmihailow/ospooflog/pkg/obfuscator"
	"github.com/sanekmihailow/ospooflog/pkg/restorer"
)

// Field matcher: "proctitle" or "aN" (where N is 0–3 digits), an "=" and an
// even-length hex blob of 2+ bytes. The byte floor avoids matching short
// numeric fields like "a0=3" that aren't hex payloads.
var reField = regexp.MustCompile(`\b(proctitle|a\d{1,3})=([0-9A-Fa-f]{4,})\b`)

// Process rewrites every audit hex field in text by decoding it, running
// the obfuscator on the joined argv, and re-encoding.
func Process(text string, obf *obfuscator.Obfuscator) string {
	return reField.ReplaceAllStringFunc(text, func(m string) string {
		sub := reField.FindStringSubmatch(m)
		key, h := sub[1], sub[2]
		if len(h)%2 != 0 {
			return m
		}
		raw, err := hex.DecodeString(h)
		if err != nil {
			return m
		}
		joined := strings.ReplaceAll(string(raw), "\x00", " ")
		masked := obf.Obfuscate(joined)
		return key + "=" + hex.EncodeToString([]byte(masked))
	})
}

// Restore is the inverse of Process: decode each audit hex field, run the
// restorer on the plaintext, then re-encode. Only the in-hex content is
// touched; surrounding audit metadata is left intact.
func Restore(text string, r *restorer.Restorer) string {
	return reField.ReplaceAllStringFunc(text, func(m string) string {
		sub := reField.FindStringSubmatch(m)
		key, h := sub[1], sub[2]
		if len(h)%2 != 0 {
			return m
		}
		raw, err := hex.DecodeString(h)
		if err != nil {
			return m
		}
		restored := r.Restore(string(raw))
		return key + "=" + hex.EncodeToString([]byte(restored))
	})
}
