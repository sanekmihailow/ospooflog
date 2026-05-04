package jsonproc

import (
	"strings"
	"testing"

	"github.com/sanekmihailow/ospooflog/pkg/detector"
	"github.com/sanekmihailow/ospooflog/pkg/mapper"
	"github.com/sanekmihailow/ospooflog/pkg/obfuscator"
	"github.com/sanekmihailow/ospooflog/pkg/replacer"
)

func newProc(allowKeys []string) *Processor {
	d := detector.New(detector.DefaultRules())
	m := mapper.New(replacer.New())
	return New(obfuscator.New(d, m), m, allowKeys)
}

func TestProcess_JSONLineObfuscatesStrings(t *testing.T) {
	p := newProc(nil)
	in := `{"user":"alice","ip":"10.1.2.3","msg":"connect from 10.1.2.3 with user=alice"}`
	out := p.processLine(in)

	// "user" key triggers the kind-hint path; "ip" matches the IP regex.
	if !strings.Contains(out, `"user":"user1"`) {
		t.Errorf("user value not obfuscated via key hint: %s", out)
	}
	if !strings.Contains(out, `"ip":"192.168.1.1"`) {
		t.Errorf("ip value not obfuscated: %s", out)
	}
	// Inside the free-form msg, the detector chain catches both the IP and
	// the user= context. Mapping is shared so origins line up across fields.
	if strings.Contains(out, "10.1.2.3") {
		t.Errorf("IP inside msg leaked: %s", out)
	}
	if !strings.Contains(out, "user=user1") {
		t.Errorf("user= context inside msg not obfuscated: %s", out)
	}
	for _, k := range []string{`"user"`, `"ip"`, `"msg"`} {
		if !strings.Contains(out, k) {
			t.Errorf("JSON key %s missing in output: %s", k, out)
		}
	}
}

func TestProcess_AllowKeysSkipped(t *testing.T) {
	p := newProc([]string{"level", "timestamp"})
	in := `{"level":"alice","user":"alice","timestamp":"10.1.2.3"}`
	// level and timestamp values stay verbatim even though they look obfuscatable;
	// user value gets obfuscated.
	out := p.processLine(in)
	if !strings.Contains(out, `"level":"alice"`) {
		t.Errorf("allow-key level was modified: %s", out)
	}
	if !strings.Contains(out, `"timestamp":"10.1.2.3"`) {
		t.Errorf("allow-key timestamp was modified: %s", out)
	}
	if !strings.Contains(out, `"user":"user1"`) {
		t.Errorf("user should be obfuscated to user1: %s", out)
	}
}

func TestProcess_NestedStructures(t *testing.T) {
	p := newProc(nil)
	in := `{"meta":{"actor":"alice"},"sources":["10.1.2.3","10.4.5.6"]}`
	out := p.processLine(in)
	if strings.Contains(out, "alice") || strings.Contains(out, "10.1.2.3") || strings.Contains(out, "10.4.5.6") {
		t.Errorf("nested origins leaked: %s", out)
	}
	if !strings.Contains(out, "user1") || !strings.Contains(out, "192.168.1.1") || !strings.Contains(out, "192.168.1.2") {
		t.Errorf("nested replacements missing: %s", out)
	}
}

func TestProcess_NumberLeavesUntouched(t *testing.T) {
	p := newProc(nil)
	in := `{"port":5432,"count":42}`
	out := p.processLine(in)
	if !strings.Contains(out, `"port":5432`) || !strings.Contains(out, `"count":42`) {
		t.Errorf("numeric leaves should not change: %s", out)
	}
}

func TestProcess_PlainLineFallback(t *testing.T) {
	p := newProc(nil)
	in := "ERROR plain text from user=alice"
	out := p.processLine(in)
	if strings.Contains(out, "alice") {
		t.Errorf("plain fallback did not obfuscate: %s", out)
	}
	if !strings.Contains(out, "user1") {
		t.Errorf("plain fallback missing replacement: %s", out)
	}
}

func TestProcess_MalformedJSONFallsBackToPlain(t *testing.T) {
	p := newProc(nil)
	in := `{not really json but contains user=alice}`
	out := p.processLine(in)
	// Should fall back to plain mode and obfuscate the user= context.
	if strings.Contains(out, "alice") {
		t.Errorf("malformed JSON not handled: %s", out)
	}
}

func TestProcess_KubernetesPrefixFallsBackToPlain(t *testing.T) {
	p := newProc([]string{"level"})
	// k8s CRI prefix — line as a whole is not JSON, so falls back to plain.
	in := `2026-05-03T19:00:01Z stdout F {"level":"error","ip":"10.1.2.3"}`
	out := p.processLine(in)
	// Plain mode runs the detector chain — IP should be obfuscated.
	if strings.Contains(out, "10.1.2.3") {
		t.Errorf("k8s-prefix line: IP not obfuscated: %s", out)
	}
}

func TestProcess_MultilinePreservesNewlines(t *testing.T) {
	p := newProc(nil)
	in := `{"user":"alice"}` + "\n" + `{"user":"bob"}` + "\n"
	out := p.Process(in)
	parts := strings.Split(out, "\n")
	if len(parts) != 3 || parts[2] != "" {
		t.Errorf("expected trailing newline preserved, got %d parts: %#v", len(parts), parts)
	}
	if !strings.Contains(parts[0], `"user":"user1"`) {
		t.Errorf("line 1 missing user1: %s", parts[0])
	}
	if !strings.Contains(parts[1], `"user":"user2"`) {
		t.Errorf("line 2 missing user2: %s", parts[1])
	}
}
