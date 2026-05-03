package obfuscator

import (
	"strings"
	"testing"

	"github.com/sanekmihailow/ospooflog/pkg/detector"
	"github.com/sanekmihailow/ospooflog/pkg/mapper"
	"github.com/sanekmihailow/ospooflog/pkg/replacer"
)

func newDefault() *Obfuscator {
	return New(detector.New(detector.DefaultRules()), mapper.New(replacer.New()))
}

func TestObfuscate_Basic(t *testing.T) {
	o := newDefault()
	in := "connect to 10.1.2.3:5432 as user=alice"
	out := o.Obfuscate(in)
	for _, leaked := range []string{"10.1.2.3", "alice"} {
		if strings.Contains(out, leaked) {
			t.Errorf("origin %q leaked into output: %q", leaked, out)
		}
	}
	for _, want := range []string{"192.168.1.1:5432", "user1"} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output, got %q", want, out)
		}
	}
}

func TestObfuscate_PreservesGaps(t *testing.T) {
	o := newDefault()
	in := "prefix 10.1.2.3 middle 10.4.5.6 suffix"
	out := o.Obfuscate(in)
	if !strings.HasPrefix(out, "prefix ") {
		t.Errorf("prefix lost: %q", out)
	}
	if !strings.HasSuffix(out, " suffix") {
		t.Errorf("suffix lost: %q", out)
	}
	if !strings.Contains(out, " middle ") {
		t.Errorf("middle gap lost: %q", out)
	}
}

func TestObfuscate_Empty(t *testing.T) {
	o := newDefault()
	if got := o.Obfuscate(""); got != "" {
		t.Errorf("empty in, got %q", got)
	}
}

func TestObfuscate_NoMatches_ReturnsUnchanged(t *testing.T) {
	o := newDefault()
	in := "this text has nothing sensitive in it whatsoever"
	out := o.Obfuscate(in)
	if out != in {
		t.Errorf("unchanged input was modified: %q", out)
	}
}

func TestObfuscate_StableMappingAcrossCalls(t *testing.T) {
	o := newDefault()
	out1 := o.Obfuscate("ip=10.1.2.3")
	out2 := o.Obfuscate("again ip=10.1.2.3")
	// Same origin must map to same fake in both invocations.
	if !strings.Contains(out1, "192.168.1.1") || !strings.Contains(out2, "192.168.1.1") {
		t.Errorf("not stable: %q vs %q", out1, out2)
	}
}
