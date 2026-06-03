package restorer

import (
	"strings"
	"testing"

	"github.com/sanekmihailow/ospooflog/pkg/detector"
	"github.com/sanekmihailow/ospooflog/pkg/mapper"
	"github.com/sanekmihailow/ospooflog/pkg/replacer"
)

func newMapper() *mapper.Mapper {
	return mapper.New(replacer.New())
}

func TestRestore_FastBasic(t *testing.T) {
	m := newMapper()
	m.Obfuscate("alice", detector.KindUser, nil)
	m.Obfuscate("10.1.2.3", detector.KindIP, nil)

	r := New(m, false)
	in := "Login as user1 from 192.168.0.1"
	want := "Login as alice from 10.1.2.3"
	if got := r.Restore(in); got != want {
		t.Errorf("got %q want %q", got, want)
	}
}

func TestRestore_LongestFirst(t *testing.T) {
	// 11 IPs registered — replace values grow to "192.168.0.10", "192.168.0.11".
	// Without longest-first sort, "192.168.0.1" would shadow "192.168.0.10".
	m := newMapper()
	for i := 1; i <= 11; i++ {
		m.Obfuscate(strings.Repeat("a", i), detector.KindIP, nil) // unique origins
	}
	r := New(m, false)
	// Origin for IP_010 was 10 a's; replace was "192.168.0.10".
	in := "address 192.168.0.10 here"
	want := "address " + strings.Repeat("a", 10) + " here"
	if got := r.Restore(in); got != want {
		t.Errorf("got %q want %q", got, want)
	}
}

func TestRestore_StrictAvoidsSubstringFalsePositive(t *testing.T) {
	m := newMapper()
	m.Obfuscate("10.1.2.3", detector.KindIP, nil) // -> 192.168.0.1

	rStrict := New(m, true)
	// AI mentions an IP that wasn't in the mapping but starts with our replace value.
	in := "try 192.168.0.10 instead"
	if got := rStrict.Restore(in); got != in {
		t.Errorf("strict mode corrupted unrelated string: got %q", got)
	}

	// Sanity: strict still restores legitimate hits.
	in2 := "use 192.168.0.1 for that"
	want2 := "use 10.1.2.3 for that"
	if got := rStrict.Restore(in2); got != want2 {
		t.Errorf("strict failed legit replace: got %q want %q", got, want2)
	}
}

func TestRestore_StrictWithPunctuationBoundary(t *testing.T) {
	// ":8080" — left side starts with non-word ":" so adjacency rules out
	// only the right side.
	m := newMapper()
	m.Obfuscate(":5432", detector.KindPort, nil) // -> ":8080"

	r := New(m, true)
	in := "listen on :8080 for traffic"
	want := "listen on :5432 for traffic"
	if got := r.Restore(in); got != want {
		t.Errorf("got %q want %q", got, want)
	}
}

func TestRestore_StrictUnicodeWordBoundary(t *testing.T) {
	// Neighbour bytes that belong to a multi-byte UTF-8 letter (cyrillic, CJK)
	// must be decoded as a rune — checking a single continuation byte sees
	// it as non-word and lets the splice through.
	m := newMapper()
	m.Obfuscate("bob", detector.KindUser, nil) // -> user1
	r := New(m, true)

	cases := []struct {
		name string
		in   string
		want string
	}{
		{"cyrillic left glue", "пользовательuser1 logged in", "пользовательuser1 logged in"},
		{"cyrillic right glue", "logged user1зашёл system", "logged user1зашёл system"},
		{"cjk right glue", "see user1日本語 there", "see user1日本語 there"},
		{"space-separated still restores", "user user1 here", "user bob here"},
		{"cyrillic with space still restores", "пользователь user1 зашёл", "пользователь bob зашёл"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := r.Restore(tc.in); got != tc.want {
				t.Errorf("got %q want %q", got, tc.want)
			}
		})
	}
}

func TestRestore_NothingToRestore(t *testing.T) {
	m := newMapper()
	r := New(m, false)
	if got := r.Restore("plain text"); got != "plain text" {
		t.Errorf("empty mapper should pass through, got %q", got)
	}
}

func TestRestore_UnknownReplaceLeftAlone(t *testing.T) {
	m := newMapper()
	m.Obfuscate("alice", detector.KindUser, nil)

	r := New(m, false)
	// "user1" → "alice", but "user99" not in mapping.
	in := "user1 vs user99"
	want := "alice vs user99"
	if got := r.Restore(in); got != want {
		t.Errorf("got %q want %q", got, want)
	}
}

// Round-trip — the headline guarantee.
func TestRoundTrip(t *testing.T) {
	originals := []string{
		"alice",
		"10.1.2.3",
		"db-prod.internal",
		"alice@corp.com",
		"550e8400-e29b-41d4-a716-446655440000",
	}
	kinds := []detector.EntityKind{
		detector.KindUser,
		detector.KindIP,
		detector.KindHost,
		detector.KindEmail,
		detector.KindUUID,
	}
	m := newMapper()
	for i, o := range originals {
		m.Obfuscate(o, kinds[i], nil)
	}

	// Build a synthetic AI response containing every replace value.
	var aiText strings.Builder
	aiText.WriteString("Steps:\n")
	for _, e := range m.Entries() {
		aiText.WriteString("- check ")
		aiText.WriteString(e.Replace)
		aiText.WriteString("\n")
	}

	for _, strict := range []bool{false, true} {
		r := New(m, strict)
		out := r.Restore(aiText.String())
		for _, o := range originals {
			if !strings.Contains(out, o) {
				t.Errorf("strict=%v: origin %q missing from restore output:\n%s", strict, o, out)
			}
		}
	}
}
