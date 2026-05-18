package detector

import (
	"testing"
)

func findKinds(matches []Match) map[EntityKind]int {
	c := map[EntityKind]int{}
	for _, m := range matches {
		c[m.Kind]++
	}
	return c
}

func TestDSN_DoesNotGetSplitByLowerRules(t *testing.T) {
	text := `connection=postgres://alice:secret@10.1.2.3:5432/appdb failed`
	matches := New(DefaultRules()).Find(text)
	counts := findKinds(matches)
	if counts[KindDSN] != 1 {
		t.Fatalf("want 1 DSN, got %d (matches=%+v)", counts[KindDSN], matches)
	}
	for _, k := range []EntityKind{KindEmail, KindAddr, KindIP, KindFQDN, KindHost, KindUser} {
		if counts[k] != 0 {
			t.Errorf("%s leaked through covered-range guard: %d hits", k, counts[k])
		}
	}
	if matches[0].Value != "postgres://alice:secret@10.1.2.3:5432/appdb" {
		t.Errorf("unexpected DSN value: %q", matches[0].Value)
	}
	if matches[0].Extra["scheme"] != "postgres" || matches[0].Extra["port"] != "5432" {
		t.Errorf("dsnExtra missing fields: %+v", matches[0].Extra)
	}
}

func TestAddr_BeatsBareIP(t *testing.T) {
	text := "service at 10.1.2.3:5432 plus 10.4.5.6 standalone"
	matches := New(DefaultRules()).Find(text)
	counts := findKinds(matches)
	if counts[KindAddr] != 1 {
		t.Errorf("want 1 ADDR, got %d", counts[KindAddr])
	}
	if counts[KindIP] != 1 {
		t.Errorf("want 1 IP, got %d", counts[KindIP])
	}
	for _, m := range matches {
		if m.Kind == KindAddr && m.Extra["port"] != "5432" {
			t.Errorf("ADDR extra port missing: %+v", m.Extra)
		}
	}
}

func TestUser_OnlyInExplicitContext(t *testing.T) {
	text := "user=alice and login: bob and somewhere alice appears bare"
	matches := New(DefaultRules()).Find(text)
	var users []string
	for _, m := range matches {
		if m.Kind == KindUser {
			users = append(users, m.Value)
		}
	}
	// "alice" (from user=alice) and "bob" (from login: bob) — yes
	// bare "alice" later — no (conservative mode)
	if len(users) != 2 {
		t.Fatalf("want 2 users, got %d: %v", len(users), users)
	}
	want := map[string]bool{"alice": false, "bob": false}
	for _, u := range users {
		if _, ok := want[u]; ok {
			want[u] = true
		}
	}
	for k, v := range want {
		if !v {
			t.Errorf("user %q not detected", k)
		}
	}
}

func TestUser_HTTPDCombinedFormat(t *testing.T) {
	text := `192.168.1.10 - frank [10/Oct/2000:13:55:36 -0700] "GET / HTTP/1.0" 200 1234` + "\n" +
		`192.168.1.11 - - [10/Oct/2000:13:55:37 -0700] "GET /a HTTP/1.0" 404 12`
	matches := New(DefaultRules()).Find(text)
	var users []string
	for _, m := range matches {
		if m.Kind == KindUser {
			users = append(users, m.Value)
		}
	}
	if len(users) != 1 || users[0] != "frank" {
		t.Fatalf("want [frank], got %v (matches=%+v)", users, matches)
	}
}

func TestUser_AggressiveAddsAsFor(t *testing.T) {
	text := "running as alice for processing"
	conservative := New(DefaultRules()).Find(text)
	if k := findKinds(conservative); k[KindUser] != 0 {
		t.Errorf("conservative should not fire on 'as alice', got %d", k[KindUser])
	}
	aggressive := New(AggressiveRules()).Find(text)
	if k := findKinds(aggressive); k[KindUser] == 0 {
		t.Errorf("aggressive should fire on 'as alice'")
	}
}

func TestHost_LocalInternalSuffix(t *testing.T) {
	text := "connect to db-prod.internal and api.svc.local"
	matches := New(DefaultRules()).Find(text)
	hosts := []string{}
	for _, m := range matches {
		if m.Kind == KindHost {
			hosts = append(hosts, m.Value)
		}
	}
	if len(hosts) != 2 {
		t.Fatalf("want 2 hosts, got %d: %v (all matches=%+v)", len(hosts), hosts, matches)
	}
}

func TestFQDN_RejectsPureDigits(t *testing.T) {
	text := "version 1.2.3.4 and api.example.com"
	matches := New(DefaultRules()).Find(text)
	for _, m := range matches {
		if m.Kind == KindFQDN && m.Value == "1.2.3.4" {
			t.Errorf("FQDN should not match all-digit string")
		}
	}
}

func TestPath_Conservative(t *testing.T) {
	text := "open /var/log/app.log but skip /custom/path/here"
	matches := New(DefaultRules()).Find(text)
	paths := []string{}
	for _, m := range matches {
		if m.Kind == KindPath {
			paths = append(paths, m.Value)
		}
	}
	if len(paths) != 1 || paths[0] != "/var/log/app.log" {
		t.Errorf("conservative path want [/var/log/app.log], got %v", paths)
	}
}

func TestPath_Aggressive(t *testing.T) {
	text := "open /custom/path/here"
	matches := New(AggressiveRules()).Find(text)
	paths := []string{}
	for _, m := range matches {
		if m.Kind == KindPath {
			paths = append(paths, m.Value)
		}
	}
	if len(paths) != 1 || paths[0] != "/custom/path/here" {
		t.Errorf("aggressive path want [/custom/path/here], got %v", paths)
	}
}

func TestEmail(t *testing.T) {
	text := "send to alice@corp.com today"
	matches := New(DefaultRules()).Find(text)
	if c := findKinds(matches); c[KindEmail] != 1 {
		t.Errorf("want 1 EMAIL, got %d", c[KindEmail])
	}
}

func TestUUID(t *testing.T) {
	text := "trace 550e8400-e29b-41d4-a716-446655440000 done"
	matches := New(DefaultRules()).Find(text)
	if c := findKinds(matches); c[KindUUID] != 1 {
		t.Errorf("want 1 UUID, got %d", c[KindUUID])
	}
}

func TestJWT(t *testing.T) {
	text := "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyMSJ9.SflKxwRJSMeKKF tail"
	matches := New(DefaultRules()).Find(text)
	if c := findKinds(matches); c[KindToken] != 1 {
		t.Errorf("want 1 TOKEN, got %d", c[KindToken])
	}
}

func TestIP6_RejectsTimestamps(t *testing.T) {
	text := "2026-05-03 19:00:01 INFO ok at fe80::1 done"
	matches := New(DefaultRules()).Find(text)
	for _, m := range matches {
		if m.Kind == KindIP6 && m.Value == "19:00:01" {
			t.Errorf("timestamp leaked as IPv6")
		}
	}
	// fe80::1 should still be caught.
	var ip6 int
	for _, m := range matches {
		if m.Kind == KindIP6 {
			ip6++
			if m.Value != "fe80::1" {
				t.Errorf("unexpected IPv6 value: %q", m.Value)
			}
		}
	}
	if ip6 != 1 {
		t.Errorf("want 1 IPv6 match, got %d (matches=%+v)", ip6, matches)
	}
}

func TestIP_RejectsInvalidOctets(t *testing.T) {
	text := "version 999.999.999.999 vs real 10.1.2.3"
	matches := New(DefaultRules()).Find(text)
	var ips []string
	for _, m := range matches {
		if m.Kind == KindIP {
			ips = append(ips, m.Value)
		}
	}
	if len(ips) != 1 || ips[0] != "10.1.2.3" {
		t.Errorf("want only [10.1.2.3], got %v", ips)
	}
}

func TestCreditCard_LuhnAndBrand(t *testing.T) {
	cases := []struct {
		text string
		want []string
	}{
		// Visa test card, no separators
		{"payment 4111111111111111 done", []string{"4111111111111111"}},
		// Visa test card, hyphenated
		{"card 4111-1111-1111-1111 ok", []string{"4111-1111-1111-1111"}},
		// Visa test card, space-separated
		{"PAN 4111 1111 1111 1111 ok", []string{"4111 1111 1111 1111"}},
		// AmEx test card, 15 digits, hyphenated 4-6-5
		{"amex 3782-822463-10005 ok", []string{"3782-822463-10005"}},
		// Random 16 digits — Luhn invalid → not a match
		{"id 1234567890123456 ok", nil},
		// All zeros — passes Luhn but brand digit '0' rejected
		{"id 0000000000000000 ok", nil},
		// Brand digit '7' — rejected even if Luhn-valid (test case has bad Luhn anyway)
		{"id 7111111111111111 ok", nil},
	}
	for _, tc := range cases {
		matches := New(DefaultRules()).Find(tc.text)
		var got []string
		for _, m := range matches {
			if m.Kind == KindCard {
				got = append(got, m.Value)
			}
		}
		if len(got) != len(tc.want) {
			t.Errorf("text=%q: want %v, got %v", tc.text, tc.want, got)
			continue
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Errorf("text=%q: want %v, got %v", tc.text, tc.want, got)
				break
			}
		}
	}
}

func TestEmpty(t *testing.T) {
	matches := New(DefaultRules()).Find("")
	if len(matches) != 0 {
		t.Errorf("empty text should yield no matches, got %+v", matches)
	}
}

func TestSortedByStart(t *testing.T) {
	text := "user=bob then 10.1.2.3 then alice@x.com"
	matches := New(DefaultRules()).Find(text)
	for i := 1; i < len(matches); i++ {
		if matches[i-1].Start > matches[i].Start {
			t.Errorf("not sorted: %+v", matches)
		}
	}
}
