package detector

import (
	"regexp"
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

func TestFQDN_IANATLDsAndBlacklist(t *testing.T) {
	cases := []struct {
		text string
		want []string
	}{
		{"reach api.example.com", []string{"api.example.com"}},
		// new gTLDs from IANA list
		{"deploy dashboard.example.cloud and shop.acme.shop", []string{"dashboard.example.cloud", "shop.acme.shop"}},
		// city / region TLDs
		{"site at example.tokyo", []string{"example.tokyo"}},
		// punycoded IDN ccTLDs: xn--p1ai (.рф), xn--fiqs8s (.中国)
		{"reach host.xn--p1ai or shop.xn--fiqs8s", []string{"host.xn--p1ai", "shop.xn--fiqs8s"}},
		// blacklisted .so / .zip / .mov / .bar must NOT match
		{"libc.so.6 archive.zip movie.mov foo.bar", nil},
	}
	for _, tc := range cases {
		matches := New(DefaultRules()).Find(tc.text)
		var got []string
		for _, m := range matches {
			if m.Kind == KindFQDN {
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

func TestPath_ExtendedSystemRoots(t *testing.T) {
	text := "exe=/sbin/auditctl ld /lib/x86_64-linux-gnu/libcrypto boot /boot/vmlinuz-6.8 sock /run/systemd/private bin /bin/bash but skip /custom/whatever"
	matches := New(DefaultRules()).Find(text)
	want := map[string]bool{
		"/sbin/auditctl":                  false,
		"/lib/x86_64-linux-gnu/libcrypto": false,
		"/boot/vmlinuz-6.8":               false,
		"/run/systemd/private":            false,
		"/bin/bash":                       false,
	}
	for _, m := range matches {
		if m.Kind == KindPath {
			if _, ok := want[m.Value]; ok {
				want[m.Value] = true
			} else if m.Value == "/custom/whatever" {
				t.Errorf("conservative path leaked outside known roots: %q", m.Value)
			}
		}
	}
	for k, v := range want {
		if !v {
			t.Errorf("path not detected: %q", k)
		}
	}
}

func TestUser_SSHDLoginPatterns(t *testing.T) {
	cases := []struct {
		text string
		want string
	}{
		{"Failed publickey for sanya from 1.2.3.4 port 22", "sanya"},
		{"Accepted password for alice from 5.6.7.8 port 22", "alice"},
		{"Invalid user backdoor from 9.10.11.12 port 22", "backdoor"},
		{"Failed password for invalid user attacker from 13.14.15.16", "attacker"},
		{"session opened for user bob(uid=1001)", "bob"},
		{"Connection closed by authenticating user carol 17.18.19.20", "carol"},
	}
	for _, tc := range cases {
		matches := New(DefaultRules()).Find(tc.text)
		var got string
		for _, m := range matches {
			if m.Kind == KindUser {
				got = m.Value
				break
			}
		}
		if got != tc.want {
			t.Errorf("text=%q: want user %q, got %q", tc.text, tc.want, got)
		}
	}
}

func TestSecretAssign_GenericNames(t *testing.T) {
	cases := []struct {
		text string
		want string
	}{
		{"secret=abc123def456ghi789", "abc123def456ghi789"},
		{"access_token=ya29.a0AfH6SMBabcdef123456789", "ya29.a0AfH6SMBabcdef123456789"},
		{"client_secret: 'p8e-very-long-secret-string'", "p8e-very-long-secret-string"},
		{"refresh-token=1//0eabcdefghijklmnopqr", "1//0eabcdefghijklmnopqr"},
		// Short config token should NOT trigger
		{"token=true", ""},
	}
	for _, tc := range cases {
		matches := New(DefaultRules()).Find(tc.text)
		var got string
		for _, m := range matches {
			if m.Kind == KindAPIKey {
				got = m.Value
				break
			}
		}
		if got != tc.want {
			t.Errorf("text=%q: want %q, got %q", tc.text, tc.want, got)
		}
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

func TestPhone_E164AndContext(t *testing.T) {
	cases := []struct {
		text string
		want []string
	}{
		// Bare E.164
		{"call +14155552671 now", []string{"+14155552671"}},
		// Russian E.164 (11 digits after +)
		{"sms +74951234567 ok", []string{"+74951234567"}},
		// Keyword anchor, hyphenated US
		{"phone: 415-555-2671 home", []string{"415-555-2671"}},
		// Keyword anchor with leading +
		{"mobile=+14155552671 stored", []string{"+14155552671"}},
		// Too few digits — rejected by validPhone
		{"phone: 12-34 noise", nil},
		// No anchor + no leading + → not picked up (avoid false positives)
		{"id 4155552671 here", nil},
	}
	for _, tc := range cases {
		matches := New(DefaultRules()).Find(tc.text)
		var got []string
		for _, m := range matches {
			if m.Kind == KindPhone {
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

func TestAPIKey_VendorPrefixes(t *testing.T) {
	cases := []struct {
		name string
		text string
	}{
		{"AWS A3T extension", "key=A3TGEXAMPLE234567ABC"},
		{"AWS ABIA", "key=ABIAEXAMPLE234567ABC"},
		{"GitLab PAT", "GITLAB_TOKEN=glpat-AbCdEfGhIjKlMnOpQrSt"},
		{"Google API key", "key=AIza" + repeat("a", 35)},
		// Split the prefix so the literal "sk_live_…" / "rk_test_…" doesn't
		// appear contiguously in the source — GitHub Push Protection flags
		// fake test fixtures that look like real Stripe keys at rest.
		{"Stripe live secret", "stripe=sk_" + "live_" + "abcdefghij1234567890ABCDEF"},
		{"Stripe restricted test", "stripe=rk_" + "test_" + "abcdefghij1234567890ABCDEF"},
		{"Anthropic api", "ANTHROPIC_API_KEY=sk-ant-api03-" + repeat("a", 93) + "AA"},
		{"OpenAI legacy", "OPENAI_API_KEY=sk-" + repeat("a", 20) + "T3BlbkFJ" + repeat("b", 20)},
	}
	for _, tc := range cases {
		matches := New(DefaultRules()).Find(tc.text)
		var got []string
		for _, m := range matches {
			if m.Kind == KindAPIKey {
				got = append(got, m.Value)
			}
		}
		if len(got) != 1 {
			t.Errorf("%s: want exactly 1 APIKEY match, got %d (matches=%+v)", tc.name, len(got), matches)
		}
	}
}

func repeat(s string, n int) string {
	out := make([]byte, 0, len(s)*n)
	for i := 0; i < n; i++ {
		out = append(out, s...)
	}
	return string(out)
}

func TestOCIDigest(t *testing.T) {
	text := "pulled image@sha256:5b0bcabd1ed22e9fb1310cf6c2dec7cdef19f0ad69efa1f392e94a4333501270 ok"
	matches := New(DefaultRules()).Find(text)
	var got []string
	for _, m := range matches {
		if m.Kind == KindFingerprint {
			got = append(got, m.Value)
		}
	}
	if len(got) != 1 || got[0] != "sha256:5b0bcabd1ed22e9fb1310cf6c2dec7cdef19f0ad69efa1f392e94a4333501270" {
		t.Errorf("want 1 fingerprint match for OCI digest, got %v", got)
	}
}

func TestARN_PreservesServiceAndRegion(t *testing.T) {
	cases := []struct {
		text    string
		service string
		region  string
	}{
		// IAM ARN, no region
		{"created arn:aws:iam::123456789012:user/Bob and quit", "iam", ""},
		// S3 bucket ARN, no region or account
		{"reading arn:aws:s3:::my-data-bucket/path/to/object now", "s3", ""},
		// EC2 ARN with region and account
		{"started arn:aws:ec2:us-east-1:123456789012:instance/i-1234567890abcdef0 ok", "ec2", "us-east-1"},
	}
	for _, tc := range cases {
		matches := New(DefaultRules()).Find(tc.text)
		var got *Match
		for i := range matches {
			if matches[i].Kind == KindARN {
				got = &matches[i]
				break
			}
		}
		if got == nil {
			t.Errorf("text=%q: no ARN match (matches=%+v)", tc.text, matches)
			continue
		}
		if got.Extra["service"] != tc.service {
			t.Errorf("text=%q: service want %q got %q", tc.text, tc.service, got.Extra["service"])
		}
		if got.Extra["region"] != tc.region {
			t.Errorf("text=%q: region want %q got %q", tc.text, tc.region, got.Extra["region"])
		}
	}
}

func TestEmpty(t *testing.T) {
	matches := New(DefaultRules()).Find("")
	if len(matches) != 0 {
		t.Errorf("empty text should yield no matches, got %+v", matches)
	}
}

func TestMinEntropy_FiltersLowEntropyCaptures(t *testing.T) {
	rule := Rule{
		Kind:         "TEST",
		Re:           regexp.MustCompile(`token=(\S+)`),
		CaptureGroup: 1,
		MinEntropy:   2.0,
	}
	cases := []struct {
		text string
		want int
	}{
		// Single repeated char — entropy 0
		{"token=AAAAAAAA", 0},
		// 2-unique-char alternation — entropy 1.0
		{"token=ababab", 0},
		// Mixed varied chars — entropy >2.0
		{"token=AbC3xY9zQ", 1},
	}
	for _, tc := range cases {
		got := New([]Rule{rule}).Find(tc.text)
		if len(got) != tc.want {
			t.Errorf("text=%q: want %d matches, got %d (%+v)", tc.text, tc.want, len(got), got)
		}
	}
}

func TestPassword_FiltersPlaceholderValues(t *testing.T) {
	cases := []struct {
		text string
		want bool
	}{
		// Repeated-char placeholders the entropy floor should drop
		{"password=xxxxxxxxxxxx", false},
		{"passwd: AAAAAAAA", false},
		// Real-shaped passwords stay
		{"password=hunter2", true},
		{"password=S3cr3t!Pass", true},
	}
	for _, tc := range cases {
		matches := New(DefaultRules()).Find(tc.text)
		var hit bool
		for _, m := range matches {
			if m.Kind == KindPassword {
				hit = true
				break
			}
		}
		if hit != tc.want {
			t.Errorf("text=%q: want hit=%v, got %v (matches=%+v)", tc.text, tc.want, hit, matches)
		}
	}
}

func TestKeyword_SkipsRegexWhenAbsent(t *testing.T) {
	rule := Rule{
		Kind:    "TEST",
		Re:      regexp.MustCompile(`\bhello\b`),
		Keyword: "ZZZ",
	}
	if got := New([]Rule{rule}).Find("hello world"); len(got) != 0 {
		t.Errorf("keyword absent: want 0 matches, got %d (%+v)", len(got), got)
	}
	if got := New([]Rule{rule}).Find("ZZZ hello world"); len(got) != 1 {
		t.Errorf("keyword present: want 1 match, got %d (%+v)", len(got), got)
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
