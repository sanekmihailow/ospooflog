package detector

import (
	"net"
	"net/url"
	"regexp"
	"strings"
)

var (
	reDSN   = regexp.MustCompile(`\b(?:postgres(?:ql)?|mysql|redis|mongodb(?:\+srv)?|amqps?|kafka)://[^\s"'<>\x60]+`)
	reJWT   = regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{4,}\.eyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\b`)
	reUUID  = regexp.MustCompile(`\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b`)
	reEmail = regexp.MustCompile(`\b[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+\b`)
	reAddr  = regexp.MustCompile(`\b((?:\d{1,3}\.){3}\d{1,3}):(\d{1,5})\b`)
	reIP    = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	// MAC — 6 hex pairs separated by ':' or '-'. The pair-anchor avoids
	// confusion with IPv6 (which has variable-width groups separated by ':').
	reMAC = regexp.MustCompile(`\b[0-9a-fA-F]{2}(?:[:-][0-9a-fA-F]{2}){5}\b`)
	// IPv6 — wide regex (allows empty blocks for the "::" compressed form,
	// optional %zone suffix), final filtering happens in validIPv6 via
	// net.ParseIP. The leading/trailing non-hex-colon class anchors prevent
	// mid-word false matches.
	reIP6 = regexp.MustCompile(`(?:^|[^A-Fa-f0-9:])((?:[A-Fa-f0-9]{0,4}:){2,7}[A-Fa-f0-9]{0,4}(?:%[A-Za-z0-9]+)?)(?:$|[^A-Fa-f0-9:])`)

	// HOST syslog — hostname token right after a syslog timestamp at start of
	// line. Covers both ISO 8601 ("2026-03-16T04:40:00.267616+00:00 host …")
	// and legacy BSD ("Mar 16 09:09:12 host …") forms. (?m) anchors ^ at
	// each line. Captures the hostname; the trailing whitespace + non-space
	// process word is required so we don't snag the next token in oddly
	// formatted lines.
	reHostSyslog = regexp.MustCompile(`(?m)^(?:\d{4}-\d{2}-\d{2}T[\d:.+\-Z]+|[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+([a-zA-Z][a-zA-Z0-9._-]+)\s+\S+`)
	// HOST conservative — must end in a private/internal-looking suffix.
	reHostConservative = regexp.MustCompile(`\b[a-zA-Z0-9][a-zA-Z0-9-]*\.(?:local|internal|lan|home)\b`)
	// HOST aggressive — single-label hostname with a hyphen, only after a
	// "host=" / "server=" / "node=" keyword. Without the keyword anchor this
	// matches any random "well-known" or "non-empty".
	reHostAggressive = regexp.MustCompile(`(?i)\b(?:host|server|node|hostname)\s*[=:]\s*([a-zA-Z][a-zA-Z0-9]*-[a-zA-Z0-9-]+[a-zA-Z0-9])\b`)

	// FQDN — last label must be from a known TLD list so we don't snag
	// unrelated dotted strings like "app.log" or "module.go".
	reFQDN = regexp.MustCompile(`\b[a-zA-Z][a-zA-Z0-9-]*(?:\.[a-zA-Z0-9][a-zA-Z0-9-]*)*\.(?:com|org|net|io|dev|app|info|biz|co|edu|gov|mil|ai|cloud|tech|us|uk|de|fr|jp|ru|cn|es|it|nl|pl|au|ca|br|in|me|tv|gg|so|ch|se|no|fi|dk|be|at|cz)\b`)

	// PORT — standalone ":1234". Leading non-word char prevents matching the
	// port half of an "ip:port" pair (which is already eaten by ADDR anyway).
	rePort = regexp.MustCompile(`(?:^|[^a-zA-Z0-9_.\-])(:\d{2,5})\b`)

	// USER conservative — explicit "user=" / "login=" / "username:" / "acct="
	// context. "acct" picks up auditd / PAM records like acct="root". The
	// optional quote after "=" lets the capture cross past quoted values.
	reUserConservative = regexp.MustCompile(`(?i)\b(?:user(?:name)?|login|acct)\s*[=:]\s*["']?([a-zA-Z][a-zA-Z0-9._-]{0,30})\b`)
	// USER in httpd combined log format: third whitespace-delimited token on
	// the line, anchored to the next-up "[DD/Mon/YYYY" timestamp shape that
	// only httpd-family access logs produce. The leading [a-zA-Z0-9_] in the
	// capture rejects the canonical "-" placeholder when no auth user is set.
	reUserHTTPD = regexp.MustCompile(`(?m)^\S+\s+\S+\s+([a-zA-Z0-9_][a-zA-Z0-9._-]*)\s+\[\d{2}/[A-Z][a-z]{2}/\d{4}`)
	// USER aggressive — also "as <name>" / "for <name>". Lots of false-positive
	// risk ("as needed", "for example").
	reUserAggressive = regexp.MustCompile(`(?i)\b(?:as|for)\s+([a-zA-Z][a-zA-Z0-9._-]{1,30})\b`)

	// PATH conservative — only absolute paths under known system roots.
	rePathConservative = regexp.MustCompile(`(/(?:var|etc|home|opt|usr|tmp|mnt|srv|root)(?:/[A-Za-z0-9._-]+)+)`)
	// PATH aggressive — any 2+ segment absolute path starting with a letter.
	rePathAggressive = regexp.MustCompile(`(/[a-zA-Z][A-Za-z0-9._-]*(?:/[A-Za-z0-9._-]+){1,})`)

	// PEM private key block. (?s) so "." crosses newlines. The label part
	// "[A-Z0-9 ]*PRIVATE KEY" covers OPENSSH/RSA/EC/DSA/PRIVATE variants.
	rePEMPrivate = regexp.MustCompile(`(?s)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----`)

	// SSH public key body: algorithm prefix + whitespace + long base64 blob.
	// The {40,} floor avoids snagging algorithm-name lists like
	// "ssh-rsa,ssh-ed25519" where there's no real key payload after.
	reSSHPubKey = regexp.MustCompile(`\b(?:ssh-rsa|ssh-dss|ssh-ed25519|ecdsa-sha2-[a-z0-9-]+)\s+[A-Za-z0-9+/]{40,}={0,3}`)

	// SSH wire-format base64 blob without algorithm prefix (e.g. sshd debug
	// "advance: '<blob>'" continuations). Every real SSH public key starts
	// with "AAAA" — that's the encoded 32-bit length of the first string
	// field, always 7/11/19/etc. The 60-char floor avoids random ALL-CAPS
	// tokens of length 4 that happen to begin with AAAA.
	reSSHPubKeyBare = regexp.MustCompile(`\bAAAA[A-Za-z0-9+/]{60,}={0,3}`)

	// SHA256 SSH fingerprint — accepts both OpenSSH-style base64-43
	// ("SHA256:gIIV9aBJ...") and hex-64 ("SHA256:4783cf01..."). One rule
	// covers both since the char class is a superset.
	reSHA256FP = regexp.MustCompile(`\bSHA256:[A-Za-z0-9+/]{40,}={0,2}`)
	// MD5 SSH fingerprint — 16 hex pairs separated by colons.
	reMD5FP = regexp.MustCompile(`\bMD5:(?:[0-9a-fA-F]{2}:){15}[0-9a-fA-F]{2}\b`)

	// SSH algorithm/cipher/MAC identifiers — "<token>@(openssh.com|libssh.org)"
	// shapes (chacha20-poly1305@openssh.com, curve25519-sha256@libssh.org,
	// hmac-sha2-256-etm@openssh.com, etc). Matched by a Skip rule so the
	// whole token is held verbatim — keeps email and FQDN rules off.
	reSSHAlgIdent = regexp.MustCompile(`\S+@(?:openssh\.com|libssh\.org)\b`)

	// SQL plaintext password: "IDENTIFIED BY 'secret'" / `BY "secret"`.
	reSQLIdentifiedBy = regexp.MustCompile(`(?i)IDENTIFIED\s+BY\s+['"]([^'"]+)['"]`)
	// Generic password assignment: password=..., passwd: ..., pwd = "...".
	// Captures up to the next quote/whitespace/comma/semicolon — covers
	// quoted and bare forms. The leading \b prevents matching tail-tokens
	// like "vtiger_password".
	rePasswordAssign = regexp.MustCompile(`(?i)\b(?:password|passwd|pwd)\s*[=:]\s*['"]?([^'"\s,;]+)`)
	// Command-line password flags. Long-form only — short flags like -p are
	// too ambiguous (mysql -p, ssh -p PORT) to use unconditionally.
	rePasswordFlag = regexp.MustCompile(`(?i)\B--(?:password|passwd|pwd)[= ]['"]?([^'"\s]+)`)

	// Bearer token in Authorization header. Matches "Authorization: Bearer X"
	// and bare "Bearer X". The token charset covers JWT (.) and opaque
	// base64/URL-safe forms.
	reBearerToken = regexp.MustCompile(`(?i)(?:Authorization:\s*)?Bearer\s+([A-Za-z0-9._~+/=\-]{16,})`)
	// Generic API-key assignment: api_key, apikey, api-key, x-api-key, etc.
	reAPIKeyAssign = regexp.MustCompile(`(?i)\b(?:x[-_]?)?api[-_]?key\s*[=:]\s*['"]?([A-Za-z0-9._~+/=\-]{12,})`)
	// AWS access key IDs. AKIA = long-lived, ASIA = STS session, AROA/AGPA/
	// AIPA/ANPA/ANVA/AIDA = other entity types. Always 20 chars total.
	reAWSAccessKey = regexp.MustCompile(`\b(?:AKIA|ASIA|AROA|AGPA|AIPA|ANPA|ANVA|AIDA)[A-Z0-9]{16}\b`)
	// GitHub tokens: ghp_ (PAT), gho_ (OAuth), ghu_ (user-to-server),
	// ghs_ (server-to-server), ghr_ (refresh).
	reGitHubToken = regexp.MustCompile(`\bgh[posur]_[A-Za-z0-9]{36,}\b`)
	// Slack tokens: xox[abprs]-… (bot/app/user/refresh/legacy).
	reSlackToken = regexp.MustCompile(`\bxox[abprs]-[A-Za-z0-9-]{10,}\b`)

	// Credit-card number: 13–19 digits with optional space/dash separators
	// between any two digits. Lookahead/lookbehind isn't supported in RE2,
	// so the validation (Luhn + known brand prefix) lives in validCard.
	reCreditCard = regexp.MustCompile(`\b\d(?:[- ]?\d){12,18}\b`)

	// MySQL GRANT-style 'user'@'host'. We mask only the user half — host
	// is usually 'localhost' / '%' / an IP that other rules already cover.
	reMySQLUserAt = regexp.MustCompile(`'([a-zA-Z_][a-zA-Z0-9_-]*)'@'[^']+'`)

	// SSH/TLS algorithm-name local-parts that masquerade as email addresses
	// (e.g. "rsa-sha2-512-cert-v01@openssh.com",
	// "sk-ecdsa-sha2-nistp256@openssh.com"). Used by validEmail to reject
	// algorithm strings without dragging in a domain blacklist.
	reSSHAlgLocalPart = regexp.MustCompile(`(?i)^(?:sk-)?(?:ssh-(?:rsa|dss|ed25519)|rsa-sha2-(?:256|512)|ecdsa-sha2-nistp(?:256|384|521)|ed25519)(?:-cert-v\d+)?$`)
)

// validEmail rejects matches that are actually SSH algorithm identifiers.
// SSH names use openssh.com / libssh.org as a fake "domain" half (e.g.
// "chacha20-poly1305@openssh.com", "curve25519-sha256@libssh.org") and the
// RFC-shaped "<alg>-cert-v01@..." host-key identifiers — both are e-mail
// shape but never user addresses. Cheaper than a domain allowlist.
func validEmail(s string) bool {
	at := strings.LastIndexByte(s, '@')
	if at <= 0 {
		return false
	}
	domain := strings.ToLower(s[at+1:])
	if domain == "openssh.com" || domain == "libssh.org" {
		return false
	}
	return !reSSHAlgLocalPart.MatchString(s[:at])
}

// userStopWords are common English words and OS names that get captured by
// "for X" / "as X" / "user: X" patterns but are never actual usernames.
// Lowercased; lookup is case-insensitive.
var userStopWords = map[string]bool{
	// English words that follow "as" / "for"
	"needed": true, "expected": true, "example": true, "instance": true,
	"now": true, "soon": true, "well": true, "long": true, "part": true,
	"me": true, "us": true, "you": true, "it": true, "them": true,
	"the": true, "a": true, "an": true, "this": true, "that": true,
	"running": true, "started": true, "stopped": true, "failed": true,
	"done": true, "complete": true, "all": true, "any": true, "some": true,
	// Tokens after "user:" that are field names, not usernames
	"name": true, "id": true, "uid": true, "gid": true,
	// OS / distro names that get caught by "for <name>"
	"ubuntu": true, "debian": true, "fedora": true, "centos": true,
	"alpine": true, "linux": true, "windows": true, "macos": true,
	"darwin": true, "redhat": true, "rhel": true, "arch": true,
}

// validUser rejects USER captures that are clearly English stop-words or
// OS names rather than account names. Lowercase compare so "Ubuntu" and
// "ubuntu" both get filtered. Real account names like "root", "system",
// or any digits/underscores form (user1, vtiger_user) are unaffected.
func validUser(s string) bool {
	return !userStopWords[strings.ToLower(s)]
}

// validCard accepts only digit strings that start with a known card-brand
// prefix (Visa/MC/AmEx/Discover/Diners/JCB) and pass the Luhn checksum.
// The brand-prefix gate keeps random Luhn-valid IDs (timestamps, hashes)
// from masquerading as cards.
func validCard(s string) bool {
	var first byte
	count := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < '0' || c > '9' {
			continue
		}
		if count == 0 {
			first = c
		}
		count++
	}
	if count < 13 || count > 19 {
		return false
	}
	switch first {
	case '3', '4', '5', '6':
	default:
		return false
	}
	sum := 0
	alt := false
	for i := len(s) - 1; i >= 0; i-- {
		c := s[i]
		if c < '0' || c > '9' {
			continue
		}
		d := int(c - '0')
		if alt {
			if d *= 2; d > 9 {
				d -= 9
			}
		}
		sum += d
		alt = !alt
	}
	return sum%10 == 0
}

// validSyslogHost rejects tokens that look syslog-positional but are
// actually CRI container-log stream markers ("<ts> stderr F …" /
// "<ts> stdout F …"). Avoids masking those as hostnames.
func validSyslogHost(s string) bool {
	switch s {
	case "stderr", "stdout":
		return false
	}
	return true
}

func addrExtra(sub []string) map[string]string {
	return map[string]string{"ip": sub[1], "port": sub[2]}
}

func validIPv4(s string) bool {
	ip := net.ParseIP(s)
	v4 := ip.To4()
	if v4 == nil {
		return false
	}
	// Pass through semantic constants — masking these turns "listening on
	// 0.0.0.0" or "netmask 255.255.255.0" into nonsense for the AI.
	if ip.IsUnspecified() || ip.IsLoopback() {
		return false
	}
	if v4[0] == 255 && v4[1] == 255 && v4[2] == 255 && v4[3] == 255 {
		return false
	}
	// IPv4 netmask: contiguous 1-bits from the left. net.IPv4Mask.Size()
	// returns ones>0 only for valid masks.
	if ones, bits := net.IPv4Mask(v4[0], v4[1], v4[2], v4[3]).Size(); bits == 32 && ones > 0 {
		return false
	}
	return true
}

func validIPv6(s string) bool {
	// Strip a "%zone" suffix if present — net.ParseIP doesn't, but logs do.
	if i := strings.IndexByte(s, '%'); i >= 0 {
		s = s[:i]
	}
	ip := net.ParseIP(s)
	if ip == nil || ip.To4() != nil {
		return false
	}
	if ip.IsUnspecified() || ip.IsLoopback() {
		return false
	}
	return true
}

func validAddr(s string) bool {
	colon := strings.LastIndexByte(s, ':')
	if colon < 0 {
		return false
	}
	if !validIPv4(s[:colon]) {
		return false
	}
	port := s[colon+1:]
	if len(port) == 0 || len(port) > 5 {
		return false
	}
	var n int
	for _, c := range port {
		if c < '0' || c > '9' {
			return false
		}
		n = n*10 + int(c-'0')
	}
	return n >= 1 && n <= 65535
}

func dsnExtra(sub []string) map[string]string {
	u, err := url.Parse(sub[0])
	if err != nil {
		return nil
	}
	extra := map[string]string{
		"scheme": u.Scheme,
		"host":   u.Hostname(),
		"port":   u.Port(),
		"db":     strings.TrimPrefix(u.Path, "/"),
	}
	if u.User != nil {
		extra["user"] = u.User.Username()
		if pwd, ok := u.User.Password(); ok {
			extra["pass"] = pwd
		}
	}
	return extra
}

// DefaultRules is the conservative ruleset used when --aggressive is off.
// Order is priority — first rule wins at any given byte range.
func DefaultRules() []Rule {
	return []Rule{
		// PRIVKEY first — it spans newlines and embeds base64 that would
		// otherwise be shredded by IP/UUID/etc.
		{Kind: KindPrivKey, Re: rePEMPrivate},
		// SSH algorithm identifiers — skip so neither EMAIL nor FQDN claim them.
		{Re: reSSHAlgIdent, Skip: true},
		{Kind: KindDSN, Re: reDSN, ExtraFn: dsnExtra},
		{Kind: KindPubKey, Re: reSSHPubKey},
		{Kind: KindPubKey, Re: reSSHPubKeyBare},
		{Kind: KindFingerprint, Re: reSHA256FP},
		{Kind: KindFingerprint, Re: reMD5FP},
		{Kind: KindPassword, Re: reSQLIdentifiedBy, CaptureGroup: 1},
		{Kind: KindPassword, Re: rePasswordAssign, CaptureGroup: 1},
		{Kind: KindPassword, Re: rePasswordFlag, CaptureGroup: 1},
		// JWT before the generic Bearer rule so a JWT-shaped token stays
		// tagged as TOKEN instead of being relabelled as a generic API key.
		{Kind: KindToken, Re: reJWT},
		{Kind: KindAPIKey, Re: reAWSAccessKey},
		{Kind: KindAPIKey, Re: reGitHubToken},
		{Kind: KindAPIKey, Re: reSlackToken},
		{Kind: KindAPIKey, Re: reBearerToken, CaptureGroup: 1},
		{Kind: KindAPIKey, Re: reAPIKeyAssign, CaptureGroup: 1},
		{Kind: KindUser, Re: reMySQLUserAt, CaptureGroup: 1, Validate: validUser},
		{Kind: KindUUID, Re: reUUID},
		{Kind: KindCard, Re: reCreditCard, Validate: validCard},
		{Kind: KindEmail, Re: reEmail, Validate: validEmail},
		{Kind: KindAddr, Re: reAddr, ExtraFn: addrExtra, Validate: validAddr},
		{Kind: KindMAC, Re: reMAC},
		{Kind: KindIP, Re: reIP, Validate: validIPv4},
		{Kind: KindIP6, Re: reIP6, CaptureGroup: 1, Validate: validIPv6},
		// HOST before FQDN so .local/.internal names get the "host" treatment
		// instead of being relabelled as a generic FQDN.
		{Kind: KindHost, Re: reHostSyslog, CaptureGroup: 1, Validate: validSyslogHost},
		{Kind: KindHost, Re: reHostConservative},
		{Kind: KindFQDN, Re: reFQDN},
		{Kind: KindUser, Re: reUserConservative, CaptureGroup: 1, Validate: validUser},
		{Kind: KindUser, Re: reUserHTTPD, CaptureGroup: 1, Validate: validUser, BlockCaptureOnly: true},
		{Kind: KindPath, Re: rePathConservative, CaptureGroup: 1},
	}
}

// AggressiveRules adds wider USER/HOST/PATH/PORT capture at the cost of
// more false positives. Enabled via --aggressive.
func AggressiveRules() []Rule {
	return []Rule{
		{Kind: KindPrivKey, Re: rePEMPrivate},
		{Re: reSSHAlgIdent, Skip: true},
		{Kind: KindDSN, Re: reDSN, ExtraFn: dsnExtra},
		{Kind: KindPubKey, Re: reSSHPubKey},
		{Kind: KindPubKey, Re: reSSHPubKeyBare},
		{Kind: KindFingerprint, Re: reSHA256FP},
		{Kind: KindFingerprint, Re: reMD5FP},
		{Kind: KindPassword, Re: reSQLIdentifiedBy, CaptureGroup: 1},
		{Kind: KindPassword, Re: rePasswordAssign, CaptureGroup: 1},
		{Kind: KindPassword, Re: rePasswordFlag, CaptureGroup: 1},
		// JWT before the generic Bearer rule so a JWT-shaped token stays
		// tagged as TOKEN instead of being relabelled as a generic API key.
		{Kind: KindToken, Re: reJWT},
		{Kind: KindAPIKey, Re: reAWSAccessKey},
		{Kind: KindAPIKey, Re: reGitHubToken},
		{Kind: KindAPIKey, Re: reSlackToken},
		{Kind: KindAPIKey, Re: reBearerToken, CaptureGroup: 1},
		{Kind: KindAPIKey, Re: reAPIKeyAssign, CaptureGroup: 1},
		{Kind: KindUser, Re: reMySQLUserAt, CaptureGroup: 1, Validate: validUser},
		{Kind: KindUUID, Re: reUUID},
		{Kind: KindCard, Re: reCreditCard, Validate: validCard},
		{Kind: KindEmail, Re: reEmail, Validate: validEmail},
		{Kind: KindAddr, Re: reAddr, ExtraFn: addrExtra, Validate: validAddr},
		{Kind: KindMAC, Re: reMAC},
		{Kind: KindIP, Re: reIP, Validate: validIPv4},
		{Kind: KindIP6, Re: reIP6, CaptureGroup: 1, Validate: validIPv6},
		{Kind: KindHost, Re: reHostSyslog, CaptureGroup: 1, Validate: validSyslogHost},
		{Kind: KindHost, Re: reHostConservative},
		{Kind: KindHost, Re: reHostAggressive, CaptureGroup: 1},
		{Kind: KindFQDN, Re: reFQDN},
		{Kind: KindUser, Re: reUserConservative, CaptureGroup: 1, Validate: validUser},
		{Kind: KindUser, Re: reUserHTTPD, CaptureGroup: 1, Validate: validUser, BlockCaptureOnly: true},
		{Kind: KindUser, Re: reUserAggressive, CaptureGroup: 1, Validate: validUser},
		{Kind: KindPath, Re: rePathConservative, CaptureGroup: 1},
		{Kind: KindPath, Re: rePathAggressive, CaptureGroup: 1},
		{Kind: KindPort, Re: rePort, CaptureGroup: 1},
	}
}
