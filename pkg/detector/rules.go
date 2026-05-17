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
	// IPv6 — wide regex (allows empty blocks for the "::" compressed form,
	// optional %zone suffix), final filtering happens in validIPv6 via
	// net.ParseIP. The leading/trailing non-hex-colon class anchors prevent
	// mid-word false matches.
	reIP6 = regexp.MustCompile(`(?:^|[^A-Fa-f0-9:])((?:[A-Fa-f0-9]{0,4}:){2,7}[A-Fa-f0-9]{0,4}(?:%[A-Za-z0-9]+)?)(?:$|[^A-Fa-f0-9:])`)

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

	// USER conservative — explicit "user=" / "login=" / "username:" context.
	reUserConservative = regexp.MustCompile(`(?i)\b(?:user(?:name)?|login)\s*[=:]\s*([a-zA-Z][a-zA-Z0-9._-]{0,30})\b`)
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
)

func addrExtra(sub []string) map[string]string {
	return map[string]string{"ip": sub[1], "port": sub[2]}
}

func validIPv4(s string) bool {
	ip := net.ParseIP(s)
	return ip != nil && ip.To4() != nil
}

func validIPv6(s string) bool {
	// Strip a "%zone" suffix if present — net.ParseIP doesn't, but logs do.
	if i := strings.IndexByte(s, '%'); i >= 0 {
		s = s[:i]
	}
	ip := net.ParseIP(s)
	return ip != nil && ip.To4() == nil
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
		{Kind: KindDSN, Re: reDSN, ExtraFn: dsnExtra},
		{Kind: KindPubKey, Re: reSSHPubKey},
		{Kind: KindPubKey, Re: reSSHPubKeyBare},
		{Kind: KindFingerprint, Re: reSHA256FP},
		{Kind: KindFingerprint, Re: reMD5FP},
		{Kind: KindToken, Re: reJWT},
		{Kind: KindUUID, Re: reUUID},
		{Kind: KindEmail, Re: reEmail},
		{Kind: KindAddr, Re: reAddr, ExtraFn: addrExtra, Validate: validAddr},
		{Kind: KindIP, Re: reIP, Validate: validIPv4},
		{Kind: KindIP6, Re: reIP6, CaptureGroup: 1, Validate: validIPv6},
		// HOST before FQDN so .local/.internal names get the "host" treatment
		// instead of being relabelled as a generic FQDN.
		{Kind: KindHost, Re: reHostConservative},
		{Kind: KindFQDN, Re: reFQDN},
		{Kind: KindUser, Re: reUserConservative, CaptureGroup: 1},
		{Kind: KindPath, Re: rePathConservative, CaptureGroup: 1},
	}
}

// AggressiveRules adds wider USER/HOST/PATH/PORT capture at the cost of
// more false positives. Enabled via --aggressive.
func AggressiveRules() []Rule {
	return []Rule{
		{Kind: KindPrivKey, Re: rePEMPrivate},
		{Kind: KindDSN, Re: reDSN, ExtraFn: dsnExtra},
		{Kind: KindPubKey, Re: reSSHPubKey},
		{Kind: KindPubKey, Re: reSSHPubKeyBare},
		{Kind: KindFingerprint, Re: reSHA256FP},
		{Kind: KindFingerprint, Re: reMD5FP},
		{Kind: KindToken, Re: reJWT},
		{Kind: KindUUID, Re: reUUID},
		{Kind: KindEmail, Re: reEmail},
		{Kind: KindAddr, Re: reAddr, ExtraFn: addrExtra, Validate: validAddr},
		{Kind: KindIP, Re: reIP, Validate: validIPv4},
		{Kind: KindIP6, Re: reIP6, CaptureGroup: 1, Validate: validIPv6},
		{Kind: KindHost, Re: reHostConservative},
		{Kind: KindHost, Re: reHostAggressive, CaptureGroup: 1},
		{Kind: KindFQDN, Re: reFQDN},
		{Kind: KindUser, Re: reUserConservative, CaptureGroup: 1},
		{Kind: KindUser, Re: reUserAggressive, CaptureGroup: 1},
		{Kind: KindPath, Re: rePathConservative, CaptureGroup: 1},
		{Kind: KindPath, Re: rePathAggressive, CaptureGroup: 1},
		{Kind: KindPort, Re: rePort, CaptureGroup: 1},
	}
}
