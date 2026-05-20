package detector

import (
	"encoding/base64"
	"encoding/json"
	"net"
	"net/url"
	"regexp"
	"strings"
)

var (
	reDSN   = regexp.MustCompile(`\b(?:postgres(?:ql)?|mysql|redis|mongodb(?:\+srv)?|amqps?|kafka)://[^\s"'<>\x60]+`)
	// AWS ARN: "arn:partition:service:region:account-id:resource". Region
	// and account-id are blank for some services (S3, IAM). Resource may
	// contain "/" or ":" separators. Captured greedily up to whitespace
	// or quote. Group 1 is service, group 2 is region — picked up by
	// arnExtra so the fake can preserve the service kind.
	reARN = regexp.MustCompile(`\barn:aws[a-z0-9-]*:([a-z0-9-]+):([a-z0-9-]*):[0-9]{0,12}:[a-zA-Z0-9_/:.\-]+`)
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

	// FQDN — any "label.label[.label…]" shape. The TLD check is done
	// post-match in validFQDN so the regex stays simple and the canonical
	// IANA list lives in tlds.go as data, not regex syntax.
	reFQDN = regexp.MustCompile(`\b[a-zA-Z][a-zA-Z0-9-]*(?:\.[a-zA-Z0-9][a-zA-Z0-9-]*)+\b`)

	// PORT — standalone ":1234". Leading non-word char prevents matching the
	// port half of an "ip:port" pair (which is already eaten by ADDR anyway).
	rePort = regexp.MustCompile(`(?:^|[^a-zA-Z0-9_.\-])(:\d{2,5})\b`)

	// USER conservative — explicit "user=" / "login=" / "username:" / "acct="
	// context. "acct" picks up auditd / PAM records like acct="root". The
	// optional quote after "=" lets the capture cross past quoted values.
	reUserConservative = regexp.MustCompile(`(?i)\b(?:user(?:name)?|login|acct)\s*[=:]\s*["']?([a-zA-Z][a-zA-Z0-9._-]{0,30})\b`)
	// USER in sshd login messages. Default mode misses these without a
	// dedicated rule because they use space-separated verbs, not "user="
	// syntax. Covers the standard openssh vocabulary:
	//   "Failed|Accepted <method> for [invalid user] <USER>"
	//   "Invalid user <USER>"
	//   "authenticating user <USER>"
	//   "session opened|closed for user <USER>"
	reUserSSHD = regexp.MustCompile(`(?i)\b(?:(?:Failed|Accepted)\s+(?:password|publickey|keyboard-interactive|none|gssapi-with-mic|hostbased)\s+for(?:\s+invalid\s+user)?|Invalid user|authenticating user|(?:opened|closed)\s+for\s+user)\s+([a-zA-Z_][a-zA-Z0-9._-]{0,30})\b`)
	// USER in httpd combined log format: third whitespace-delimited token on
	// the line, anchored to the next-up "[DD/Mon/YYYY" timestamp shape that
	// only httpd-family access logs produce. The leading [a-zA-Z0-9_] in the
	// capture rejects the canonical "-" placeholder when no auth user is set.
	reUserHTTPD = regexp.MustCompile(`(?m)^\S+\s+\S+\s+([a-zA-Z0-9_][a-zA-Z0-9._-]*)\s+\[\d{2}/[A-Z][a-z]{2}/\d{4}`)
	// USER aggressive — also "as <name>" / "for <name>". Lots of false-positive
	// risk ("as needed", "for example").
	reUserAggressive = regexp.MustCompile(`(?i)\b(?:as|for)\s+([a-zA-Z][a-zA-Z0-9._-]{1,30})\b`)

	// PATH conservative — only absolute paths under known system roots.
	// Covers FHS roots that commonly carry binary/library/config paths
	// worth masking (project-specific subpaths leak service topology).
	// Excludes /proc, /sys, /dev — pseudo-fs paths are generally not
	// sensitive and masking them makes logs harder for the AI to read.
	rePathConservative = regexp.MustCompile(`(/(?:var|etc|home|opt|usr|tmp|mnt|srv|root|boot|sbin|bin|lib|lib64|run)(?:/[A-Za-z0-9._-]+)+)`)
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
	// Container image / OCI digest: lowercase "sha256:" followed by
	// exactly 64 hex chars. Distinct from the SSH form because OpenSSH
	// uses uppercase "SHA256:" and base64 (43 chars), while OCI/Docker
	// fix on lowercase + hex (64 chars).
	reOCIDigest = regexp.MustCompile(`\bsha256:[a-f0-9]{64}\b`)
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
	// Generic secret / token assignments — "secret=", "token=",
	// "access_token=", "client_secret=", "refresh_token=", etc. Min
	// length 12 keeps short config values like "token=true" out.
	reSecretAssign = regexp.MustCompile(`(?i)\b(?:secret|token|(?:access|refresh|auth|client|session|bearer|id)[_-]?(?:secret|token))\s*[=:]\s*['"]?([A-Za-z0-9._~+/=\-]{12,})`)
	// AWS access key IDs. AKIA = long-lived, ASIA = STS session; the rest
	// (A3T, ABIA, ACCA, AROA, AGPA, AIPA, ANPA, ANVA, AIDA) cover other
	// IAM entity types. AWS access keys are encoded in the base32 alphabet
	// (A–Z plus 2–7), and are always 20 chars total.
	reAWSAccessKey = regexp.MustCompile(`\b(?:A3T[A-Z2-7]|AKIA|ASIA|AROA|AGPA|AIPA|ANPA|ANVA|AIDA|ABIA|ACCA)[A-Z2-7]{16}\b`)
	// GitHub tokens: ghp_ (PAT), gho_ (OAuth), ghu_ (user-to-server),
	// ghs_ (server-to-server), ghr_ (refresh).
	reGitHubToken = regexp.MustCompile(`\bgh[posur]_[A-Za-z0-9]{36,}\b`)
	// GitHub fine-grained personal access token (2022+). Distinct from the
	// classic gh[posur]_ shape — fine-grained PATs carry a fixed
	// "github_pat_" prefix followed by 82+ base62-ish chars with an
	// internal underscore separator between key-id and secret halves.
	reGitHubFineGrainedPAT = regexp.MustCompile(`\bgithub_pat_[A-Za-z0-9_]{82,}\b`)
	// Slack tokens: xox[abeprs]-… (bot/app/user/refresh/legacy/external).
	// "e" covers the xoxe- shape used for refresh and external tokens.
	reSlackToken = regexp.MustCompile(`\bxox[abeprs]-[A-Za-z0-9-]{10,}\b`)

	// Anthropic API / admin keys. The trailing "AA" is a stable terminator
	// in all currently-issued keys; the 93-char body is base64url-safe.
	reAnthropicKey = regexp.MustCompile(`\bsk-ant-(?:api03|admin01)-[A-Za-z0-9_\-]{93}AA\b`)
	// OpenAI keys — both legacy "sk-…20charsT3BlbkFJ…20chars" and current
	// project/service/admin variants. T3BlbkFJ is base64("OpenAI") and
	// appears in every issued key, which keeps FP near zero.
	reOpenAIKey = regexp.MustCompile(`\bsk-(?:(?:proj|svcacct|admin)-(?:[A-Za-z0-9_-]{74}|[A-Za-z0-9_-]{58})T3BlbkFJ(?:[A-Za-z0-9_-]{74}|[A-Za-z0-9_-]{58})|[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20})\b`)
	// Google API key (Maps, Firebase, GCP): "AIza" + 35 chars.
	reGoogleAPIKey = regexp.MustCompile(`\bAIza[A-Za-z0-9_\-]{35}\b`)
	// Stripe secret / restricted keys. Publishable "pk_" keys are public
	// by design and don't need masking.
	reStripeKey = regexp.MustCompile(`\b(?:sk|rk)_(?:live|test|prod)_[A-Za-z0-9]{10,99}\b`)
	// GitLab personal / project / group access tokens.
	reGitLabToken = regexp.MustCompile(`\bglpat-[A-Za-z0-9_\-]{20}\b`)
	// npm access token — "npm_" + 36 hex chars. Real automation/publish
	// tokens are hex-only; mixed-case tokens are legacy and rarely seen now.
	reNpmToken = regexp.MustCompile(`\bnpm_[a-f0-9]{36}\b`)
	// Hugging Face user access token — "hf_" + 34+ alphanumeric chars.
	// Length floor matches empirical observation; HF docs only specify the
	// prefix, real tokens land at 37 chars but we leave headroom.
	reHFToken = regexp.MustCompile(`\bhf_[a-zA-Z0-9]{34,}\b`)
	// Databricks API token — "dapi" + 32 hex chars + optional "-N" shard
	// suffix used by workspace-bound tokens.
	reDatabricksToken = regexp.MustCompile(`\bdapi[a-f0-9]{32}(?:-\d)?\b`)
	// Doppler personal token — "dp.pt." + 43 alphanumeric chars.
	reDopplerToken = regexp.MustCompile(`\bdp\.pt\.[a-zA-Z0-9]{43}\b`)
	// DigitalOcean tokens — common shape across PAT (dop), OAuth (doo) and
	// refresh (dor) variants: "do[opr]_v1_" + 64 hex chars.
	reDOToken = regexp.MustCompile(`\bdo[opr]_v1_[a-f0-9]{64}\b`)
	// Dynatrace API token — "dt0c01." + 24 alphanumeric + "." + 64
	// alphanumeric. Two-segment structure encodes tenant and credential.
	reDynatraceToken = regexp.MustCompile(`\bdt0c01\.[a-zA-Z0-9]{24}\.[a-zA-Z0-9]{64}\b`)
	// age secret key — "AGE-SECRET-KEY-1" + 58 Bech32 (uppercase) chars.
	// Bech32 alphabet excludes B, I, O, 1 (visually ambiguous in the
	// canonical lowercase form); the uppercase form is what age emits.
	reAgeSecretKey = regexp.MustCompile(`\bAGE-SECRET-KEY-1[023456789ACDEFGHJKLMNPQRSTUVWXYZ]{58}\b`)
	// Alibaba Cloud access key ID — "LTAI" + 20 alphanumeric chars.
	// Distinct from AWS AKIA (base32, 16 chars) by both prefix and alphabet.
	reAlibabaAK = regexp.MustCompile(`\bLTAI[a-zA-Z0-9]{20}\b`)
	// Atlassian API token (Jira / Confluence / Bitbucket Cloud) — "ATATT3"
	// + 186 base64url chars. One regex covers all Atlassian products that
	// share the cloud token format.
	reAtlassianToken = regexp.MustCompile(`\bATATT3[A-Za-z0-9_\-=]{186}\b`)
	// Twilio API key — "SK" + 32 lowercase hex. Distinct from Account SIDs
	// ("AC" + 32 hex) which are public identifiers and don't need masking.
	reTwilioAPIKey = regexp.MustCompile(`\bSK[0-9a-f]{32}\b`)
	// SendGrid API key — "SG." + 66 chars from a base64-ish charset.
	reSendGridKey = regexp.MustCompile(`\bSG\.[A-Za-z0-9=_\-.]{66}\b`)
	// Mailgun private API token — "key-" + 32 lowercase hex.
	reMailgunKey = regexp.MustCompile(`\bkey-[a-f0-9]{32}\b`)
	// Notion integration token — "ntn_" + 11 digits + 35 alphanumeric.
	reNotionToken = regexp.MustCompile(`\bntn_[0-9]{11}[A-Za-z0-9]{35}\b`)
	// Linear API key — "lin_api_" + 40 alphanumeric (case-insensitive).
	reLinearKey = regexp.MustCompile(`(?i)\blin_api_[A-Za-z0-9]{40}\b`)
	// Stripe webhook signing secret — "whsec_" + 32+ alphanumeric.
	// Distinct from reStripeKey (sk_/rk_) which catches secret/restricted
	// API keys but not webhook signatures.
	reStripeWebhook = regexp.MustCompile(`\bwhsec_[A-Za-z0-9]{32,}\b`)
	// HashiCorp Vault token — "hv[sbr]." + 90+ base64url chars. The single
	// regex covers all three modern Vault token classes: service (hvs.),
	// batch (hvb.) and recovery (hvr.). Legacy "s.<random>" format omitted —
	// the bare "s." prefix is too generic for safe pre-filtering.
	reVaultToken = regexp.MustCompile(`\bhv[sbr]\.[A-Za-z0-9_\-]{90,}\b`)
	// Sentry auth token — "sntrys_" + 60+ base64url. Modern (2023+) format;
	// the older hex-only tokens have no usable prefix and fall through to
	// the generic api_key/Bearer rules.
	reSentryToken = regexp.MustCompile(`\bsntrys_[A-Za-z0-9_\-]{60,}\b`)
	// PostHog personal API key — "phx_" + 40+ alphanumeric. Distinct from
	// "phc_" project keys, which are public (embedded in client SDKs) and
	// intentionally not masked.
	rePostHogKey = regexp.MustCompile(`\bphx_[A-Za-z0-9]{40,}\b`)
	// Replicate API token — "r8_" + 37 alphanumeric.
	reReplicateKey = regexp.MustCompile(`\br8_[A-Za-z0-9]{37}\b`)
	// Tailscale API / auth / OAuth client key — "tskey-{auth,api,client}-"
	// + 20+ chars (alphanumeric with dashes; tokens carry an internal
	// key-id/secret separator).
	reTailscaleKey = regexp.MustCompile(`\btskey-(?:auth|api|client)-[A-Za-z0-9\-]{20,}\b`)
	// Okta API token — sent in an "SSWS <token>" Authorization header, the
	// same shape as reBearerToken but with Okta's custom scheme name.
	reOktaToken = regexp.MustCompile(`(?i)(?:Authorization:\s*)?SSWS\s+([A-Za-z0-9_\-]{40,})`)
	// Datadog API/APP keys — opaque 32-/40-hex strings carrying no usable
	// prefix on their own; identified instead by the DD-API-KEY /
	// DD-APPLICATION-KEY header name that ships them. Captures just the
	// key value (group 1).
	reDatadogHeader = regexp.MustCompile(`(?i)(?:DD-API-KEY|DD-APPLICATION-KEY):\s*([a-f0-9]{32,40})`)
	// New Relic user API key — "NRAK-" + 27 uppercase alphanumeric. The
	// license key and INSERT key formats have no equally stable prefix.
	reNewRelicKey = regexp.MustCompile(`\bNRAK-[A-Z0-9]{27}\b`)
	// Perplexity API key — "pplx-" + 40+ alphanumeric.
	rePerplexityKey = regexp.MustCompile(`\bpplx-[A-Za-z0-9]{40,}\b`)
	// Fly.io macaroon-based token — "fm2_" + 80+ base64url. The legacy
	// "fo1_" / "fm1_" prefixes are deprecated and dropped from this rule
	// to keep the keyword pre-filter unambiguous.
	reFlyIOToken = regexp.MustCompile(`\bfm2_[A-Za-z0-9_\-]{80,}\b`)
	// Shopify admin/storefront/customer tokens — "shp(at|ss|ca)_" + 32 hex.
	// All three Shopify token classes share the shape, only the 2-char
	// suffix differs.
	reShopifyToken = regexp.MustCompile(`\bshp(?:at|ss|ca)_[a-f0-9]{32}\b`)
	// Square access token — "EAAA" + 60+ base64url. "EAAA" is the fixed
	// base64 encoding of the leading bytes of Square's token header.
	reSquareToken = regexp.MustCompile(`\bEAAA[A-Za-z0-9_\-]{60,}\b`)
	// Telegram bot API token — "<8-10 digit bot id>:<35-char secret>".
	// No textual prefix; the digits-colon-token shape is the only anchor.
	reTelegramBot = regexp.MustCompile(`\b\d{8,10}:[A-Za-z0-9_\-]{35}\b`)
	// Discord bot token — three base64url segments separated by dots,
	// first segment starts with "M" or "N" (base64 of the snowflake bot
	// user id). Distinct from JWT by both first-char and the JWT rule's
	// "eyJ" keyword pre-filter.
	reDiscordBot = regexp.MustCompile(`\b[MN][A-Za-z0-9_\-]{23,26}\.[A-Za-z0-9_\-]{6,7}\.[A-Za-z0-9_\-]{27,40}\b`)
	// Groq API key — "gsk_" + 50+ alphanumeric.
	reGroqKey = regexp.MustCompile(`\bgsk_[A-Za-z0-9]{50,}\b`)
	// xAI (Grok) API key — "xai-" + 80+ alphanumeric.
	reXAIKey = regexp.MustCompile(`\bxai-[A-Za-z0-9]{80,}\b`)
	// NVIDIA NGC API key — "nvapi-" + 60+ base64url.
	reNVNGCKey = regexp.MustCompile(`\bnvapi-[A-Za-z0-9_\-]{60,}\b`)
	// PlanetScale tokens — "pscale_<class>_" with class being one of the
	// documented token types.
	rePlanetScaleKey = regexp.MustCompile(`\bpscale_(?:tkn|oauth|pw|app|webauthn)_[A-Za-z0-9_\-]{20,}\b`)
	// Supabase personal access token — "sbp_" + 40 hex. Service-role keys
	// are JWT-shaped and caught by reJWT.
	reSupabaseKey = regexp.MustCompile(`\bsbp_[a-f0-9]{40,}\b`)
	// Buildkite user access token — "bkua_" + 40 hex.
	reBuildkiteKey = regexp.MustCompile(`\bbkua_[a-f0-9]{40}\b`)
	// Grafana Cloud access policy token — "glc_" + 40+ base64-ish chars.
	reGrafanaCloudKey = regexp.MustCompile(`\bglc_[A-Za-z0-9_\-=]{40,}\b`)
	// Honeycomb ingest key — "hcaik_" + 40+ alphanumeric. Classic
	// 32-hex Honeycomb keys have no prefix and aren't covered here.
	reHoneycombKey = regexp.MustCompile(`\bhcaik_[A-Za-z0-9_\-]{40,}\b`)
	// PyPI API token — "pypi-" + 130+ base64url. Extremely long compared
	// to other provider tokens; the format embeds a JSON payload.
	rePyPIToken = regexp.MustCompile(`\bpypi-[A-Za-z0-9_\-]{130,}\b`)
	// Resend API key — "re_" + 25+ alphanumeric. The 3-char prefix is
	// common in unrelated identifiers ("core_", "store_"); the length
	// floor + MinEntropy 3.0 filter out near-misses.
	reResendKey = regexp.MustCompile(`\bre_[A-Za-z0-9]{25,}\b`)
	// JFrog Artifactory API key — "AKCp" + 64+ alphanumeric.
	reJFrogKey = regexp.MustCompile(`\bAKCp[A-Za-z0-9]{64,}\b`)
	// SonarQube / SonarCloud tokens — sqp_ (project), sqa_ (analysis),
	// squ_ (user) + 40 hex.
	reSonarToken = regexp.MustCompile(`\bsq[pau]_[a-f0-9]{40}\b`)
	// NuGet.org API key — "oy2" + 47+ base32-ish lowercase chars.
	reNuGetKey = regexp.MustCompile(`\boy2[a-z0-9]{47,}\b`)
	// LaunchDarkly SDK / mobile / API keys — "(sdk|mob|api)-" + UUID.
	// Placed in the APIKEY chain before reUUID so the prefix stays
	// attached to the captured range.
	reLaunchDarklyKey = regexp.MustCompile(`\b(?:sdk|mob|api)-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b`)
	// Backblaze B2 application key — "K00" + 28+ alphanumeric. The bare
	// account-id form "00<22 hex>" is too generic and not covered here.
	reBackblazeB2Key = regexp.MustCompile(`\bK00[A-Za-z0-9]{28,}\b`)
	// HubSpot personal access token — "pat-<region>-<UUID>". Region is a
	// short alphanumeric tag like "na1" / "eu1".
	reHubSpotPAT = regexp.MustCompile(`\bpat-[a-z0-9]{2,5}-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b`)
	// OpenRouter API key — "sk-or-v1-" + 64 hex. Distinct from reStripeKey
	// ("sk_live_…") by the dash-vs-underscore separator.
	reOpenRouterKey = regexp.MustCompile(`\bsk-or-v1-[a-f0-9]{64}\b`)
	// Xata API key — "xau_" + 25+ alphanumeric.
	reXataKey = regexp.MustCompile(`\bxau_[A-Za-z0-9]{25,}\b`)
	// Stytch project secret — "secret-(test|live)-" + 40+ base64url.
	reStytchSecret = regexp.MustCompile(`\bsecret-(?:test|live)-[A-Za-z0-9_\-]{40,}\b`)
	// LangSmith access token — "lsv2_(pt|sk)_" + 40+ alphanumeric. The
	// modern format covers personal (pt) and service (sk) tokens; legacy
	// "ls__" tokens are out of scope.
	reLangSmithToken = regexp.MustCompile(`\blsv2_(?:pt|sk)_[A-Za-z0-9]{40,}\b`)
	// Brevo (formerly Sendinblue) API key — "xkeysib-" + 60+ hex.
	reBrevoKey = regexp.MustCompile(`\bxkeysib-[a-f0-9]{60,}\b`)
	// Terraform Cloud user / team token — "<id>.atlasv1.<secret>". The
	// ".atlasv1." middle marker is the anchor; both segments carry the
	// same base64url alphabet.
	reTerraformCloudToken = regexp.MustCompile(`\b[A-Za-z0-9]{14,}\.atlasv1\.[A-Za-z0-9_\-]{60,}\b`)
	// Postman API key — "PMAK-" + 24 hex + "-" + 34 hex. Common in CI
	// pipelines that run newman-based API tests.
	rePostmanKey = regexp.MustCompile(`\bPMAK-[a-f0-9]{24}-[a-f0-9]{34}\b`)
	// Sourcegraph personal access token — "sgp_" + 40+ alphanumeric.
	reSourcegraphToken = regexp.MustCompile(`\bsgp_[A-Za-z0-9]{40,}\b`)
	// Airtable personal access token — "pat" + 14 base62 + "." + 64 hex.
	// No keyword pre-filter: "pat" is a common English substring; the
	// pattern's strict structure (14 chars + dot + 64 hex) is the anchor.
	reAirtablePAT = regexp.MustCompile(`\bpat[A-Za-z0-9]{14}\.[a-f0-9]{64}\b`)
	// GCP service-account private_key_id field — the 40-hex id that
	// fingerprints the key. The matching PEM private_key is already
	// caught by rePEMPrivate; the client_email field is caught by
	// reEmail. This rule covers the remaining sensitive piece of the
	// SA JSON blob.
	reGCPPrivateKeyId = regexp.MustCompile(`(?i)"private_key_id"\s*:\s*"([a-f0-9]{32,})"`)
	// AWS session credentials — the secret access key and session token
	// that ship as the second and third leg of a temporary-credentials
	// triple. The matching access key id ("ASIA…") is caught by
	// reAWSAccessKey. Covers both snake_case env-var / credentials-file
	// form and PascalCase JSON form (e.g. "SecretAccessKey": "…").
	reAWSSessionCred = regexp.MustCompile(`(?i)\b(?:aws_secret_access_key|secretaccesskey|aws_session_token|sessiontoken)\s*['"]?\s*[=:]\s*['"]?([A-Za-z0-9_/+=\-]{20,})`)
	// HTTP Basic Authorization — captures the base64 blob after "Basic ".
	// Mirrors reBearerToken — both can appear with or without the literal
	// "Authorization:" header prefix in the same log line.
	reBasicAuth = regexp.MustCompile(`(?i)(?:Authorization:\s*)?Basic\s+([A-Za-z0-9+/=]{16,})`)

	// K8s Secret-style YAML value — indented "key: <b64>" lines where the
	// value is exclusively base64 charset and ≥ 40 chars. Covers raw K8s
	// Secrets (data:), helm releases (gzip+b64 blobs in sh.helm.release.v1.*
	// — can be hundreds of KB single-line), prometheus-operator config
	// secrets, ansible-vault, docker secrets. We trust the structural
	// context (indented YAML key under a `data:`-style block); no decode is
	// needed for this rule, the regex pattern alone implies sensitivity.
	// {40,} has no upper bound — Go RE2 handles multi-MB single-line matches
	// in linear time, fine for whole-Helm-release captures.
	reK8sSecretValue = regexp.MustCompile(`(?m)^\s+[A-Za-z0-9_.-]+:\s+([A-Za-z0-9+/=]{40,})\s*$`)

	// Environment variable with _B64 / _BASE64 suffix — common pattern for
	// shipping credentials through env without quoting issues (CI runners,
	// Docker envFrom, kubectl set env). The capture is the base64 value.
	reB64EnvVar = regexp.MustCompile(`(?i)\b[A-Za-z][A-Za-z0-9_]*(?:_B64|_BASE64)\s*[=:]\s*['"]?([A-Za-z0-9+/=]{16,})`)

	// Generic base64 blob — aggressive-only fallback for credentials packed
	// into base64 outside of any recognised context (curl pipes, JSON config
	// dumps, raw kubectl describe output). High entropy floor + decode-
	// verify keeps S3 ETags / pod UIDs / SHA hashes from getting masked.
	reGenericB64 = regexp.MustCompile(`\b[A-Za-z0-9+/]{32,}={0,2}`)

	// Credit-card number: 13–19 digits with optional space/dash separators
	// between any two digits. Lookahead/lookbehind isn't supported in RE2,
	// so the validation (Luhn + known brand prefix) lives in validCard.
	reCreditCard = regexp.MustCompile(`\b\d(?:[- ]?\d){12,18}\b`)

	// Phone in E.164 international form: "+" plus 7–15 digits, first digit
	// 1–9. The leading "+" is what keeps the FP rate near zero — bare digit
	// runs of this length are too noisy without context.
	rePhoneE164 = regexp.MustCompile(`\+[1-9]\d{6,14}\b`)
	// Phone with an explicit "phone:" / "tel=" / "mobile=" / "fax:" /
	// "cell:" / "msisdn=" keyword. Capture must start and end with a digit
	// so trailing whitespace or punctuation doesn't leak into the value.
	rePhoneContext = regexp.MustCompile(`(?i)\b(?:phone|tel|mobile|fax|cell|msisdn)\s*[:=]\s*(\+?\d[\d\s\-().]{5,18}\d)`)

	// MySQL GRANT-style 'user'@'host'. We mask only the user half — host
	// is usually 'localhost' / '%' / an IP that other rules already cover.
	reMySQLUserAt = regexp.MustCompile(`'([a-zA-Z_][a-zA-Z0-9_-]*)'@'[^']+'`)

	// SSH/TLS algorithm-name local-parts that masquerade as email addresses
	// (e.g. "rsa-sha2-512-cert-v01@openssh.com",
	// "sk-ecdsa-sha2-nistp256@openssh.com"). Used by validEmail to reject
	// algorithm strings without dragging in a domain blacklist.
	reSSHAlgLocalPart = regexp.MustCompile(`(?i)^(?:sk-)?(?:ssh-(?:rsa|dss|ed25519)|rsa-sha2-(?:256|512)|ecdsa-sha2-nistp(?:256|384|521)|ed25519)(?:-cert-v\d+)?$`)
)

// validTLDs is the IANA TLD set in lowercase form. Initialised once from
// the embedded ianaTLDs string with a small blacklist of TLDs that collide
// with common log-content tokens: ".so" (shared-library extension), ".zip"
// and ".mov" (archive / video extensions), ".bar" (the "foo.bar" idiom).
// Users can extend via --overrides if a specific TLD is noisy in their logs.
var validTLDs = func() map[string]bool {
	m := make(map[string]bool, 1500)
	for _, t := range strings.Split(ianaTLDs, "\n") {
		t = strings.TrimSpace(t)
		if t != "" {
			m[t] = true
		}
	}
	for _, t := range []string{"so", "zip", "mov", "bar"} {
		delete(m, t)
	}
	return m
}()

// validFQDN keeps regex matches whose last label is an IANA-registered TLD.
func validFQDN(s string) bool {
	i := strings.LastIndexByte(s, '.')
	if i < 0 {
		return false
	}
	return validTLDs[strings.ToLower(s[i+1:])]
}

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

// validPhone keeps captures that hold 7–15 digits (E.164 spec range)
// ignoring any separators. Cuts both too-short noise and over-long IDs
// that drifted through the keyword-anchored rule.
func validPhone(s string) bool {
	n := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= '0' && c <= '9' {
			n++
		}
	}
	return n >= 7 && n <= 15
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

func arnExtra(sub []string) map[string]string {
	return map[string]string{
		"service": sub[1],
		"region":  sub[2],
	}
}

// jwtExtra decodes a JWT's payload segment and pulls out sensitive claims
// (email, phone_number, preferred_username, name) so the obfuscator can
// pre-register them in the mapper. This gives cross-text consistency: if
// the same email appears bare elsewhere in the same run it resolves to
// the same fake as the one encoded inside the JWT.
//
// Keys use the "claim:<KIND>" convention so the obfuscator can route each
// value to the right per-kind counter. Returns nil if the payload doesn't
// decode cleanly or carries no sensitive claims.
func jwtExtra(sub []string) map[string]string {
	if len(sub) < 1 {
		return nil
	}
	parts := strings.Split(sub[0], ".")
	if len(parts) != 3 {
		return nil
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		// Some JWTs in the wild keep trailing '=' padding.
		payload, err = base64.URLEncoding.DecodeString(parts[1])
		if err != nil {
			return nil
		}
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil
	}
	extra := map[string]string{}
	if v, ok := claims["email"].(string); ok && v != "" {
		extra["claim:"+string(KindEmail)] = v
	}
	if v, ok := claims["phone_number"].(string); ok && v != "" {
		extra["claim:"+string(KindPhone)] = v
	}
	// Pick the first non-empty username-like claim — JWTs usually carry
	// one of these, the order encodes preference. "sub" is intentionally
	// excluded: it's most often an opaque IdP-side user ID, not a name
	// the user would recognise elsewhere in their logs.
	for _, key := range []string{"preferred_username", "nickname", "given_name", "name", "family_name"} {
		if v, ok := claims[key].(string); ok && v != "" {
			extra["claim:"+string(KindUser)] = v
			break
		}
	}
	if len(extra) == 0 {
		return nil
	}
	return extra
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

// coreRules contains the rules shared across all detection modes — they
// don't vary by aggressiveness. The three public ruleset functions append
// their own HOST/USER/PATH/PORT/B64 tail on top of this.
//
// Order is priority — first rule wins at any given byte range.
func coreRules() []Rule {
	return []Rule{
		// PRIVKEY first — it spans newlines and embeds base64 that would
		// otherwise be shredded by IP/UUID/etc.
		{Kind: KindPrivKey, Re: rePEMPrivate, Keyword: "-----BEGIN"},
		// SSH algorithm identifiers — skip so neither EMAIL nor FQDN claim them.
		{Re: reSSHAlgIdent, Skip: true},
		{Kind: KindDSN, Re: reDSN, ExtraFn: dsnExtra},
		{Kind: KindARN, Re: reARN, ExtraFn: arnExtra, Keyword: "arn:aws"},
		{Kind: KindPubKey, Re: reSSHPubKey},
		{Kind: KindPubKey, Re: reSSHPubKeyBare, Keyword: "AAAA"},
		{Kind: KindFingerprint, Re: reSHA256FP, Keyword: "SHA256:"},
		{Kind: KindFingerprint, Re: reOCIDigest, Keyword: "sha256:"},
		{Kind: KindFingerprint, Re: reMD5FP, Keyword: "MD5:"},
		{Kind: KindPassword, Re: reSQLIdentifiedBy, CaptureGroup: 1, MinEntropy: 2.0},
		{Kind: KindPassword, Re: rePasswordAssign, CaptureGroup: 1, MinEntropy: 2.0},
		{Kind: KindPassword, Re: rePasswordFlag, CaptureGroup: 1, MinEntropy: 2.0},
		// JWT before the generic Bearer rule so a JWT-shaped token stays
		// tagged as TOKEN instead of being relabelled as a generic API key.
		{Kind: KindToken, Re: reJWT, Keyword: "eyJ", ExtraFn: jwtExtra},
		{Kind: KindAPIKey, Re: reAWSAccessKey},
		{Kind: KindAPIKey, Re: reGitHubToken},
		{Kind: KindAPIKey, Re: reGitHubFineGrainedPAT, Keyword: "github_pat_", MinEntropy: 3.0},
		{Kind: KindAPIKey, Re: reGitLabToken, Keyword: "glpat-"},
		{Kind: KindAPIKey, Re: reSlackToken, Keyword: "xox"},
		{Kind: KindAPIKey, Re: reAnthropicKey, Keyword: "sk-ant-"},
		{Kind: KindAPIKey, Re: reOpenAIKey, Keyword: "T3BlbkFJ"},
		{Kind: KindAPIKey, Re: reGoogleAPIKey, Keyword: "AIza"},
		{Kind: KindAPIKey, Re: reNpmToken, Keyword: "npm_", MinEntropy: 3.0},
		{Kind: KindAPIKey, Re: reHFToken, Keyword: "hf_", MinEntropy: 3.0},
		{Kind: KindAPIKey, Re: reDatabricksToken, Keyword: "dapi", MinEntropy: 3.0},
		{Kind: KindAPIKey, Re: reDopplerToken, Keyword: "dp.pt.", MinEntropy: 3.0},
		{Kind: KindAPIKey, Re: reDOToken, Keyword: "_v1_", MinEntropy: 3.0},
		{Kind: KindAPIKey, Re: reDynatraceToken, Keyword: "dt0c01.", MinEntropy: 3.0},
		{Kind: KindAPIKey, Re: reAgeSecretKey, Keyword: "AGE-SECRET-KEY-1", MinEntropy: 3.0},
		{Kind: KindAPIKey, Re: reAlibabaAK, Keyword: "LTAI", MinEntropy: 3.0},
		{Kind: KindAPIKey, Re: reAtlassianToken, Keyword: "ATATT3", MinEntropy: 3.0},
		{Kind: KindAPIKey, Re: reTwilioAPIKey, Keyword: "SK", MinEntropy: 3.0},
		{Kind: KindAPIKey, Re: reSendGridKey, Keyword: "SG.", MinEntropy: 3.0},
		{Kind: KindAPIKey, Re: reMailgunKey, Keyword: "key-", MinEntropy: 3.0},
		{Kind: KindAPIKey, Re: reNotionToken, Keyword: "ntn_", MinEntropy: 3.0},
		{Kind: KindAPIKey, Re: reLinearKey, Keyword: "lin_api_", MinEntropy: 3.0},
		{Kind: KindAPIKey, Re: reStripeWebhook, Keyword: "whsec_", MinEntropy: 3.0},
		{Kind: KindAPIKey, Re: reVaultToken, Keyword: "hv", MinEntropy: 3.0},
		{Kind: KindAPIKey, Re: reSentryToken, Keyword: "sntrys_", MinEntropy: 3.0},
		{Kind: KindAPIKey, Re: rePostHogKey, Keyword: "phx_", MinEntropy: 3.0},
		{Kind: KindAPIKey, Re: reReplicateKey, Keyword: "r8_", MinEntropy: 3.0},
		{Kind: KindAPIKey, Re: reTailscaleKey, Keyword: "tskey-", MinEntropy: 3.0},
		{Kind: KindAPIKey, Re: reOktaToken, CaptureGroup: 1, MinEntropy: 3.0},
		{Kind: KindAPIKey, Re: reDatadogHeader, CaptureGroup: 1, MinEntropy: 3.0},
		{Kind: KindAPIKey, Re: reNewRelicKey, Keyword: "NRAK-", MinEntropy: 3.0},
		{Kind: KindAPIKey, Re: rePerplexityKey, Keyword: "pplx-", MinEntropy: 3.0},
		{Kind: KindAPIKey, Re: reFlyIOToken, Keyword: "fm2_", MinEntropy: 3.0},
		{Kind: KindAPIKey, Re: reShopifyToken, Keyword: "shp", MinEntropy: 3.0},
		{Kind: KindAPIKey, Re: reSquareToken, Keyword: "EAAA", MinEntropy: 3.0},
		{Kind: KindAPIKey, Re: reTelegramBot, MinEntropy: 3.0},
		{Kind: KindAPIKey, Re: reDiscordBot, MinEntropy: 3.0},
		{Kind: KindAPIKey, Re: reGroqKey, Keyword: "gsk_", MinEntropy: 3.0},
		{Kind: KindAPIKey, Re: reXAIKey, Keyword: "xai-", MinEntropy: 3.0},
		{Kind: KindAPIKey, Re: reNVNGCKey, Keyword: "nvapi-", MinEntropy: 3.0},
		{Kind: KindAPIKey, Re: rePlanetScaleKey, Keyword: "pscale_", MinEntropy: 3.0},
		{Kind: KindAPIKey, Re: reSupabaseKey, Keyword: "sbp_", MinEntropy: 3.0},
		{Kind: KindAPIKey, Re: reBuildkiteKey, Keyword: "bkua_", MinEntropy: 3.0},
		{Kind: KindAPIKey, Re: reGrafanaCloudKey, Keyword: "glc_", MinEntropy: 3.0},
		{Kind: KindAPIKey, Re: reHoneycombKey, Keyword: "hcaik_", MinEntropy: 3.0},
		{Kind: KindAPIKey, Re: rePyPIToken, Keyword: "pypi-", MinEntropy: 3.0},
		{Kind: KindAPIKey, Re: reResendKey, Keyword: "re_", MinEntropy: 3.0},
		{Kind: KindAPIKey, Re: reJFrogKey, Keyword: "AKCp", MinEntropy: 3.0},
		{Kind: KindAPIKey, Re: reSonarToken, Keyword: "sq", MinEntropy: 3.0},
		{Kind: KindAPIKey, Re: reNuGetKey, Keyword: "oy2", MinEntropy: 3.0},
		{Kind: KindAPIKey, Re: reLaunchDarklyKey, MinEntropy: 3.0},
		{Kind: KindAPIKey, Re: reBackblazeB2Key, Keyword: "K00", MinEntropy: 3.0},
		{Kind: KindAPIKey, Re: reHubSpotPAT, Keyword: "pat-", MinEntropy: 3.0},
		{Kind: KindAPIKey, Re: reOpenRouterKey, Keyword: "sk-or-v1-", MinEntropy: 3.0},
		{Kind: KindAPIKey, Re: reXataKey, Keyword: "xau_", MinEntropy: 3.0},
		{Kind: KindAPIKey, Re: reStytchSecret, Keyword: "secret-", MinEntropy: 3.0},
		{Kind: KindAPIKey, Re: reLangSmithToken, Keyword: "lsv2_", MinEntropy: 3.0},
		{Kind: KindAPIKey, Re: reBrevoKey, Keyword: "xkeysib-", MinEntropy: 3.0},
		{Kind: KindAPIKey, Re: reTerraformCloudToken, Keyword: ".atlasv1.", MinEntropy: 3.0},
		{Kind: KindAPIKey, Re: rePostmanKey, Keyword: "PMAK-", MinEntropy: 3.0},
		{Kind: KindAPIKey, Re: reSourcegraphToken, Keyword: "sgp_", MinEntropy: 3.0},
		{Kind: KindAPIKey, Re: reAirtablePAT, MinEntropy: 3.0},
		{Kind: KindAPIKey, Re: reGCPPrivateKeyId, CaptureGroup: 1, Keyword: "private_key_id", MinEntropy: 3.0},
		{Kind: KindAPIKey, Re: reAWSSessionCred, CaptureGroup: 1, MinEntropy: 3.0},
		{Kind: KindAPIKey, Re: reStripeKey},
		{Kind: KindAPIKey, Re: reBearerToken, CaptureGroup: 1, MinEntropy: 3.0},
		{Kind: KindAPIKey, Re: reBasicAuth, CaptureGroup: 1, MinEntropy: 3.0},
		{Kind: KindAPIKey, Re: reK8sSecretValue, CaptureGroup: 1, MinEntropy: 4.0},
		{Kind: KindAPIKey, Re: reB64EnvVar, CaptureGroup: 1, MinEntropy: 4.0},
		{Kind: KindAPIKey, Re: reAPIKeyAssign, CaptureGroup: 1, MinEntropy: 3.0},
		{Kind: KindAPIKey, Re: reSecretAssign, CaptureGroup: 1, MinEntropy: 3.0},
		{Kind: KindUser, Re: reMySQLUserAt, CaptureGroup: 1, Validate: validUser, Keyword: "'@'"},
		{Kind: KindUUID, Re: reUUID},
		{Kind: KindCard, Re: reCreditCard, Validate: validCard},
		{Kind: KindPhone, Re: rePhoneE164, Validate: validPhone},
		{Kind: KindPhone, Re: rePhoneContext, CaptureGroup: 1, Validate: validPhone},
		{Kind: KindEmail, Re: reEmail, Validate: validEmail},
		{Kind: KindAddr, Re: reAddr, ExtraFn: addrExtra, Validate: validAddr},
		{Kind: KindMAC, Re: reMAC},
		{Kind: KindIP, Re: reIP, Validate: validIPv4},
		{Kind: KindIP6, Re: reIP6, CaptureGroup: 1, Validate: validIPv6},
	}
}

// tailRules builds the HOST/FQDN/USER/PATH/PORT/B64 tail with mode-specific
// extras. Each flag enables one of the wider-capture variants:
//   - host:    catches bare single-label hostnames anchored on "host=" / "node=".
//   - user:    catches "as alice" / "for alice" outside the strict user= form.
//   - path:    catches any 2+ segment absolute path, not just /var,/etc,/home.
//   - port:    catches bare ":NNNN" port numbers.
//   - b64:     decode-verify on long base64 spans (slowest, most FP-prone).
func tailRules(host, user, path, port, b64 bool) []Rule {
	r := []Rule{
		// HOST before FQDN so .local/.internal names get the "host" treatment
		// instead of being relabelled as a generic FQDN.
		{Kind: KindHost, Re: reHostSyslog, CaptureGroup: 1, Validate: validSyslogHost},
		{Kind: KindHost, Re: reHostConservative},
	}
	if host {
		r = append(r, Rule{Kind: KindHost, Re: reHostAggressive, CaptureGroup: 1})
	}
	r = append(r,
		Rule{Kind: KindFQDN, Re: reFQDN, Validate: validFQDN},
		Rule{Kind: KindUser, Re: reUserConservative, CaptureGroup: 1, Validate: validUser},
		Rule{Kind: KindUser, Re: reUserSSHD, CaptureGroup: 1, Validate: validUser},
		Rule{Kind: KindUser, Re: reUserHTTPD, CaptureGroup: 1, Validate: validUser, BlockCaptureOnly: true},
	)
	if user {
		r = append(r, Rule{Kind: KindUser, Re: reUserAggressive, CaptureGroup: 1, Validate: validUser})
	}
	r = append(r, Rule{Kind: KindPath, Re: rePathConservative, CaptureGroup: 1})
	if path {
		r = append(r, Rule{Kind: KindPath, Re: rePathAggressive, CaptureGroup: 1})
	}
	if port {
		r = append(r, Rule{Kind: KindPort, Re: rePort, CaptureGroup: 1})
	}
	if b64 {
		// Generic base64 decode-verify runs last so it only inspects spans
		// not already claimed by higher-precision rules. Emits a Match only
		// if the decoded text contains a credential-class kind — keeps S3
		// ETags, pod UIDs, SHA hashes unmasked.
		r = append(r, Rule{Kind: KindAPIKey, Re: reGenericB64, MinEntropy: 4.5, DecodeBase64: true})
	}
	return r
}

// DefaultRules is the conservative ruleset — strict context required for
// USER / HOST / PATH, no PORT or generic base64 detection.
func DefaultRules() []Rule {
	return append(coreRules(), tailRules(false, false, false, false, false)...)
}

// BalancedRules adds wider USER ("as alice"), PATH (any abs path) and PORT
// (":5432") capture without enabling the noisier HOST single-label rule
// or the generic-B64 decode-verify pass.
func BalancedRules() []Rule {
	return append(coreRules(), tailRules(false, true, true, true, false)...)
}

// AggressiveRules enables every wider-capture variant — single-label
// HOST, "as alice" USER, any-abs-path PATH, bare PORT, and the
// generic-B64 decode-verify pass.
func AggressiveRules() []Rule {
	return append(coreRules(), tailRules(true, true, true, true, true)...)
}
