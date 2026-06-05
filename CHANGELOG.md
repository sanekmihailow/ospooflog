# Changelog

All notable changes to ospooflog are documented here. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/), but each release entry is a
narrative summary rather than a strict Added/Changed/Fixed split — see the
linked PR for the full commit list.

## [v0.3.5] — 2026-06-05

Diff [v0.3.4...v0.3.5](https://github.com/sanekmihailow/ospooflog/compare/v0.3.4...v0.3.5)

Aggregates several patch PRs merged into `dev`. No new CLI flags. One new
entity kind (`SID`) and a behaviour change for IPv6: global addresses now
render in `2001:db8::/32` instead of collapsing into the private-looking
`fd00::` range — mirrors the IPv4 scope split from v0.3.4. Existing session
files restore unchanged.

- **IPv6 masking by scope** — global-unicast origins map to `2001:db8::/32`
  (RFC 3849 documentation prefix), ULA / link-local (`fe80::/10`) stay in
  `fd00::`. A global address no longer looks internal. Well-known IPv6
  resolvers (Google/Cloudflare/Quad9) are still preserved.
- **Windows SID detection** — `S-1-5-21-…` account identifiers (PII) are
  masked to a zeroed-domain fake (`S-1-5-21-0-0-0-<rid>`); well-known /
  builtin SIDs (`S-1-5-18`, `S-1-5-32-544`) are kept as constants. New
  `SID` entity kind.
- **Windows / connection-string usernames** — `Account Name: <user>`
  (Event Log), `User Id=` / `UserID=` (ADO.NET / JDBC connection strings),
  and MongoDB `as principal <name>` now mask the real account.
- **More provider tokens** — Docker Hub (`dckr_pat_…`), Figma (`figd_…`),
  Google OAuth (`ya29.…`), and a broadened GitLab set (runner, deploy,
  scoped-OAuth, pipeline-trigger, cluster-agent, feed, incoming-mail,
  CI/CD-build prefixes beyond `glpat-`).
- **Cloud service domains / k8s service IPs preserved** — `s3.amazonaws.com`,
  `storage.googleapis.com`, `*.blob.core.windows.net` and the default
  kubeadm/k3s service IPs (`10.96.0.1`, `10.43.0.1`) carry infrastructure
  context, not PII — kept like the existing public-domain allowlist.
- **`--json` username keys** — `remote_user` (nginx/apache) and `principal`
  (mongo/auth) bare usernames now mask in NDJSON mode via key hints.
- **Detector performance** — dropped a redundant second regex pass in
  `Find`; `audit.log` (3.7 MB) obfuscate roughly halves (aggressive
  ~8.0s → ~1.7s).

## [v0.3.4] — 2026-06-04

Diff [v0.3.3...v0.3.4](https://github.com/sanekmihailow/ospooflog/compare/v0.3.3...v0.3.4)

Aggregates several patch PRs merged into `dev`. No new CLI flags. One
visible behaviour change: fake IPs now render in scope-specific ranges
(`192.168.0.x` for private, `77.x` for public) instead of a single
`192.168.1.x` block — existing session files still restore fine, since
restore reads the stored mapping rather than regenerating it.

- **IP masking by public/private scope** — routable origins map to
  `77.0.0.0/8`, RFC1918 / ULA to `192.168.0.0/16`, each spread across
  its free octets so neither overflows. An external attacker IP no
  longer collapses into the same space as an internal host. Well-known
  public resolvers (`8.8.8.8`, `1.1.1.1`, `9.9.9.9`, OpenDNS, AdGuard,
  Yandex, plus the Google/Cloudflare/Quad9 IPv6 forms) are preserved as
  global constants, like the public-domain allowlist.
- **Cloud-provider internal DNS preserved** — `*.ec2.internal`,
  `*.compute.internal` (AWS), `google.internal` (GCP metadata),
  `*.c.<project>.internal` (GCP per-project), `*.ru-central1.internal`
  (Yandex) carry "which cloud" context, not PII. Bare `.internal`
  corporate hosts (`db-prod.internal`) are still masked.
- **postgres / journald keyword usernames** — `for user "bob"`,
  `role "readonly_user"`, `as user deploy` now mask the real account
  name (was leaking) instead of capturing the noun `user`. Does not
  break sshd's `Failed password for user from <ip>`.
- **Card validator brand-length matrix** — 15-digit Luhn-valid IMEIs
  (and other non-Amex 15-digit IDs) no longer masquerade as AmEx
  cards; each length is pinned to its brand's prefix.
- **TLD blacklist** — `.map` (JS/CSS sourcemaps) and `.cab` (Windows
  cabinet) added to the file-extension exclusions.
- **Balanced-mode `process`** — `starting as process <pid>` (mysqld)
  no longer captures `process` as a username.

## [v0.3.3] — 2026-05-29

PR [#20](https://github.com/sanekmihailow/ospooflog/pull/20) · Diff [v0.3.2...v0.3.3](https://github.com/sanekmihailow/ospooflog/compare/v0.3.2...v0.3.3)

Patch release on top of v0.3.2. False-positive cleanup across two sweeps
(safe-mode + balanced-mode) plus two real bugs surfaced by round-trip
integration testing.

- **`protectedValues` extensions** — ~115 software/daemon names that surface
  as USER/HOST captures but aren't PII: web/proxy (`nginx`, `apache`,
  `traefik`), databases (`postgres`, `mariadb`, `redis`, `mongo`,
  `elasticsearch`, `kafka`, `rabbitmq`), system accounts (`nobody`,
  `daemon`, `www-data`, `sshd`, `_apt`), init/services (`systemd`,
  `journald`, `auditd`, `cloud-init`), container/k8s (`containerd`,
  `kubelet`, `etcd`, `flannel`, `calico`), package managers, DNS/LDAP,
  storage, PAM modules, MAC frameworks, mail, time sync, VPN, backup.
- **`validTLDs` blacklist extensions** — `.md`, `.pub`, `.pid`, `.new`,
  `.save`, `.prof`, `.work` (filename extensions that shadow registered
  gTLDs: `README.md`, `id_rsa.pub`, `nginx.pid`, `cpu.prof`).
- **USER-capture cleanup** — drop sudo/audit log field names from
  conservative USER rule (`TTY`, `PWD`, `CMD`, `COMMAND`, `PTS`); ~35 new
  stop-words + all-uppercase 2-5 char acronym filter for balanced-mode
  noise (`DNS`, `DB`, `CPU`, `IRQ`, `GRUB`, `volume`, `processes`,
  `caches`).
- **PATH cleanup** — drop `/proc/`, `/sys/`, `/dev/`, `/run/` from all PATH
  rules (kernel/runtime state, never PII).
- **JWT UPN claim** — Azure AD / Office 365 use `upn` instead of `email`
  for the email-shaped principal; both now route to the same fake.
- **IPv6 short-form fix** — `validIPv6` now rejects `e::`, `ca::`, `1::1`
  (technically valid but in real logs come from `::` as a separator in
  non-IP tokens like `client-ca-bundle::/var/lib/...`). Required ≥4 hex
  digits. Without this, strict-restore couldn't round-trip syslog.

Audit-log `proctitle=` hex round-trip remains lossy by design (NUL→space
substitution in Process has no inverse in Restore, documented in
`pkg/audithex/audithex.go`).

## [v0.3.2] — 2026-05-28

PR [#18](https://github.com/sanekmihailow/ospooflog/pull/18) · Diff [v0.3.1...v0.3.2](https://github.com/sanekmihailow/ospooflog/compare/v0.3.1...v0.3.2)

Three false-positive fixes. No new CLI flags, no breaking changes.

- **Protect system bin dirs and interpreters** — `/bin/sh`, `/bin/bash`,
  `/usr/bin/python3.12` and bare shell names (`bash`, `dash`, `perl`,
  `ruby`, `python`, `node`) drop via new `protectedBinDirs` and
  `protectedInterpreters`. Version-suffix tolerant (`python3.12` →
  `python`).
- **Preserve path structure** — replacer is now origin-aware. Shallow
  paths (≤4 segments) pass through verbatim; deeper paths keep the first
  4 segments and mask only the tail
  (`/var/lib/postgresql/data/14/main` → `/var/lib/postgresql/data/path1`).
  New `reUserHomePath` extracts only the username from `/home/<u>`,
  `/Users/<u>`, `/var/spool/mail/<u>`.
- **Unicode-aware word boundary in strict restore** — `isWordBoundary`
  now decodes neighbour runes via `utf8.DecodeLastRuneInString` /
  `DecodeRuneInString` instead of looking at one byte. Without this,
  `пользовательuser1зашёл` restored as `пользовательbobзашёл` —
  fake-token glued to a cyrillic word was treated as standalone.

## [v0.3.1] — 2026-05-22

PR [#16](https://github.com/sanekmihailow/ospooflog/pull/16) · Diff [v0.3.0...v0.3.1](https://github.com/sanekmihailow/ospooflog/compare/v0.3.0...v0.3.1)

Pure false-positive cleanup and documentation refresh — no new CLI
flags, no breaking changes. Two passes through real syslog/auth/
audit/cloud-init/k8s logs.

- **Public domain allowlist** — `docker.io`, `kubernetes.io`, `k8s.io`,
  `k3s.io`, `redhat.com`, `ubuntu.com`, `kernel.org`, `launchpad.net`,
  `openssh.com`, `libssh.org`, `github.com`, `gitlab.com`, `bitbucket.org`,
  container registries (`gcr.io`, `ghcr.io`, `quay.io`,
  `mcr.microsoft.com`, `public.ecr.aws`), etc. Subdomain matching via
  `*.<protected>` so `api.github.com` and `security.ubuntu.com` come
  along. Slug-style suffix matching catches k8s volume mount paths.
- **System identifiers** — `protectedValues` filter for `localhost`,
  `mysql`, `root`, `system`. Drops the Match post-validate without
  claiming any byte range, so neighbouring matches still fire
  (e.g. `'vtiger_user'@'localhost'` still captures `vtiger_user`).
- **TLD blacklist additions** — `.py`, `.rb`, `.go`, `.sh` (source
  files), `.arpa` (DNS reverse zones), systemd unit suffixes
  (`.service`, `.target`, `.network`, …).
- **Validator tightening** — `validPassword` rejects sudo `PWD=/home/...`
  (working directory, not a password); `validEmail` requires real IANA
  TLD (catches Go module paths like `client-go@v1.33.6-k3s1`);
  `NOT_LOGGING_PARAMETER` added to Ansible placeholder words.
- **Docs refresh** — `CLAUDE.md` updated for `coreRules()` + `tailRules()`
  refactor, three detection modes, new `Rule` fields, value-level
  allowlist mechanism.

## [v0.3.0] — 2026-05-20

PR [#13](https://github.com/sanekmihailow/ospooflog/pull/13) · Diff [v0.2.0...v0.3.0](https://github.com/sanekmihailow/ospooflog/compare/v0.2.0...v0.3.0)

Major content and CLI release. No end-user breaking changes
(`--aggressive` / `--strict-restore` stay as deprecated aliases with
stderr warnings).

- **40 new SaaS/infra provider token rules** — Airtable, Atlassian,
  Backblaze B2, Brevo, Buildkite, Datadog, Discord bot, Fly.io, GitHub
  fine-grained PAT, Perplexity, PlanetScale, PostHog, Postman, PyPI,
  Replicate, Resend, Sentry, Shopify, SonarQube, Sourcegraph, Square,
  Stripe webhook, Stytch, Supabase, Tailscale, Telegram bot, Terraform
  Cloud, Twilio, SendGrid, Vault, xAI, Xata.
- **Base64 detection** — K8s/Helm Secret values, `_B64`/`_BASE64` env
  vars, generic decode-verify pass in aggressive mode.
- **JWT claim extraction** — `email` / `phone_number` /
  `preferred_username` inside JWT payloads pre-registered in the
  mapper so they share fakes with bare occurrences elsewhere.
- **GCP service-account JSON** — `private_key_id`, `project_id` (JSON
  / env / `--project` flag), SA-specific 21-digit `client_id`.
- **AWS session credentials** — `aws_secret_access_key` /
  `aws_session_token` in env-var and PascalCase JSON forms.
- **`--mode {safe,balanced,aggressive}`** replaces boolean
  `--aggressive`. Balanced adds wider USER/PATH/PORT; aggressive adds
  single-label HOST and base64 decode-verify.
- **Strict restore by default** — the substring trap (replacing
  `192.168.1.1` inside `192.168.1.10`) is silent corruption that
  shouldn't be opt-in. `--fast-restore` for the old behaviour.
- **Prebuilt binaries on every release** — `v*` tag pushes trigger a
  5-platform build (linux/macOS/Windows × amd64/arm64) with
  `SHA256SUMS`. Tag protection ruleset + in-workflow main-reachability
  check guarantee releases ship only off main.
- **Internal refactor** — `coreRules()` + `tailRules(host, user, path,
  port, b64)` replaces the previous triplicate per-mode rule lists.
  `Match.Extra["claim:<KIND>"]` convention added for cross-text
  consistency via mapper pre-registration.

## [v0.2.0] — 2026-05-20

PR [#4](https://github.com/sanekmihailow/ospooflog/pull/4) · Diff [v0.1.0...v0.2.0](https://github.com/sanekmihailow/ospooflog/compare/v0.1.0...v0.2.0)

Three layered filters on top of the regex chain, reducing false
positives in real-world logs. No API breakage; new optional fields on
`Rule{}`. Behaviour change: previously-masked placeholder values
(`password=changeme`, `secret=$DB_SECRET`, `Bearer XXXX...`) no longer
get rewritten.

- **Keyword pre-filter** (PR [#1](https://github.com/sanekmihailow/ospooflog/pull/1)) —
  literal-substring check skips the regex entirely when its anchor
  token (`AIza`, `sk-ant-`, `T3BlbkFJ`, …) isn't in the input.
- **Entropy floor** (PR [#2](https://github.com/sanekmihailow/ospooflog/pull/2)) —
  `Rule.MinEntropy` rejects repeating-char and tiny-alphabet captures
  from generic `password=` / `secret=` / `Bearer` rules.
- **Placeholder allowlist** (PR [#3](https://github.com/sanekmihailow/ospooflog/pull/3)) —
  package-level filter for `${VAR}`, `{{var}}`, `<your-token>`,
  `changeme`, our own `FAKE_*` output, and similar stand-ins.

## [v0.1.0] — 2026-05-18

Initial public release. Three-verb CLI (`obfuscate` / `restore` /
`show`) with the `detector → mapper → replacer → obfuscator` pipeline
and a session file that makes the swap bidirectional.

Detection coverage shipped at v0.1.0:

- **Network**: IPv4, IPv6, MAC, ports, host:port pairs, FQDN (validated
  against full IANA TLD list), bare hostnames in syslog headers.
- **Credentials**: API keys (provider-specific patterns), bearer tokens,
  AWS / GitHub / Slack / Anthropic / OpenAI / Google / Stripe / GitLab
  credentials, PEM private keys.
- **Identity**: emails, usernames (sshd login patterns, httpd
  combined-log, `user=` / `USER=` contexts), AWS ARNs, OCI image
  digests.
- **Personal data**: credit-card numbers with Luhn validation, phone
  numbers in E.164 and keyword-anchored shapes.
- **System**: UUIDs, absolute paths (FHS-allowlisted roots), audit
  `proctitle=` / `aN=` hex argv decoder.

Build / packaging:

- Single static Go binary (`bin/ospooflog`).
- README with full entity list and per-platform build notes.
