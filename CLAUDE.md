# CLAUDE.md

Guidance for AI coding agents working in this repo. README.md is the
user-facing description; this file is what you read before touching code.

## Project

CLI that obfuscates sensitive values in logs into plausible fakes and
restores the originals after an AI roundtrip. Three verbs: `obfuscate`,
`restore`, `show`. Pipeline:

```
detector → mapper → replacer → obfuscator
```

- **detector** finds spans of sensitive text using a priority-ordered
  regex chain.
- **mapper** is the bidirectional registry (origin ↔ token ↔ replace).
  Same origin always returns the same fake.
- **replacer** generates the fake value for a (kind, counter) pair.
- **obfuscator** stitches matches back into text.

`restore` reverses the swap using the mapper loaded from the session file.

## Build & test

The Makefile prefers a project-local Go install if `./.go/go/bin/go`
exists (drop-in Go SDK), otherwise it falls back to `go` on PATH.

```sh
make build      # writes bin/ospooflog
make test       # all package tests
make lint       # golangci-lint if installed, else go vet
```

Run the binary against logs in `log/`. Sessions land in `/tmp/*.json`
during exploration.

## Layout

```
cmd/ospooflog/           CLI entry point (flag parsing, command dispatch)
pkg/detector/            regex rules + chain runner, EntityKind enum,
                         protectedValues / placeholderWords allowlists
pkg/mapper/              thread-safe origin→token→replace registry
pkg/replacer/            per-kind fake-value templates
pkg/obfuscator/          runs detector + mapper over text;
                         pre-registers JWT claim values for cross-text
                         consistency (Match.Extra["claim:<KIND>"])
pkg/restorer/            reverse pass; strict (default) vs fast mode
pkg/session/             JSON load/save for mapper state
pkg/jsonproc/            NDJSON mode (--json)
pkg/audithex/            audit `proctitle=`/`aN=` hex argv decoder
.github/workflows/       ci.yml (test on push/PR) + release.yml
                         (cross-platform binary publish on v* tag)
```

## Three detection modes

Configured via `--mode {safe,balanced,aggressive}`. Implemented as
`DefaultRules() / BalancedRules() / AggressiveRules()` in `rules.go`,
all built on top of `coreRules()` + `tailRules(host, user, path, port, b64)`:

- **safe** (default): explicit context required for USER / HOST / PATH.
  `user=alice` matches; bare `alice` in prose does not.
- **balanced**: adds wider USER (`as alice` / `for alice`), wider PATH
  (any 2+ segment absolute path) and bare PORT capture.
- **aggressive**: further adds single-label HOST (`host=db-prod`) and
  the generic base64 decode-verify pass.

`--aggressive` is kept as a deprecated alias mapping to `--mode aggressive`.

## Adding a new entity kind

Four touch-points, in order:

1. **`pkg/detector/detector.go`** — add `KindFoo EntityKind = "FOO"`.
2. **`pkg/detector/rules.go`** — add the regex (`reFoo = …`) and the
   `Rule{}` entry. For mode-independent rules (most provider tokens,
   etc.) put it in `coreRules()`. For mode-specific behaviour put it in
   `tailRules()` behind one of the boolean flags. **Order matters** —
   first rule wins for any overlapping byte range. Put a more specific
   rule before a more general one.
3. **`pkg/replacer/templates.go`** — add a builder. Missing template
   falls back to `FAKE_<KIND>_<N>`.
4. Tests in the relevant package. The provider-token test pattern
   (`TestAPIKey_NewProviderTokens` in `detector_test.go`) takes a
   `{name, text}` table — add one row per provider variant.

## Detector chain rules

- The chain blocks the **whole regex match** (not just the capture
  group) so context prefixes like `user=` aren't picked apart by a
  later rule scanning the value.
- `Rule.Skip = true` marks the range covered without emitting a Match.
  Use it for tokens that look sensitive but must be preserved verbatim
  (e.g. SSH algorithm identifiers `chacha20-poly1305@openssh.com`,
  the PAM `systemd-user:` service prefix).
- `Rule.Validate` rejects a regex match that passes the pattern but
  isn't actually the thing it looks like (e.g. `19:00:01` shaped like
  IPv6 but rejected by `net.ParseIP`, English stop-words as USER).
- `Rule.CaptureGroup` picks which submatch becomes the value (0 = whole
  match). Used when the regex needs context to anchor but only part is
  the sensitive span.
- `Rule.BlockCaptureOnly = true` narrows the covered-range claim to
  just the captured span. Use when the regex anchor legitimately
  overlaps other entities (e.g. httpd line prefix containing an IP
  that a later rule must still catch).
- `Rule.Keyword` is a literal substring pre-filter — the regex isn't
  evaluated if the keyword isn't in the input. Case-sensitive. Cheap
  speedup for rules with a fixed anchor (`AIza`, `sk-ant-`).
- `Rule.MinEntropy` (Shannon bits/char) drops low-entropy captures —
  filters placeholder values like `xxxxxxx` without a giant allowlist.
- `Rule.ExtraFn` returns a `map[string]string` attached to the Match.
  Two flavours: structured fields for the replacer (DSN scheme/host/
  port for `dsnExtra`), or `"claim:<KIND>"` entries that the
  obfuscator pre-registers in the mapper for cross-text consistency
  (used by `jwtExtra` so an email inside a JWT shares the fake with
  the same email appearing bare elsewhere).
- `Rule.DecodeBase64 = true` turns a rule into a verifier: the
  captured value is base64-decoded and the chain is re-run on the
  decoded text using an inner chain (DecodeBase64 rules stripped, no
  recursion). The outer Match is emitted only if the decoded text
  contains a credential-class kind.

## Value-level allowlists (post-validate filters)

Applied in `detector.Find` after `Validate` / `MinEntropy` but before
emitting a Match. Both drop the Match without claiming any byte range,
so neighbouring rules whose match span overlaps the value are unaffected.

- **`placeholderWords` + `placeholderPatterns`** (`detector.go`) —
  stand-in tokens that aren't real (`changeme`, `placeholder`, `null`,
  `NOT_LOGGING_PARAMETER`, `${VAR}`, `<your-token>`, our own
  `FAKE_<KIND>_<N>` output).
- **`protectedValues`** (`rules.go`) — real common identifiers that
  shouldn't be masked: system identifiers (`localhost`, `mysql`,
  `root`, `system`) and public domains (`docker.io`, `kubernetes.io`,
  `kernel.org`, `github.com`, …). `isProtectedValue` also matches
  `*.<protected>` subdomains, `<slug>-<protected>` k8s-style suffixes,
  and the email-domain half (`dm-devel@redhat.com` preserved because
  `redhat.com` is on the list).
- **`validTLDs` blacklist** — TLDs that exist in IANA but are noisy
  in logs (`.so`, `.zip`, `.py`, `.arpa`, all systemd unit suffixes).

## Conventions

- **Comments explain WHY, not WHAT.** Named identifiers cover the WHAT.
  Only write a comment when the reason isn't obvious — hidden
  constraints, why a regex floor is the value it is, a workaround for a
  specific format. Don't reference current tasks or PRs.
- **No backwards-compat shims.** If you change behavior, change it
  cleanly. Don't keep dead fields, removed-code comments, or rename
  unused vars with `_`. Deprecated CLI flags (`--aggressive`,
  `--strict-restore`) stay only because they're documented promises to
  end users; new internal additions don't get this treatment.
- **Minimal blast radius.** A new entity kind is one rule + one
  template + one Kind constant. Don't add helpers, abstractions, or
  config knobs that aren't immediately used.
- **No half-finished code.** If you can't fully implement a path
  (e.g. JSON-mode for `--overrides` won't work because NUL is illegal
  in JSON), skip that path explicitly with a comment explaining why,
  not a TODO.

## Release flow

- Feature branches → PR into `dev`. Rebase-and-merge.
- Release time: PR `dev` → `main`, Squash-and-merge, tag `vX.Y.Z` from
  `main`. The tag push triggers `.github/workflows/release.yml` which
  refuses to build if the tag commit isn't reachable from `main`.
- Tag protection ruleset restricts `v*` tag creation/update/deletion to
  repo admins. Bypass = admin only.
- `dev` is permanent — never delete.

## Commit style

Imperative subject, no `feat:`/`fix:` prefix. Body explains the why
and any non-obvious trade-offs.

```
Mask MAC addresses

reMAC matches 6 hex pairs separated by ':' or '-'. Placed before the IP
and IPv6 rules so the MAC kind wins — IPv6 would technically match
too, but validIPv6 rejects it.
```
