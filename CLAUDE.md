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
cmd/ospooflog/   CLI entry point (flag parsing, command dispatch)
pkg/detector/   regex rules + chain runner, EntityKind enum
pkg/mapper/     thread-safe origin→token→replace registry
pkg/replacer/   per-kind fake-value templates
pkg/obfuscator/ runs detector + mapper over text
pkg/restorer/   reverse pass; fast vs strict word-boundary mode
pkg/session/    JSON load/save for mapper state
pkg/jsonproc/   NDJSON mode (--json)
pkg/audithex/   audit `proctitle=`/`aN=` hex argv decoder, both directions
```

## Adding a new entity kind

Four touch-points, in order:

1. **`pkg/detector/detector.go`** — add `KindFoo EntityKind = "FOO"`.
2. **`pkg/detector/rules.go`** — add the regex (`reFoo = …`) and the
   `Rule{}` entry in both `DefaultRules()` and `AggressiveRules()` if
   applicable. **Order matters** — first rule wins for any overlapping
   byte range. Put a more specific rule before a more general one.
3. **`pkg/replacer/templates.go`** — add a builder. Missing template
   falls back to `FAKE_<KIND>_<N>`.
4. Tests in the relevant package.

## Detector chain rules

- The chain blocks the **whole regex match** (not just the capture
  group) so context prefixes like `user=` aren't picked apart by a
  later rule scanning the value.
- `Rule.Skip = true` marks the range covered without emitting a Match.
  Use it for tokens that look sensitive but must be preserved verbatim
  (e.g. SSH algorithm identifiers `chacha20-poly1305@openssh.com`).
- `Rule.Validate` rejects a regex match that passes the pattern but
  isn't actually the thing it looks like (e.g. `19:00:01` shaped like
  IPv6 but rejected by `net.ParseIP`, English stop-words as USER).
- `Rule.CaptureGroup` picks which submatch becomes the value (0 = whole
  match). Used when the regex needs context to anchor but only part is
  the sensitive span.

## Conventions

- **Comments explain WHY, not WHAT.** Named identifiers cover the WHAT.
  Only write a comment when the reason isn't obvious — hidden
  constraints, why a regex floor is the value it is, a workaround for a
  specific format. Don't reference current tasks or PRs.
- **No backwards-compat shims.** If you change behavior, change it
  cleanly. Don't keep dead fields, removed-code comments, or rename
  unused vars with `_`.
- **Minimal blast radius.** A new entity kind is one rule + one
  template + one Kind constant. Don't add helpers, abstractions, or
  config knobs that aren't immediately used.
- **No half-finished code.** If you can't fully implement a path
  (e.g. JSON-mode for `--overrides` won't work because NUL is illegal
  in JSON), skip that path explicitly with a comment explaining why,
  not a TODO.

## Commit style

Imperative subject, no `feat:`/`fix:` prefix. Body explains the why
and any non-obvious trade-offs.

```
Mask MAC addresses

reMAC matches 6 hex pairs separated by ':' or '-'. Placed before the IP
and IPv6 rules so the MAC kind wins — IPv6 would technically match
too, but validIPv6 rejects it.
```
