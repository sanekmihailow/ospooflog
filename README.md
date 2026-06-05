# ospooflog

**O**bfuscate & **S**poof log — a CLI tool for reversible log obfuscation.
Replace sensitive values with plausible fakes before sending logs to an AI,
then map the AI's response back to the real values.

```
[raw log] → obfuscate → [safe log for AI] → AI → [AI response] → restore → [real instructions]
```

The session file (`-s session.json`) is the contract between the two
directions: `obfuscate` writes to it, `restore` reads from it.

## Why "replace, not tokenize"

A token like `DSN_001` strips all context — the AI gives you back useless
"check your DSN_001". A plausible-looking fake like
`postgres://user1:strong_password@localhost:5432/mydb1` gives the AI enough
shape to produce real SQL, real syntax, real steps. The token still exists
internally as the stable mapping key but never leaves the tool.

## Install

### Prebuilt binaries

Download from the [releases page](https://github.com/sanekmihailow/ospooflog/releases).
Each release ships statically-linked binaries for Linux / macOS / Windows
(amd64 and arm64) plus a `SHA256SUMS` file. Drop the binary into your
`$PATH` and run.

```sh
# example for Linux amd64
curl -L -o ospooflog https://github.com/sanekmihailow/ospooflog/releases/latest/download/ospooflog-linux-amd64
chmod +x ospooflog && sudo mv ospooflog /usr/local/bin/
```

### From source

Requires Go 1.21+. Install Go from <https://go.dev/dl/> or via a package
manager (see per-platform notes below).

### Linux / macOS

```sh
make build
# or directly:
go build -ldflags="-s -w" -o bin/ospooflog ./cmd/ospooflog
```

On macOS Go is available through Homebrew (`brew install go`) or MacPorts.
The Makefile detects a project-local Go install in `./.go/go/bin/go` and
falls back to the system `go`, so no PATH tweaks are needed.

### Windows

The `Makefile` targets POSIX shells; build directly with `go build`
under PowerShell or `cmd`:

```powershell
go build -ldflags="-s -w" -o bin\ospooflog.exe .\cmd\ospooflog
```

Go itself is available via Scoop (`scoop install go`), Chocolatey
(`choco install golang`), or the official MSI installer.

### Cross-compilation

Go builds release binaries for any target from a single host. Useful for
producing artifacts to attach to a GitHub release:

```sh
GOOS=linux   GOARCH=amd64 go build -ldflags="-s -w" -o ospooflog-linux-amd64    ./cmd/ospooflog
GOOS=darwin  GOARCH=arm64 go build -ldflags="-s -w" -o ospooflog-darwin-arm64   ./cmd/ospooflog
GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o ospooflog-windows-amd64.exe ./cmd/ospooflog
```

The binary is statically linked and has no runtime dependencies — drop
it into the target machine and run.

## Usage

### Obfuscate a log file

```sh
cat error.log | ospooflog -s session.json obfuscate > safe.txt
# or
ospooflog -s session.json -i error.log -o safe.txt obfuscate
```

### Restore an AI response

```sh
cat ai_answer.txt | ospooflog -s session.json restore > real_instructions.txt
```

### Inspect the current mapping

```sh
ospooflog -s session.json show
# TOKEN     KIND   ORIGIN              REPLACE
# HOST_001  HOST   db-prod.internal    myhost1.local
# IP_001    IP     10.23.41.5          192.168.0.1
# USER_001  USER   alice               user1
```

## Detected entity types

| Kind     | Example origin                                          | Example replace                                |
|----------|---------------------------------------------------------|------------------------------------------------|
| DSN      | `postgres://alice:pwd@db:5432/appdb`                    | `postgres://user1:strong_password@localhost:5432/mydb1` |
| ARN      | `arn:aws:s3:::secrets/key`                              | `arn:aws:s3::000000000000:fake-resource/n1` (service/region preserved) |
| APIKEY   | [list providers](#covered-providers%3A)                 | `FAKE_API_KEY_001`                             |
| TOKEN    | `eyJhbGciOiJIUzI1NiJ9.eyJzdWIi…` (JWT)                  | fake JWT-shaped string                         |
| PWD      | `password=hunter2`, `IDENTIFIED BY 'secret'`            | `FAKE_PASSWORD_001`                            |
| PUBKEY   | `ssh-rsa AAAAB3NzaC1…`                                  | `ssh-rsa AAAAFAKEPUBKEY0001`                   |
| PRIVKEY  | `-----BEGIN OPENSSH PRIVATE KEY-----…`                  | shape-preserving fake PEM block                |
| FP       | `SHA256:gIIV9aBJ…`, `MD5:aa:bb:…`, OCI `sha256:abc…`    | `SHA256:000…001`                               |
| CARD     | `4111-1111-1111-1111` (Luhn-validated)                  | `4000-0000-0000-0010` (Luhn-valid Visa test)   |
| PHONE    | `+14155552671`, `phone: 415-555-2671`                   | `+15555550001` (NANP fictional range)          |
| UUID     | `550e8400-e29b-41d4-a716-446655440000`                  | `00000000-0000-0000-0000-000000000001`         |
| SID      | `S-1-5-21-3623811015-3361044348-30300820-1013`          | `S-1-5-21-0-0-0-1` (well-known SIDs like `S-1-5-18` kept) |
| EMAIL    | `alice@corp.com`                                        | `user1@example.com`                            |
| ADDR     | `10.23.41.5:5432`                                       | `192.168.0.1:5432` (port preserved)            |
| IP       | `10.23.41.5` (private), `203.0.113.5` (public)          | `192.168.0.1` / `77.0.0.1` (public → 77.0.0.0/8; well-known resolvers like `8.8.8.8` and k8s default service IPs like `10.96.0.1` / `10.43.0.1` kept) |
| IP6      | `fe80::1` (link-local/ULA), `2a00:1450::1` (global)     | `fd00::1` / `2001:db8::1` (global → RFC 3849 doc prefix; well-known resolvers like `2001:4860:4860::8888` kept) |
| MAC      | `aa:bb:cc:dd:ee:ff`                                     | `02:00:00:00:00:01` (locally-administered)     |
| HOST     | `db-prod.internal` (corporate)                          | `myhost1.local`; cloud-provider internal DNS (`*.ec2.internal`, `*.compute.internal`, `*.c.<project>.internal`, `*.ru-central1.internal`, `google.internal`) is kept |
| FQDN     | `api.example.com`, `host.xn--p1ai`                      | `service1.example.com` (full IANA TLD set; cloud service domains like `s3.amazonaws.com`, `storage.googleapis.com`, `*.blob.core.windows.net` kept) |
| USER     | `user=alice`, `Failed publickey for alice`              | `user1` (only the value swaps)                 |
| PATH     | `/var/lib/postgresql/data`, `/sbin/auditctl`            | `/var/lib/myapp1/data`                         |
| PORT     | `:5432` (only with `--aggressive`)                      | `:8080`                                        |


### Covered providers:

- AWS `AKIA…` / `AWS_SECRET_ACCESS_KEY=…` / `AWS_SESSION_TOKEN=…`,
- Airtable `pat<id>.<secret>`,
- Anthropic `sk-ant-…`,
- Atlassian `ATATT3…`,
- Backblaze B2 `K00…`,
- Brevo `xkeysib-…`,
- Buildkite `bkua_…`,
- Datadog `DD-API-KEY:…`,
- Discord bot,
- Docker Hub `dckr_pat_…`,
- Figma `figd_…`,
- Fly.io `fm2_…`,
- GCP service-account `"private_key_id":…` / `"client_id":…` (21-digit) / `project_id` (JSON, env, `--project` flag),
- GitHub `ghp_…` / `github_pat_…`,
- GitLab `glpat-…` / `glrt-…` / `gldt-…` / `glsoat-…` / `glptt-…` / `glagent-…` / `glfeed-…` / `glimt-…` / `glcbt-…`,
- Google `AIza…` / OAuth `ya29.…`,
- Grafana Cloud `glc_…`,
- Groq `gsk_…`,
- Honeycomb `hcaik_…`,
- HubSpot `pat-<region>-<uuid>`,
- JFrog `AKCp…`,
- LangSmith `lsv2_(pt\|sk)_…`,
- LaunchDarkly `(sdk\|mob\|api)-<uuid>`,
- Linear `lin_api_…`,
- Mailgun `key-…`,
- NVIDIA NGC `nvapi-…`,
- New Relic `NRAK-…`,
- Notion `ntn_…`,
- NuGet `oy2…`,
- Okta `SSWS …`,
- OpenAI `sk-…T3BlbkFJ…`,
- OpenRouter `sk-or-v1-…`,
- Perplexity `pplx-…`,
- PlanetScale `pscale_…`,
- PostHog `phx_…`,
- Postman `PMAK-…`,
- PyPI `pypi-…`,
- Replicate `r8_…`,
- Resend `re_…`,
- SendGrid `SG.…`,
- Sentry `sntrys_…`,
- Shopify `shp(at\|ss\|ca)_…`,
- Slack `xox[abprs]-…`,
- SonarQube `sq(p\|a\|u)_…`,
- Sourcegraph `sgp_…`,
- Square `EAAA…`,
- Stripe `sk_live_…` / `whsec_…`,
- Stytch `secret-(test\|live)-…`,
- Supabase `sbp_…`,
- Tailscale `tskey-…`,
- Telegram bot,
- Terraform Cloud `…atlasv1…`,
- Twilio `SK…`,
- Vault `hvs.…`,
- Xata `xau_…`,
- `Bearer X`,
- `access_token=…`
- `api_key=…`,
- `secret=…`,
- xAI `xai-…`,


## Flags

```
  -i, --input        input file (default: stdin)
  -o, --output       output file (default: stdout)
  -s, --session      session file (required)

  --mode             detection breadth: safe (default) | balanced |
                     aggressive. Higher levels catch more, with higher
                     false-positive risk.
  --aggressive       deprecated — alias for `--mode aggressive`.
  --fast-restore     opt out of the default word-boundary aware restore.
                     Faster, but vulnerable to substring traps where a
                     registered fake is a prefix of an unrelated string
                     in the AI response.
  --strict-restore   deprecated — strict restore is now the default;
                     pass `--fast-restore` to opt out.
  --dry-run          obfuscate: print detected matches without modifying
                     text or persisting the session.
  --overrides path   YAML file with origin → replace pairs that win over the
                     built-in templates; a literal origin matches verbatim,
                     `origin: re:<pattern>` matches a class by Go regexp.
  --json             obfuscate: parse each line as JSON (NDJSON) and
                     obfuscate string leaves while preserving structure.
  --allow-keys csv   --json: skip these JSON keys (e.g. level,timestamp,msg).
  --dbg              debug logging on stderr.
```

## Examples

### Detection modes

`safe` (default) requires explicit context for USER / HOST / PATH —
`user=alice` matches, bare `alice` in prose does not. `balanced` adds
`as alice` / `for alice`, any 2-segment absolute path, and bare
`:PORT` numbers. `aggressive` further adds single-label hostnames
(`host=db-prod`) and a generic base64-decode-verify pass.

```sh
echo "user=alice handled by alice's team" | ospooflog -s s.json obfuscate
# user=user1 handled by alice's team

echo "user=alice handled by alice's team" | ospooflog -s s.json --mode balanced obfuscate
# user=user1 handled by user1's team    # "for/as <name>" patterns now match
```

### Substring trap (strict restore is on by default)

```sh
# session has 192.168.0.1 ↔ 10.1.2.3
echo "also try 192.168.0.10 instead" | ospooflog -s s.json restore
# also try 192.168.0.10 instead         # word-boundary check protects the AI's invented IP

echo "also try 192.168.0.10 instead" | ospooflog -s s.json --fast-restore restore
# also try 10.1.2.30 instead            # opt-in to fast restore — substring collision returns
```

### Custom replacements with `--overrides`

```yaml
# overrides.yaml
overrides:
  - origin: alice            # literal — matches verbatim (one-to-one)
    replace: bob
  - origin: 10.1.2.3
    replace: 172.16.0.5
  - origin: "re:user[0-9]+"  # re: prefix — Go regexp masking a whole class
    replace: MASKED_USER
```

```sh
ospooflog -s s.json --overrides overrides.yaml -i error.log obfuscate
```

A literal `origin` is replaced one-to-one. An `origin: re:<pattern>` masks every
value matching the regexp to the same `replace` (so `user1`, `user42`, `user99`
all become `MASKED_USER`); each distinct value is still recorded as its own
session entry, so `restore` maps the shared fake back to a real value. Regex
overrides are plain-text only — they're skipped under `--json`.

### Structured (NDJSON) logs

```sh
cat k8s.log | ospooflog -s s.json --json --allow-keys level,time,msg obfuscate
```

For lines with a CRI prefix (`2026-... stdout F {...}`), the line falls
back to plain-text obfuscation. Pure JSON lines have their string leaves
swapped while keys, numbers and the JSON shape are preserved.

## Session file

```json
{
  "version": 2,
  "created": "...",
  "updated": "...",
  "mapping": {
    "USER_001": {
      "kind": "USER",
      "origin": "alice",
      "replace": "user1"
    },
    "ADDR_001": {
      "kind": "ADDR",
      "origin": "10.23.41.5:5432",
      "replace": "192.168.0.1:5432",
      "extra": {"ip": "10.23.41.5", "port": "5432", "scope": "private"}
    }
  }
}
```

Re-running `obfuscate` against the same session is append-only:
already-known origins reuse their existing fake, new origins get fresh
ones. The user owns the file — delete it when you want a fresh start.

## Round-trip guarantee

`restore(obfuscate(x))` returns the original `x` for every value the tool
mapped. The integration test in `cmd/ospooflog/main_test.go` exercises
this end-to-end through the CLI entry point.

## License

MIT — see [LICENSE](./LICENSE).
