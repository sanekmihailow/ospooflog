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
# IP_001    IP     10.23.41.5          192.168.1.1
# USER_001  USER   alice               user1
```

## Detected entity types

| Kind     | Example origin                                          | Example replace                                |
|----------|---------------------------------------------------------|------------------------------------------------|
| DSN      | `postgres://alice:pwd@db:5432/appdb`                    | `postgres://user1:strong_password@localhost:5432/mydb1` |
| ARN      | `arn:aws:s3:::secrets/key`                              | `arn:aws:s3::000000000000:fake-resource/n1` (service/region preserved) |
| APIKEY   | AWS `AKIA…`, GitHub `ghp_…`, GitLab `glpat-…`, Slack `xox[abprs]-…`, Anthropic `sk-ant-…`, OpenAI `sk-…T3BlbkFJ…`, Google `AIza…`, Stripe `sk_live_…`, `Bearer X`, `api_key=…`, `secret=…`, `access_token=…` | `FAKE_API_KEY_001` |
| TOKEN    | `eyJhbGciOiJIUzI1NiJ9.eyJzdWIi…` (JWT)                  | fake JWT-shaped string                         |
| PWD      | `password=hunter2`, `IDENTIFIED BY 'secret'`            | `FAKE_PASSWORD_001`                            |
| PUBKEY   | `ssh-rsa AAAAB3NzaC1…`                                  | `ssh-rsa AAAAFAKEPUBKEY0001`                   |
| PRIVKEY  | `-----BEGIN OPENSSH PRIVATE KEY-----…`                  | shape-preserving fake PEM block                |
| FP       | `SHA256:gIIV9aBJ…`, `MD5:aa:bb:…`, OCI `sha256:abc…`    | `SHA256:000…001`                               |
| CARD     | `4111-1111-1111-1111` (Luhn-validated)                  | `4000-0000-0000-0010` (Luhn-valid Visa test)   |
| PHONE    | `+14155552671`, `phone: 415-555-2671`                   | `+15555550001` (NANP fictional range)          |
| UUID     | `550e8400-e29b-41d4-a716-446655440000`                  | `00000000-0000-0000-0000-000000000001`         |
| EMAIL    | `alice@corp.com`                                        | `user1@example.com`                            |
| ADDR     | `10.23.41.5:5432`                                       | `192.168.1.1:5432` (port preserved)            |
| IP       | `10.23.41.5`                                            | `192.168.1.1`                                  |
| IP6      | `fe80::1`                                               | `fd00::1`                                      |
| MAC      | `aa:bb:cc:dd:ee:ff`                                     | `02:00:00:00:00:01` (locally-administered)     |
| HOST     | `db-prod.internal`                                      | `myhost1.local`                                |
| FQDN     | `api.example.com`, `host.xn--p1ai`                      | `service1.example.com` (full IANA TLD set)     |
| USER     | `user=alice`, `Failed publickey for alice`              | `user1` (only the value swaps)                 |
| PATH     | `/var/lib/postgresql/data`, `/sbin/auditctl`            | `/var/lib/myapp1/data`                         |
| PORT     | `:5432` (only with `--aggressive`)                      | `:8080`                                        |

## Flags

```
  -i, --input        input file (default: stdin)
  -o, --output       output file (default: stdout)
  -s, --session      session file (required)

  --aggressive       wider USER/HOST/PATH/PORT detection — more matches,
                     more false positives. Off by default.
  --strict-restore   word-boundary aware restore. Slower, but immune to
                     substring traps where a registered fake is a prefix
                     of an unrelated string in the AI response.
  --dry-run          obfuscate: print detected matches without modifying
                     text or persisting the session.
  --overrides path   YAML file with fixed origin → replace pairs that win
                     over the built-in templates.
  --json             obfuscate: parse each line as JSON (NDJSON) and
                     obfuscate string leaves while preserving structure.
  --allow-keys csv   --json: skip these JSON keys (e.g. level,timestamp,msg).
  --dbg              debug logging on stderr.
```

## Examples

### Conservative vs aggressive

By default USER/HOST/PATH only fire in explicit contexts to keep false
positives low — `user=alice` is captured but bare "alice" sitting in prose
is not.

```sh
echo "user=alice handled by alice's team" | ospooflog -s s.json obfuscate
# user=user1 handled by alice's team

echo "user=alice handled by alice's team" | ospooflog -s s.json --aggressive obfuscate
# user=user1 handled by user1's team    # "for/as <name>" patterns now match
```

### Substring trap and `--strict-restore`

```sh
# session has 192.168.1.1 ↔ 10.1.2.3
echo "also try 192.168.1.10 instead" | ospooflog -s s.json restore
# also try 10.1.2.30 instead              # broken — substring collision

echo "also try 192.168.1.10 instead" | ospooflog -s s.json --strict-restore restore
# also try 192.168.1.10 instead           # left alone — boundary check
```

### Custom replacements with `--overrides`

```yaml
# overrides.yaml
overrides:
  - origin: alice
    replace: bob
  - origin: 10.1.2.3
    replace: 172.16.0.5
```

```sh
ospooflog -s s.json --overrides overrides.yaml -i error.log obfuscate
```

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
      "replace": "192.168.1.1:5432",
      "extra": {"ip": "10.23.41.5", "port": "5432"}
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
