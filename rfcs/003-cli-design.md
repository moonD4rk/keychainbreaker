# RFC 003: CLI Tool Design

Status: Draft
Author: @moonD4rk
Date: 2026-03-30

## Summary

A standalone CLI tool under `cmd/keychainbreaker/` that exports all keychain
data to a single JSON file. The CLI has its own Go module so that its
dependencies (Cobra, x/term) never leak into the zero-dependency library.

Architecture follows the same pattern as `github.com/moond4rk/things3/cmd/things3`:
separate module, `go.work` for local dev, two-stage release via GoReleaser.

## 1. Module Layout

```
keychainbreaker/
  go.mod                        # library (zero dependencies)
  go.work                       # local dev only
  cmd/keychainbreaker/
    go.mod                      # CLI module (cobra, x/term, library)
    main.go
    cmd/
      root.go                   # global flags
      dump.go                   # export all data -> JSON file
      hash.go                   # export hash -> stdout
      version.go                # build info
      output.go                 # JSON types and file writing
```

CLI dependencies: `spf13/cobra`, `golang.org/x/term`, library itself.

## 2. Commands and Flags

```
keychainbreaker [global flags] <command>

Commands:
  dump       Export all keychain data to a JSON file
  hash       Print password hash to stdout (no unlock needed)
  version    Print version info

Global Flags:
  -f, --file <path>        Keychain file (default: ~/Library/Keychains/login.keychain-db)
  -p, --password <pwd>     Keychain password (omit to prompt interactively)
  -k, --key <hex>          Raw hex-encoded 24-byte master key
  -o, --output <path>      Output file path (default: ./keychain_dump.json)

Dump Flags:
  --encoding <type>        Password encoding: plaintext (default), hex, base64
```

### Unlock Flow

The `dump` command uses `TryUnlock` so that metadata is always exported,
even when the password is wrong or unavailable:

1. If `--key` is set, `TryUnlock(WithKey(...))`
2. If `--password` is set, `TryUnlock(WithPassword(...))`
3. Otherwise, prompt via `golang.org/x/term.ReadPassword()`, then `TryUnlock(WithPassword(...))`
4. On wrong password, `TryUnlock` returns `ErrWrongKey` — CLI prints a
   warning to stderr and continues with metadata-only export
5. Check `kc.Unlocked()` to report whether data is fully decrypted

The `hash` command skips unlock entirely.

## 3. JSON Output

Single file, all keys use **snake_case**. Empty fields omitted (`omitempty`).

```json
{
  "generic_passwords": [
    {
      "service": "moond4rk.com",
      "account": "admin",
      "password": "password#123",
      "description": "test password",
      "print_name": "moond4rk.com",
      "created_at": "2024-01-15T10:30:00Z",
      "modified_at": "2024-01-15T10:30:00Z"
    }
  ],
  "internet_passwords": [
    {
      "server": "moond4rk.com",
      "port": 443,
      "protocol": "htps",
      "account": "admin",
      "password": "password#123",
      "security_domain": "example",
      "auth_type": "http",
      "path": "/login"
    }
  ],
  "private_keys": [
    {
      "name": "keychainbreaker-test",
      "key_type": 42,
      "key_size": 2048,
      "data": "MIIEvQIBADA..."
    }
  ],
  "certificates": [
    {
      "print_name": "keychainbreaker-test",
      "subject": "...",
      "issuer": "...",
      "serial": "01",
      "data": "MIIDxTCCAq2..."
    }
  ]
}
```

### Password Encoding

`--encoding` controls how `password` ([]byte) is rendered in JSON.
Binary data fields (private key/cert `data`) always use a safe encoding.

| `--encoding` | password fields | key/cert `data` |
|--------------|----------------|-----------------|
| `plaintext` (default) | UTF-8 string | base64 |
| `hex` | hex | hex |
| `base64` | base64 | base64 |

### hash command

Prints directly to stdout, no JSON wrapping:

```
$ keychainbreaker hash
$keychain$*<salt_hex>*<iv_hex>*<ciphertext_hex>
```

Compatible with hashcat mode 23100 and John the Ripper.

## 4. Stderr Feedback

```
$ keychainbreaker dump
Keychain: ~/Library/Keychains/login.keychain-db
Enter keychain password:
Extracted:
  Generic passwords:  12
  Internet passwords: 8
  Private keys:       2
  Certificates:       3
Output: ./keychain_dump.json
```

When the password is wrong:

```
$ keychainbreaker dump -p "wrong"
Keychain: ~/Library/Keychains/login.keychain-db
Warning: wrong key or password, exporting metadata only
Extracted:
  Generic passwords:  12 (metadata only)
  Internet passwords: 8  (metadata only)
  Private keys:       2  (metadata only)
  Certificates:       3
Output: ./keychain_dump.json
```

Stdout stays clean; all user-facing messages go to stderr.

## 5. Version

Dual-method: ldflags injection for release builds, `debug.ReadBuildInfo()`
fallback for dev builds. Same pattern as things3.

```
$ keychainbreaker version
keychainbreaker 0.1.0
  commit: abc12345
  built:  2026-03-30T12:00:00Z
```

## 6. Release

Two-stage `workflow_dispatch` release, same as things3:

1. Tag library `vX.Y.Z`, push, wait for Go module proxy indexing
2. Update `cmd/keychainbreaker/go.mod` to require new library version
3. Commit, tag `cmd/keychainbreaker/vX.Y.Z`, push
4. GoReleaser builds cross-platform binaries (darwin/linux, amd64/arm64, CGO_ENABLED=0)
5. Publish to GitHub Releases + Homebrew tap

## 7. Checklist

- [ ] `cmd/keychainbreaker/go.mod` (separate module)
- [ ] `go.work` at root
- [ ] Root command with global flags
- [ ] `dump` command with `--encoding`
- [ ] `hash` command (stdout)
- [ ] `version` command
- [ ] Interactive password prompt (`x/term`)
- [ ] JSON output types (snake_case, omitempty)
- [ ] `.goreleaser.yml`
- [ ] `.github/workflows/release.yml`
- [ ] Homebrew tap
