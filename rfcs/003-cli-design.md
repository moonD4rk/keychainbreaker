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
  go.mod                        # library (zero dependencies, Go 1.20)
  go.work                       # local dev only (not committed)
  cmd/keychainbreaker/
    go.mod                      # CLI module (cobra, x/term, library, Go 1.26)
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
```

### Unlock Flow

The `dump` command uses `TryUnlock` so that metadata is always exported,
even when the password is wrong or unavailable:

1. If `--key` is set, `TryUnlock(WithKey(...))`
2. If `--password` is set, `TryUnlock(WithPassword(...))`
3. Otherwise, prompt via `golang.org/x/term.ReadPassword()`, then `TryUnlock(WithPassword(...))`
4. On wrong password, `TryUnlock` returns `ErrWrongKey` -- CLI prints a
   warning to stderr and continues with metadata-only export
5. Check `kc.Unlocked()` to report whether data is fully decrypted

The `hash` command skips unlock entirely.

## 3. JSON Output

Single file, all keys use **snake_case**. Empty fields omitted (`omitempty`).

Passwords are output in three formats simultaneously (plaintext, hex, base64).
Binary data (private key, certificate) is output in two formats (hex, base64).

```json
{
  "generic_passwords": [
    {
      "service": "moond4rk.com",
      "account": "admin",
      "password": "password#123",
      "hex_password": "70617373776f726423313233",
      "base64_password": "cGFzc3dvcmQjMTIz",
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
      "hex_password": "70617373776f726423313233",
      "base64_password": "cGFzc3dvcmQjMTIz"
    }
  ],
  "private_keys": [
    {
      "name": "keychainbreaker-test",
      "key_type": 42,
      "key_size": 2048,
      "data_hex": "3082...",
      "data_base64": "MIIEvQ..."
    }
  ],
  "certificates": [
    {
      "print_name": "keychainbreaker-test",
      "subject": "...",
      "issuer": "...",
      "serial": "01",
      "data_hex": "3082...",
      "data_base64": "MIIDxTCCAq2..."
    }
  ]
}
```

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
Keychain: /Users/user/Library/Keychains/login.keychain-db
Enter keychain password:
Extracted:
  Generic passwords:  42
  Internet passwords: 15
  Private keys:       2
  Certificates:       8
Output: ./keychain_dump.json
```

When the password is wrong:

```
$ keychainbreaker dump -p "wrong"
Keychain: /Users/user/Library/Keychains/login.keychain-db
Warning: wrong key or password, exporting metadata only
Extracted:
  Generic passwords:  42 (metadata only)
  Internet passwords: 15 (metadata only)
  Private keys:       2  (metadata only)
  Certificates:       8
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

Two-stage `workflow_dispatch` release:

1. Tag library `vX.Y.Z`, push, wait for Go module proxy indexing
2. Create branch, update `cmd/keychainbreaker/go.mod`, commit, tag `cmd/keychainbreaker/vX.Y.Z`
3. GoReleaser builds cross-platform binaries (darwin/linux/windows, amd64/arm64, CGO_ENABLED=0)
4. Publish to GitHub Releases + Homebrew tap
5. Auto-create PR to merge go.mod update into main (auto-merge via squash)

The CLI tag points to the commit with the updated go.mod, ensuring
`go install` resolves the correct library version. The go.mod update
is merged into main via PR to respect branch protection rules.

## 7. Checklist

- [x] `cmd/keychainbreaker/go.mod` (separate module, Go 1.26)
- [x] `go.work` at root (not committed)
- [x] Root command with global flags
- [x] `dump` command with triple password encoding
- [x] `hash` command (stdout)
- [x] `version` command
- [x] Interactive password prompt (`x/term`)
- [x] JSON output types (snake_case, omitempty)
- [x] `.goreleaser.yml`
- [x] `.github/workflows/release.yml`
- [x] Homebrew tap
