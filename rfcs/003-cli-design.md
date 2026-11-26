# RFC 003: CLI Tool Design

Status: Implemented Author: @moonD4rk Date: 2026-03-30 Updated: 2026-11-26

## Summary

A standalone CLI under `cmd/keychainbreaker/` that exports keychain records to JSON and prints the keychain password hash. It is a Go module of its own, so its dependencies (Cobra, x/term) never reach the zero-dependency library, and so it can use the latest Go while the library stays on Go 1.20.

## 1. Module Layout

```
keychainbreaker/
  go.mod                  # library: go 1.20, no dependencies
  go.work                 # local development only (gitignored)
  cmd/keychainbreaker/
    go.mod                # CLI: latest Go; cobra, x/term, the published library
    main.go               # entry point
    root.go               # root command and --verbose
    keychain.go           # locating, opening and unlocking the keychain
    dump.go               # dump command and the output file
    records.go            # JSON document types
    hash.go               # hash command
    version.go            # version command
```

Everything is in `package main`, which no other module can import.

## 2. Commands and Flags

```
keychainbreaker [-v] <command> [flags]

Commands:
  dump       Export all keychain records to JSON
  hash       Print the keychain password hash for offline cracking
  version    Print version information
```

Each flag belongs to the commands that use it:

| Flag | Commands | Meaning |
| --- | --- | --- |
| `-v, --verbose` | all | Library diagnostics on stderr, through `log/slog` |
| `-f, --file` | dump, hash | Keychain file; default `~/Library/Keychains/login.keychain-db` |
| `-p, --password` | dump | Keychain password; other local users can see it |
| `--password-stdin` | dump | Read the password from stdin |
| `-k, --key` | dump | Hex-encoded 24-byte master key |
| `--entropy` | dump | Entropy file for a macOS 26.4+ login keychain; default auto from `/var/db/SystemKeys` |
| `-o, --output` | dump | Output file, or `-` for stdout; default `keychain_dump.json` |

`--password`, `--password-stdin` and `--key` are mutually exclusive, as are `--key` and `--entropy` (entropy combines with a password, not a key).

### Unlock Flow

`dump` unlocks with the credential it is given:

1. `--key`: hex-decoded (a `0x` prefix is accepted), then `UnlockWithKey`
2. Otherwise a password: `--password` or `--password-stdin` (one trailing line ending is trimmed), else a `golang.org/x/term` prompt, only when stdin is a terminal. Without a terminal the command fails and names `--password-stdin` and `--key`. Ctrl-C at the prompt restores terminal echo before exiting.
3. The password path then handles the macOS 26.4+ entropy file: `--entropy <file>` is used directly via `UnlockWithEntropy`; with no flag the password is tried alone first, and only on `ErrWrongKey` does the CLI read `EntropyPath()` (`/var/db/SystemKeys/<salt>`, root-only and SIP-protected) and retry with entropy. A missing entropy file leaves the original wrong-password error; an unreadable one explains that root and SIP-off, or `--entropy`, are needed.

A wrong key or password (`ErrWrongKey`) prints a warning and continues with a metadata-only export: a locked keychain still returns every record's metadata. Any other error, such as a `--key` that is not 24 bytes of hex or an unreadable `--entropy` file, fails the command. `hash` never unlocks.

## 3. JSON Output

The CLI owns the document: `records.go` maps the library's records into types that exist only for output, so the library's types carry no JSON tags. Keys are snake_case, empty values are omitted (`omitempty`, and `omitzero` for timestamps).

Each password appears three ways (`password`, `hex_password`, `base64_password`) because a secret need not be valid UTF-8; key and certificate data appear as `data_hex` and `data_base64`.

```json
{
  "generic_passwords": [
    {
      "service": "moond4rk.com",
      "account": "admin",
      "password": "password#123",
      "hex_password": "70617373776f726423313233",
      "base64_password": "cGFzc3dvcmQjMTIz",
      "description": "application password",
      "comment": "test generic password",
      "creator": "mD4k",
      "type": "note",
      "print_name": "moond4rk.com",
      "created_at": "2026-03-27T15:36:43Z",
      "modified_at": "2026-03-27T15:36:43Z"
    }
  ],
  "internet_passwords": [
    {
      "server": "moond4rk.com",
      "account": "admin",
      "password": "password#123",
      "hex_password": "70617373776f726423313233",
      "base64_password": "cGFzc3dvcmQjMTIz",
      "security_domain": "moond4rk.com",
      "protocol": "htps",
      "auth_type": "dflt",
      "port": 443,
      "path": "/login",
      "print_name": "moond4rk.com"
    }
  ],
  "private_keys": [
    {
      "data_hex": "308204bd0201...",
      "data_base64": "MIIEvQIBADAN...",
      "print_name": "93B7C5C0",
      "label_hex": "57b87b23be287c9b51cc3f9283a4466dcbe4eb93",
      "key_class": 16,
      "key_type": 42,
      "key_size": 2048
    }
  ],
  "certificates": [
    {
      "data_hex": "308203213082...",
      "data_base64": "MIIDITCCAgmg...",
      "type": 1,
      "encoding": 3,
      "print_name": "keychainbreaker-test",
      "subject_hex": "301f311d301b...",
      "issuer_hex": "301f311d301b...",
      "serial_hex": "51946dcaf718..."
    }
  ]
}
```

### Output File

The JSON goes to a temporary file that is created with mode `0600` next to the target and renamed into place: the secrets are never readable by other users, and a failed run leaves an earlier dump intact. `-o -` writes to stdout instead.

### hash

Prints one line to stdout, with no JSON:

```
$ keychainbreaker hash
$keychain$*<salt_hex>*<iv_hex>*<ciphertext_hex>
```

hashcat (mode 23100) and John the Ripper accept it.

## 4. Stderr Feedback

Stdout carries only the requested data; everything else goes to stderr.

```
$ keychainbreaker dump
Keychain: /Users/user/Library/Keychains/login.keychain-db
Enter keychain password:
Extracted:
  Generic passwords:  42
  Internet passwords: 15
  Private keys:       2
  Certificates:       8
Output: keychain_dump.json
```

With a wrong password:

```
$ keychainbreaker dump -p "wrong"
Keychain: /Users/user/Library/Keychains/login.keychain-db
Warning: keychainbreaker: wrong key or password: ...; exporting metadata only
Extracted:
  Generic passwords:  42 (metadata only)
  Internet passwords: 15 (metadata only)
  Private keys:       2 (metadata only)
  Certificates:       8
Output: keychain_dump.json
```

## 5. Version

Release builds get the version, commit and build date through `-ldflags -X`; other builds fall back to `debug.ReadBuildInfo()`.

```
$ keychainbreaker version
keychainbreaker 0.3.0
  commit: abc12345
  built:  2026-11-26T12:00:00Z
```

## 6. Release

The CLI is released with the library, under the same version, in two steps:

1. Running the Release workflow tests both modules, tags the library `vX.Y.Z` on `main`, waits for proxy.golang.org, points `cmd/keychainbreaker/go.mod` at the published module, builds the CLI against it, and opens `chore(release): vX.Y.Z` with auto-merge.
2. Merging that pull request tags `cmd/keychainbreaker/vX.Y.Z` on the merge commit, so the tag is on `main` and `go install ...@latest` resolves the library version that `go.mod` names. GoReleaser then publishes darwin, linux and windows binaries for amd64 and arm64 (`CGO_ENABLED=0`), the GitHub release and the Homebrew cask.

## 7. Checklist

- [x] Separate module on the latest Go, `go.work` for local development
- [x] Internal command package
- [x] Flags scoped to the commands that use them; mutually exclusive credentials
- [x] `--password-stdin`, and a prompt only on a terminal
- [x] CLI-owned JSON types with three password encodings
- [x] Output file created `0600` and replaced atomically; `-o -` for stdout
- [x] `log/slog` diagnostics behind `--verbose`
- [x] Command tests against the fixture in `testdata/`
- [x] Release workflow that tags the CLI on `main`; GoReleaser and Homebrew cask
