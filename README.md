# keychainbreaker

[![Go CI](https://github.com/moonD4rk/keychainbreaker/actions/workflows/ci.yml/badge.svg)](https://github.com/moonD4rk/keychainbreaker/actions/workflows/ci.yml) [![codecov](https://codecov.io/gh/moonD4rk/keychainbreaker/branch/main/graph/badge.svg)](https://codecov.io/gh/moonD4rk/keychainbreaker) [![Go Reference](https://pkg.go.dev/badge/github.com/moond4rk/keychainbreaker.svg)](https://pkg.go.dev/github.com/moond4rk/keychainbreaker) [![License](https://img.shields.io/github/license/moonD4rk/keychainbreaker)](https://github.com/moonD4rk/keychainbreaker/blob/main/LICENSE)

Go library for reading and decrypting macOS Keychain files (`login.keychain-db`). Supports OS X 10.6 (Snow Leopard) through macOS 26 (Tahoe).

## What It Does

Open a macOS Keychain file, unlock it with the user's password, and extract:

- **Generic passwords** -- app-stored credentials (Chrome Safe Storage, Wi-Fi, etc.)
- **Internet passwords** -- web and network credentials (GitHub tokens, Docker registry, SMB shares, etc.)
- **Private keys** -- RSA/EC private keys stored in the keychain
- **X.509 certificates** -- DER-encoded certificates

Works on any OS (Linux, macOS, Windows). No CGO. No macOS APIs. Just reads the binary file.

## CLI Tool

### Install

**Homebrew**

```bash
brew install moond4rk/tap/keychainbreaker
```

**Go install** (requires Go 1.27+)

```bash
go install github.com/moond4rk/keychainbreaker/cmd/keychainbreaker@latest
```

**Binary**

Download from [GitHub Releases](https://github.com/moonD4rk/keychainbreaker/releases).

### Usage

```
$ keychainbreaker -h
Usage:
  keychainbreaker [command]

Available Commands:
  completion  Generate the autocompletion script for the specified shell
  dump        Export all keychain records to JSON
  hash        Print the keychain password hash for offline cracking
  help        Help about any command
  version     Print version information

Flags:
  -h, --help      help for keychainbreaker
  -v, --verbose   print diagnostics to stderr
```

Every command reads `~/Library/Keychains/login.keychain-db` unless `-f/--file` names another keychain. Progress and warnings go to stderr, so stdout carries only the requested data.

### dump

Export generic and internet passwords, private keys and certificates to JSON. Each password appears three ways (`password`, `hex_password`, `base64_password`) because a secret need not be valid text; key and certificate data appear as hex and base64.

```
    --entropy string    entropy file for a macOS 26.4+ login keychain (default: auto from /var/db/SystemKeys)
-f, --file string       keychain file (default ~/Library/Keychains/login.keychain-db)
-k, --key string        hex-encoded 24-byte master key, used instead of the password
-o, --output string     output file, or "-" for stdout (default "keychain_dump.json")
-p, --password string   keychain password; other local users can see it, prefer --password-stdin or the prompt
    --password-stdin    read the keychain password from stdin
```

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

```bash
# Read the password from stdin instead of the prompt
keychainbreaker dump -f /path/to/login.keychain-db --password-stdin < password.txt

# Unlock with a recovered master key and pipe the JSON
keychainbreaker dump --key <48-char-hex> -o - | jq '.generic_passwords[].service'

# Wrong password: still exports metadata (service, account, timestamps, certificates)
keychainbreaker dump -p "wrong"

# macOS 26.4+: read the entropy file automatically (root + SIP off), or supply one from a backup
sudo keychainbreaker dump
keychainbreaker dump --entropy ./SystemKeys/<SALT> --password-stdin < password.txt
```

The output file is created with mode `0600` and replaced in one step, so the secrets are never readable by other users and an interrupted run leaves the previous file intact.

### hash

```bash
# Export the hash for offline cracking (no password needed)
keychainbreaker hash
# $keychain$*<salt_hex>*<iv_hex>*<ciphertext_hex>
```

The format is accepted by hashcat (mode 23100) and John the Ripper. On a macOS 26.4+ login keychain the master key also depends on the per-machine entropy file, so no password recovers this hash; use `--key` or `--entropy` instead.

## Go Library

### Install

```bash
go get github.com/moond4rk/keychainbreaker
```

Requires Go 1.20+. The library depends on nothing outside the standard library.

### Quick Start

```go
path, err := keychainbreaker.DefaultKeychainPath() // ~/Library/Keychains/login.keychain-db
if err != nil {
    return err
}
kc, err := keychainbreaker.Open(path)
if err != nil {
    return err
}
if err := kc.UnlockWithPassword("your-macos-login-password"); err != nil {
    return err
}
passwords, err := kc.GenericPasswords()
if err != nil {
    return err
}
for _, p := range passwords {
    fmt.Printf("%s %s %s\n", p.Service, p.Account, p.Password)
}
```

### Open

```go
kc, err := keychainbreaker.Open("/path/to/login.keychain-db")             // a file
kc, err := keychainbreaker.OpenBytes(buf)                                // a keychain already in memory; buf is copied
kc, err := keychainbreaker.Open(path, keychainbreaker.WithLogger(logger)) // diagnostics, e.g. to a *slog.Logger
```

### Unlock

```go
err := kc.UnlockWithPassword("macos-login-password")   // derives the master key with PBKDF2-HMAC-SHA1
err := kc.UnlockWithEntropy("macos-login-password", e)  // macOS 26.4+: folds in a per-machine entropy file
err := kc.UnlockWithKey(masterKey)                      // the 24-byte master key itself
```

All return `ErrWrongKey` for a wrong credential. A failed attempt leaves the keychain as it was, so another credential can be tried; `kc.Unlocked()` reports whether one succeeded.

> **macOS 26.4+ (login keychain):** since Tahoe 26.4, the login keychain is protected by a per-machine 32-byte entropy file in `/var/db/SystemKeys/` in addition to the password. The master key is derived from `HMAC-SHA256(entropy, password)`, so the password alone no longer unlocks it and `UnlockWithPassword` returns `ErrWrongKey`. The blob version (`0x200`) is unrelated — it means partition support and has since OS X 10.11.4. Apple documents the file in [Technical Note TN3137](https://developer.apple.com/documentation/technotes/tn3137-on-mac-keychains); its name, location and format are explicitly not an API.

### Unlock a macOS 26.4+ login keychain

You need the entropy file. It is 32 random bytes stored in `/var/db/SystemKeys/<SALT>`, named by the keychain's salt. The directory is readable only by root and only while [SIP is disabled](https://developer.apple.com/documentation/security/disabling-and-enabling-system-integrity-protection); Time Machine and Migration Assistant copy it with the keychain.

```go
kc, _ := keychainbreaker.Open(path)
data, err := os.ReadFile(kc.EntropyPath()) // /var/db/SystemKeys/<SALT>; needs root + SIP off
if err != nil {
    return err
}
entropy, err := keychainbreaker.DecodeEntropy(data) // parses the XML plist, returns the 32 bytes
if err != nil {
    return err
}
err = kc.UnlockWithEntropy("macos-login-password", entropy)
```

The CLI does this for you: run `keychainbreaker dump` as root with SIP disabled and it reads the entropy file automatically, or pass `--entropy <file>` to supply one (for example from a backup):

```bash
sudo keychainbreaker dump
```

### Recover the master key by capturing it in securityd

As an alternative to the entropy file, the 24-byte master key can be captured on the **machine that created the keychain** and replayed offline with `UnlockWithKey` / `--key`, which needs no entropy file. `securityd` derives that key through `CSSM_DeriveKey`, so an lldb breakpoint on the running daemon exposes it.

Requirements: macOS 26.4+ on **Apple Silicon**, an admin account, the login password, and [SIP temporarily disabled](https://developer.apple.com/documentation/security/disabling-and-enabling-system-integrity-protection) (re-enable it as soon as you're done).

**1. Lock the keychain** so the next unlock re-derives the key:

```bash
security lock-keychain ~/Library/Keychains/login.keychain-db
```

**2. Attach lldb to `securityd`** and break on the deriver. Attaching to the root-owned daemon needs `sudo`; if `pgrep` returns more than one PID (e.g. with the iOS Simulator installed), pick the one from your login session:

```bash
sudo lldb -p "$(pgrep -x securityd)"
```

```
(lldb) expression -l objective-c -- @import Security
(lldb) breakpoint set -n CSSM_DeriveKey
(lldb) continue
```

**3. Trigger a derive** from another shell (enter your login password when prompted):

```bash
security unlock-keychain ~/Library/Keychains/login.keychain-db
```

**4. Read the master key.** When the breakpoint hits, `$x6` holds the `DerivedKey` output pointer; step out so it gets filled in, then read 24 bytes of its `KeyData`:

```
(lldb) expr void *$derived = (void *)$x6
(lldb) thread step-out
(lldb) p *(CSSM_KEY *)$derived
(lldb) memory read --format x --size 1 --count 24 `((CSSM_KEY *)$derived)->KeyData.Data`
```

The `p` line is a sanity check: expect `HeaderVersion = 2`, `KeyData.Length = 24`, and `BlobType = 0` -- any other `BlobType` means you captured the wrong key. Concatenate the 24 printed bytes into a 48-character hex string.

**5. Replay it offline** (re-enable SIP first):

```bash
keychainbreaker dump --key=<48-char-hex>
```

```go
key, err := hex.DecodeString("<48-char-hex>")
if err != nil {
    return err
}
err = kc.UnlockWithKey(key)
```

The master key is stable per machine + password + keychain, so one capture is reusable. A worked demo with sample output is in [issue #18](https://github.com/moonD4rk/keychainbreaker/issues/18), where this method was contributed by [@gmazzola](https://github.com/gmazzola).

### Read Records

```go
genericPasswords, err := kc.GenericPasswords()   // application passwords
internetPasswords, err := kc.InternetPasswords() // website, server and file share passwords
privateKeys, err := kc.PrivateKeys()             // PKCS#8 private keys
certificates, err := kc.Certificates()           // DER-encoded X.509 certificates
hash, err := kc.PasswordHash()                   // for hashcat and John the Ripper; needs no unlock
```

Records do not wait for an unlock: every record carries its metadata (service, account, timestamps and so on) from the start, and only the secrets, passwords and private key data, stay nil until an unlock succeeds or when a record cannot be decrypted. An empty password is an empty, non-nil slice. Certificates are not encrypted, so they are always complete. A `Keychain` is safe for concurrent use.

#### Record Types

<details>
<summary>GenericPassword</summary>

```go
type GenericPassword struct {
    Service     string
    Account     string
    Password    []byte // nil while locked or when the record cannot be decrypted
    Description string
    Comment     string
    Creator     string // four-character code
    Type        string // four-character code
    PrintName   string
    Alias       string
    Created     time.Time
    Modified    time.Time
}
```

</details>

<details>
<summary>InternetPassword</summary>

```go
type InternetPassword struct {
    Server         string
    Account        string
    Password       []byte // nil while locked or when the record cannot be decrypted
    SecurityDomain string
    Protocol       string // four-character code, such as "htps" or "smb "
    AuthType       string // four-character code, such as "dflt"
    Port           uint32
    Path           string
    Description    string
    Comment        string
    Creator        string
    Type           string
    PrintName      string
    Alias          string
    Created        time.Time
    Modified       time.Time
}
```

</details>

<details>
<summary>PrivateKey</summary>

```go
type PrivateKey struct {
    Data      []byte // PKCS#8; nil while locked or when the record cannot be decrypted
    PrintName string
    Label     []byte // usually the SHA-1 hash of the public key
    KeyClass  uint32
    KeyType   uint32
    KeySize   uint32 // in bits
}
```

</details>

<details>
<summary>Certificate</summary>

```go
type Certificate struct {
    Data      []byte // DER-encoded certificate
    Type      uint32
    Encoding  uint32
    PrintName string
    Subject   []byte // DER-encoded subject name
    Issuer    []byte // DER-encoded issuer name
    Serial    []byte
}
```

</details>

## How It Works

macOS Keychain uses a three-layer encryption scheme:

```
Password --> PBKDF2 --> Master Key --> DB Key --> Per-Record Keys --> Plaintext
```

1. **Master key** derived from password via PBKDF2-HMAC-SHA1 (macOS 26.4+ first folds the password into a per-machine entropy file with `HMAC-SHA256`)
2. **Database key** decrypted from the keychain's metadata blob
3. **Per-record keys** unwrapped using RFC 3217 Triple-DES Key Wrap
4. **Passwords/keys** decrypted using per-record keys with 3DES-CBC

The library dynamically discovers table schemas from the keychain file itself, making it robust across macOS versions (10.6 through 26).

See [RFC 001](rfcs/001-keychain-encryption.md) for the full encryption specification.

## Compatibility

| Supported                             | Not Supported                     |
| ------------------------------------- | --------------------------------- |
| `.keychain` and `.keychain-db` files  | `keychain-2.db` (iCloud Keychain) |
| OS X 10.6 through macOS 26 (Tahoe)    | Secure Enclave protected keys     |
| Linux, macOS, Windows (cross-compile) |                                   |

## License

[Apache-2.0](LICENSE)
