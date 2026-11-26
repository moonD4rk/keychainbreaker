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
```

The output file is created with mode `0600` and replaced in one step, so the secrets are never readable by other users and an interrupted run leaves the previous file intact.

### hash

```bash
# Export the hash for offline cracking (no password needed)
keychainbreaker hash
# $keychain$*<salt_hex>*<iv_hex>*<ciphertext_hex>
```

The format is accepted by hashcat (mode 23100) and John the Ripper.

## Go Library

### Install

```bash
go get github.com/moond4rk/keychainbreaker
```

Requires Go 1.20+.

#### Quick Start

```go
// Open the default macOS login keychain
kc, err := keychainbreaker.Open()

// Unlock with the user's macOS login password
err = kc.Unlock(keychainbreaker.WithPassword("your-macos-login-password"))

// Extract all saved passwords
passwords, err := kc.GenericPasswords()
for _, p := range passwords {
    fmt.Printf("Service: %s, Account: %s, Password: %s\n",
        p.Service, p.Account, p.Password)
}
```

### Usage

#### Open a Keychain

```go
kc, err := keychainbreaker.Open()                                      // default system keychain
kc, err := keychainbreaker.Open(keychainbreaker.WithFile("/path/to"))   // specific file
kc, err := keychainbreaker.Open(keychainbreaker.WithBytes(buf))         // from memory
```

#### Unlock

```go
err = kc.Unlock(keychainbreaker.WithPassword("macos-login-password"))   // with password
err = kc.Unlock(keychainbreaker.WithKey("hex-encoded-24-byte-key"))     // with master key
```

> **macOS 26.4+ (login keychain v2):** freshly re-keyed login keychains report blob version `0x200`. Offline password unlock no longer works for them: `WithPassword` returns `ErrUnsupportedBlobVersion` instead of a misleading "wrong password" error. Recover the 24-byte master key on the originating machine and use `WithKey`. Version 1 (`0x100`) keychains are unaffected.

#### Recover the master key on macOS 26.4+ (v2)

A v2 keychain can't be decrypted offline from the file and password alone, but its 24-byte master key can be captured on the **machine that created it** and then replayed offline with `WithKey` / `--key`. `securityd` still derives that key through `CSSM_DeriveKey`, so an lldb breakpoint on the running daemon exposes it.

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
keychainbreaker dump --key=<48-char-hex>   # or in Go: kc.Unlock(keychainbreaker.WithKey("<hex>"))
```

The master key is stable per machine + password + keychain, so one capture is reusable. A worked demo with sample output is in [issue #18](https://github.com/moonD4rk/keychainbreaker/issues/18), where this method was contributed by [@gmazzola](https://github.com/gmazzola).

#### TryUnlock (partial extraction)

`TryUnlock` attempts to decrypt but does not block extraction on failure. When the password is wrong or unavailable, metadata (service, account, timestamps, etc.) is still returned with encrypted fields set to nil.

```go
// Wrong password: metadata still available, passwords nil
err = kc.TryUnlock(keychainbreaker.WithPassword("maybe-wrong"))
passwords, _ := kc.GenericPasswords()   // passwords[0].Service = "moond4rk.com"
                                        // passwords[0].Password = nil

// No credential: just metadata
kc.TryUnlock()
passwords, _ := kc.GenericPasswords()

// Check if decryption succeeded
if kc.Unlocked() {
    // full data available
}
```

#### Extract Records

```go
genericPasswords, err := kc.GenericPasswords()     // app credentials
internetPasswords, err := kc.InternetPasswords()   // web/network credentials
privateKeys, err := kc.PrivateKeys()               // encrypted private keys
certificates, err := kc.Certificates()             // X.509 certificates
hash, err := kc.PasswordHash()                     // offline cracking hash (no unlock needed)
```

#### Record Types

<details>
<summary>GenericPassword</summary>

```go
type GenericPassword struct {
    Service     string
    Account     string
    Password    []byte    // raw bytes; caller decides encoding
    Description string
    Comment     string
    Creator     string
    Type        string
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
    Password       []byte
    SecurityDomain string
    Protocol       string    // "htps", "smb ", etc.
    AuthType       string
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
    Name      string // first 12 bytes of decrypted data
    Data      []byte // raw key material (PKCS#8)
    PrintName string
    Label     string
    KeyClass  uint32
    KeyType   uint32
    KeySize   uint32
}
```

</details>

<details>
<summary>Certificate</summary>

```go
type Certificate struct {
    Data      []byte // raw DER-encoded certificate
    Type      uint32
    Encoding  uint32
    PrintName string
    Subject   []byte
    Issuer    []byte
    Serial    []byte
}
```

</details>

## How It Works

macOS Keychain uses a three-layer encryption scheme:

```
Password --> PBKDF2 --> Master Key --> DB Key --> Per-Record Keys --> Plaintext
```

1. **Master key** derived from password via PBKDF2-HMAC-SHA1
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
