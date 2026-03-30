# keychainbreaker

[![Go CI](https://github.com/moonD4rk/keychainbreaker/actions/workflows/ci.yml/badge.svg)](https://github.com/moonD4rk/keychainbreaker/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/moonD4rk/keychainbreaker/branch/main/graph/badge.svg)](https://codecov.io/gh/moonD4rk/keychainbreaker)
[![Go Reference](https://pkg.go.dev/badge/github.com/moond4rk/keychainbreaker.svg)](https://pkg.go.dev/github.com/moond4rk/keychainbreaker)
[![Go Report Card](https://goreportcard.com/badge/github.com/moond4rk/keychainbreaker)](https://goreportcard.com/report/github.com/moond4rk/keychainbreaker)
[![License](https://img.shields.io/github/license/moonD4rk/keychainbreaker)](https://github.com/moonD4rk/keychainbreaker/blob/main/LICENSE)

Go library for reading and decrypting macOS Keychain files (`login.keychain-db`).
Supports OS X 10.6 (Snow Leopard) through macOS 26 (Tahoe).

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
brew tap moond4rk/tap
brew install moond4rk/tap/keychainbreaker
```

**Go install** (requires Go 1.26+)

```bash
go install github.com/moond4rk/keychainbreaker/cmd/keychainbreaker@latest
```

**Binary**

Download from [GitHub Releases](https://github.com/moonD4rk/keychainbreaker/releases).

### Usage

```
$ keychainbreaker -h

Commands:
  dump        Export all keychain data to a JSON file
  hash        Print password hash for offline cracking (no unlock needed)
  version     Print version information

Flags:
  -f, --file string       Keychain file path (default: ~/Library/Keychains/login.keychain-db)
  -p, --password string   Keychain password (omit to be prompted)
  -k, --key string        Hex-encoded 24-byte master key
  -o, --output string     Output file path (default: ./keychain_dump.json)
```

### dump

Export all keychain data (passwords, keys, certificates) to a single JSON file.
Passwords are output in three formats: plaintext, hex, and base64.

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
# Specify keychain file and password
keychainbreaker dump -f /path/to/login.keychain-db -p "password"

# Export to a specific file
keychainbreaker dump -o result.json

# Wrong password: still exports metadata (service, account, timestamps, certs)
keychainbreaker dump -p "wrong"
```

### hash

```bash
# Export hash for offline cracking (no password needed)
keychainbreaker hash
# $keychain$*<salt_hex>*<iv_hex>*<ciphertext_hex>
```

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

#### TryUnlock (partial extraction)

`TryUnlock` attempts to decrypt but does not block extraction on failure.
When the password is wrong or unavailable, metadata (service, account,
timestamps, etc.) is still returned with encrypted fields set to nil.

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

The library dynamically discovers table schemas from the keychain file itself,
making it robust across macOS versions (10.6 through 26).

See [RFC 001](rfcs/001-keychain-encryption.md) for the full encryption specification.

## Compatibility

| Supported | Not Supported |
|-----------|---------------|
| `.keychain` and `.keychain-db` files | `keychain-2.db` (iCloud Keychain) |
| OS X 10.6 through macOS 26 (Tahoe) | Secure Enclave protected keys |
| Linux, macOS, Windows (cross-compile) | |

## License

[Apache-2.0](LICENSE)
