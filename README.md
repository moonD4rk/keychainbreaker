# keychainbreaker

[![Go CI](https://github.com/moonD4rk/keychainbreaker/actions/workflows/ci.yml/badge.svg)](https://github.com/moonD4rk/keychainbreaker/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/moonD4rk/keychainbreaker/branch/main/graph/badge.svg)](https://codecov.io/gh/moonD4rk/keychainbreaker)
[![Go Reference](https://pkg.go.dev/badge/github.com/moond4rk/keychainbreaker.svg)](https://pkg.go.dev/github.com/moond4rk/keychainbreaker)
[![Go Report Card](https://goreportcard.com/badge/github.com/moond4rk/keychainbreaker)](https://goreportcard.com/report/github.com/moond4rk/keychainbreaker)
[![License](https://img.shields.io/github/license/moonD4rk/keychainbreaker)](https://github.com/moonD4rk/keychainbreaker/blob/main/LICENSE)

Go library for reading and decrypting macOS Keychain files (`login.keychain-db`).

## What It Does

Open a macOS Keychain file, unlock it with the user's password, and extract:

- **Generic passwords** -- app-stored credentials (Chrome Safe Storage, Wi-Fi, etc.)
- **Internet passwords** -- web and network credentials (GitHub tokens, Docker registry, SMB shares, etc.)
- **Private keys** -- RSA/EC private keys stored in the keychain
- **X.509 certificates** -- DER-encoded certificates

Works on any OS (Linux, macOS, Windows). No CGO. No macOS APIs. Just reads the binary file.

## Install

```bash
go get github.com/moond4rk/keychainbreaker
```

Requires Go 1.20+.

## Quick Start

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

## Usage

### Open a Keychain

```go
kc, err := keychainbreaker.Open()                                      // default system keychain
kc, err := keychainbreaker.Open(keychainbreaker.WithFile("/path/to"))   // specific file
kc, err := keychainbreaker.Open(keychainbreaker.WithBytes(buf))         // from memory
```

### Unlock

```go
err = kc.Unlock(keychainbreaker.WithPassword("macos-login-password"))   // with password
err = kc.Unlock(keychainbreaker.WithKey("hex-encoded-24-byte-key"))     // with master key
```

### Extract Records

```go
genericPasswords, err := kc.GenericPasswords()     // app credentials
internetPasswords, err := kc.InternetPasswords()   // web/network credentials
privateKeys, err := kc.PrivateKeys()               // encrypted private keys
certificates, err := kc.Certificates()             // X.509 certificates
hash, err := kc.PasswordHash()                     // offline cracking hash (no unlock needed)
```

### Record Types

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
making it robust across macOS versions (10.6 through 13).

See [RFC 001](rfcs/001-keychain-encryption.md) for the full encryption specification.

## Compatibility

| Supported | Not Supported |
|-----------|---------------|
| `.keychain` and `.keychain-db` files | `keychain-2.db` (iCloud Keychain) |
| OS X 10.6 through macOS 13 | Secure Enclave protected keys |
| Linux, macOS, Windows (cross-compile) | |

## License

[Apache-2.0](LICENSE)
