# keychainbreaker

[![Go CI](https://github.com/moonD4rk/keychainbreaker/actions/workflows/ci.yml/badge.svg)](https://github.com/moonD4rk/keychainbreaker/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/moonD4rk/keychainbreaker/branch/main/graph/badge.svg)](https://codecov.io/gh/moonD4rk/keychainbreaker)
[![Go Reference](https://pkg.go.dev/badge/github.com/moond4rk/keychainbreaker.svg)](https://pkg.go.dev/github.com/moond4rk/keychainbreaker)
[![Go Report Card](https://goreportcard.com/badge/github.com/moond4rk/keychainbreaker)](https://goreportcard.com/report/github.com/moond4rk/keychainbreaker)
[![License](https://img.shields.io/github/license/moonD4rk/keychainbreaker)](https://github.com/moonD4rk/keychainbreaker/blob/main/LICENSE)

A Go library for parsing and decrypting macOS Keychain files (`login.keychain-db`).
Extracts stored credentials from the Apple CSSM binary format without requiring
macOS or any CGO dependencies.

## Features

- **Dynamic schema discovery** -- parses table schemas from the keychain file at runtime, no hardcoded struct layouts
- **Password decryption** -- extracts and decrypts generic passwords using 3DES-CBC
- **Multiple unlock methods** -- keychain password (PBKDF2-HMAC-SHA1) or raw master key (from memory forensics)
- **Hash export** -- exports password hash compatible with hashcat (mode 23100) and John the Ripper
- **Zero dependencies** -- standard library only, no CGO required
- **Cross-platform** -- compiles on Linux, macOS, and Windows; parses keychain files from any OS

## Install

```bash
go get github.com/moond4rk/keychainbreaker
```

Requires Go 1.20 or later.

## Quick Start

```go
kc, err := keychainbreaker.Open("/path/to/login.keychain-db")
if err != nil {
    log.Fatal(err)
}

if err := kc.Unlock(keychainbreaker.WithPassword("your-keychain-password")); err != nil {
    log.Fatal(err)
}

passwords, err := kc.GenericPasswords()
if err != nil {
    log.Fatal(err)
}

for _, p := range passwords {
    fmt.Printf("Service: %s, Account: %s\n", p.Service, p.Account)
}
```

## API

### Open

```go
// From file path
kc, err := keychainbreaker.Open("/path/to/login.keychain-db")

// From in-memory buffer
kc, err := keychainbreaker.OpenBytes(buf)
```

`Open` parses the keychain file structure and discovers table schemas.
The returned `Keychain` is in a locked state -- call `Unlock` before extracting records.

### Unlock

```go
// With keychain password (most common)
err = kc.Unlock(keychainbreaker.WithPassword("password"))

// With hex-encoded 24-byte master key (from memory forensics tools)
err = kc.Unlock(keychainbreaker.WithKey("6d43376c0d257bbaca2c41eded65b3b34a1a96bd19979bde"))
```

### Extract Records

```go
passwords, err := kc.GenericPasswords()
```

Each `GenericPassword` contains:

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

### Password Hash Export

Export the keychain password hash for offline cracking (does not require `Unlock`):

```go
hash, err := kc.PasswordHash()
// Output: $keychain$*<salt_hex>*<iv_hex>*<ciphertext_hex>
```

## How It Works

macOS Keychain uses a three-layer key hierarchy with Triple-DES CBC encryption:

```
Password --> PBKDF2 --> Master Key --> DB Key --> Per-Record Keys --> Plaintext
```

1. **Master key** is derived from the keychain password via PBKDF2-HMAC-SHA1 (1000 iterations)
2. **Database key** is decrypted from the DBBlob using the master key
3. **Per-record keys** are unwrapped from the SymmetricKey table using RFC 3217 Triple-DES Key Wrap
4. **Passwords** are decrypted from SSGP (Secure Storage Group Password) blobs using per-record keys

The library uses dynamic schema discovery: it reads `SchemaInfo` and `SchemaAttributes`
tables to learn the record layout at runtime, rather than relying on hardcoded struct
definitions. This makes it robust against format variations across macOS versions.

See [RFC 001: macOS Keychain Encryption](rfcs/001-keychain-encryption.md) for the full
technical specification.

## Compatibility

- **macOS versions**: OS X 10.6 (Snow Leopard) through macOS 13 (Ventura)
- **File formats**: `.keychain` and `.keychain-db` (traditional CSSM format)
- **Not supported**: `keychain-2.db` (iCloud Keychain, SQLite-based) and Secure Enclave keys

## License

[Apache-2.0](LICENSE)
