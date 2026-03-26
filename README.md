# keychainbreaker

[![Go CI](https://github.com/moonD4rk/keychainbreaker/actions/workflows/ci.yml/badge.svg)](https://github.com/moonD4rk/keychainbreaker/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/moonD4rk/keychainbreaker/branch/main/graph/badge.svg)](https://codecov.io/gh/moonD4rk/keychainbreaker)
[![Go Reference](https://pkg.go.dev/badge/github.com/moond4rk/keychainbreaker.svg)](https://pkg.go.dev/github.com/moond4rk/keychainbreaker)
[![Go Report Card](https://goreportcard.com/badge/github.com/moond4rk/keychainbreaker)](https://goreportcard.com/report/github.com/moond4rk/keychainbreaker)
[![License](https://img.shields.io/github/license/moonD4rk/keychainbreaker)](https://github.com/moonD4rk/keychainbreaker/blob/main/LICENSE)

A Go library for parsing and decrypting macOS Keychain files (`login.keychain-db`).

## Features

- Parse macOS Keychain binary format with dynamic schema discovery
- Decrypt generic passwords
- Multiple unlock methods: password (PBKDF2) or hex-encoded master key
- Export password hash for offline cracking (hashcat / John the Ripper)
- Zero external dependencies (standard library only)
- Compatible with Go 1.20+

## Install

```bash
go get github.com/moond4rk/keychainbreaker
```

## Usage

```go
package main

import (
	"fmt"
	"log"

	"github.com/moond4rk/keychainbreaker"
)

func main() {
	kc, err := keychainbreaker.Open("/path/to/login.keychain-db")
	if err != nil {
		log.Fatal(err)
	}

	// Unlock with password
	if err := kc.Unlock(keychainbreaker.WithPassword("your-keychain-password")); err != nil {
		log.Fatal(err)
	}

	passwords, err := kc.GenericPasswords()
	if err != nil {
		log.Fatal(err)
	}

	for _, p := range passwords {
		fmt.Printf("Service: %s, Account: %s, Password: %s\n", p.Service, p.Account, p.Password)
	}
}
```

## API

### Open

```go
kc, err := keychainbreaker.Open("/path/to/login.keychain-db")
kc, err := keychainbreaker.OpenBytes(buf)
```

### Unlock

```go
// With keychain password (PBKDF2-HMAC-SHA1 derivation)
err = kc.Unlock(keychainbreaker.WithPassword("password"))

// With hex-encoded 24-byte master key (from memory forensics)
err = kc.Unlock(keychainbreaker.WithKey("hex-key"))
```

### Extract Records

```go
passwords, err := kc.GenericPasswords()
```

### Password Hash Export

```go
hash, err := kc.PasswordHash() // $keychain$*<salt>*<iv>*<ciphertext>
```

## License

[Apache-2.0](LICENSE)
