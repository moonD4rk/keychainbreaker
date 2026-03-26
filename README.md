# keychainbreaker

[![Go CI](https://github.com/moonD4rk/keychainbreaker/actions/workflows/ci.yml/badge.svg)](https://github.com/moonD4rk/keychainbreaker/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/moond4rk/keychainbreaker.svg)](https://pkg.go.dev/github.com/moond4rk/keychainbreaker)

A Go library for parsing and decrypting macOS Keychain files (`login.keychain-db`).

## Features

- Parse macOS Keychain binary format with dynamic schema discovery
- Decrypt generic passwords, internet passwords, and private keys
- Multiple unlock methods: hex key, password (PBKDF2), SystemKey file
- Export password hash for offline cracking (hashcat / John the Ripper)
- Zero external dependencies (standard library only, except testify for tests)
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
	// Open a keychain file
	kc, err := keychainbreaker.Open("/path/to/login.keychain-db")
	if err != nil {
		log.Fatal(err)
	}

	// Unlock with a hex-encoded master key
	err = kc.Unlock(keychainbreaker.WithKey("your-hex-key-here"))
	if err != nil {
		log.Fatal(err)
	}

	// Extract generic passwords
	passwords, err := kc.GenericPasswords()
	if err != nil {
		log.Fatal(err)
	}

	for _, p := range passwords {
		fmt.Printf("Service: %s\n", p.Service)
		fmt.Printf("Account: %s\n", p.Account)
		fmt.Printf("Password: %s\n", p.Password)
		fmt.Println()
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
err = kc.Unlock(keychainbreaker.WithKey("hex-encoded-24-byte-master-key"))
```

### Extract Records

```go
passwords, err := kc.GenericPasswords()
```

### Password Hash Export

```go
hash := kc.PasswordHash() // $keychain$*<salt>*<iv>*<ciphertext>
```

## License

[Apache-2.0](LICENSE)
