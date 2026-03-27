# RFC 002: Go API Design

Status: Implemented
Author: @moonD4rk
Date: 2026-03-27

## Summary

This document defines the public API and internal architecture of the keychainbreaker
Go library. The library parses macOS Keychain files and decrypts stored credentials
using the encryption scheme described in RFC 001.

Design principles:
- **Open/Unlock separation**: parse file structure without requiring credentials upfront
- **Functional options**: extensible unlock methods without breaking API
- **Dynamic schema**: parse record attributes from the file's self-describing schema
- **Single package**: all code in the root `keychainbreaker` package
- **Zero dependencies**: standard library only, Go 1.20 compatible

## 1. Public API

### Open

```go
// Open parses a keychain and returns a locked Keychain.
func Open(opts ...OpenOption) (*Keychain, error)

// OpenOption configures how to open a keychain.
type OpenOption func(*openConfig)

func WithFile(path string) OpenOption  // specific file path
func WithBytes(buf []byte) OpenOption  // in-memory buffer
```

With no options, `Open()` reads the default macOS login keychain
(`~/Library/Keychains/login.keychain-db`).

After `Open`, the following are available without unlocking:
- `PasswordHash()` for offline cracking hash export

### Unlock

```go
// Unlock decrypts the keychain using the provided credential.
func (kc *Keychain) Unlock(opt UnlockOption) error

// UnlockOption configures how to unlock the keychain.
type UnlockOption func(*unlockConfig)

// WithKey unlocks using a raw hex-encoded 24-byte master key.
func WithKey(hexKey string) UnlockOption

// WithPassword unlocks using the user's keychain password (PBKDF2 derivation).
func WithPassword(password string) UnlockOption
```

`Unlock` derives the master key, decrypts the database key, and unwraps all
per-record symmetric keys. After a successful `Unlock`, record extraction
methods become available.

### Record Extraction

```go
// GenericPasswords returns all decrypted generic password records.
func (kc *Keychain) GenericPasswords() ([]GenericPassword, error)

// InternetPasswords returns all decrypted internet password records.
func (kc *Keychain) InternetPasswords() ([]InternetPassword, error)
```

All extraction methods return `ErrLocked` if called before `Unlock`.

### Utility

```go
// PasswordHash exports the keychain password hash for offline cracking.
// Format: $keychain$*<salt_hex>*<iv_hex>*<ciphertext_hex>
// Compatible with hashcat mode 23100 and John the Ripper.
// Does not require Unlock.
func (kc *Keychain) PasswordHash() string
```

## 2. Exported Types

```go
type GenericPassword struct {
    Service     string
    Account     string
    Password    []byte    // raw decrypted bytes; caller decides encoding
    Description string
    Comment     string
    Creator     string
    Type        string
    PrintName   string
    Alias       string
    Created     time.Time
    Modified    time.Time
}

type InternetPassword struct {
    Server      string
    Account     string
    Password    []byte
    Protocol    string
    AuthType    string
    Port        uint32
    Path        string
    Description string
    Comment     string
    Creator     string
    Type        string
    PrintName   string
    Alias       string
    Created     time.Time
    Modified    time.Time
}

type PrivateKey struct {
    Name string // first 12 bytes of decrypted data
    Data []byte // raw private key material
}
```

`Password` is `[]byte` instead of `string` because keychain entries may contain
non-UTF-8 binary data. The caller decides how to interpret or encode the result.

## 3. Errors

```go
// Errors returned by Open.
var (
    ErrInvalidSignature = errors.New("keychainbreaker: invalid keychain signature")
    ErrParseFailed      = errors.New("keychainbreaker: parse failed")
)

// Errors returned by Unlock.
var (
    ErrWrongKey = errors.New("keychainbreaker: wrong key or password")
)

// Errors returned by record extraction methods.
var (
    ErrLocked = errors.New("keychainbreaker: keychain is locked")
)
```

## 4. Export Boundary

Only the minimal API surface is exported. All binary structures, parsing logic,
and cryptographic internals are unexported.

### Exported (uppercase)

```
Functions:    Open
Types:        Keychain, OpenOption, UnlockOption, GenericPassword, InternetPassword
Methods:      Keychain.Unlock, Keychain.GenericPasswords, Keychain.InternetPasswords,
              Keychain.PasswordHash
Options:      WithFile, WithBytes, WithKey, WithPassword
Errors:       ErrInvalidSignature, ErrParseFailed, ErrLocked, ErrWrongKey
```

### Unexported

All binary structures, parsing logic, cryptographic internals, and option configs
are unexported. The `Keychain` struct is exported but all its fields are unexported.

## 5. Internal Architecture

Single package, split by responsibility: `keychainbreaker.go` (Open, record extraction),
`unlock.go` (Unlock, key derivation), `decrypt.go` (3DES-CBC, PBKDF2, key unwrap),
`schema.go` (dynamic schema discovery), `parse.go` (binary parsing), `types.go`
(exported types), `errors.go` (sentinel errors).

### Dynamic Schema

On `Open`, the parser:

1. Parses `ApplDBHeader` and `ApplDBSchema` (hardcoded, always the same)
2. Bootstraps `SchemaInfo` (0x00000000) and `SchemaAttributes` (0x00000002)
   using hardcoded schemas (required to discover all other schemas)
3. Reads `SchemaAttributes` records to build attribute definitions for each table
4. Parses all tables using their discovered schemas
5. Extracts `DBBlob` from the Metadata table

Record extraction (e.g. `GenericPasswords()`) uses the dynamic schema to read
attribute values by name rather than by hardcoded struct offsets.

### Decryption Flow

On `Unlock`:

1. Derive master key from the provided credential (hex key / password / SystemKey)
2. Decrypt database key: `kcDecrypt(masterKey, DBBlob.IV, EncryptedDBKey)`
3. For each SymmetricKey record: RFC 3217 two-stage unwrap -> build `keyList`

On `GenericPasswords()` / `InternetPasswords()`:

1. Iterate records in the target table
2. Parse blob area as SSGP
3. Look up per-record key from `keyList`
4. `kcDecrypt(recordKey, SSGP.IV, SSGP.EncryptedPassword)` -> raw plaintext

## 6. Implementation Status

| Feature | Status |
|---------|--------|
| `Open` with functional options | Done |
| `WithPassword` (PBKDF2) | Done |
| `WithKey` (hex master key) | Done |
| `GenericPasswords` | Done |
| `InternetPasswords` | Done |
| `PasswordHash` | Done |
| Dynamic schema | Done |
| `WithSystemKey` | Future |
| `PrivateKeys` | Future |

## 7. Testing

### Test Fixture

`testdata/test.keychain-db` is a self-contained keychain created with the macOS
`security` command. It contains no personal information and is safe for public repos.

- **Keychain password**: `keychainbreaker-test`
- **Master key (hex)**: derived from password via `PBKDF2(password, Salt, 1000, 24, SHA1)`

Records in the test keychain:

| Type | Service/Server | Account | Password | Extra Fields |
|------|---------------|---------|----------|--------------|
| GenericPassword | moond4rk.com | admin | password#123 | Desc, Comment, Creator(mD4k), Type(note) |
| GenericPassword | HackBrowserData | admin | password#123 | (minimal) |
| InternetPassword | moond4rk.com:443 | admin | password#123 | Protocol(htps), Path(/login), Domain, all fields |
| InternetPassword | moond4rk.com:445 | admin | password#123 | Protocol(smb), minimal |
| PrivateKey | keychainbreaker-test | - | RSA 2048-bit | - |
| X509Certificate | keychainbreaker-test | - | self-signed | - |

### Test Categories

**End-to-end** (highest priority):

```go
func TestGenericPasswords(t *testing.T)      // Open -> Unlock -> GenericPasswords -> verify all fields
func TestInternetPasswords(t *testing.T)     // Open -> Unlock -> InternetPasswords -> verify all fields
func TestPrivateKeys(t *testing.T)           // Open -> Unlock -> PrivateKeys -> verify
```

**Schema validation**:

```go
func TestDynamicSchema(t *testing.T)         // verify discovered attributes match known schema
```

**Unit tests**:

```go
func TestKcDecrypt(t *testing.T)             // 3DES-CBC with known key/iv/ciphertext
func TestKeyblobDecrypt(t *testing.T)        // RFC 3217 two-stage unwrap
func TestParseHeader(t *testing.T)           // 20-byte header parsing
func TestParseDBBlob(t *testing.T)           // 92-byte DBBlob parsing
func TestParseSSGP(t *testing.T)             // SSGP structure parsing
```

**Error paths**:

```go
func TestOpenInvalidFile(t *testing.T)       // non-keychain file -> ErrInvalidSignature
func TestUnlockWrongKey(t *testing.T)        // bad key -> ErrWrongKey
func TestExtractBeforeUnlock(t *testing.T)   // locked keychain -> ErrLocked
func TestOpenTruncatedFile(t *testing.T)     // corrupted/short file -> error
```
