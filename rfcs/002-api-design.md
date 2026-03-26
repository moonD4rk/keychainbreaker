# RFC 002: Go API Design

Status: Draft
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
// Open reads and parses a keychain file from disk.
func Open(path string) (*Keychain, error)

// OpenBytes parses a keychain from an in-memory buffer.
func OpenBytes(buf []byte) (*Keychain, error)
```

`Open` / `OpenBytes` parse the file structure (header, schema, tables, DBBlob)
but do **not** decrypt anything. The returned `Keychain` is in a locked state.

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

// WithSystemKey unlocks using a SystemKey file (e.g. /var/db/SystemKey).
func WithSystemKey(path string) UnlockOption
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

// PrivateKeys returns all decrypted private key records.
func (kc *Keychain) PrivateKeys() ([]PrivateKey, error)
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
var (
    ErrInvalidSignature = errors.New("keychainbreaker: invalid keychain signature")
    ErrLocked           = errors.New("keychainbreaker: keychain is locked")
    ErrWrongKey         = errors.New("keychainbreaker: wrong key or password")
    ErrNoKeys           = errors.New("keychainbreaker: no symmetric keys recovered")
)
```

## 4. Export Boundary

Only the minimal API surface is exported. All binary structures, parsing logic,
and cryptographic internals are unexported.

### Exported (uppercase)

```
Functions:    Open, OpenBytes
Types:        Keychain, UnlockOption, GenericPassword, InternetPassword, PrivateKey
Methods:      Keychain.Unlock, Keychain.GenericPasswords, Keychain.InternetPasswords,
              Keychain.PrivateKeys, Keychain.PasswordHash
Options:      WithKey, WithPassword, WithSystemKey
Errors:       ErrInvalidSignature, ErrLocked, ErrWrongKey, ErrNoKeys
```

### Unexported (lowercase)

```
Binary structs:   applDBHeader, applDBSchema, tableHeader, commonBlob,
                  dbBlob, keyBlob, ssgp, unlockBlob
Schema:           dbSchema, tableSchema, attrDef, record
Parsing:          parseHeader, parseSchema, parseDBBlob, parseTable,
                  parseRecord, parseSSGP, parseKeyBlob
Crypto:           kcDecrypt, keyblobDecrypt, privateKeyDecrypt
Config:           unlockConfig
Constants:        keychainSignature, keyBlobMagic, secureStorageGroup,
                  magicCMSIV, blockSize, keyLength, all tableID constants
```

The `Keychain` struct is exported but all its fields are unexported:

```go
type Keychain struct {
    buf       []byte
    header    applDBHeader
    schema    *dbSchema          // dynamic schema from SchemaInfo + SchemaAttributes
    tables    map[uint32]*table  // tableID -> parsed table
    dbBlob    dbBlob
    dbKey     []byte             // 24-byte database key (nil when locked)
    keyList   map[string][]byte  // SSGP label -> per-record key (nil when locked)
}
```

## 5. Internal Architecture

### File Layout

Single package, split by responsibility:

```
keychainbreaker.go   Keychain, Open, OpenBytes
unlock.go            Unlock, unlockConfig, WithKey, WithPassword, WithSystemKey
decrypt.go           kcDecrypt, keyblobDecrypt, privateKeyDecrypt
schema.go            dbSchema, tableSchema, attrDef, dynamic schema bootstrap
parse.go             applDBHeader, dbBlob, ssgp, keyBlob, all parse* functions
types.go             GenericPassword, InternetPassword, PrivateKey
errors.go            ErrInvalidSignature, ErrLocked, ErrWrongKey, ErrNoKeys
```

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

## 6. Phase 1 Scope

Phase 1 implements the full architecture with focus on the HackBrowserData use case:

| Feature | Phase 1 | Phase 2 |
|---------|---------|---------|
| `Open` / `OpenBytes` | Yes | - |
| `WithKey` | Yes | - |
| `WithPassword` | - | Yes (adds `crypto/sha1` + `golang.org/x/crypto/pbkdf2`) |
| `WithSystemKey` | - | Yes |
| `GenericPasswords` | Yes | - |
| `InternetPasswords` | - | Yes |
| `PrivateKeys` | - | Yes |
| `PasswordHash` | - | Yes |
| Dynamic schema | Yes | - |

Phase 1 delivers a working library that HackBrowserData can import:

```go
kc, err := keychainbreaker.Open(keychainPath)
if err != nil { ... }

err = kc.Unlock(keychainbreaker.WithKey(hexKey))
if err != nil { ... }

passwords, err := kc.GenericPasswords()
for _, p := range passwords {
    if p.Account == storageName {
        return p.Password, nil
    }
}
```

## 7. Testing

### Test Fixture

`testdata/test.keychain-db` is a self-contained keychain created with the macOS
`security` command. It contains no personal information and is safe for public repos.

- **Keychain password**: `keychainbreaker-test`
- **Master key (hex)**: derived from password via `PBKDF2(password, Salt, 1000, 24, SHA1)`

Records in the test keychain:

| Type | Service/Server | Account | Password |
|------|---------------|---------|----------|
| GenericPassword | moond4rk.com | user@moond4rk.com | PlainTextPassword |
| GenericPassword | HackBrowserData | admin@moond4rk.com | Another!Pass#123 |
| InternetPassword | moond4rk.com | webuser | WebPass456 |
| PrivateKey | keychainbreaker-test | - | RSA 2048-bit |
| X509Certificate | keychainbreaker-test | - | self-signed |

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
