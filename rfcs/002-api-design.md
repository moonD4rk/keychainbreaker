# RFC 002: Go API Design

Status: Implemented
Author: @moonD4rk
Date: 2026-03-27
Updated: 2026-11-26

## Summary

The public API and internal architecture of the keychainbreaker Go library, which parses macOS Keychain files and decrypts their credentials with the scheme described in RFC 001.

Design principles:

- **Open and unlock are separate.** Parsing needs no credential; metadata, certificates and the password hash are available before any unlock.
- **Explicit calls over options.** Each input has its own function (`Open`, `OpenBytes`, `UnlockWithPassword`, `UnlockWithKey`); options are left for settings that combine, such as a logger.
- **Raw data out.** Records carry bytes and plain values; encoding them (text, hex, base64, JSON) is the caller's business.
- **Self-describing records.** Attributes are read by name and decoded by the format the file's own schema declares.
- **One package, standard library only, Go 1.20.** HackBrowserData and other consumers build it with Go 1.20.

## 1. Public API

### Open

```go
// Open reads and parses the keychain file at path.
func Open(path string, opts ...Option) (*Keychain, error)

// OpenBytes parses a keychain held in memory. It keeps a copy of buf.
func OpenBytes(buf []byte, opts ...Option) (*Keychain, error)

// DefaultKeychainPath returns ~/Library/Keychains/login.keychain-db.
func DefaultKeychainPath() (string, error)

type Option func(*options)

// WithLogger sends diagnostics to l; *slog.Logger satisfies Logger.
func WithLogger(l Logger) Option
```

There is no implicit default: an empty path or buffer is an error, never a silent read of the user's login keychain.

### Unlock

```go
// UnlockWithPassword derives the master key with PBKDF2-HMAC-SHA1 (blob version 0x100 only).
func (kc *Keychain) UnlockWithPassword(password string) error

// UnlockWithKey takes the 24-byte master key; it works for every blob version.
func (kc *Keychain) UnlockWithKey(key []byte) error

// Unlocked reports whether an unlock has succeeded.
func (kc *Keychain) Unlocked() bool
```

A wrong credential returns `ErrWrongKey`; a password on a version 0x200 keychain returns `ErrUnsupportedBlobVersion`. A failed attempt changes nothing, so the caller can try another credential, and a failed attempt after a successful one keeps the keychain unlocked. A key of the wrong length is a caller error, not `ErrWrongKey`.

### Records

```go
func (kc *Keychain) GenericPasswords() ([]GenericPassword, error)
func (kc *Keychain) InternetPasswords() ([]InternetPassword, error)
func (kc *Keychain) PrivateKeys() ([]PrivateKey, error)
func (kc *Keychain) Certificates() ([]Certificate, error)

// PasswordHash returns $keychain$*<salt>*<iv>*<ciphertext> for hashcat (mode 23100) and John the Ripper.
func (kc *Keychain) PasswordHash() (string, error)
```

Extraction never depends on the lock state. Every record carries its metadata; `Password` and `PrivateKey.Data` are nil while the keychain is locked and for a record that cannot be decrypted, which is logged rather than returned as an error. An empty password is an empty, non-nil slice, so nil always means "not available". Certificates are not encrypted and are always complete.

A `Keychain` is safe for concurrent use: schemas are immutable once parsed, and the keys an unlock recovers are swapped in under a lock.

### Logger

```go
type Logger interface {
    Debug(msg string, args ...any)
    Warn(msg string, args ...any)
}
```

The arguments alternate keys and values, as in `log/slog`, so a `*slog.Logger` can be passed directly; the library cannot import `log/slog` itself on Go 1.20. Debug carries routine progress; Warn reports records that were skipped or not decrypted. Errors are returned, never logged.

## 2. Types

```go
type GenericPassword struct {
    Service, Account string
    Password         []byte // nil while locked or not decryptable
    Description, Comment string
    Creator, Type    string // four-character codes
    PrintName, Alias string
    Created, Modified time.Time
}

type InternetPassword struct {
    Server, Account  string
    Password         []byte
    SecurityDomain   string
    Protocol         string // four-character code: "htps", "smb ", ...
    AuthType         string // four-character code: "dflt", ...
    Port             uint32
    Path             string
    Description, Comment string
    Creator, Type    string
    PrintName, Alias string
    Created, Modified time.Time
}

type PrivateKey struct {
    Data      []byte // PKCS#8; nil while locked or not decryptable
    PrintName string
    Label     []byte // usually the SHA-1 hash of the public key
    KeyClass, KeyType, KeySize uint32
}

type Certificate struct {
    Data            []byte // DER
    Type, Encoding  uint32
    PrintName       string
    Subject, Issuer []byte // DER-encoded names
    Serial          []byte
}
```

The types have no JSON tags and no pre-encoded copies of their bytes. The CLI defines its own output types (RFC 003).

## 3. Errors

```go
var (
    ErrInvalidSignature       // Open, OpenBytes: not a keychain
    ErrParseFailed            // malformed structure
    ErrWrongKey               // UnlockWithPassword, UnlockWithKey: the credential does not decrypt the keychain
    ErrUnsupportedBlobVersion // UnlockWithPassword, PasswordHash: blob version other than 0x100
)
```

Every error wraps one of these where it applies, so callers use `errors.Is`. There is no "locked" error: a locked keychain returns metadata instead.

## 4. Internal Architecture

| File          | Holds                                                                                     |
| ------------- | ----------------------------------------------------------------------------------------- |
| `keychain.go` | `Keychain`, `Open`, `OpenBytes`, `DefaultKeychainPath`, parsing order, `PasswordHash`     |
| `records.go`  | the four extraction methods and per-record decryption                                     |
| `unlock.go`   | `UnlockWithPassword`, `UnlockWithKey`, database key and record key recovery               |
| `decrypt.go`  | 3DES-CBC, RFC 3217 key unwrapping, PBKDF2                                                 |
| `parse.go`    | binary structures, all read through one bounds-checked `span` helper                      |
| `schema.go`   | schema discovery and attribute decoding by format                                         |
| `types.go`, `errors.go`, `logger.go` | the exported types, errors and logger interface                    |

### Parsing

`Open` and `OpenBytes`:

1. Parse the 20-byte file header and check the `kych` signature.
2. Read the table directory at the header's offset and validate the table count against the file size before allocating anything.
3. Parse every table header and its record offsets.
4. Read the SchemaAttributes table (0x00000002) with its bootstrap schema: `RelationID`, `AttributeID`, `AttributeNameFormat`, `AttributeName`, `AttributeNameID`, `AttributeFormat`. Every other table's schema, attribute names and formats, comes from these records.
5. Locate the database blob in the Metadata table.

Attributes are read by name through the table's schema and decoded by the declared format (CSSM_DB_ATTRIBUTE_FORMAT): blobs and strings are length-prefixed, integers are four bytes, dates are 16-byte `YYYYMMDDhhmmssZ` strings. A four-character code stored as an integer, such as `crtr` or `ptcl`, reads as text; one stored as a blob, such as `atyp`, reads the same way.

### Decryption

Unlocking:

1. Take the master key, or derive it with `PBKDF2(password, salt, 1000, 24, SHA-1)`.
2. Decrypt the database key from the database blob with 3DES-CBC.
3. Unwrap each SymmetricKey record (RFC 3217) and index the keys by the SSGP label they serve.
4. Store the database key and the record keys only if all of this succeeds.

Reading a password record: parse its blob as SSGP, look up the record key by label, and decrypt with 3DES-CBC. A private key is unwrapped with the database key; the PKCS#8 data follows a 12-byte prefix.

## 5. Testing

### Fixture

`testdata/test.keychain-db` is a keychain created with the macOS `security` command. It contains no personal information.

- Password: `keychainbreaker-test`
- Master key: `4557eb716bbf20200945109cf3b884af9aca72e890e47c07`, PBKDF2 of the password

| Type             | Service or server | Account | Secret        | Notes                                                       |
| ---------------- | ----------------- | ------- | ------------- | ----------------------------------------------------------- |
| GenericPassword  | moond4rk.com      | admin   | password#123  | description, comment, creator `mD4k`, type `note`           |
| GenericPassword  | HackBrowserData   | admin   | password#123  | minimal                                                     |
| InternetPassword | moond4rk.com:443  | admin   | password#123  | protocol `htps`, auth type `dflt`, path `/login`, all fields |
| InternetPassword | moond4rk.com:445  | admin   | password#123  | protocol `smb `, minimal                                    |
| PrivateKey       | 93B7C5C0          | -       | RSA 2048-bit  | 20-byte label                                               |
| X509Certificate  | keychainbreaker-test | -    | self-signed   | -                                                           |

### Coverage

- **End to end:** every record type against the fixture, field by field, unlocked by password and by key; metadata from a locked keychain.
- **Unlock semantics:** wrong credentials, retry after a failure, a failure after a success, key length, version 0x200 gating.
- **Parsing:** the bounds helper, each binary structure, truncated and oversized inputs, including a table count that once triggered a 64 MiB allocation.
- **Schema:** the discovered formats, and attribute decoding by format.
- **Concurrency:** parallel opening, unlocking and extraction under `-race`.
- **Fuzzing:** `FuzzOpenBytes` mutates the fixture through parsing, unlocking and extraction.
- **Examples:** runnable examples for pkg.go.dev, checked against the fixture.

CI runs the tests on Go 1.20 and on the latest Go, on Linux, macOS and Windows.
