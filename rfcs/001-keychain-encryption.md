# RFC 001: macOS Keychain Encryption

Status: Accepted
Author: @moonD4rk
Date: 2026-03-26

## Summary

This document describes how macOS Keychain files (`.keychain` / `.keychain-db`) store
and protect credentials. It serves as the foundational reference for implementing
the keychainbreaker library.

The Keychain uses Apple's CSSM (Common Security Services Manager) framework with a
**three-layer key hierarchy** and **Triple-DES CBC** encryption throughout. All
multi-byte fields are **Big-Endian**. The binary format has remained stable from
OS X 10.6 (Snow Leopard) through macOS 13 (Ventura).

## 1. File Structure

```
Offset 0x00:
+-------------------------------------------------------------+
|  ApplDBHeader (20 bytes)                                    |
|    Signature    [4]byte   = "kych"                          |
|    Version      uint32    (expected: 0x00010000)            |
|    HeaderSize   uint32                                      |
|    SchemaOff    uint32    -> offset to ApplDBSchema          |
|    AuthOff      uint32                                      |
+-------------------------------------------------------------+
|  ApplDBSchema (at SchemaOff, relative to end of header)     |
|    SchemaSize   uint32                                      |
|    TableCount   uint32                                      |
|    TableOffsets [TableCount]uint32                           |
+-------------------------------------------------------------+
|  Tables                                                     |
|    GenericPassword      (0x80000000)  app-stored passwords  |
|    InternetPassword     (0x80000001)  web/network passwords |
|    X509Certificate      (0x80001000)  certificates          |
|    PublicKey             (0x0000000F)  public keys           |
|    PrivateKey            (0x00000010)  private keys          |
|    SymmetricKey          (0x00000011)  per-record enc keys   |
|    Metadata              (0x80008000)  contains DBBlob       |
|    SchemaInfo / SchemaAttributes / ...                       |
+-------------------------------------------------------------+
```

### Table Layout

Each table has a 28-byte header followed by a record offset array:

```
TableHeader (28 bytes):
+------------------+------------------+---------------------+
| TableSize (4)    | TableID (4)      | AllocatedRowCount(4)|
+------------------+------------------+---------------------+
| Records (4)      | IndexesOff (4)   | FreeListHead (4)    |
+------------------+------------------+---------------------+
| TotalRowCount (4)                                         |
+-----------------------------------------------------------+
| RecordOffsets[TotalRowCount] (4 bytes each)               |
|   offset == 0         -> empty slot                       |
|   offset & 1 != 0     -> invalid (LSB flag)               |
|   offset % 4 != 0     -> invalid (alignment)              |
+-----------------------------------------------------------+
```

`AllocatedRowCount` is the number of valid records. `TotalRowCount` is the total
number of offset entries including empty and invalid slots.

### Record Layout

Each record has a generic header, a blob area, and attribute data:

```
Record:
+-----------+-----------+-----------+-----------+
| RecSize   | RecNumber | unk1      | unk2      |
+-----------+-----------+-----------+-----------+
| BlobSize  | 0x0       | Attribute Offsets...  |
+-----------+-----------+                       |
|                       (one uint32 per attr)   |
+-----------------------------------------------+
| BlobData (BlobSize bytes)                     |
|   -> SSGP / KeyBlob / DBBlob depending on    |
|      the table type                           |
+-----------------------------------------------+
| AttributeData (remaining bytes)               |
|   -> fields referenced by Attribute Offsets   |
+-----------------------------------------------+  <- RecSize
```

**Attribute offset convention**: a value of 0 means the attribute is empty.
Non-zero offsets are **1-based**: subtract 1 to get the actual byte offset
within the record (`actual = stored - 1`).

### Schema

The Keychain is self-describing: `SchemaInfo` and `SchemaAttributes` tables
define the attributes for each record type. The parser should read the schema
dynamically at runtime, interpreting records according to the discovered
attribute list. This approach is robust against future layout changes.

**Bootstrap**: the `SchemaInfo` (`0x00000000`) and `SchemaAttributes` (`0x00000002`)
tables themselves must be parsed with hardcoded schemas, since they are needed to
discover the schemas of all other tables.

## 2. Binary Structures

```go
// ApplDBHeader - file header, 20 bytes
type ApplDBHeader struct {
    Signature  [4]byte  // must be "kych"
    Version    uint32   // expected: 0x00010000 (major=1, minor=0)
    HeaderSize uint32
    SchemaOff  uint32   // offset to ApplDBSchema (relative to end of header)
    AuthOff    uint32
}

// ApplDBSchema - variable size
type ApplDBSchema struct {
    SchemaSize   uint32
    TableCount   uint32
    TableOffsets []uint32 // length = TableCount
}

// TableHeader - 28 bytes + variable RecordOffsets
type TableHeader struct {
    TableSize          uint32
    TableID            uint32   // record type (see Record Types)
    AllocatedRowCount  uint32   // valid record count
    Records            uint32
    IndexesOffset      uint32
    FreeListHead       uint32
    TotalRowCount      uint32   // total offset entries (including invalid)
    RecordOffsets      []uint32 // length = TotalRowCount
}

// CommonBlob - 8 bytes, appears at the start of several encrypted structures
type CommonBlob struct {
    Magic       uint32  // 0xFADE0711 for key blobs
    BlobVersion uint32
}

// DBBlob - database encryption blob (92 bytes), stored in the Metadata table.
// This is the entry point of the entire encryption system.
//
// Byte layout:
//   Offset  Size  Field
//   0       8     CommonBlob (Magic + BlobVersion)
//   8       4     StartCryptoBlob
//   12      4     TotalLength
//   16      16    RandomSignature
//   32      4     Sequence
//   36      4     IdleTimeout (DBParameters)
//   40      4     LockOnSleep (DBParameters)
//   44      20    Salt (PBKDF2 salt)
//   64      8     IV (3DES-CBC IV for decrypting the wrapping key)
//   72      20    BlobSignature
//
// EncryptedDBKey follows immediately after BlobSignature.
// Size = TotalLength - StartCryptoBlob (typically 48 bytes).
type DBBlob struct {
    CommonBlob      CommonBlob // offset 0, 8 bytes
    StartCryptoBlob uint32     // offset 8
    TotalLength     uint32     // offset 12
    RandomSignature [16]byte   // offset 16
    Sequence        uint32     // offset 32
    IdleTimeout     uint32     // offset 36
    LockOnSleep     uint32     // offset 40
    Salt            [20]byte   // offset 44
    IV              [8]byte    // offset 64
    BlobSignature   [20]byte   // offset 72
}

// SSGP - Secure Storage Group Password
// 28-byte header + variable-length encrypted data.
// Each encrypted password record's blob area is parsed as this structure.
type SSGP struct {
    Magic             [4]byte  // must be "ssgp"
    Label             [16]byte // lookup key into keyList for the per-record decryption key
    IV                [8]byte  // 3DES-CBC IV for decrypting this record's password
    EncryptedPassword []byte   // variable length; empty if BlobSize == 28
}

// KeyBlob - symmetric key record blob (key wrapping info)
type KeyBlob struct {
    CommonBlob      CommonBlob // Magic must be 0xFADE0711
    StartCryptoBlob uint32
    TotalLength     uint32
    IV              [8]byte    // IV for second stage of key unwrapping
    // EncryptedKey occupies [StartCryptoBlob:TotalLength].
}

// UnlockBlob - SystemKey file structure (48 bytes)
// Found at /var/db/SystemKey, used to unlock System.keychain.
type UnlockBlob struct {
    CommonBlob    CommonBlob
    MasterKey     [24]byte  // 24-byte master key, used directly (skip PBKDF2)
    BlobSignature [16]byte
}
```

## 3. Three-Layer Key Hierarchy

```
+----------------------------------------------------------------------+
| Layer 1: User Credential -> Master Key (24 bytes)                    |
|                                                                      |
|   Method A: PBKDF2-HMAC-SHA1(password, DBBlob.Salt, 1000, 24)       |
|   Method B: Raw hex key (from memory forensics)                      |
|   Method C: SystemKey file (/var/db/SystemKey)                       |
+----------------------------------------------------------------------+
                    |
                    v
+----------------------------------------------------------------------+
| Layer 2: Master Key -> Database Key (24 bytes)                       |
|                                                                      |
|   3DES-CBC(masterKey, DBBlob.IV, DBBlob.EncryptedDBKey) -> dbKey     |
+----------------------------------------------------------------------+
                    |
                    v
+----------------------------------------------------------------------+
| Layer 3: Database Key -> Per-Record Keys (24 bytes each)             |
|                                                                      |
|   For each SymmetricKey record:                                      |
|     RFC 3217 two-stage CMS unwrap -> recordKey                       |
|     Stored as: keyList[SSGP.Label] = recordKey                       |
+----------------------------------------------------------------------+
                    |
                    v
+----------------------------------------------------------------------+
| Final: Per-Record Key -> Plaintext                                   |
|                                                                      |
|   3DES-CBC(recordKey, SSGP.IV, SSGP.EncryptedPassword) -> plaintext |
+----------------------------------------------------------------------+
```

## 4. Cryptographic Primitives

All encryption in the Keychain uses:

- **Algorithm**: Triple-DES (3DES-EDE) in CBC mode
- **Key length**: 24 bytes (192 bits, three 56-bit DES keys)
- **Block size**: 8 bytes
- **Padding**: PKCS#7
- **Key derivation**: PBKDF2-HMAC-SHA1, 1000 iterations, 24-byte output

### Fixed Constants

```
Keychain Signature:    "kych"
KeyBlob Magic:         0xFADE0711
SSGP Magic:            "ssgp"
CMS IV (RFC 3217):     {0x4a, 0xdd, 0xa2, 0x2c, 0x79, 0xe8, 0x21, 0x05}
PBKDF2 Iterations:     1000
PBKDF2 Salt Length:    20 bytes
3DES Key Length:       24 bytes
3DES Block Size:       8 bytes
```

The CMS IV is Apple's fixed initialization vector used in the outer layer of
RFC 3217 Triple-DES Key Wrap (source: `Security/AppleCSP/AppleCSP/wrapKeyCms.cpp`).

## 5. Decryption Flow

### Step 1: Parse File Structure

1. Read file into memory buffer
2. Parse `ApplDBHeader` (20 bytes) at offset 0, verify `Signature == "kych"`
3. Parse `ApplDBSchema` at `SchemaOff`, read `TableOffsets[TableCount]`
4. Build table index: map each `TableID` to its offset
5. Parse `SchemaInfo` and `SchemaAttributes` tables to build dynamic schema

### Step 2: Extract DBBlob from Metadata Table

Find the Metadata table (`TableID = 0x80008000`). Parse the first record's blob
area as `DBBlob` (92 bytes).

Key fields extracted:
- **Salt** (20 bytes): PBKDF2 salt for password-based key derivation
- **IV** (8 bytes): 3DES-CBC IV for decrypting the database key
- **EncryptedDBKey**: `blob[StartCryptoBlob:TotalLength]` (typically 48 bytes)

### Step 3: Derive Master Key

Three methods to obtain the 24-byte master key:

| Method | Input | Process |
|--------|-------|---------|
| Password | User's macOS login password | `PBKDF2(password, Salt, 1000, 24, SHA1)` |
| Raw Key | 24-byte hex string | Direct hex decode |
| SystemKey | `/var/db/SystemKey` file | Read `UnlockBlob.MasterKey` (24 bytes) |

### Step 4: Decrypt Database Key

```
Input:  masterKey (24 bytes), DBBlob.IV (8 bytes), EncryptedDBKey (~48 bytes)
Process: 3DES-CBC-Decrypt(masterKey, DBBlob.IV, EncryptedDBKey)
Output: first 24 bytes of unpadded plaintext = dbKey
```

If PKCS#7 padding validation fails, the master key (or password) is wrong.

### Step 5: Unwrap Per-Record Symmetric Keys

Each password record has its own encryption key, stored in the SymmetricKey table
(`TableID = 0x00000011`). These keys are wrapped using a variant of RFC 3217
Triple-DES Key Wrap.

For each SymmetricKey record:

1. Validate `KeyBlob.CommonBlob.Magic == 0xFADE0711`
2. Extract `EncryptedKey = blob[StartCryptoBlob:TotalLength]`
3. **Stage 1**: `3DES-CBC-Decrypt(dbKey, MagicCMSIV, EncryptedKey) -> intermediate`
4. **Stage 2**: Reverse first 32 bytes of `intermediate`
5. **Stage 3**: `3DES-CBC-Decrypt(dbKey, KeyBlob.IV, reversed) -> plaintext`
6. Validate: `len(plaintext[4:]) == 24` (must yield a 24-byte key)
7. Extract: `recordKey = plaintext[4:]` (skip 4-byte header, take 24 bytes)
8. Store: `keyList[SSGP.Magic + SSGP.Label] = recordKey`

**Why two stages with reversal?** RFC 3217 specifies that during wrapping, the
plaintext is encrypted, then the ciphertext is reversed and encrypted again.
Unwrapping reverses this process. Apple uses the fixed `MagicCMSIV` for the outer
layer and a per-key IV for the inner layer.

### Step 6: Decrypt Password Records

For each GenericPassword or InternetPassword record:

1. Parse the record using the dynamic schema
2. Parse the blob area as SSGP:

```
SSGP (28 bytes header + variable data):
+----------------+------------------+
| Magic (4)      | Label (16)       |
+----------------+------------------+
| IV (8)         | EncryptedPwd ... |
+----------------+------------------+
```

3. Validate `Magic == "ssgp"`
4. If `EncryptedPassword` is empty (BlobSize == 28), skip this record
5. Look up `recordKey = keyList[Magic + Label]`
6. Decrypt: `3DES-CBC-Decrypt(recordKey, SSGP.IV, EncryptedPassword) -> plaintext`

### Step 7: Decrypt Private Keys

Private keys use the same two-stage CMS unwrap, but reverse **all** bytes of the
Stage 1 output (not just the first 32), because private keys are larger.

1. Extract `KeyBlob` from the PrivateKey record
2. **Stage 1**: `3DES-CBC-Decrypt(dbKey, MagicCMSIV, EncryptedKey) -> intermediate`
3. **Stage 2**: Reverse **all** bytes of `intermediate` (not just first 32)
4. **Stage 3**: `3DES-CBC-Decrypt(dbKey, KeyBlob.IV, reversed) -> plaintext`
5. Split result: `keyName = plaintext[:12]`, `privateKey = plaintext[12:]`

Note: private keys use `dbKey` directly, not a per-record key from `keyList`.

### Step 8: Public Keys and Certificates

Public keys and X.509 certificates are **not encrypted**. Their data is stored
directly in the record's blob area:
- PublicKey: raw key data at `blob[StartCryptoBlob:TotalLength]`
- X509Certificate: raw DER certificate in blob data

## 6. Record Types

```
Application-Defined (0x80000000+):
  0x80000000  GenericPassword      App-stored credentials
  0x80000001  InternetPassword     Web/network passwords
  0x80000002  AppleShare           AFP passwords (deprecated)
  0x80000003  UserTrust            User-defined certificate trust settings
  0x80000004  X509CRL              X.509 Certificate Revocation Lists
  0x80000005  UnlockReferral       Unlock referral records
  0x80000006  ExtendedAttr         Extended attributes
  0x80001000  X509Certificate      X.509 Certificates
  0x80008000  Metadata             Contains DBBlob

Open Group (0x0000000A+):
  0x0000000F  PublicKey            Public keys (not encrypted)
  0x00000010  PrivateKey           Private keys (encrypted)
  0x00000011  SymmetricKey         Per-record encryption keys

Schema Management:
  0x00000000  SchemaInfo           Schema information
  0x00000001  SchemaIndexes        Schema indexes
  0x00000002  SchemaAttributes     Attribute definitions
```

## 7. Attribute Data Types

Attribute values in records use the following format identifiers:

```
  0  String       Length-prefixed UTF-8 string (uint32 length + data)
  1  SInt32       Signed 32-bit integer
  2  UInt32       Unsigned 32-bit integer
  3  BigNum       Big number
  4  Real         64-bit floating point
  5  TimeDate     16-byte timestamp: "YYYYMMDDHHmmSSZ\0"
  6  Blob         Length-prefixed binary blob (uint32 length + data)
  7  MultiUInt32  Array of uint32 values
  8  Complex      Complex type
```

## 8. Password Hash Export

When no password is available, the hash can be exported for offline cracking:

```
Format: $keychain$*<salt_hex>*<iv_hex>*<ciphertext_hex>
```

Compatible with hashcat mode 23100 and John the Ripper. The cracking process:
1. `PBKDF2(candidate, salt, 1000, 24, SHA1)` -> candidate master key
2. `3DES-CBC(candidate_key, iv, ciphertext)` -> check PKCS#7 padding validity

Valid padding = correct password found.

## 9. Version Compatibility

**Supported**: OS X 10.6 through macOS 13, traditional `.keychain` / `.keychain-db` files.

The format has maintained binary compatibility across 13 major OS versions. The
encryption algorithm (3DES-CBC), key derivation (PBKDF2-SHA1, 1000 iterations),
and key wrapping (RFC 3217 variant) are all unchanged. The self-describing schema
makes the parser inherently forward-compatible.

**Not supported**:
- `keychain-2.db`: SQLite-based iCloud Keychain format, entirely different scheme
- Secure Enclave protected keys: hardware-level protection, not file-accessible

## References

- RFC 3217 - Triple-DES and RC2 Key Wrapping
- Apple CSSM Framework Documentation
