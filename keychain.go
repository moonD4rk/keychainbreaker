package keychainbreaker

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
)

// Keychain is a parsed keychain file. It starts locked: record metadata, certificates and PasswordHash are available
// at once, passwords and private keys after UnlockWithPassword, UnlockWithEntropy or UnlockWithKey. A Keychain is
// safe for concurrent use.
type Keychain struct {
	buf          []byte
	tables       map[uint32]*table
	dbBlob       dbBlob
	dbBlobOffset int
	logger       Logger

	mu         sync.RWMutex
	dbKey      []byte            // nil while locked
	recordKeys map[string][]byte // SSGP label -> record key
}

// Option configures Open and OpenBytes.
type Option func(*options)

type options struct {
	logger Logger
}

// WithLogger sends the library's diagnostics to l; by default they are discarded.
func WithLogger(l Logger) Option {
	return func(o *options) {
		if l != nil {
			o.logger = l
		}
	}
}

// DefaultKeychainPath returns the login keychain of the current user, ~/Library/Keychains/login.keychain-db.
func DefaultKeychainPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("keychainbreaker: locate the login keychain: %w", err)
	}
	return filepath.Join(home, "Library", "Keychains", "login.keychain-db"), nil
}

// Open reads and parses the keychain file at path.
func Open(path string, opts ...Option) (*Keychain, error) {
	buf, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("keychainbreaker: %w", err)
	}
	return parse(buf, opts)
}

// OpenBytes parses a keychain held in memory. It keeps a copy of buf, so the caller may reuse it.
func OpenBytes(buf []byte, opts ...Option) (*Keychain, error) {
	return parse(bytes.Clone(buf), opts)
}

func parse(buf []byte, opts []Option) (*Keychain, error) {
	o := options{logger: nopLogger{}}
	for _, opt := range opts {
		opt(&o)
	}

	header, err := parseFileHeader(buf)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrParseFailed, err)
	}
	if string(header.signature[:]) != keychainSignature {
		return nil, ErrInvalidSignature
	}
	offsets, err := parseTableDirectory(buf, header.tableDirectoryOffset)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrParseFailed, err)
	}

	tables := make(map[uint32]*table, len(offsets))
	for _, off := range offsets {
		t, err := parseTable(buf, off)
		if err != nil {
			o.logger.Debug("table skipped", "offset", off, "error", err)
			continue
		}
		if _, dup := tables[t.id]; !dup {
			tables[t.id] = t
		}
	}
	if err := attachSchemas(buf, tables); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrParseFailed, err)
	}

	kc := &Keychain{buf: buf, tables: tables, logger: o.logger}
	if err := kc.locateDBBlob(); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrParseFailed, err)
	}
	kc.logLayout(header)
	return kc, nil
}

func (kc *Keychain) locateDBBlob() error {
	meta, ok := kc.tables[tableMetadata]
	if !ok {
		return errors.New("metadata table not found")
	}
	kc.dbBlobOffset = meta.offset + metadataDBBlobOffset
	blob, err := parseDBBlob(kc.buf, kc.dbBlobOffset)
	if err != nil {
		return err
	}
	kc.dbBlob = blob
	return nil
}

func (kc *Keychain) logLayout(header fileHeader) {
	ids := make([]uint32, 0, len(kc.tables))
	for id := range kc.tables {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	for _, id := range ids {
		kc.logger.Debug("table", "name", tableName(id), "id", fmt.Sprintf("0x%08X", id),
			"records", len(kc.tables[id].recordOffsets))
	}
	kc.logger.Debug("parsed keychain",
		"version", fmt.Sprintf("0x%08X", header.version),
		"tables", len(kc.tables),
		"blob_version", fmt.Sprintf("0x%08X", kc.dbBlob.version),
		"salt_len", len(kc.dbBlob.salt),
	)
}

// encryptedDBKey returns the wrapped database key that follows the database blob header.
func (kc *Keychain) encryptedDBKey() ([]byte, error) {
	start := kc.dbBlobOffset + int(kc.dbBlob.cryptoStart)
	b, ok := span(kc.buf, start, int(kc.dbBlob.totalLength)-int(kc.dbBlob.cryptoStart))
	if !ok || len(b) == 0 {
		return nil, fmt.Errorf("%w: encrypted database key out of bounds", ErrParseFailed)
	}
	return b, nil
}

// PasswordHash returns the keychain password hash for offline cracking, as $keychain$*<salt>*<iv>*<ciphertext> in
// hex, the form hashcat (mode 23100) and John the Ripper accept. It needs no unlock.
//
// The hash is crackable only for keychains whose master key derives from the password alone. On macOS 26.4 and later
// the login keychain also mixes in its entropy file (see EntropyPath), so no password recovers this hash.
func (kc *Keychain) PasswordHash() (string, error) {
	encrypted, err := kc.encryptedDBKey()
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("$keychain$*%x*%x*%x", kc.dbBlob.salt, kc.dbBlob.iv, encrypted), nil
}

func tableName(id uint32) string {
	switch id {
	case tableSchemaInfo:
		return "SchemaInfo"
	case tableSchemaIndexes:
		return "SchemaIndexes"
	case tableSchemaAttributes:
		return "SchemaAttributes"
	case tableSchemaParsingModule:
		return "SchemaParsingModule"
	case tablePublicKey:
		return "PublicKey"
	case tablePrivateKey:
		return "PrivateKey"
	case tableSymmetricKey:
		return "SymmetricKey"
	case tableGenericPassword:
		return "GenericPassword"
	case tableInternetPassword:
		return "InternetPassword"
	case tableAppleSharePassword:
		return "AppleSharePassword"
	case tableX509Certificate:
		return "X509Certificate"
	case tableMetadata:
		return "Metadata"
	default:
		return fmt.Sprintf("Unknown(0x%08X)", id)
	}
}
