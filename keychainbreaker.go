// Package keychainbreaker parses and decrypts macOS Keychain files.
package keychainbreaker

import (
	"fmt"
	"os"
	"path/filepath"
)

// metadataOffsetAdjustment is the fixed offset from the Metadata table base
// to the DBBlob structure within the keychain file.
const metadataOffsetAdjustment = 0x38

// defaultKeychainPath returns the default login keychain path for macOS.
func defaultKeychainPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("get home directory: %w", err)
	}
	return filepath.Join(home, "Library", "Keychains", "login.keychain-db"), nil
}

// Keychain represents a parsed macOS keychain file.
type Keychain struct {
	buf          []byte
	header       applDBHeader
	schema       *dbSchema
	tables       map[uint32]*tableInfo
	dbBlob       dbBlob
	blobBaseAddr int               // absolute offset of the DBBlob in buf
	dbKey        []byte            // 24-byte database key (nil when locked)
	keyList      map[string][]byte // SSGP label -> per-record key (nil when locked)
	allowPartial bool              // allow extraction without successful unlock
}

// OpenOption configures how to open a keychain.
type OpenOption func(*openConfig)

type openConfig struct {
	path string
	buf  []byte
}

// WithFile specifies a keychain file path.
func WithFile(path string) OpenOption {
	return func(c *openConfig) {
		c.path = path
	}
}

// WithBytes provides keychain data from an in-memory buffer.
func WithBytes(buf []byte) OpenOption {
	return func(c *openConfig) {
		c.buf = buf
	}
}

// Open parses a keychain file and returns a locked Keychain.
// Call Unlock before extracting records.
//
// With no options, it opens the default macOS login keychain
// (~/Library/Keychains/login.keychain-db):
//
//	kc, err := keychainbreaker.Open()
//
// With a specific file path:
//
//	kc, err := keychainbreaker.Open(keychainbreaker.WithFile("/path/to/keychain"))
//
// From an in-memory buffer:
//
//	kc, err := keychainbreaker.Open(keychainbreaker.WithBytes(buf))
func Open(opts ...OpenOption) (*Keychain, error) {
	var cfg openConfig
	for _, opt := range opts {
		opt(&cfg)
	}

	buf, err := resolveInput(&cfg)
	if err != nil {
		return nil, err
	}

	return parse(buf)
}

func resolveInput(cfg *openConfig) ([]byte, error) {
	switch {
	case len(cfg.buf) > 0:
		return cfg.buf, nil
	case cfg.path != "":
		buf, err := os.ReadFile(cfg.path)
		if err != nil {
			return nil, fmt.Errorf("open keychain %q: %w", cfg.path, err)
		}
		return buf, nil
	default:
		path, err := defaultKeychainPath()
		if err != nil {
			return nil, err
		}
		buf, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("open default keychain %q: %w", path, err)
		}
		return buf, nil
	}
}

func parse(buf []byte) (*Keychain, error) {
	hdr, err := parseHeader(buf)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrParseFailed, err)
	}
	if string(hdr.signature[:]) != keychainSignature {
		return nil, ErrInvalidSignature
	}

	_, tableOffsets, err := parseSchema(buf, hdr.schemaOff)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrParseFailed, err)
	}

	kc := &Keychain{
		buf:     buf,
		header:  hdr,
		tables:  make(map[uint32]*tableInfo),
		keyList: make(map[string][]byte),
	}

	for _, off := range tableOffsets {
		if off == 0 {
			continue
		}
		absOffset := headerSize + int(off)
		ti, parseErr := parseTable(buf, absOffset)
		if parseErr != nil {
			continue
		}
		if _, exists := kc.tables[ti.tableID]; !exists {
			kc.tables[ti.tableID] = &ti
		}
	}

	schema, err := buildSchema(buf, kc.tables)
	if err != nil {
		return nil, fmt.Errorf("%w: schema discovery: %w", ErrParseFailed, err)
	}
	kc.schema = schema

	if err := kc.extractDBBlob(); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrParseFailed, err)
	}

	return kc, nil
}

func (kc *Keychain) extractDBBlob() error {
	metaTable, ok := kc.tables[tableMetadata]
	if !ok {
		return fmt.Errorf("metadata table not found")
	}

	kc.blobBaseAddr = metaTable.baseOffset + metadataOffsetAdjustment
	if kc.blobBaseAddr+dbBlobSize > len(kc.buf) {
		return fmt.Errorf("db blob exceeds file size")
	}

	blob, err := parseDBBlob(kc.buf[kc.blobBaseAddr : kc.blobBaseAddr+dbBlobSize])
	if err != nil {
		return err
	}
	kc.dbBlob = blob
	return nil
}

// iterateRecords parses and returns all records from a table.
func (kc *Keychain) iterateRecords(tableID uint32) ([]*record, error) {
	if kc.dbKey == nil && !kc.allowPartial {
		return nil, ErrLocked
	}

	table, ok := kc.tables[tableID]
	if !ok {
		return nil, nil
	}

	schema := kc.schema.forTable(tableID)
	if schema == nil {
		return nil, fmt.Errorf("%w: no schema for table 0x%08x", ErrParseFailed, tableID)
	}

	var records []*record
	for _, recOffset := range table.recordOffsets {
		absOffset := table.baseOffset + int(recOffset)
		rec, err := parseRecord(kc.buf, absOffset, schema)
		if err != nil {
			continue
		}
		records = append(records, rec)
	}
	return records, nil
}

// GenericPasswords returns all decrypted generic password records.
// Returns ErrLocked if the keychain has not been unlocked.
func (kc *Keychain) GenericPasswords() ([]GenericPassword, error) {
	records, err := kc.iterateRecords(tableGenericPassword)
	if err != nil || len(records) == 0 {
		return nil, err
	}

	results := make([]GenericPassword, 0, len(records))
	for _, rec := range records {
		password, _ := kc.decryptBlob(rec)
		results = append(results, GenericPassword{
			Service:     rec.stringAttr(attrServiceName),
			Account:     rec.stringAttr(attrAccountName),
			Password:    password,
			Description: rec.stringAttr(attrDescription),
			Comment:     rec.stringAttr(attrComment),
			Creator:     rec.fourCharAttr(attrCreator),
			Type:        rec.fourCharAttr(attrType),
			PrintName:   rec.stringAttr(attrPrintName),
			Alias:       rec.stringAttr(attrAlias),
			Created:     rec.timeAttr(attrCreated),
			Modified:    rec.timeAttr(attrModified),
		})
	}
	return results, nil
}

// InternetPasswords returns all decrypted internet password records.
// Returns ErrLocked if the keychain has not been unlocked.
func (kc *Keychain) InternetPasswords() ([]InternetPassword, error) {
	records, err := kc.iterateRecords(tableInternetPassword)
	if err != nil || len(records) == 0 {
		return nil, err
	}

	results := make([]InternetPassword, 0, len(records))
	for _, rec := range records {
		password, _ := kc.decryptBlob(rec)
		results = append(results, InternetPassword{
			Server:         rec.stringAttr(attrServer),
			Account:        rec.stringAttr(attrAccountName),
			Password:       password,
			SecurityDomain: rec.stringAttr(attrSecurityDomain),
			Protocol:       rec.fourCharAttr(attrProtocol),
			AuthType:       rec.fourCharAttr(attrAuthType),
			Port:           rec.uint32Attr(attrPort),
			Path:           rec.stringAttr(attrPath),
			Description:    rec.stringAttr(attrDescription),
			Comment:        rec.stringAttr(attrComment),
			Creator:        rec.fourCharAttr(attrCreator),
			Type:           rec.fourCharAttr(attrType),
			PrintName:      rec.stringAttr(attrPrintName),
			Alias:          rec.stringAttr(attrAlias),
			Created:        rec.timeAttr(attrCreated),
			Modified:       rec.timeAttr(attrModified),
		})
	}
	return results, nil
}

// PrivateKeys returns all private key records.
// Returns ErrLocked if the keychain has not been unlocked (unless TryUnlock was used).
// When operating in partial mode, metadata fields (PrintName, KeyType, KeySize)
// are returned but Name and Data will be empty.
func (kc *Keychain) PrivateKeys() ([]PrivateKey, error) {
	records, err := kc.iterateRecords(tablePrivateKey)
	if err != nil || len(records) == 0 {
		return nil, err
	}

	var results []PrivateKey
	for _, rec := range records {
		pk, err := kc.decryptPrivateKey(rec)
		if err != nil {
			if !kc.allowPartial {
				continue
			}
			pk = PrivateKey{
				PrintName: rec.stringAttr(attrPrintName),
				Label:     rec.stringAttr(attrLabel),
				KeyClass:  rec.uint32Attr(attrKeyClass),
				KeyType:   rec.uint32Attr(attrKeyType),
				KeySize:   rec.uint32Attr(attrKeySizeInBits),
			}
		}
		results = append(results, pk)
	}
	return results, nil
}

func (kc *Keychain) decryptPrivateKey(rec *record) (PrivateKey, error) {
	data := rec.rawPayload
	if len(data) < keyBlobLen {
		return PrivateKey{}, fmt.Errorf("private key blob too small")
	}

	blob, err := parseKeyBlob(data[:keyBlobLen])
	if err != nil {
		return PrivateKey{}, err
	}
	if blob.magic != keyBlobMagic {
		return PrivateKey{}, fmt.Errorf("unexpected keyblob magic: 0x%08x", blob.magic)
	}

	cipherStart := int(blob.startCryptoBlob)
	cipherEnd := int(blob.totalLength)
	if cipherEnd > len(data) || cipherStart >= cipherEnd {
		return PrivateKey{}, fmt.Errorf("invalid cipher bounds")
	}

	plain, err := privateKeyDecrypt(data[cipherStart:cipherEnd], blob.iv, kc.dbKey)
	if err != nil {
		return PrivateKey{}, err
	}

	var name string
	var keyData []byte
	if len(plain) > privateKeyNameLen {
		name = string(plain[:privateKeyNameLen])
		keyData = plain[privateKeyNameLen:]
	} else {
		keyData = plain
	}

	return PrivateKey{
		Name:      name,
		Data:      keyData,
		PrintName: rec.stringAttr(attrPrintName),
		Label:     rec.stringAttr(attrLabel),
		KeyClass:  rec.uint32Attr(attrKeyClass),
		KeyType:   rec.uint32Attr(attrKeyType),
		KeySize:   rec.uint32Attr(attrKeySizeInBits),
	}, nil
}

// Certificates returns all X.509 certificate records.
// Certificates themselves are not encrypted, but Unlock must be
// called first to initialize record parsing and allow iteration.
func (kc *Keychain) Certificates() ([]Certificate, error) {
	records, err := kc.iterateRecords(tableX509Certificate)
	if err != nil || len(records) == 0 {
		return nil, err
	}

	var results []Certificate
	for _, rec := range records {
		results = append(results, Certificate{
			Data:      append([]byte(nil), rec.blobData...),
			Type:      rec.uint32Attr(attrCertType),
			Encoding:  rec.uint32Attr(attrCertEncoding),
			PrintName: rec.stringAttr(attrCertLabel),
			Subject:   rec.blobAttr(attrSubject),
			Issuer:    rec.blobAttr(attrIssuer),
			Serial:    rec.blobAttr(attrSerial),
		})
	}
	return results, nil
}

// decryptBlob decrypts the SSGP blob area of a password record.
func (kc *Keychain) decryptBlob(rec *record) ([]byte, error) {
	if len(rec.blobData) < ssgpHeaderLen {
		return nil, fmt.Errorf("blob too small: %d < %d", len(rec.blobData), ssgpHeaderLen)
	}

	block, err := parseSSGP(rec.blobData)
	if err != nil {
		return nil, fmt.Errorf("parse SSGP: %w", err)
	}
	if string(block.magic) != secureStorageGroup {
		return nil, fmt.Errorf("invalid SSGP magic: %q", block.magic)
	}
	if len(block.encryptedPassword) == 0 {
		return nil, nil
	}

	keyIndex := make([]byte, 0, len(block.magic)+len(block.label))
	keyIndex = append(keyIndex, block.magic...)
	keyIndex = append(keyIndex, block.label...)
	dbkey, ok := kc.keyList[string(keyIndex)]
	if !ok {
		return nil, fmt.Errorf("no matching key for SSGP label")
	}

	plain, err := kcDecrypt(dbkey, block.iv, block.encryptedPassword)
	if err != nil {
		return nil, fmt.Errorf("decrypt password: %w", err)
	}
	return plain, nil
}

// PasswordHash exports the keychain password hash for offline cracking.
// Format: $keychain$*<salt_hex>*<iv_hex>*<ciphertext_hex>
// Compatible with hashcat mode 23100 and John the Ripper.
// Does not require Unlock.
func (kc *Keychain) PasswordHash() (string, error) {
	start := kc.blobBaseAddr + int(kc.dbBlob.startCryptoBlob)
	end := kc.blobBaseAddr + int(kc.dbBlob.totalLength)
	if start >= end || end > len(kc.buf) {
		return "", fmt.Errorf("%w: encrypted db key bounds invalid", ErrParseFailed)
	}
	encryptedDBKey := kc.buf[start:end]
	return fmt.Sprintf("$keychain$*%x*%x*%x", kc.dbBlob.salt, kc.dbBlob.iv, encryptedDBKey), nil
}
