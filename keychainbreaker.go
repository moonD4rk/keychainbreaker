// Package keychainbreaker parses and decrypts macOS Keychain files.
package keychainbreaker

import (
	"fmt"
	"os"
)

// metadataOffsetAdjustment is the fixed offset from the Metadata table base
// to the DBBlob structure within the keychain file.
const metadataOffsetAdjustment = 0x38

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
}

// Open reads and parses a keychain file from disk.
// The returned Keychain is in a locked state; call Unlock to decrypt.
func Open(path string) (*Keychain, error) {
	buf, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return OpenBytes(buf)
}

// OpenBytes parses a keychain from an in-memory buffer.
// The returned Keychain is in a locked state; call Unlock to decrypt.
func OpenBytes(buf []byte) (*Keychain, error) {
	hdr, err := parseHeader(buf)
	if err != nil {
		return nil, err
	}
	if string(hdr.signature[:]) != keychainSignature {
		return nil, ErrInvalidSignature
	}

	_, tableOffsets, err := parseSchema(buf, hdr.schemaOff)
	if err != nil {
		return nil, err
	}

	kc := &Keychain{
		buf:     buf,
		header:  hdr,
		tables:  make(map[uint32]*tableInfo),
		keyList: make(map[string][]byte),
	}

	// Parse all tables and build the table index.
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

	// Build dynamic schema from SchemaAttributes.
	schema, err := buildSchema(buf, kc.tables)
	if err != nil {
		return nil, fmt.Errorf("schema discovery failed: %w", err)
	}
	kc.schema = schema

	// Extract DBBlob from Metadata table.
	if err := kc.extractDBBlob(); err != nil {
		return nil, err
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

// GenericPasswords returns all decrypted generic password records.
// Returns ErrLocked if the keychain has not been unlocked.
func (kc *Keychain) GenericPasswords() ([]GenericPassword, error) {
	if kc.dbKey == nil {
		return nil, ErrLocked
	}

	gpTable, ok := kc.tables[tableGenericPassword]
	if !ok {
		return nil, nil // no generic passwords
	}

	schema := kc.schema.forTable(tableGenericPassword)
	if schema == nil {
		return nil, fmt.Errorf("no schema for GenericPassword table")
	}

	var results []GenericPassword
	for _, recOffset := range gpTable.recordOffsets {
		absOffset := gpTable.baseOffset + int(recOffset)
		gp, err := kc.parseGenericPassword(absOffset, schema)
		if err != nil {
			continue
		}
		results = append(results, gp)
	}
	return results, nil
}

func (kc *Keychain) parseGenericPassword(offset int, schema *tableSchema) (GenericPassword, error) {
	rec, err := parseRecord(kc.buf, offset, schema)
	if err != nil {
		return GenericPassword{}, err
	}

	password, _ := kc.decryptBlob(rec) // password is nil if decryption fails

	return GenericPassword{
		Service:     rec.stringAttr("svce"),
		Account:     rec.stringAttr("acct"),
		Password:    password,
		Description: rec.stringAttr("desc"),
		Comment:     rec.stringAttr("icmt"),
		Creator:     rec.fourCharAttr("crtr"),
		Type:        rec.fourCharAttr("type"),
		PrintName:   rec.stringAttr("labl"),
		Alias:       rec.stringAttr("alis"),
		Created:     rec.timeAttr("cdat"),
		Modified:    rec.timeAttr("mdat"),
	}, nil
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
		return nil, nil // no encrypted data present (header-only SSGP)
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
		return "", fmt.Errorf("encrypted db key bounds invalid: [%d:%d] in buffer of %d", start, end, len(kc.buf))
	}
	encryptedDBKey := kc.buf[start:end]
	return fmt.Sprintf("$keychain$*%x*%x*%x", kc.dbBlob.salt, kc.dbBlob.iv, encryptedDBKey), nil
}
