package keychainbreaker

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
)

// UnlockOption configures how to unlock the keychain.
type UnlockOption func(*unlockConfig)

type unlockConfig struct {
	hexKey string
}

// WithKey unlocks using a raw hex-encoded 24-byte master key.
func WithKey(hexKey string) UnlockOption {
	return func(c *unlockConfig) {
		c.hexKey = hexKey
	}
}

// Unlock decrypts the keychain using the provided credential.
// After a successful Unlock, record extraction methods become available.
func (kc *Keychain) Unlock(opt UnlockOption) error {
	var cfg unlockConfig
	opt(&cfg)

	masterKey, err := deriveMasterKey(&cfg, kc)
	if err != nil {
		return err
	}

	dbKey, err := kc.findWrappingKey(masterKey)
	if err != nil {
		return err
	}
	kc.dbKey = dbKey

	if err := kc.generateKeyList(); err != nil {
		return err
	}

	return nil
}

func deriveMasterKey(cfg *unlockConfig, _ *Keychain) ([]byte, error) {
	if cfg.hexKey != "" {
		return decodeHexKey(cfg.hexKey)
	}
	return nil, fmt.Errorf("no unlock method provided")
}

func decodeHexKey(hexKey string) ([]byte, error) {
	cleaned := strings.TrimSpace(hexKey)
	cleaned = strings.TrimPrefix(cleaned, "0x")
	key, err := hex.DecodeString(cleaned)
	if err != nil {
		return nil, fmt.Errorf("unable to decode unlock key: %w", err)
	}
	if len(key) != keyLength {
		return nil, fmt.Errorf("unlock key must be %d bytes (got %d)", keyLength, len(key))
	}
	return key, nil
}

func (kc *Keychain) findWrappingKey(master []byte) ([]byte, error) {
	metaTable := kc.tables[tableMetadata]
	if metaTable == nil {
		return nil, fmt.Errorf("metadata table not found")
	}

	blobOffset := metaTable.baseOffset + 0x38
	if blobOffset+dbBlobSize > len(kc.buf) {
		return nil, fmt.Errorf("db blob exceeds file size")
	}

	start := blobOffset + int(kc.dbBlob.startCryptoBlob)
	end := blobOffset + int(kc.dbBlob.totalLength)
	if start < 0 || end > len(kc.buf) || start >= end {
		return nil, fmt.Errorf("db blob cipher bounds invalid")
	}

	plain, err := kcDecrypt(master, kc.dbBlob.iv, kc.buf[start:end])
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrWrongKey, err)
	}
	if len(plain) < keyLength {
		return nil, fmt.Errorf("db key shorter than expected")
	}
	return append([]byte{}, plain[:keyLength]...), nil
}

func (kc *Keychain) generateKeyList() error {
	symTable := kc.tables[tableSymmetricKey]
	if symTable == nil {
		return ErrNoKeys
	}

	schema := kc.schema.forTable(tableSymmetricKey)
	if schema == nil {
		return fmt.Errorf("no schema for SymmetricKey table")
	}

	for _, recOffset := range symTable.recordOffsets {
		absOffset := symTable.baseOffset + int(recOffset)
		index, ciphertext, iv, err := kc.parseKeyblobRecord(absOffset, schema)
		if err != nil {
			continue
		}
		key, err := keyblobDecrypt(ciphertext, iv, kc.dbKey)
		if err != nil || len(key) == 0 {
			continue
		}
		kc.keyList[string(index)] = key
	}

	if len(kc.keyList) == 0 {
		return ErrNoKeys
	}
	return nil
}

const keyBlobRecordHeaderLen = 132

func (kc *Keychain) parseKeyblobRecord(offset int, _ *tableSchema) (index, ciphertext, iv []byte, err error) {
	if offset+keyBlobRecordHeaderLen > len(kc.buf) {
		return nil, nil, nil, fmt.Errorf("keyblob header exceeds file size")
	}

	recSize := int(binary.BigEndian.Uint32(kc.buf[offset : offset+4]))
	recordStart := offset + keyBlobRecordHeaderLen
	recordEnd := offset + recSize
	if recordEnd > len(kc.buf) || recordStart >= recordEnd {
		return nil, nil, nil, fmt.Errorf("keyblob record exceeds file size")
	}

	recData := kc.buf[recordStart:recordEnd]
	if len(recData) < keyBlobLen {
		return nil, nil, nil, fmt.Errorf("keyblob structure incomplete")
	}

	blob, err := parseKeyBlob(recData[:keyBlobLen])
	if err != nil {
		return nil, nil, nil, err
	}
	if blob.magic != keyBlobMagic {
		return nil, nil, nil, fmt.Errorf("unexpected keyblob magic")
	}

	ssgpOffset := int(blob.totalLength) + 8
	if ssgpOffset+4 > len(recData) {
		return nil, nil, nil, fmt.Errorf("ssgp check exceeds record")
	}
	if string(recData[ssgpOffset:ssgpOffset+4]) != secureStorageGroup {
		return nil, nil, nil, fmt.Errorf("keyblob not part of secure storage group")
	}

	cipherStart := int(blob.startCryptoBlob)
	cipherEnd := int(blob.totalLength)
	if cipherEnd > len(recData) || cipherStart >= cipherEnd {
		return nil, nil, nil, fmt.Errorf("invalid cipher bounds")
	}
	ciphertext = append([]byte{}, recData[cipherStart:cipherEnd]...)

	indexStart := ssgpOffset
	indexEnd := indexStart + 20
	if indexEnd > len(recData) {
		return nil, nil, nil, fmt.Errorf("key index exceeds record length")
	}
	index = append([]byte{}, recData[indexStart:indexEnd]...)
	iv = append([]byte{}, blob.iv...)

	return index, ciphertext, iv, nil
}
