package keychainbreaker

import (
	"encoding/hex"
	"fmt"
	"strings"
)

// UnlockOption configures how to unlock the keychain.
type UnlockOption func(*unlockConfig)

type unlockConfig struct {
	hexKey      string
	password    string
	passwordSet bool
}

// WithKey unlocks using a raw hex-encoded 24-byte master key.
func WithKey(hexKey string) UnlockOption {
	return func(c *unlockConfig) {
		c.hexKey = hexKey
	}
}

// WithPassword unlocks using the keychain password.
// The master key is derived via PBKDF2-HMAC-SHA1 with the salt from the keychain file.
// An empty password is treated as a valid unlock attempt, not as "no password provided".
func WithPassword(password string) UnlockOption {
	return func(c *unlockConfig) {
		c.password = password
		c.passwordSet = true
	}
}

// Unlock decrypts the keychain using the provided credential.
// After a successful Unlock, record extraction methods become available.
// If Unlock fails, extraction methods return ErrLocked.
// Use TryUnlock instead if you want to extract metadata even when
// the password is wrong or unavailable.
func (kc *Keychain) Unlock(opt UnlockOption) error {
	kc.allowPartial = false
	return kc.unlock(opt)
}

// TryUnlock attempts to decrypt the keychain, but does not block record
// extraction on failure. If the credential is wrong or missing, extraction
// methods still return record metadata (service, account, timestamps, etc.)
// with encrypted fields (passwords, private key data) set to nil.
//
// TryUnlock returns any unlock error (e.g. ErrWrongKey) for informational
// purposes, but the caller can safely ignore it and proceed with extraction.
func (kc *Keychain) TryUnlock(opts ...UnlockOption) error {
	kc.allowPartial = true
	if len(opts) == 0 {
		return nil
	}
	return kc.unlock(opts...)
}

// Unlocked reports whether the keychain has been successfully decrypted.
func (kc *Keychain) Unlocked() bool {
	return kc.dbKey != nil
}

func (kc *Keychain) unlock(opts ...UnlockOption) error {
	var cfg unlockConfig
	for _, opt := range opts {
		opt(&cfg)
	}

	masterKey, err := deriveMasterKey(&cfg, kc)
	if err != nil {
		return err
	}
	logFields := []any{"method", deriveMethod(&cfg)}
	if cfg.passwordSet {
		logFields = append(logFields, "iterations", pbkdf2Iter)
	}
	logFields = append(logFields, "keyLen", len(masterKey))
	kc.logger.Info("master key derived", logFields...)

	dbKey, err := kc.findWrappingKey(masterKey)
	if err != nil {
		kc.logger.Error("decrypt DB key failed", "error", err)
		return err
	}
	kc.logger.Info("DB key decrypted", "keyLen", len(dbKey))

	kc.dbKey = dbKey
	if err := kc.generateKeyList(); err != nil {
		kc.dbKey = nil
		kc.keyList = make(map[string][]byte)
		kc.logger.Error("generate key list failed", "error", err)
		return err
	}
	kc.logger.Info("key list generated", "keyCount", len(kc.keyList))

	return nil
}

func deriveMethod(cfg *unlockConfig) string {
	switch {
	case cfg.hexKey != "":
		return "hex-key"
	case cfg.passwordSet:
		return "PBKDF2-SHA1"
	default:
		return "none"
	}
}

func deriveMasterKey(cfg *unlockConfig, kc *Keychain) ([]byte, error) {
	switch {
	case cfg.hexKey != "":
		return decodeHexKey(cfg.hexKey)
	case cfg.passwordSet:
		return generateMasterKey(cfg.password, kc.dbBlob.salt), nil
	default:
		return nil, fmt.Errorf("no unlock method provided")
	}
}

func decodeHexKey(hexKey string) ([]byte, error) {
	cleaned := strings.TrimSpace(hexKey)
	cleaned = strings.TrimPrefix(cleaned, "0x")
	key, err := hex.DecodeString(cleaned)
	if err != nil {
		return nil, fmt.Errorf("decode unlock key: %w", err)
	}
	if len(key) != keyLength {
		return nil, fmt.Errorf("unlock key must be %d bytes, got %d", keyLength, len(key))
	}
	return key, nil
}

func (kc *Keychain) findWrappingKey(master []byte) ([]byte, error) {
	start := kc.blobBaseAddr + int(kc.dbBlob.startCryptoBlob)
	end := kc.blobBaseAddr + int(kc.dbBlob.totalLength)
	if start < 0 || end > len(kc.buf) || start >= end {
		return nil, fmt.Errorf("%w: db blob cipher bounds invalid", ErrParseFailed)
	}
	kc.logger.Debug("decrypting DB key", "ciphertextLen", end-start)

	plain, err := kcDecrypt(master, kc.dbBlob.iv, kc.buf[start:end])
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrWrongKey, err)
	}
	if len(plain) < keyLength {
		return nil, fmt.Errorf("%w: db key too short", ErrWrongKey)
	}
	return append([]byte{}, plain[:keyLength]...), nil
}

func (kc *Keychain) generateKeyList() error {
	symTable := kc.tables[tableSymmetricKey]
	if symTable == nil {
		return fmt.Errorf("%w: no symmetric key table", ErrParseFailed)
	}

	schema := kc.schema.forTable(tableSymmetricKey)
	if schema == nil {
		return fmt.Errorf("%w: no schema for SymmetricKey table", ErrParseFailed)
	}

	var skipped int
	for _, recOffset := range symTable.recordOffsets {
		absOffset := symTable.baseOffset + int(recOffset)
		rec, err := parseRecord(kc.buf, absOffset, schema)
		if err != nil {
			skipped++
			continue
		}
		index, ciphertext, iv, err := extractKeyBlob(rec)
		if err != nil {
			skipped++
			continue
		}
		key, err := keyblobDecrypt(ciphertext, iv, kc.dbKey)
		if err != nil || len(key) == 0 {
			skipped++
			continue
		}
		kc.keyList[string(index)] = key
	}
	if skipped > 0 {
		kc.logger.Warn("symmetric key records skipped",
			"skipped", skipped,
			"total", len(symTable.recordOffsets),
		)
	}

	if len(kc.keyList) == 0 {
		return fmt.Errorf("%w: no symmetric keys recovered", ErrWrongKey)
	}
	return nil
}

// extractKeyBlob extracts the key material from a SymmetricKey record.
func extractKeyBlob(rec *record) (index, ciphertext, iv []byte, err error) {
	data := rec.rawPayload
	if len(data) < keyBlobLen {
		return nil, nil, nil, fmt.Errorf("keyblob structure incomplete")
	}

	blob, err := parseKeyBlob(data[:keyBlobLen])
	if err != nil {
		return nil, nil, nil, err
	}
	if blob.magic != keyBlobMagic {
		return nil, nil, nil, fmt.Errorf("unexpected keyblob magic: 0x%08x", blob.magic)
	}

	ssgpOffset := int(blob.totalLength) + ssgpMagicOffset
	if ssgpOffset+4 > len(data) {
		return nil, nil, nil, fmt.Errorf("ssgp check exceeds record")
	}
	if string(data[ssgpOffset:ssgpOffset+4]) != secureStorageGroup {
		return nil, nil, nil, fmt.Errorf("keyblob not part of secure storage group")
	}

	cipherStart := int(blob.startCryptoBlob)
	cipherEnd := int(blob.totalLength)
	if cipherEnd > len(data) || cipherStart >= cipherEnd {
		return nil, nil, nil, fmt.Errorf("invalid cipher bounds")
	}
	ciphertext = append([]byte{}, data[cipherStart:cipherEnd]...)

	indexStart := ssgpOffset
	indexEnd := indexStart + 20
	if indexEnd > len(data) {
		return nil, nil, nil, fmt.Errorf("key index exceeds record length")
	}
	index = append([]byte{}, data[indexStart:indexEnd]...)
	iv = append([]byte{}, blob.iv...)

	return index, ciphertext, iv, nil
}
