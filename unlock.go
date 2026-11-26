package keychainbreaker

import (
	"bytes"
	"errors"
	"fmt"
)

// UnlockWithPassword unlocks the keychain with its password, from which PBKDF2-HMAC-SHA1 derives the master key.
// It returns ErrWrongKey for a wrong password and ErrUnsupportedBlobVersion for keychains that only UnlockWithKey can
// open. A failed attempt leaves the keychain as it was, so another credential can be tried.
func (kc *Keychain) UnlockWithPassword(password string) error {
	if kc.dbBlob.version != blobVersionV1 {
		return fmt.Errorf("%w: blob version 0x%08X; a password derives the master key only for 0x%08X, use UnlockWithKey",
			ErrUnsupportedBlobVersion, kc.dbBlob.version, blobVersionV1)
	}
	return kc.unlock(deriveMasterKey(password, kc.dbBlob.salt))
}

// UnlockWithKey unlocks the keychain with its 24-byte master key, which works for every blob version. It returns
// ErrWrongKey for a wrong key. A failed attempt leaves the keychain as it was, so another key can be tried.
func (kc *Keychain) UnlockWithKey(key []byte) error {
	if len(key) != tripleDESKeyLen {
		return fmt.Errorf("keychainbreaker: master key is %d bytes, want %d", len(key), tripleDESKeyLen)
	}
	return kc.unlock(key)
}

// Unlocked reports whether an unlock has succeeded.
func (kc *Keychain) Unlocked() bool {
	kc.mu.RLock()
	defer kc.mu.RUnlock()
	return kc.dbKey != nil
}

func (kc *Keychain) unlock(masterKey []byte) error {
	encrypted, err := kc.encryptedDBKey()
	if err != nil {
		return err
	}
	plain, err := decryptCBC(masterKey, kc.dbBlob.iv, encrypted)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrWrongKey, err)
	}
	if len(plain) < tripleDESKeyLen {
		return fmt.Errorf("%w: database key too short", ErrWrongKey)
	}
	dbKey := bytes.Clone(plain[:tripleDESKeyLen])

	recordKeys, err := kc.recoverRecordKeys(dbKey)
	if err != nil {
		return err
	}
	kc.mu.Lock()
	kc.dbKey, kc.recordKeys = dbKey, recordKeys
	kc.mu.Unlock()
	kc.logger.Debug("unlocked", "record_keys", len(recordKeys))
	return nil
}

// recoverRecordKeys unwraps the per-record keys in the SymmetricKey table, indexed by the SSGP label they serve.
func (kc *Keychain) recoverRecordKeys(dbKey []byte) (map[string][]byte, error) {
	t, ok := kc.tables[tableSymmetricKey]
	if !ok || t.schema == nil {
		return nil, fmt.Errorf("%w: no SymmetricKey table", ErrParseFailed)
	}
	keys := make(map[string][]byte, len(t.recordOffsets))
	for _, off := range t.recordOffsets {
		rec, err := parseRecord(kc.buf, t.offset+int(off), t.schema)
		if err != nil {
			continue
		}
		label, wrapped, iv, err := parseWrappedKey(rec)
		if err != nil {
			continue
		}
		key, err := unwrapKey(wrapped, iv, dbKey)
		if err != nil {
			continue
		}
		keys[string(label)] = key
	}
	kc.logger.Debug("recovered record keys", "keys", len(keys), "records", len(t.recordOffsets))
	if len(keys) == 0 {
		return nil, fmt.Errorf("%w: no record keys recovered", ErrWrongKey)
	}
	return keys, nil
}

// parseWrappedKey returns the SSGP label a symmetric key record serves, and the key's ciphertext and IV.
func parseWrappedKey(rec *record) (label, wrapped, iv []byte, err error) {
	header, err := parseKeyBlobHeader(rec.payload)
	if err != nil {
		return nil, nil, nil, err
	}
	label, ok := span(rec.payload, int(header.totalLength)+wrappedKeyLabelGap, ssgpLabelLen)
	if !ok || string(label[:4]) != secureStorageGroup {
		return nil, nil, nil, errors.New("key is not filed under an SSGP label")
	}
	wrapped, err = header.ciphertext(rec.payload)
	if err != nil {
		return nil, nil, nil, err
	}
	return label, wrapped, header.iv, nil
}
