package keychainbreaker

import (
	"bytes"
	"errors"
	"fmt"
)

// GenericPasswords returns every generic password record. While the keychain is locked the records carry their
// metadata and a nil Password.
func (kc *Keychain) GenericPasswords() ([]GenericPassword, error) {
	return extract(kc, tableGenericPassword, decodeGenericPassword)
}

// InternetPasswords returns every internet password record. While the keychain is locked the records carry their
// metadata and a nil Password.
func (kc *Keychain) InternetPasswords() ([]InternetPassword, error) {
	return extract(kc, tableInternetPassword, decodeInternetPassword)
}

// PrivateKeys returns every private key record. While the keychain is locked the records carry their metadata and
// nil Data.
func (kc *Keychain) PrivateKeys() ([]PrivateKey, error) {
	return extract(kc, tablePrivateKey, decodePrivateKey)
}

// Certificates returns every certificate record. Certificates are not encrypted, so they need no unlock.
func (kc *Keychain) Certificates() ([]Certificate, error) {
	return extract(kc, tableX509Certificate, decodeCertificate)
}

// secrets is a snapshot of the keys an unlock recovered; both are nil while the keychain is locked.
type secrets struct {
	dbKey      []byte
	recordKeys map[string][]byte
}

func (kc *Keychain) secrets() secrets {
	kc.mu.RLock()
	defer kc.mu.RUnlock()
	return secrets{dbKey: kc.dbKey, recordKeys: kc.recordKeys}
}

// extract decodes every record of a table. A record that cannot be decrypted keeps its metadata and is reported
// through the logger, not as an error.
func extract[T any](kc *Keychain, tableID uint32, decode func(*record, secrets) (T, error)) ([]T, error) {
	records, err := kc.tableRecords(tableID)
	if err != nil || len(records) == 0 {
		return nil, err
	}
	keys := kc.secrets()
	out := make([]T, 0, len(records))
	failed := 0
	for _, rec := range records {
		v, err := decode(rec, keys)
		if err != nil {
			failed++
			kc.logger.Debug("record not decrypted", "table", tableName(tableID), "error", err)
		}
		out = append(out, v)
	}
	if failed > 0 {
		kc.logger.Warn("records not decrypted", "table", tableName(tableID), "failed", failed, "total", len(out))
	}
	return out, nil
}

// tableRecords parses the records of a table, skipping malformed ones.
func (kc *Keychain) tableRecords(tableID uint32) ([]*record, error) {
	t, ok := kc.tables[tableID]
	if !ok {
		return nil, nil
	}
	if t.schema == nil {
		return nil, fmt.Errorf("%w: no schema for table %s", ErrParseFailed, tableName(tableID))
	}
	records := make([]*record, 0, len(t.recordOffsets))
	for _, off := range t.recordOffsets {
		rec, err := parseRecord(kc.buf, t.offset+int(off), t.schema)
		if err != nil {
			kc.logger.Debug("record skipped", "table", tableName(tableID), "error", err)
			continue
		}
		records = append(records, rec)
	}
	if skipped := len(t.recordOffsets) - len(records); skipped > 0 {
		kc.logger.Warn("records skipped", "table", tableName(tableID), "skipped", skipped,
			"total", len(t.recordOffsets))
	}
	return records, nil
}

func decodeGenericPassword(rec *record, keys secrets) (GenericPassword, error) {
	password, err := keys.decryptPassword(rec)
	return GenericPassword{
		Service:     rec.textAttr(attrService),
		Account:     rec.textAttr(attrAccount),
		Password:    password,
		Description: rec.textAttr(attrDescription),
		Comment:     rec.textAttr(attrComment),
		Creator:     rec.textAttr(attrCreator),
		Type:        rec.textAttr(attrType),
		PrintName:   rec.textAttr(attrPrintName),
		Alias:       rec.textAttr(attrAlias),
		Created:     rec.timeAttr(attrCreated),
		Modified:    rec.timeAttr(attrModified),
	}, err
}

func decodeInternetPassword(rec *record, keys secrets) (InternetPassword, error) {
	password, err := keys.decryptPassword(rec)
	return InternetPassword{
		Server:         rec.textAttr(attrServer),
		Account:        rec.textAttr(attrAccount),
		Password:       password,
		SecurityDomain: rec.textAttr(attrSecurityDomain),
		Protocol:       rec.textAttr(attrProtocol),
		AuthType:       rec.textAttr(attrAuthType),
		Port:           rec.uint32Attr(attrPort),
		Path:           rec.textAttr(attrPath),
		Description:    rec.textAttr(attrDescription),
		Comment:        rec.textAttr(attrComment),
		Creator:        rec.textAttr(attrCreator),
		Type:           rec.textAttr(attrType),
		PrintName:      rec.textAttr(attrPrintName),
		Alias:          rec.textAttr(attrAlias),
		Created:        rec.timeAttr(attrCreated),
		Modified:       rec.timeAttr(attrModified),
	}, err
}

func decodePrivateKey(rec *record, keys secrets) (PrivateKey, error) {
	data, err := keys.decryptPrivateKey(rec)
	return PrivateKey{
		Data:      data,
		PrintName: rec.textAttr(attrPrintName),
		Label:     rec.bytesAttr(attrLabel),
		KeyClass:  rec.uint32Attr(attrKeyClass),
		KeyType:   rec.uint32Attr(attrKeyType),
		KeySize:   rec.uint32Attr(attrKeySizeInBits),
	}, err
}

func decodeCertificate(rec *record, _ secrets) (Certificate, error) {
	return Certificate{
		Data:      bytes.Clone(rec.blob),
		Type:      rec.uint32Attr(attrCertType),
		Encoding:  rec.uint32Attr(attrCertEncoding),
		PrintName: rec.textAttr(attrCertLabel),
		Subject:   rec.bytesAttr(attrSubject),
		Issuer:    rec.bytesAttr(attrIssuer),
		Serial:    rec.bytesAttr(attrSerial),
	}, nil
}

// decryptPassword returns the password of a password record: nil while locked, empty but non-nil when it is empty.
func (s secrets) decryptPassword(rec *record) ([]byte, error) {
	if s.dbKey == nil {
		return nil, nil
	}
	block, err := parseSSGP(rec.blob)
	if err != nil {
		return nil, err
	}
	if len(block.ciphertext) == 0 {
		return []byte{}, nil
	}
	key, ok := s.recordKeys[string(block.label)]
	if !ok {
		return nil, errors.New("no record key for the SSGP label")
	}
	password, err := decryptCBC(key, block.iv, block.ciphertext)
	if err != nil {
		return nil, fmt.Errorf("decrypt password: %w", err)
	}
	return password, nil
}

// decryptPrivateKey returns the PKCS#8 data of a private key record, or nil while locked.
func (s secrets) decryptPrivateKey(rec *record) ([]byte, error) {
	if s.dbKey == nil {
		return nil, nil
	}
	header, err := parseKeyBlobHeader(rec.payload)
	if err != nil {
		return nil, err
	}
	wrapped, err := header.ciphertext(rec.payload)
	if err != nil {
		return nil, err
	}
	plain, err := unwrapPrivateKey(wrapped, header.iv, s.dbKey)
	if err != nil {
		return nil, err
	}
	if len(plain) > privateKeyPrefixLen {
		return plain[privateKeyPrefixLen:], nil
	}
	return plain, nil
}
