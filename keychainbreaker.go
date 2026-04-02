// Package keychainbreaker parses and decrypts macOS Keychain files.
package keychainbreaker

import (
	"encoding/base64"
	"encoding/hex"
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
	keyList      map[string][]byte // SSGP label -> per-record key (empty until unlocked)
	allowPartial bool              // allow extraction without successful unlock
	logger       Logger
}

// OpenOption configures how to open a keychain.
type OpenOption func(*openConfig)

type openConfig struct {
	path   string
	buf    []byte
	logger Logger
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

// WithLogger sets a custom logger for diagnostic output.
// By default, the library is silent (no-op logger).
func WithLogger(l Logger) OpenOption {
	return func(c *openConfig) {
		c.logger = l
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
	cfg := openConfig{
		logger: nopLogger{},
	}
	for _, opt := range opts {
		opt(&cfg)
	}

	buf, err := resolveInput(&cfg)
	if err != nil {
		return nil, err
	}

	return parse(buf, cfg.logger)
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

func parse(buf []byte, logger Logger) (*Keychain, error) {
	hdr, err := parseHeader(buf)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrParseFailed, err)
	}
	if string(hdr.signature[:]) != keychainSignature {
		return nil, ErrInvalidSignature
	}
	logger.Info("parsed header",
		"signature", string(hdr.signature[:]),
		"version", hdr.version,
	)

	_, tableOffsets, err := parseSchema(buf, hdr.schemaOff)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrParseFailed, err)
	}
	logger.Debug("parsed schema", "tableCount", len(tableOffsets))

	kc := &Keychain{
		buf:     buf,
		header:  hdr,
		tables:  make(map[uint32]*tableInfo),
		keyList: make(map[string][]byte),
		logger:  logger,
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

	tableIDs := make([]uint32, 0, len(kc.tables))
	for id := range kc.tables {
		tableIDs = append(tableIDs, id)
	}
	sortUint32s(tableIDs)
	for _, id := range tableIDs {
		t := kc.tables[id]
		logger.Debug("parsed table",
			"name", tableIDName(id),
			"id", fmt.Sprintf("0x%08X", id),
			"records", len(t.recordOffsets),
		)
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

	cipherLen := 0
	if blob.totalLength > blob.startCryptoBlob {
		cipherLen = int(blob.totalLength - blob.startCryptoBlob)
	}
	kc.logger.Info("parsed DBBlob",
		"startCryptoBlob", blob.startCryptoBlob,
		"totalLength", blob.totalLength,
		"saltLen", len(blob.salt),
		"ivLen", len(blob.iv),
		"ciphertextLen", cipherLen,
	)
	return nil
}

func sortUint32s(s []uint32) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}

func tableIDName(id uint32) string {
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
	var skipped int
	for _, recOffset := range table.recordOffsets {
		absOffset := table.baseOffset + int(recOffset)
		rec, err := parseRecord(kc.buf, absOffset, schema)
		if err != nil {
			skipped++
			continue
		}
		records = append(records, rec)
	}
	if skipped > 0 {
		kc.logger.Warn("records skipped during parse",
			"table", tableIDName(tableID),
			"skipped", skipped,
			"total", len(table.recordOffsets),
		)
	}
	return records, nil
}

// GenericPasswords returns all generic password records.
// Returns ErrLocked if neither Unlock nor TryUnlock has been called.
// When TryUnlock is used and decryption fails, metadata fields are
// returned but Password will be nil.
func (kc *Keychain) GenericPasswords() ([]GenericPassword, error) {
	records, err := kc.iterateRecords(tableGenericPassword)
	if err != nil || len(records) == 0 {
		return nil, err
	}

	var decrypted, failed int
	results := make([]GenericPassword, 0, len(records))
	for _, rec := range records {
		password, err := kc.decryptBlob(rec)
		gp := GenericPassword{
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
		}
		if password != nil {
			gp.PlainPassword = string(password)
			gp.HexPassword = hex.EncodeToString(password)
			gp.Base64Password = base64.StdEncoding.EncodeToString(password)
			decrypted++
		} else if err != nil {
			failed++
		}
		results = append(results, gp)
	}
	kc.logger.Debug("GenericPasswords extracted",
		"total", len(results),
		"decrypted", decrypted,
		"failed", failed,
	)
	return results, nil
}

// InternetPasswords returns all internet password records.
// Returns ErrLocked if neither Unlock nor TryUnlock has been called.
// When TryUnlock is used and decryption fails, metadata fields are
// returned but Password will be nil.
func (kc *Keychain) InternetPasswords() ([]InternetPassword, error) {
	records, err := kc.iterateRecords(tableInternetPassword)
	if err != nil || len(records) == 0 {
		return nil, err
	}

	var decrypted, failed int
	results := make([]InternetPassword, 0, len(records))
	for _, rec := range records {
		password, err := kc.decryptBlob(rec)
		ip := InternetPassword{
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
		}
		if password != nil {
			ip.PlainPassword = string(password)
			ip.HexPassword = hex.EncodeToString(password)
			ip.Base64Password = base64.StdEncoding.EncodeToString(password)
			decrypted++
		} else if err != nil {
			failed++
		}
		results = append(results, ip)
	}
	kc.logger.Debug("InternetPasswords extracted",
		"total", len(results),
		"decrypted", decrypted,
		"failed", failed,
	)
	return results, nil
}

// PrivateKeys returns all private key records.
// Returns ErrLocked if neither Unlock nor TryUnlock has been called.
// When TryUnlock is used and decryption fails, metadata fields are
// returned but Name and Data will be empty.
func (kc *Keychain) PrivateKeys() ([]PrivateKey, error) {
	records, err := kc.iterateRecords(tablePrivateKey)
	if err != nil || len(records) == 0 {
		return nil, err
	}

	var decrypted, failed int
	var results []PrivateKey
	for _, rec := range records {
		pk, err := kc.decryptPrivateKey(rec)
		if err != nil {
			failed++
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
		} else {
			decrypted++
		}
		results = append(results, pk)
	}
	kc.logger.Debug("PrivateKeys extracted",
		"total", len(results),
		"decrypted", decrypted,
		"failed", failed,
	)
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
		Name:       name,
		Data:       keyData,
		DataHex:    hex.EncodeToString(keyData),
		DataBase64: base64.StdEncoding.EncodeToString(keyData),
		PrintName:  rec.stringAttr(attrPrintName),
		Label:      rec.stringAttr(attrLabel),
		KeyClass:   rec.uint32Attr(attrKeyClass),
		KeyType:    rec.uint32Attr(attrKeyType),
		KeySize:    rec.uint32Attr(attrKeySizeInBits),
	}, nil
}

// Certificates returns all X.509 certificate records.
// Returns ErrLocked if neither Unlock nor TryUnlock has been called.
// Certificates are not encrypted, so they are always fully available
// regardless of whether decryption succeeded.
func (kc *Keychain) Certificates() ([]Certificate, error) {
	records, err := kc.iterateRecords(tableX509Certificate)
	if err != nil || len(records) == 0 {
		return nil, err
	}

	var results []Certificate
	for _, rec := range records {
		data := append([]byte(nil), rec.blobData...)
		subject := rec.blobAttr(attrSubject)
		issuer := rec.blobAttr(attrIssuer)
		serial := rec.blobAttr(attrSerial)
		results = append(results, Certificate{
			Data:       data,
			DataHex:    hex.EncodeToString(data),
			DataBase64: base64.StdEncoding.EncodeToString(data),
			Type:       rec.uint32Attr(attrCertType),
			Encoding:   rec.uint32Attr(attrCertEncoding),
			PrintName:  rec.stringAttr(attrCertLabel),
			Subject:    subject,
			SubjectHex: hex.EncodeToString(subject),
			Issuer:     issuer,
			IssuerHex:  hex.EncodeToString(issuer),
			Serial:     serial,
			SerialHex:  hex.EncodeToString(serial),
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
