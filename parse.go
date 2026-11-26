package keychainbreaker

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	uint32Len               = 4
	fileHeaderLen           = 20
	tableDirectoryHeaderLen = 8
	tableHeaderLen          = 28
	recordHeaderWords       = 6 // size, number, two unknown words, blob size, reserved
	dbBlobLen               = 92
	keyBlobHeaderLen        = 24
	ssgpHeaderLen           = 28
	ssgpLabelLen            = 20 // "ssgp" followed by a 16-byte label
	timeDateLen             = 16

	keychainSignature  = "kych"
	secureStorageGroup = "ssgp"
	keyBlobMagic       = 0xFADE0711

	// metadataDBBlobOffset locates the database blob inside the Metadata table.
	metadataDBBlobOffset = 0x38
	// privateKeyPrefixLen is the length of the prefix an unwrapped private key carries before its PKCS#8 data.
	privateKeyPrefixLen = 12
	// wrappedKeyLabelGap separates the end of a symmetric key blob from the SSGP label it is filed under.
	wrappedKeyLabelGap = 8
)

// Table IDs (CSSM record types).
const (
	tableSchemaInfo          uint32 = 0x00000000
	tableSchemaIndexes       uint32 = 0x00000001
	tableSchemaAttributes    uint32 = 0x00000002
	tableSchemaParsingModule uint32 = 0x00000003
	tablePublicKey           uint32 = 0x0000000F
	tablePrivateKey          uint32 = 0x00000010
	tableSymmetricKey        uint32 = 0x00000011
	tableGenericPassword     uint32 = 0x80000000
	tableInternetPassword    uint32 = 0x80000001
	tableAppleSharePassword  uint32 = 0x80000002
	tableX509Certificate     uint32 = 0x80001000
	tableMetadata            uint32 = 0x80008000
)

// Database blob versions. Version 0x100 derives the master key from the password with PBKDF2 and can be decrypted
// offline; version 0x200, introduced in macOS 26.4, cannot be decrypted from the file and the password alone.
const (
	blobVersionV1 uint32 = 0x00000100
	blobVersionV2 uint32 = 0x00000200
)

// span returns buf[off:off+n] when that range lies within buf, without overflowing on hostile offsets.
func span(buf []byte, off, n int) ([]byte, bool) {
	if off < 0 || n < 0 || off > len(buf) || n > len(buf)-off {
		return nil, false
	}
	return buf[off : off+n], true
}

func readUint32(buf []byte, off int) (uint32, bool) {
	b, ok := span(buf, off, uint32Len)
	if !ok {
		return 0, false
	}
	return binary.BigEndian.Uint32(b), true
}

type fileHeader struct {
	signature            [4]byte
	version              uint32
	tableDirectoryOffset uint32
}

func parseFileHeader(buf []byte) (fileHeader, error) {
	b, ok := span(buf, 0, fileHeaderLen)
	if !ok {
		return fileHeader{}, errors.New("file too small for the header")
	}
	var h fileHeader
	copy(h.signature[:], b[:4])
	h.version = binary.BigEndian.Uint32(b[4:8])
	h.tableDirectoryOffset = binary.BigEndian.Uint32(b[12:16])
	return h, nil
}

// parseTableDirectory returns the absolute offsets of the tables the directory at offset lists.
func parseTableDirectory(buf []byte, offset uint32) ([]int, error) {
	base := int(offset)
	count, ok := readUint32(buf, base+uint32Len)
	if !ok {
		return nil, errors.New("table directory exceeds the file")
	}
	list := base + tableDirectoryHeaderLen
	if available := (len(buf) - list) / uint32Len; list > len(buf) || int64(count) > int64(available) {
		return nil, fmt.Errorf("table directory lists %d tables, more than the file holds", count)
	}
	offsets := make([]int, 0, count)
	for i := 0; i < int(count); i++ {
		off, _ := readUint32(buf, list+i*uint32Len)
		if off != 0 {
			offsets = append(offsets, base+int(off))
		}
	}
	return offsets, nil
}

// table is one table of the keychain database, with the schema of its records once schemas are discovered.
type table struct {
	id            uint32
	offset        int      // absolute offset of the table in the file
	recordOffsets []uint32 // relative to offset
	schema        *tableSchema
}

func parseTable(buf []byte, offset int) (*table, error) {
	header, ok := span(buf, offset, tableHeaderLen)
	if !ok {
		return nil, errors.New("table header exceeds the file")
	}
	t := &table{
		id:     binary.BigEndian.Uint32(header[4:8]),
		offset: offset,
	}
	list := offset + tableHeaderLen
	count := int64(binary.BigEndian.Uint32(header[8:12]))
	if available := int64((len(buf) - list) / uint32Len); count > available {
		count = available
	}
	for i := 0; i < int(count); i++ {
		v, _ := readUint32(buf, list+i*uint32Len)
		if v != 0 && v%4 == 0 {
			t.recordOffsets = append(t.recordOffsets, v)
		}
	}
	return t, nil
}

// dbBlob is the header of the database blob in the Metadata table, which wraps the database key.
type dbBlob struct {
	magic       uint32
	version     uint32
	cryptoStart uint32 // offset of the wrapped database key, from the start of the blob
	totalLength uint32
	salt        []byte // 20 bytes
	iv          []byte // 8 bytes
}

func parseDBBlob(buf []byte, offset int) (dbBlob, error) {
	b, ok := span(buf, offset, dbBlobLen)
	if !ok {
		return dbBlob{}, errors.New("database blob exceeds the file")
	}
	return dbBlob{
		magic:       binary.BigEndian.Uint32(b[0:4]),
		version:     binary.BigEndian.Uint32(b[4:8]),
		cryptoStart: binary.BigEndian.Uint32(b[8:12]),
		totalLength: binary.BigEndian.Uint32(b[12:16]),
		salt:        bytes.Clone(b[44:64]),
		iv:          bytes.Clone(b[64:72]),
	}, nil
}

// ssgp is a Secure Storage Group Password: the encrypted password of a password record, filed under a label that
// names its record key.
type ssgp struct {
	label      []byte // "ssgp" and the 16-byte label, the key of recordKeys
	iv         []byte
	ciphertext []byte
}

func parseSSGP(buf []byte) (ssgp, error) {
	if len(buf) < ssgpHeaderLen {
		return ssgp{}, errors.New("SSGP block too small")
	}
	if string(buf[:4]) != secureStorageGroup {
		return ssgp{}, fmt.Errorf("invalid SSGP magic %q", buf[:4])
	}
	return ssgp{
		label:      buf[:ssgpLabelLen],
		iv:         buf[ssgpLabelLen:ssgpHeaderLen],
		ciphertext: buf[ssgpHeaderLen:],
	}, nil
}

// keyBlobHeader starts every wrapped key: the database blob's key, symmetric keys and private keys.
type keyBlobHeader struct {
	magic       uint32
	cryptoStart uint32
	totalLength uint32
	iv          []byte
}

func parseKeyBlobHeader(buf []byte) (keyBlobHeader, error) {
	b, ok := span(buf, 0, keyBlobHeaderLen)
	if !ok {
		return keyBlobHeader{}, errors.New("key blob too small")
	}
	h := keyBlobHeader{
		magic:       binary.BigEndian.Uint32(b[0:4]),
		cryptoStart: binary.BigEndian.Uint32(b[8:12]),
		totalLength: binary.BigEndian.Uint32(b[12:16]),
		iv:          b[16:24],
	}
	if h.magic != keyBlobMagic {
		return keyBlobHeader{}, fmt.Errorf("unexpected key blob magic 0x%08X", h.magic)
	}
	return h, nil
}

// ciphertext returns the wrapped key that follows the header in buf.
func (h keyBlobHeader) ciphertext(buf []byte) ([]byte, error) {
	b, ok := span(buf, int(h.cryptoStart), int(h.totalLength)-int(h.cryptoStart))
	if !ok || len(b) == 0 {
		return nil, errors.New("wrapped key out of bounds")
	}
	return b, nil
}

// record is one row of a table, read through the table's schema.
type record struct {
	buf         []byte   // the whole record
	blob        []byte   // the blob area after the header; nil when empty or truncated
	payload     []byte   // everything after the header: the blob and the attribute data
	attrOffsets []uint32 // 1-based offsets of the attribute values, in schema order
	schema      *tableSchema
}

func parseRecord(buf []byte, offset int, schema *tableSchema) (*record, error) {
	size, ok := readUint32(buf, offset)
	if !ok {
		return nil, errors.New("record offset exceeds the file")
	}
	recBuf, ok := span(buf, offset, int(size))
	if !ok || size == 0 {
		return nil, errors.New("invalid record size")
	}

	attrCount := len(schema.attrs)
	headerLen := (recordHeaderWords + attrCount) * uint32Len
	if len(recBuf) < headerLen {
		return nil, fmt.Errorf("record too small for its header: need %d bytes, have %d", headerLen, len(recBuf))
	}
	attrOffsets := make([]uint32, attrCount)
	for i := range attrOffsets {
		attrOffsets[i] = binary.BigEndian.Uint32(recBuf[(recordHeaderWords+i)*uint32Len:])
	}
	blob, _ := span(recBuf, headerLen, int(binary.BigEndian.Uint32(recBuf[16:20])))
	if len(blob) == 0 {
		blob = nil
	}
	return &record{
		buf:         recBuf,
		blob:        blob,
		payload:     recBuf[headerLen:],
		attrOffsets: attrOffsets,
		schema:      schema,
	}, nil
}
