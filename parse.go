package keychainbreaker

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"time"
)

const (
	headerSize     = 20
	schemaSize     = 8
	tableHeaderLen = 28
	dbBlobSize     = 92
	keyBlobLen     = 24
	ssgpHeaderLen  = 28
	atomSize       = 4

	keychainSignature  = "kych"
	secureStorageGroup = "ssgp"
	keyBlobMagic       = 0xFADE0711

	ssgpMagicOffset   = 8  // offset from blob.totalLength to SSGP magic ("ssgp")
	privateKeyNameLen = 12 // first N bytes of decrypted private key data
)

// Attribute name constants used by record extraction.
// Most are FourCC codes from Apple's CSSM framework;
// some (PrintName, Alias, Label) are string names from SchemaAttributes.
const (
	attrServiceName    = "svce"
	attrAccountName    = "acct"
	attrDescription    = "desc"
	attrComment        = "icmt"
	attrCreator        = "crtr"
	attrType           = "type"
	attrPrintName      = "PrintName"
	attrAlias          = "Alias"
	attrCreated        = "cdat"
	attrModified       = "mdat"
	attrServer         = "srvr"
	attrSecurityDomain = "sdmn"
	attrProtocol       = "ptcl"
	attrAuthType       = "atyp"
	attrPort           = "port"
	attrPath           = "path"
	attrLabel          = "Label"
	attrKeyClass       = "KeyClass"
	attrKeyType        = "KeyType"
	attrKeySizeInBits  = "KeySizeInBits"
	attrCertType       = "ctyp"
	attrCertEncoding   = "cenc"
	attrCertLabel      = "labl" // certificate table uses FourCC, not "PrintName"
	attrSubject        = "subj"
	attrIssuer         = "issu"
	attrSerial         = "snbr"
)

// Record type constants (TableID values from Apple's CSSM framework).
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

// applDBHeader is the 20-byte file header.
type applDBHeader struct {
	signature  [4]byte
	version    uint32
	headerSize uint32
	schemaOff  uint32
	authOff    uint32
}

func parseHeader(buf []byte) (applDBHeader, error) {
	if len(buf) < headerSize {
		return applDBHeader{}, errors.New("file too small for header")
	}
	var h applDBHeader
	copy(h.signature[:], buf[:4])
	h.version = binary.BigEndian.Uint32(buf[4:8])
	h.headerSize = binary.BigEndian.Uint32(buf[8:12])
	h.schemaOff = binary.BigEndian.Uint32(buf[12:16])
	h.authOff = binary.BigEndian.Uint32(buf[16:20])
	return h, nil
}

// applDBSchema holds the table count and offsets.
type applDBSchema struct {
	schemaSize uint32
	tableCount uint32
}

func parseSchema(buf []byte, offset uint32) (applDBSchema, []uint32, error) {
	start := int(offset)
	if start+schemaSize > len(buf) {
		return applDBSchema{}, nil, errors.New("schema offset exceeds file size")
	}
	s := applDBSchema{
		schemaSize: binary.BigEndian.Uint32(buf[start : start+4]),
		tableCount: binary.BigEndian.Uint32(buf[start+4 : start+8]),
	}
	base := headerSize + schemaSize
	offsets := make([]uint32, s.tableCount)
	for i := 0; i < int(s.tableCount); i++ {
		pos := base + i*atomSize
		if pos+atomSize > len(buf) {
			return applDBSchema{}, nil, errors.New("table list exceeds file size")
		}
		offsets[i] = binary.BigEndian.Uint32(buf[pos : pos+atomSize])
	}
	return s, offsets, nil
}

// tableInfo holds a parsed table header and its record offsets.
type tableInfo struct {
	tableID       uint32
	recordCount   uint32
	recordOffsets []uint32
	baseOffset    int // absolute offset of this table in the buffer
}

func parseTable(buf []byte, offset int) (tableInfo, error) {
	if offset+tableHeaderLen > len(buf) {
		return tableInfo{}, errors.New("table header exceeds file size")
	}
	data := buf[offset : offset+tableHeaderLen]
	t := tableInfo{
		tableID:     binary.BigEndian.Uint32(data[4:8]),
		recordCount: binary.BigEndian.Uint32(data[8:12]),
		baseOffset:  offset,
	}
	recBase := offset + tableHeaderLen
	for i := 0; i < int(t.recordCount); i++ {
		pos := recBase + i*atomSize
		if pos+atomSize > len(buf) {
			break
		}
		v := binary.BigEndian.Uint32(buf[pos : pos+atomSize])
		if v != 0 && v%4 == 0 {
			t.recordOffsets = append(t.recordOffsets, v)
		}
	}
	return t, nil
}

// dbBlob is the 92-byte database encryption blob from the Metadata table.
type dbBlob struct {
	startCryptoBlob uint32
	totalLength     uint32
	salt            []byte // 20 bytes
	iv              []byte // 8 bytes
}

func parseDBBlob(buf []byte) (dbBlob, error) {
	if len(buf) < dbBlobSize {
		return dbBlob{}, errors.New("db blob buffer too small")
	}
	return dbBlob{
		startCryptoBlob: binary.BigEndian.Uint32(buf[8:12]),
		totalLength:     binary.BigEndian.Uint32(buf[12:16]),
		salt:            append([]byte{}, buf[44:64]...),
		iv:              append([]byte{}, buf[64:72]...),
	}, nil
}

// ssgpBlock represents a Secure Storage Group Password structure.
type ssgpBlock struct {
	magic             []byte // 4 bytes
	label             []byte // 16 bytes
	iv                []byte // 8 bytes
	encryptedPassword []byte
}

func parseSSGP(buf []byte) (*ssgpBlock, error) {
	if len(buf) < ssgpHeaderLen {
		return nil, errors.New("ssgp buffer too small")
	}
	return &ssgpBlock{
		magic:             append([]byte{}, buf[0:4]...),
		label:             append([]byte{}, buf[4:20]...),
		iv:                append([]byte{}, buf[20:28]...),
		encryptedPassword: append([]byte{}, buf[28:]...),
	}, nil
}

// keyBlobInfo holds parsed key blob data from a SymmetricKey record.
type keyBlobInfo struct {
	magic           uint32
	startCryptoBlob uint32
	totalLength     uint32
	iv              []byte // 8 bytes
}

func parseKeyBlob(buf []byte) (keyBlobInfo, error) {
	if len(buf) < keyBlobLen {
		return keyBlobInfo{}, errors.New("key blob buffer too small")
	}
	return keyBlobInfo{
		magic:           binary.BigEndian.Uint32(buf[0:4]),
		startCryptoBlob: binary.BigEndian.Uint32(buf[8:12]),
		totalLength:     binary.BigEndian.Uint32(buf[12:16]),
		iv:              append([]byte{}, buf[16:24]...),
	}, nil
}

// record represents a parsed keychain record with dynamic attribute access.
type record struct {
	buf         []byte   // full record bytes
	blobData    []byte   // blob area (blobSize bytes after header)
	rawPayload  []byte   // all bytes after header (blob + attribute data)
	attrOffsets []uint32 // attribute offsets from header
	schema      *tableSchema
}

const recordFixedFields = 6 // RecSize, RecNumber, unk1, unk2, BlobSize, Reserved

func parseRecord(buf []byte, offset int, schema *tableSchema) (*record, error) {
	if offset+atomSize > len(buf) {
		return nil, errors.New("record offset exceeds buffer")
	}
	recSize := int(binary.BigEndian.Uint32(buf[offset : offset+atomSize]))
	if recSize == 0 || offset+recSize > len(buf) {
		return nil, errors.New("invalid record size")
	}
	recBuf := buf[offset : offset+recSize]

	attrCount := len(schema.attrs)
	headerLen := (recordFixedFields + attrCount) * atomSize
	if len(recBuf) < headerLen {
		return nil, fmt.Errorf("record too small for header: need %d, got %d", headerLen, len(recBuf))
	}

	blobSize := int(binary.BigEndian.Uint32(recBuf[16:20]))

	attrOffsets := make([]uint32, attrCount)
	for i := 0; i < attrCount; i++ {
		pos := (recordFixedFields + i) * atomSize
		attrOffsets[i] = binary.BigEndian.Uint32(recBuf[pos : pos+atomSize])
	}

	var blobData []byte
	if blobSize > 0 && headerLen+blobSize <= len(recBuf) {
		blobData = recBuf[headerLen : headerLen+blobSize]
	}

	return &record{
		buf:         recBuf,
		blobData:    blobData,
		rawPayload:  recBuf[headerLen:],
		attrOffsets: attrOffsets,
		schema:      schema,
	}, nil
}

// attrOffset resolves the byte offset for a named attribute.
// Returns -1 if the attribute is not present or not found.
func (r *record) attrOffset(name string) int {
	idx := r.schema.attrIndex(name)
	if idx < 0 || idx >= len(r.attrOffsets) {
		return -1
	}
	off := r.attrOffsets[idx]
	if off == 0 {
		return -1
	}
	return int(off - 1) // 1-based to 0-based
}

// stringAttr reads a length-prefixed string attribute by name.
func (r *record) stringAttr(name string) string {
	pos := r.attrOffset(name)
	if pos < 0 || pos+4 > len(r.buf) {
		return ""
	}
	length := int(binary.BigEndian.Uint32(r.buf[pos : pos+4]))
	start := pos + 4
	if start+length > len(r.buf) {
		return ""
	}
	return string(bytes.TrimRight(r.buf[start:start+length], "\x00"))
}

// uint32Attr reads a uint32 attribute by name.
func (r *record) uint32Attr(name string) uint32 {
	pos := r.attrOffset(name)
	if pos < 0 || pos+4 > len(r.buf) {
		return 0
	}
	return binary.BigEndian.Uint32(r.buf[pos : pos+4])
}

// timeAttr reads a 16-byte TimeDate attribute by name.
func (r *record) timeAttr(name string) time.Time {
	pos := r.attrOffset(name)
	if pos < 0 || pos+16 > len(r.buf) {
		return time.Time{}
	}
	raw := bytes.TrimRight(r.buf[pos:pos+16], "\x00")
	if len(raw) == 0 {
		return time.Time{}
	}
	parsed, err := time.Parse("20060102150405Z", string(raw))
	if err != nil {
		return time.Time{}
	}
	return parsed
}

// blobAttr reads a length-prefixed binary blob attribute by name.
func (r *record) blobAttr(name string) []byte {
	pos := r.attrOffset(name)
	if pos < 0 || pos+4 > len(r.buf) {
		return nil
	}
	length := int(binary.BigEndian.Uint32(r.buf[pos : pos+4]))
	start := pos + 4
	if length == 0 || start+length > len(r.buf) {
		return nil
	}
	return append([]byte{}, r.buf[start:start+length]...)
}

// fourCharAttr reads a 4-byte FourCC attribute by name.
func (r *record) fourCharAttr(name string) string {
	pos := r.attrOffset(name)
	if pos < 0 || pos+4 > len(r.buf) {
		return ""
	}
	return strings.TrimRight(string(r.buf[pos:pos+4]), "\x00")
}
