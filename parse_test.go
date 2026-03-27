package keychainbreaker

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func readTestKeychain(t *testing.T) []byte {
	t.Helper()
	buf, err := os.ReadFile(testKeychainPath)
	require.NoError(t, err)
	return buf
}

func TestParseHeader(t *testing.T) {
	buf := readTestKeychain(t)
	hdr, err := parseHeader(buf)
	require.NoError(t, err)

	assert.Equal(t, "kych", string(hdr.signature[:]))
	assert.Equal(t, uint32(0x00010000), hdr.version)
	assert.Equal(t, uint32(16), hdr.headerSize)
	assert.Equal(t, uint32(20), hdr.schemaOff)
}

func TestParseHeaderTooSmall(t *testing.T) {
	_, err := parseHeader([]byte{1, 2, 3})
	assert.Error(t, err)
}

func TestParseSchema(t *testing.T) {
	buf := readTestKeychain(t)
	hdr, err := parseHeader(buf)
	require.NoError(t, err)

	schema, offsets, err := parseSchema(buf, hdr.schemaOff)
	require.NoError(t, err)

	assert.Equal(t, uint32(12), schema.tableCount)
	assert.Len(t, offsets, 12)
}

func TestParseTable(t *testing.T) {
	buf := readTestKeychain(t)
	hdr, err := parseHeader(buf)
	require.NoError(t, err)

	_, offsets, err := parseSchema(buf, hdr.schemaOff)
	require.NoError(t, err)

	// Parse the first non-zero table.
	var table tableInfo
	var found bool
	for _, off := range offsets {
		if off == 0 {
			continue
		}
		table, err = parseTable(buf, headerSize+int(off))
		if err == nil {
			found = true
			break
		}
	}
	require.True(t, found, "no valid table found")
	assert.Positive(t, table.baseOffset)
}

func TestParseDBBlob(t *testing.T) {
	kc := openTestKeychain(t)

	blobBuf := kc.buf[kc.blobBaseAddr : kc.blobBaseAddr+dbBlobSize]
	blob, err := parseDBBlob(blobBuf)
	require.NoError(t, err)

	assert.Len(t, blob.salt, 20)
	assert.Len(t, blob.iv, 8)
	assert.Equal(t, uint32(120), blob.startCryptoBlob)
	assert.Equal(t, uint32(168), blob.totalLength)
}

func TestParseDBBlobTooSmall(t *testing.T) {
	_, err := parseDBBlob(make([]byte, 10))
	assert.Error(t, err)
}

func TestParseSSGP(t *testing.T) {
	// Build a valid SSGP: magic(4) + label(16) + iv(8) + encrypted data.
	var buf []byte
	buf = append(buf, "ssgp"...)             // magic
	buf = append(buf, "0123456789abcdef"...) // label (16 bytes)
	buf = append(buf, "iviviviv"...)         // iv (8 bytes)
	buf = append(buf, "encrypted"...)        // encrypted password

	block, err := parseSSGP(buf)
	require.NoError(t, err)

	assert.Equal(t, []byte("ssgp"), block.magic)
	assert.Equal(t, []byte("0123456789abcdef"), block.label)
	assert.Equal(t, []byte("iviviviv"), block.iv)
	assert.Equal(t, []byte("encrypted"), block.encryptedPassword)
}

func TestParseSSGPTooSmall(t *testing.T) {
	_, err := parseSSGP(make([]byte, 10))
	assert.Error(t, err)
}

func TestParseKeyBlob(t *testing.T) {
	// Build a minimal valid key blob: magic(4) + unk(4) + startCrypto(4) + totalLen(4) + iv(8) = 24.
	buf := make([]byte, keyBlobLen)
	buf[0] = 0xFA
	buf[1] = 0xDE
	buf[2] = 0x07
	buf[3] = 0x11
	// startCryptoBlob at offset 8
	buf[11] = 0x10
	// totalLength at offset 12
	buf[15] = 0x20

	blob, err := parseKeyBlob(buf)
	require.NoError(t, err)

	assert.Equal(t, uint32(keyBlobMagic), blob.magic)
	assert.Equal(t, uint32(0x10), blob.startCryptoBlob)
	assert.Equal(t, uint32(0x20), blob.totalLength)
	assert.Len(t, blob.iv, 8)
}

func TestParseKeyBlobTooSmall(t *testing.T) {
	_, err := parseKeyBlob(make([]byte, 10))
	assert.Error(t, err)
}

func TestRecordAttrOffset(t *testing.T) {
	schema := &tableSchema{
		attrs: []attrDef{
			{name: "first"},
			{name: "second"},
		},
	}
	rec := &record{
		attrOffsets: []uint32{0, 42},
		schema:      schema,
	}

	assert.Equal(t, -1, rec.attrOffset("first"))   // offset 0 means empty
	assert.Equal(t, 41, rec.attrOffset("second"))  // 42-1 = 41 (1-based to 0-based)
	assert.Equal(t, -1, rec.attrOffset("missing")) // not in schema
}
