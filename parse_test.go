package keychainbreaker

import (
	"encoding/binary"
	"math"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSpan(t *testing.T) {
	buf := []byte("0123456789")
	tests := []struct {
		name   string
		off, n int
		want   string
		ok     bool
	}{
		{name: "inside", off: 2, n: 3, want: "234", ok: true},
		{name: "to the end", off: 7, n: 3, want: "789", ok: true},
		{name: "empty at the end", off: 10, n: 0, want: "", ok: true},
		{name: "past the end", off: 8, n: 3},
		{name: "negative offset", off: -1, n: 2},
		{name: "negative length", off: 2, n: -1},
		{name: "length overflow", off: 2, n: math.MaxInt},
		{name: "offset overflow", off: math.MaxInt, n: 1},
	}
	for _, tt := range tests {
		got, ok := span(buf, tt.off, tt.n)
		assert.Equal(t, tt.ok, ok, tt.name)
		assert.Equal(t, tt.want, string(got), tt.name)
	}
}

func TestParseFileHeader(t *testing.T) {
	header, err := parseFileHeader(readTestKeychain(t))
	require.NoError(t, err)
	assert.Equal(t, keychainSignature, string(header.signature[:]))
	assert.Equal(t, uint32(0x00010000), header.version)
	assert.Equal(t, uint32(fileHeaderLen), header.tableDirectoryOffset)

	_, err = parseFileHeader([]byte{1, 2, 3})
	assert.Error(t, err)
}

func TestParseTableDirectory(t *testing.T) {
	buf := readTestKeychain(t)
	offsets, err := parseTableDirectory(buf, fileHeaderLen)
	require.NoError(t, err)
	assert.Len(t, offsets, 12)
	for _, off := range offsets {
		table, parseErr := parseTable(buf, off)
		require.NoError(t, parseErr)
		assert.Equal(t, off, table.offset)
	}

	binary.BigEndian.PutUint32(buf[fileHeaderLen+uint32Len:], math.MaxUint32)
	_, err = parseTableDirectory(buf, fileHeaderLen)
	require.Error(t, err)

	_, err = parseTableDirectory(buf, math.MaxUint32)
	assert.Error(t, err)
}

func TestParseTableCapsRecordCount(t *testing.T) {
	buf := make([]byte, tableHeaderLen+2*uint32Len)
	binary.BigEndian.PutUint32(buf[4:], tableGenericPassword)
	binary.BigEndian.PutUint32(buf[8:], math.MaxUint32)
	binary.BigEndian.PutUint32(buf[tableHeaderLen:], 8)
	binary.BigEndian.PutUint32(buf[tableHeaderLen+uint32Len:], 3) // not 4-byte aligned, ignored

	table, err := parseTable(buf, 0)
	require.NoError(t, err)
	assert.Equal(t, tableGenericPassword, table.id)
	assert.Equal(t, []uint32{8}, table.recordOffsets)

	_, err = parseTable(buf, len(buf))
	assert.Error(t, err)
}

func TestParseDBBlob(t *testing.T) {
	kc := openTestKeychain(t)
	blob, err := parseDBBlob(kc.buf, kc.dbBlobOffset)
	require.NoError(t, err)
	assert.Equal(t, uint32(keyBlobMagic), blob.magic)
	assert.Equal(t, blobVersionV1, blob.version)
	assert.Equal(t, uint32(120), blob.cryptoStart)
	assert.Equal(t, uint32(168), blob.totalLength)
	assert.Len(t, blob.salt, 20)
	assert.Len(t, blob.iv, 8)

	_, err = parseDBBlob(kc.buf, len(kc.buf)-dbBlobLen+1)
	assert.Error(t, err)
}

func TestParseSSGP(t *testing.T) {
	buf := []byte("ssgp0123456789abcdefiviviviv" + "encrypted")
	block, err := parseSSGP(buf)
	require.NoError(t, err)
	assert.Equal(t, []byte("ssgp0123456789abcdef"), block.label)
	assert.Equal(t, []byte("iviviviv"), block.iv)
	assert.Equal(t, []byte("encrypted"), block.ciphertext)

	_, err = parseSSGP(buf[:ssgpHeaderLen-1])
	require.Error(t, err)
	_, err = parseSSGP([]byte("nope0123456789abcdefiviviviv"))
	assert.Error(t, err)
}

func TestParseKeyBlobHeader(t *testing.T) {
	buf := make([]byte, keyBlobHeaderLen+8)
	binary.BigEndian.PutUint32(buf[0:], keyBlobMagic)
	binary.BigEndian.PutUint32(buf[8:], keyBlobHeaderLen)
	binary.BigEndian.PutUint32(buf[12:], keyBlobHeaderLen+8)
	copy(buf[16:], "iviviviv")
	copy(buf[keyBlobHeaderLen:], "wrapped!")

	header, err := parseKeyBlobHeader(buf)
	require.NoError(t, err)
	assert.Equal(t, []byte("iviviviv"), header.iv)
	wrapped, err := header.ciphertext(buf)
	require.NoError(t, err)
	assert.Equal(t, []byte("wrapped!"), wrapped)

	header.totalLength = uint32(len(buf) + 1)
	_, err = header.ciphertext(buf)
	require.Error(t, err)
	header.totalLength = header.cryptoStart
	_, err = header.ciphertext(buf)
	require.Error(t, err)

	_, err = parseKeyBlobHeader(buf[:keyBlobHeaderLen-1])
	require.Error(t, err)
	buf[0] = 0
	_, err = parseKeyBlobHeader(buf)
	assert.Error(t, err)
}

func TestParseRecordRejectsBadSizes(t *testing.T) {
	schema := newTableSchema([]attrDef{{name: "a", format: formatUInt32}})
	buf := make([]byte, 64)

	_, err := parseRecord(buf, 0, schema)
	require.Error(t, err, "zero size")

	binary.BigEndian.PutUint32(buf, 65)
	_, err = parseRecord(buf, 0, schema)
	require.Error(t, err, "size past the end")

	binary.BigEndian.PutUint32(buf, 8)
	_, err = parseRecord(buf, 0, schema)
	require.Error(t, err, "size smaller than the header")

	_, err = parseRecord(buf, len(buf), schema)
	assert.Error(t, err, "offset past the end")
}
