package keychainbreaker

import (
	"encoding/binary"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The bootstrap schema once listed five SchemaAttributes columns instead of six, so every format read as 0 and
// AuthType came back as its length prefix.
func TestAttachSchemasReadsFormats(t *testing.T) {
	kc := openTestKeychain(t)
	tests := []struct {
		table  uint32
		attr   string
		format uint32
	}{
		{tableGenericPassword, attrService, formatBlob},
		{tableGenericPassword, attrPrintName, formatBlob},
		{tableGenericPassword, attrCreated, formatTimeDate},
		{tableGenericPassword, attrCreator, formatUInt32},
		{tableInternetPassword, attrAuthType, formatBlob},
		{tableInternetPassword, attrProtocol, formatUInt32},
		{tableInternetPassword, attrPort, formatUInt32},
		{tablePrivateKey, attrLabel, formatBlob},
		{tablePrivateKey, attrKeySizeInBits, formatUInt32},
		{tableX509Certificate, attrSubject, formatBlob},
	}
	for _, tt := range tests {
		schema := kc.tables[tt.table].schema
		require.NotNil(t, schema, tableName(tt.table))
		i, ok := schema.index[tt.attr]
		require.True(t, ok, "%s.%s", tableName(tt.table), tt.attr)
		assert.Equal(t, tt.format, schema.attrs[i].format, "%s.%s", tableName(tt.table), tt.attr)
	}
	assert.Len(t, kc.tables[tableGenericPassword].schema.attrs, 16)
}

func TestFourCC(t *testing.T) {
	assert.Equal(t, "svce", fourCC(0x73766365))
	assert.True(t, isPrintable("smb "))
	assert.False(t, isPrintable(""))
	assert.False(t, isPrintable("\x00\x00\x00\x07"))
}

// testRecord lays out one value per attribute the way a keychain record stores it, after a header of zeros.
func testRecord(t *testing.T, attrs []attrDef, values [][]byte) *record {
	t.Helper()
	require.Len(t, values, len(attrs))
	buf := make([]byte, (recordHeaderWords+len(attrs))*uint32Len)
	offsets := make([]uint32, len(attrs))
	for i, v := range values {
		if v == nil {
			continue
		}
		offsets[i] = uint32(len(buf)) + 1
		buf = append(buf, v...)
	}
	return &record{buf: buf, attrOffsets: offsets, schema: newTableSchema(attrs)}
}

func lengthPrefixed(s string) []byte {
	b := binary.BigEndian.AppendUint32(nil, uint32(len(s)))
	return append(b, s...)
}

func TestAttributeDecoding(t *testing.T) {
	rec := testRecord(t,
		[]attrDef{
			{name: "blob", format: formatBlob},
			{name: "string", format: formatString},
			{name: "code", format: formatUInt32},
			{name: "time", format: formatTimeDate},
			{name: "absent", format: formatBlob},
		},
		[][]byte{
			lengthPrefixed("dflt"),
			lengthPrefixed("name\x00\x00"),
			[]byte("htps"),
			[]byte("20260327153643Z\x00"),
			nil,
		})

	assert.Equal(t, "dflt", rec.textAttr("blob"))
	assert.Equal(t, []byte("dflt"), rec.bytesAttr("blob"))
	assert.Equal(t, "name", rec.textAttr("string"))
	assert.Equal(t, "htps", rec.textAttr("code"))
	assert.Equal(t, uint32(0x68747073), rec.uint32Attr("code"))
	assert.Equal(t, time.Date(2026, 3, 27, 15, 36, 43, 0, time.UTC), rec.timeAttr("time"))

	assert.Zero(t, rec.uint32Attr("blob"), "a blob is not an integer")
	assert.Nil(t, rec.bytesAttr("code"), "an integer is not a blob")
	assert.True(t, rec.timeAttr("blob").IsZero(), "a blob is not a time")
	assert.Empty(t, rec.textAttr("absent"))
	assert.Empty(t, rec.textAttr("unknown"))
}

func TestAttributeDecodingStaysInBounds(t *testing.T) {
	rec := testRecord(t, []attrDef{{name: "blob", format: formatBlob}}, [][]byte{{0xFF, 0xFF, 0xFF, 0xFF, 'x'}})
	assert.Empty(t, rec.textAttr("blob"))
	assert.Nil(t, rec.bytesAttr("blob"))

	rec.attrOffsets[0] = uint32(len(rec.buf)) + 10
	assert.Empty(t, rec.textAttr("blob"))
}
