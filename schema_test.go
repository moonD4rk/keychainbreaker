package keychainbreaker

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildSchema(t *testing.T) {
	kc := openTestKeychain(t)

	// Schema should discover multiple tables.
	assert.Greater(t, len(kc.schema.tables), 3)

	// GenericPassword table should have known attributes.
	gpSchema := kc.schema.forTable(tableGenericPassword)
	require.NotNil(t, gpSchema)
	assert.Greater(t, len(gpSchema.attrs), 10)
	assert.GreaterOrEqual(t, gpSchema.attrIndex(attrServiceName), 0)
	assert.GreaterOrEqual(t, gpSchema.attrIndex(attrAccountName), 0)
	assert.GreaterOrEqual(t, gpSchema.attrIndex(attrPrintName), 0)

	// InternetPassword table should have server/protocol/port.
	ipSchema := kc.schema.forTable(tableInternetPassword)
	require.NotNil(t, ipSchema)
	assert.GreaterOrEqual(t, ipSchema.attrIndex(attrServer), 0)
	assert.GreaterOrEqual(t, ipSchema.attrIndex(attrProtocol), 0)
	assert.GreaterOrEqual(t, ipSchema.attrIndex(attrPort), 0)

	// SymmetricKey table should exist with attributes.
	skSchema := kc.schema.forTable(tableSymmetricKey)
	require.NotNil(t, skSchema)
	assert.Greater(t, len(skSchema.attrs), 20)
}

func TestAttrIndex(t *testing.T) {
	schema := &tableSchema{
		attrs: []attrDef{
			{name: "alpha"},
			{name: "beta"},
			{name: "gamma"},
		},
	}

	assert.Equal(t, 0, schema.attrIndex("alpha"))
	assert.Equal(t, 1, schema.attrIndex("beta"))
	assert.Equal(t, 2, schema.attrIndex("gamma"))
	assert.Equal(t, -1, schema.attrIndex("missing"))
}

func TestAttrIndexCache(t *testing.T) {
	schema := &tableSchema{
		attrs: []attrDef{
			{name: "one"},
			{name: "two"},
		},
	}

	// First call builds the cache.
	assert.Nil(t, schema.indexMap)
	_ = schema.attrIndex("one")
	assert.NotNil(t, schema.indexMap)

	// Second call uses the cache, same result.
	assert.Equal(t, 0, schema.attrIndex("one"))
	assert.Equal(t, 1, schema.attrIndex("two"))
}

func TestUint32ToFourCC(t *testing.T) {
	assert.Equal(t, "svce", uint32ToFourCC(0x73766365))
	assert.Equal(t, "acct", uint32ToFourCC(0x61636374))
	assert.Equal(t, "kych", uint32ToFourCC(0x6b796368))
}

func TestIsPrintableFourCC(t *testing.T) {
	assert.True(t, isPrintableFourCC("svce"))
	assert.True(t, isPrintableFourCC("acct"))
	assert.True(t, isPrintableFourCC("smb "))
	assert.False(t, isPrintableFourCC(""))
	assert.False(t, isPrintableFourCC("ab"))
	assert.False(t, isPrintableFourCC("\x00\x00\x00\x07"))
}

func TestForTableNil(t *testing.T) {
	var ds *dbSchema
	assert.Nil(t, ds.forTable(tableGenericPassword))
}
