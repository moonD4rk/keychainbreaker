package keychainbreaker

import (
	"encoding/binary"
	"fmt"
)

// Attribute format constants from Apple's CSSM framework.
const (
	attrFormatString    = 0
	attrFormatSInt32    = 1
	attrFormatUInt32    = 2
	attrFormatTimeDate  = 5
	attrFormatBlob      = 6
	attrFormatMultiUInt = 7
)

// attrDef describes a single attribute in a table schema.
type attrDef struct {
	name   string // 4-char code like "svce", "acct", or descriptive name
	format uint32 // one of attrFormat* constants
}

// tableSchema describes the attributes for a specific table type.
type tableSchema struct {
	tableID  uint32
	attrs    []attrDef
	indexMap map[string]int // name -> index cache, built lazily
}

// attrIndex returns the index of the named attribute, or -1 if not found.
func (ts *tableSchema) attrIndex(name string) int {
	if ts.indexMap == nil {
		ts.indexMap = make(map[string]int, len(ts.attrs))
		for i, a := range ts.attrs {
			ts.indexMap[a.name] = i
		}
	}
	idx, ok := ts.indexMap[name]
	if !ok {
		return -1
	}
	return idx
}

// dbSchema holds schemas for all discovered tables.
type dbSchema struct {
	tables map[uint32]*tableSchema
}

func (ds *dbSchema) forTable(tableID uint32) *tableSchema {
	if ds == nil {
		return nil
	}
	return ds.tables[tableID]
}

// Bootstrap schemas for SchemaInfo and SchemaAttributes.
// These two tables must be parsed with hardcoded schemas because they are
// needed to discover the schemas of all other tables.

var schemaInfoBootstrap = &tableSchema{
	tableID: tableSchemaInfo,
	attrs: []attrDef{
		{name: "RelationID", format: attrFormatUInt32},
		{name: "AttributeNameFormat", format: attrFormatUInt32},
		{name: "AttributeID", format: attrFormatUInt32},
		{name: "AttributeNameID", format: attrFormatUInt32},
	},
}

var schemaAttributesBootstrap = &tableSchema{
	tableID: tableSchemaAttributes,
	attrs: []attrDef{
		{name: "RelationID", format: attrFormatUInt32},
		{name: "AttributeID", format: attrFormatUInt32},
		{name: "AttributeNameFormat", format: attrFormatUInt32},
		{name: "AttributeNameID", format: attrFormatUInt32},
		{name: "AttributeFormat", format: attrFormatUInt32},
	},
}

// buildSchema reads SchemaAttributes records to discover the schema for all tables.
func buildSchema(buf []byte, tables map[uint32]*tableInfo) (*dbSchema, error) {
	ds := &dbSchema{
		tables: map[uint32]*tableSchema{
			tableSchemaInfo:       schemaInfoBootstrap,
			tableSchemaAttributes: schemaAttributesBootstrap,
		},
	}

	saTable, ok := tables[tableSchemaAttributes]
	if !ok {
		return nil, fmt.Errorf("SchemaAttributes table (0x%08X) not found", tableSchemaAttributes)
	}

	// Collect attribute definitions grouped by RelationID.
	attrsByTable := make(map[uint32][]attrDef)

	for _, recOffset := range saTable.recordOffsets {
		absOffset := saTable.baseOffset + int(recOffset)
		rec, err := parseRecord(buf, absOffset, schemaAttributesBootstrap)
		if err != nil {
			continue
		}

		relationID := rec.uint32Attr("RelationID")
		if relationID == 0 {
			continue
		}

		attrFormat := rec.uint32Attr("AttributeFormat")

		// Use AttributeID as the attribute name. In Apple's CSSM,
		// AttributeID is typically a 4-char code (e.g. 0x73766365 = "svce").
		attrID := rec.uint32Attr("AttributeID")
		name := uint32ToFourCC(attrID)

		// If FourCC is not printable, try AttributeNameID as a string.
		if !isPrintableFourCC(name) {
			name = rec.stringAttr("AttributeNameID")
		}
		if name == "" || name == "\x00\x00\x00\x00" {
			name = fmt.Sprintf("attr_0x%08x", attrID)
		}

		attrsByTable[relationID] = append(attrsByTable[relationID], attrDef{
			name:   name,
			format: attrFormat,
		})
	}

	for tableID, attrs := range attrsByTable {
		ds.tables[tableID] = &tableSchema{
			tableID: tableID,
			attrs:   attrs,
		}
	}

	return ds, nil
}

// uint32ToFourCC converts a uint32 to a 4-character string.
func uint32ToFourCC(v uint32) string {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, v)
	return string(b)
}

// isPrintableFourCC returns true if all 4 bytes are printable ASCII.
func isPrintableFourCC(s string) bool {
	if len(s) != 4 {
		return false
	}
	for i := 0; i < 4; i++ {
		if s[i] < 0x20 || s[i] > 0x7E {
			return false
		}
	}
	return true
}
