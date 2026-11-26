package keychainbreaker

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"time"
)

// Attribute formats (CSSM_DB_ATTRIBUTE_FORMAT).
const (
	formatString   uint32 = 0
	formatSInt32   uint32 = 1
	formatUInt32   uint32 = 2
	formatTimeDate uint32 = 5
	formatBlob     uint32 = 6
)

// Attribute names. Most are four-character codes; PrintName, Alias and the key attributes are names.
const (
	attrService        = "svce"
	attrAccount        = "acct"
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
	attrCertLabel      = "labl" // the certificate table's print name
	attrSubject        = "subj"
	attrIssuer         = "issu"
	attrSerial         = "snbr"
)

type attrDef struct {
	name   string
	format uint32
}

// tableSchema lists a table's attributes in record order. It is immutable once built, so records of any keychain
// can share it across goroutines.
type tableSchema struct {
	attrs []attrDef
	index map[string]int
}

func newTableSchema(attrs []attrDef) *tableSchema {
	index := make(map[string]int, len(attrs))
	for i, a := range attrs {
		index[a.name] = i
	}
	return &tableSchema{attrs: attrs, index: index}
}

// schemaAttributesSchema describes the SchemaAttributes table, which holds the schema of every other table.
var schemaAttributesSchema = newTableSchema([]attrDef{
	{name: "RelationID", format: formatUInt32},
	{name: "AttributeID", format: formatUInt32},
	{name: "AttributeNameFormat", format: formatUInt32},
	{name: "AttributeName", format: formatString},
	{name: "AttributeNameID", format: formatBlob},
	{name: "AttributeFormat", format: formatUInt32},
})

// attachSchemas reads the SchemaAttributes table and gives every table the schema of its records.
func attachSchemas(buf []byte, tables map[uint32]*table) error {
	meta, ok := tables[tableSchemaAttributes]
	if !ok {
		return fmt.Errorf("SchemaAttributes table (0x%08X) not found", tableSchemaAttributes)
	}
	meta.schema = schemaAttributesSchema

	attrs := make(map[uint32][]attrDef)
	for _, off := range meta.recordOffsets {
		rec, err := parseRecord(buf, meta.offset+int(off), meta.schema)
		if err != nil {
			continue
		}
		relation := rec.uint32Attr("RelationID")
		if relation == tableSchemaInfo {
			continue
		}
		attrs[relation] = append(attrs[relation], attrDef{
			name:   attrName(rec),
			format: rec.uint32Attr("AttributeFormat"),
		})
	}
	for id, defs := range attrs {
		if t, ok := tables[id]; ok {
			t.schema = newTableSchema(defs)
		}
	}
	return nil
}

// attrName prefers the four-character code in AttributeID and falls back to the AttributeName string.
func attrName(rec *record) string {
	id := rec.uint32Attr("AttributeID")
	if code := fourCC(id); isPrintable(code) {
		return code
	}
	if name := rec.textAttr("AttributeName"); name != "" {
		return name
	}
	return fmt.Sprintf("attr_0x%08x", id)
}

func fourCC(v uint32) string {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], v)
	return string(b[:])
}

func isPrintable(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7E {
			return false
		}
	}
	return s != ""
}

// attr returns the schema entry of the named attribute and the offset of its value in the record.
func (r *record) attr(name string) (attrDef, int, bool) {
	i, ok := r.schema.index[name]
	if !ok || i >= len(r.attrOffsets) || r.attrOffsets[i] == 0 {
		return attrDef{}, 0, false
	}
	return r.schema.attrs[i], int(r.attrOffsets[i]) - 1, true
}

// lengthPrefixed returns the value of a string or blob attribute, which is stored after its length.
func (r *record) lengthPrefixed(pos int) []byte {
	n, ok := readUint32(r.buf, pos)
	if !ok {
		return nil
	}
	b, _ := span(r.buf, pos+uint32Len, int(n))
	return b
}

// bytesAttr returns a copy of a string or blob attribute, or nil when the record has none.
func (r *record) bytesAttr(name string) []byte {
	def, pos, ok := r.attr(name)
	if !ok || (def.format != formatString && def.format != formatBlob) {
		return nil
	}
	b := r.lengthPrefixed(pos)
	if len(b) == 0 {
		return nil
	}
	return bytes.Clone(b)
}

// textAttr returns a string or blob attribute as text, or an integer attribute as its four-character code.
func (r *record) textAttr(name string) string {
	def, pos, ok := r.attr(name)
	if !ok {
		return ""
	}
	var b []byte
	switch def.format {
	case formatString, formatBlob:
		b = r.lengthPrefixed(pos)
	case formatUInt32, formatSInt32:
		b, _ = span(r.buf, pos, uint32Len)
	}
	return string(bytes.TrimRight(b, "\x00"))
}

func (r *record) uint32Attr(name string) uint32 {
	def, pos, ok := r.attr(name)
	if !ok || (def.format != formatUInt32 && def.format != formatSInt32) {
		return 0
	}
	v, _ := readUint32(r.buf, pos)
	return v
}

// timeAttr parses a TimeDate attribute, stored as "YYYYMMDDhhmmssZ" and padded with NUL bytes.
func (r *record) timeAttr(name string) time.Time {
	def, pos, ok := r.attr(name)
	if !ok || def.format != formatTimeDate {
		return time.Time{}
	}
	b, ok := span(r.buf, pos, timeDateLen)
	if !ok {
		return time.Time{}
	}
	t, err := time.Parse("20060102150405Z", string(bytes.TrimRight(b, "\x00")))
	if err != nil {
		return time.Time{}
	}
	return t
}
