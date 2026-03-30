package keychainbreaker

import "time"

// GenericPassword represents a generic password record.
type GenericPassword struct {
	Service        string    `json:"service,omitempty"`
	Account        string    `json:"account,omitempty"`
	Password       []byte    `json:"-"`
	PlainPassword  string    `json:"password,omitempty"` //nolint:gosec // intentional credential export
	HexPassword    string    `json:"hex_password,omitempty"`
	Base64Password string    `json:"base64_password,omitempty"`
	Description    string    `json:"description,omitempty"`
	Comment        string    `json:"comment,omitempty"`
	Creator        string    `json:"creator,omitempty"`
	Type           string    `json:"type,omitempty"`
	PrintName      string    `json:"print_name,omitempty"`
	Alias          string    `json:"alias,omitempty"`
	Created        time.Time `json:"created_at,omitempty"`
	Modified       time.Time `json:"modified_at,omitempty"`
}

// InternetPassword represents an internet password record.
type InternetPassword struct {
	Server         string    `json:"server,omitempty"`
	Account        string    `json:"account,omitempty"`
	Password       []byte    `json:"-"`
	PlainPassword  string    `json:"password,omitempty"` //nolint:gosec // intentional credential export
	HexPassword    string    `json:"hex_password,omitempty"`
	Base64Password string    `json:"base64_password,omitempty"`
	SecurityDomain string    `json:"security_domain,omitempty"`
	Protocol       string    `json:"protocol,omitempty"`
	AuthType       string    `json:"auth_type,omitempty"`
	Port           uint32    `json:"port,omitempty"`
	Path           string    `json:"path,omitempty"`
	Description    string    `json:"description,omitempty"`
	Comment        string    `json:"comment,omitempty"`
	Creator        string    `json:"creator,omitempty"`
	Type           string    `json:"type,omitempty"`
	PrintName      string    `json:"print_name,omitempty"`
	Alias          string    `json:"alias,omitempty"`
	Created        time.Time `json:"created_at,omitempty"`
	Modified       time.Time `json:"modified_at,omitempty"`
}

// PrivateKey represents a private key record.
type PrivateKey struct {
	Name       string `json:"name,omitempty"`
	Data       []byte `json:"-"`
	DataHex    string `json:"data_hex,omitempty"`
	DataBase64 string `json:"data_base64,omitempty"`
	PrintName  string `json:"print_name,omitempty"`
	Label      string `json:"label,omitempty"`
	KeyClass   uint32 `json:"key_class,omitempty"`
	KeyType    uint32 `json:"key_type,omitempty"`
	KeySize    uint32 `json:"key_size,omitempty"`
}

// Certificate represents an X.509 certificate record.
type Certificate struct {
	Data       []byte `json:"-"`
	DataHex    string `json:"data_hex,omitempty"`
	DataBase64 string `json:"data_base64,omitempty"`
	Type       uint32 `json:"type,omitempty"`
	Encoding   uint32 `json:"encoding,omitempty"`
	PrintName  string `json:"print_name,omitempty"`
	Subject    []byte `json:"-"`
	SubjectHex string `json:"subject,omitempty"`
	Issuer     []byte `json:"-"`
	IssuerHex  string `json:"issuer,omitempty"`
	Serial     []byte `json:"-"`
	SerialHex  string `json:"serial,omitempty"`
}
