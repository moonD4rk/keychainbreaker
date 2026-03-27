package keychainbreaker

import "time"

// GenericPassword represents a decrypted generic password record.
type GenericPassword struct {
	Service     string
	Account     string
	Password    []byte `json:"-"` // raw decrypted bytes; caller decides encoding
	Description string
	Comment     string
	Creator     string
	Type        string
	PrintName   string
	Alias       string
	Created     time.Time
	Modified    time.Time
}

// PrivateKey represents a decrypted private key record.
type PrivateKey struct {
	Name      string // first 12 bytes of decrypted data
	Data      []byte // raw private key material
	PrintName string
	Label     string
	KeyClass  uint32
	KeyType   uint32
	KeySize   uint32
}

// Certificate represents an X.509 certificate record.
type Certificate struct {
	Data      []byte // raw DER-encoded certificate
	Type      uint32
	Encoding  uint32
	PrintName string
	Subject   []byte
	Issuer    []byte
	Serial    []byte
}

// InternetPassword represents a decrypted internet password record.
type InternetPassword struct {
	Server         string
	Account        string
	Password       []byte `json:"-"` // raw decrypted bytes; caller decides encoding
	SecurityDomain string
	Protocol       string
	AuthType       string
	Port           uint32
	Path           string
	Description    string
	Comment        string
	Creator        string
	Type           string
	PrintName      string
	Alias          string
	Created        time.Time
	Modified       time.Time
}
