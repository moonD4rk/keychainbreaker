package keychainbreaker

import "time"

// GenericPassword is an application password, such as a browser's Safe Storage key or a Wi-Fi password.
type GenericPassword struct {
	Service string
	Account string
	// Password is nil while the keychain is locked and when the record cannot be decrypted. An empty password is an
	// empty, non-nil slice.
	Password    []byte
	Description string
	Comment     string
	Creator     string // four-character code
	Type        string // four-character code
	PrintName   string
	Alias       string
	Created     time.Time
	Modified    time.Time
}

// InternetPassword is a password for a network service, such as a website, a server or a file share.
type InternetPassword struct {
	Server  string
	Account string
	// Password is nil while the keychain is locked and when the record cannot be decrypted. An empty password is an
	// empty, non-nil slice.
	Password       []byte
	SecurityDomain string
	Protocol       string // four-character code, such as "htps" or "smb "
	AuthType       string // four-character code, such as "dflt"
	Port           uint32
	Path           string
	Description    string
	Comment        string
	Creator        string // four-character code
	Type           string // four-character code
	PrintName      string
	Alias          string
	Created        time.Time
	Modified       time.Time
}

// PrivateKey is a private key stored in the keychain.
type PrivateKey struct {
	// Data is the PKCS#8 key; it is nil while the keychain is locked and when the record cannot be decrypted.
	Data      []byte
	PrintName string
	Label     []byte // usually the SHA-1 hash of the public key
	KeyClass  uint32
	KeyType   uint32
	KeySize   uint32 // in bits
}

// Certificate is an X.509 certificate. Certificates are not encrypted, so they are complete even while the
// keychain is locked.
type Certificate struct {
	Data      []byte // DER-encoded certificate
	Type      uint32
	Encoding  uint32
	PrintName string
	Subject   []byte // DER-encoded subject name
	Issuer    []byte // DER-encoded issuer name
	Serial    []byte
}
