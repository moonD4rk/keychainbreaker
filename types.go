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
