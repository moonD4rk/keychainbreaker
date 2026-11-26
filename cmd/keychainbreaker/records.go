package main

import (
	"encoding/base64"
	"encoding/hex"
	"time"

	"github.com/moond4rk/keychainbreaker"
)

// dump is the JSON document the dump command writes.
type dump struct {
	GenericPasswords  []genericPassword  `json:"generic_passwords,omitempty"`
	InternetPasswords []internetPassword `json:"internet_passwords,omitempty"`
	PrivateKeys       []privateKey       `json:"private_keys,omitempty"`
	Certificates      []certificate      `json:"certificates,omitempty"`
}

type genericPassword struct {
	Service string `json:"service,omitempty"`
	Account string `json:"account,omitempty"`
	passwordText
	Description string    `json:"description,omitempty"`
	Comment     string    `json:"comment,omitempty"`
	Creator     string    `json:"creator,omitempty"`
	Type        string    `json:"type,omitempty"`
	PrintName   string    `json:"print_name,omitempty"`
	Alias       string    `json:"alias,omitempty"`
	Created     time.Time `json:"created_at,omitzero"`
	Modified    time.Time `json:"modified_at,omitzero"`
}

type internetPassword struct {
	Server  string `json:"server,omitempty"`
	Account string `json:"account,omitempty"`
	passwordText
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
	Created        time.Time `json:"created_at,omitzero"`
	Modified       time.Time `json:"modified_at,omitzero"`
}

type privateKey struct {
	blobText
	PrintName string `json:"print_name,omitempty"`
	LabelHex  string `json:"label_hex,omitempty"`
	KeyClass  uint32 `json:"key_class,omitempty"`
	KeyType   uint32 `json:"key_type,omitempty"`
	KeySize   uint32 `json:"key_size,omitempty"`
}

type certificate struct {
	blobText
	Type       uint32 `json:"type,omitempty"`
	Encoding   uint32 `json:"encoding,omitempty"`
	PrintName  string `json:"print_name,omitempty"`
	SubjectHex string `json:"subject_hex,omitempty"`
	IssuerHex  string `json:"issuer_hex,omitempty"`
	SerialHex  string `json:"serial_hex,omitempty"`
}

// passwordText carries hex and base64 next to the text because a secret need not be valid UTF-8.
type passwordText struct {
	Password       string `json:"password,omitempty"` //nolint:gosec // exporting credentials is the point of a dump
	HexPassword    string `json:"hex_password,omitempty"`
	Base64Password string `json:"base64_password,omitempty"`
}

type blobText struct {
	DataHex    string `json:"data_hex,omitempty"`
	DataBase64 string `json:"data_base64,omitempty"`
}

func newPasswordText(b []byte) passwordText {
	if len(b) == 0 {
		return passwordText{}
	}
	return passwordText{
		Password:       string(b),
		HexPassword:    hex.EncodeToString(b),
		Base64Password: base64.StdEncoding.EncodeToString(b),
	}
}

func newBlobText(b []byte) blobText {
	if len(b) == 0 {
		return blobText{}
	}
	return blobText{
		DataHex:    hex.EncodeToString(b),
		DataBase64: base64.StdEncoding.EncodeToString(b),
	}
}

func convert[T, U any](records []T, fn func(*T) U) []U {
	out := make([]U, 0, len(records))
	for i := range records {
		out = append(out, fn(&records[i]))
	}
	return out
}

func newGenericPassword(p *keychainbreaker.GenericPassword) genericPassword {
	return genericPassword{
		Service:      p.Service,
		Account:      p.Account,
		passwordText: newPasswordText(p.Password),
		Description:  p.Description,
		Comment:      p.Comment,
		Creator:      p.Creator,
		Type:         p.Type,
		PrintName:    p.PrintName,
		Alias:        p.Alias,
		Created:      p.Created,
		Modified:     p.Modified,
	}
}

func newInternetPassword(p *keychainbreaker.InternetPassword) internetPassword {
	return internetPassword{
		Server:         p.Server,
		Account:        p.Account,
		passwordText:   newPasswordText(p.Password),
		SecurityDomain: p.SecurityDomain,
		Protocol:       p.Protocol,
		AuthType:       p.AuthType,
		Port:           p.Port,
		Path:           p.Path,
		Description:    p.Description,
		Comment:        p.Comment,
		Creator:        p.Creator,
		Type:           p.Type,
		PrintName:      p.PrintName,
		Alias:          p.Alias,
		Created:        p.Created,
		Modified:       p.Modified,
	}
}

func newPrivateKey(k *keychainbreaker.PrivateKey) privateKey {
	return privateKey{
		blobText:  newBlobText(k.Data),
		PrintName: k.PrintName,
		LabelHex:  hex.EncodeToString(k.Label),
		KeyClass:  k.KeyClass,
		KeyType:   k.KeyType,
		KeySize:   k.KeySize,
	}
}

func newCertificate(c *keychainbreaker.Certificate) certificate {
	return certificate{
		blobText:   newBlobText(c.Data),
		Type:       c.Type,
		Encoding:   c.Encoding,
		PrintName:  c.PrintName,
		SubjectHex: hex.EncodeToString(c.Subject),
		IssuerHex:  hex.EncodeToString(c.Issuer),
		SerialHex:  hex.EncodeToString(c.Serial),
	}
}
