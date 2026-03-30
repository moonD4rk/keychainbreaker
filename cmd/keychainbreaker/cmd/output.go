package cmd

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/moond4rk/keychainbreaker"
)

type dumpOutput struct {
	GenericPasswords  []genericPassword  `json:"generic_passwords,omitempty"`
	InternetPasswords []internetPassword `json:"internet_passwords,omitempty"`
	PrivateKeys       []privateKey       `json:"private_keys,omitempty"`
	Certificates      []certificate      `json:"certificates,omitempty"`
}

type genericPassword struct {
	Service        string `json:"service,omitempty"`
	Account        string `json:"account,omitempty"`
	Password       string `json:"password,omitempty"`        //nolint:gosec // not a credential
	HexPassword    string `json:"hex_password,omitempty"`    //nolint:gosec // not a credential
	Base64Password string `json:"base64_password,omitempty"` //nolint:gosec // not a credential
	Description    string `json:"description,omitempty"`
	Comment        string `json:"comment,omitempty"`
	Creator        string `json:"creator,omitempty"`
	Type           string `json:"type,omitempty"`
	PrintName      string `json:"print_name,omitempty"`
	Alias          string `json:"alias,omitempty"`
	CreatedAt      string `json:"created_at,omitempty"`
	ModifiedAt     string `json:"modified_at,omitempty"`
}

type internetPassword struct {
	Server         string `json:"server,omitempty"`
	Port           uint32 `json:"port,omitempty"`
	Protocol       string `json:"protocol,omitempty"`
	Account        string `json:"account,omitempty"`
	Password       string `json:"password,omitempty"`        //nolint:gosec // not a credential
	HexPassword    string `json:"hex_password,omitempty"`    //nolint:gosec // not a credential
	Base64Password string `json:"base64_password,omitempty"` //nolint:gosec // not a credential
	SecurityDomain string `json:"security_domain,omitempty"`
	AuthType       string `json:"auth_type,omitempty"`
	Path           string `json:"path,omitempty"`
	Description    string `json:"description,omitempty"`
	Comment        string `json:"comment,omitempty"`
	Creator        string `json:"creator,omitempty"`
	Type           string `json:"type,omitempty"`
	PrintName      string `json:"print_name,omitempty"`
	Alias          string `json:"alias,omitempty"`
	CreatedAt      string `json:"created_at,omitempty"`
	ModifiedAt     string `json:"modified_at,omitempty"`
}

type privateKey struct {
	Name       string `json:"name,omitempty"`
	PrintName  string `json:"print_name,omitempty"`
	Label      string `json:"label,omitempty"`
	KeyClass   uint32 `json:"key_class,omitempty"`
	KeyType    uint32 `json:"key_type,omitempty"`
	KeySize    uint32 `json:"key_size,omitempty"`
	DataHex    string `json:"data_hex,omitempty"`
	DataBase64 string `json:"data_base64,omitempty"`
}

type certificate struct {
	PrintName  string `json:"print_name,omitempty"`
	Type       uint32 `json:"type,omitempty"`
	Encoding   uint32 `json:"encoding,omitempty"`
	Subject    string `json:"subject,omitempty"`
	Issuer     string `json:"issuer,omitempty"`
	Serial     string `json:"serial,omitempty"`
	DataHex    string `json:"data_hex,omitempty"`
	DataBase64 string `json:"data_base64,omitempty"`
}

func formatTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.Format(time.RFC3339)
}

func buildDumpOutput(
	gps []keychainbreaker.GenericPassword,
	ips []keychainbreaker.InternetPassword,
	pks []keychainbreaker.PrivateKey,
	certs []keychainbreaker.Certificate,
) dumpOutput {
	out := dumpOutput{}

	for i := range gps {
		out.GenericPasswords = append(out.GenericPasswords, genericPassword{
			Service:        gps[i].Service,
			Account:        gps[i].Account,
			Password:       string(gps[i].Password),
			HexPassword:    encodeHex(gps[i].Password),
			Base64Password: encodeBase64(gps[i].Password),
			Description:    gps[i].Description,
			Comment:        gps[i].Comment,
			Creator:        gps[i].Creator,
			Type:           gps[i].Type,
			PrintName:      gps[i].PrintName,
			Alias:          gps[i].Alias,
			CreatedAt:      formatTime(gps[i].Created),
			ModifiedAt:     formatTime(gps[i].Modified),
		})
	}

	for i := range ips {
		out.InternetPasswords = append(out.InternetPasswords, internetPassword{
			Server:         ips[i].Server,
			Port:           ips[i].Port,
			Protocol:       ips[i].Protocol,
			Account:        ips[i].Account,
			Password:       string(ips[i].Password),
			HexPassword:    encodeHex(ips[i].Password),
			Base64Password: encodeBase64(ips[i].Password),
			SecurityDomain: ips[i].SecurityDomain,
			AuthType:       ips[i].AuthType,
			Path:           ips[i].Path,
			Description:    ips[i].Description,
			Comment:        ips[i].Comment,
			Creator:        ips[i].Creator,
			Type:           ips[i].Type,
			PrintName:      ips[i].PrintName,
			Alias:          ips[i].Alias,
			CreatedAt:      formatTime(ips[i].Created),
			ModifiedAt:     formatTime(ips[i].Modified),
		})
	}

	for i := range pks {
		out.PrivateKeys = append(out.PrivateKeys, privateKey{
			Name:       pks[i].Name,
			PrintName:  pks[i].PrintName,
			Label:      pks[i].Label,
			KeyClass:   pks[i].KeyClass,
			KeyType:    pks[i].KeyType,
			KeySize:    pks[i].KeySize,
			DataHex:    encodeHex(pks[i].Data),
			DataBase64: encodeBase64(pks[i].Data),
		})
	}

	for i := range certs {
		out.Certificates = append(out.Certificates, certificate{
			PrintName:  certs[i].PrintName,
			Type:       certs[i].Type,
			Encoding:   certs[i].Encoding,
			Subject:    encodeBase64(certs[i].Subject),
			Issuer:     encodeBase64(certs[i].Issuer),
			Serial:     encodeHex(certs[i].Serial),
			DataHex:    encodeHex(certs[i].Data),
			DataBase64: encodeBase64(certs[i].Data),
		})
	}

	return out
}

func encodeHex(data []byte) string {
	if data == nil {
		return ""
	}
	return hex.EncodeToString(data)
}

func encodeBase64(data []byte) string {
	if data == nil {
		return ""
	}
	return base64.StdEncoding.EncodeToString(data)
}

func writeJSONFile(path string, v interface{}) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create output file: %w", err)
	}
	defer f.Close()

	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return fmt.Errorf("encode JSON: %w", err)
	}
	return nil
}

func printDumpSummary(
	gps []keychainbreaker.GenericPassword,
	ips []keychainbreaker.InternetPassword,
	pks []keychainbreaker.PrivateKey,
	certs []keychainbreaker.Certificate,
	unlocked bool,
	outputPath string,
) {
	suffix := ""
	if !unlocked {
		suffix = " (metadata only)"
	}
	fmt.Fprintf(os.Stderr, "Extracted:\n")
	fmt.Fprintf(os.Stderr, "  Generic passwords:  %d%s\n", len(gps), suffix)
	fmt.Fprintf(os.Stderr, "  Internet passwords: %d%s\n", len(ips), suffix)
	fmt.Fprintf(os.Stderr, "  Private keys:       %d%s\n", len(pks), suffix)
	fmt.Fprintf(os.Stderr, "  Certificates:       %d\n", len(certs))
	fmt.Fprintf(os.Stderr, "Output: %s\n", outputPath)
}
