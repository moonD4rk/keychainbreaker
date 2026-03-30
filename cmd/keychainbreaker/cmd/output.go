package cmd

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/moond4rk/keychainbreaker"
)

type dumpOutput struct {
	GenericPasswords  []keychainbreaker.GenericPassword  `json:"generic_passwords,omitempty"`
	InternetPasswords []keychainbreaker.InternetPassword `json:"internet_passwords,omitempty"`
	PrivateKeys       []keychainbreaker.PrivateKey       `json:"private_keys,omitempty"`
	Certificates      []keychainbreaker.Certificate      `json:"certificates,omitempty"`
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
