package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

// NewHashCmd creates the hash subcommand.
func NewHashCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "hash",
		Short: "Print password hash for offline cracking (no unlock needed)",
		Long: `Export the keychain password hash in a format compatible with
hashcat mode 23100 and John the Ripper. No password required.`,
		RunE: runHash,
	}
}

func runHash(cmd *cobra.Command, _ []string) error {
	kc, err := openKeychain(cmd)
	if err != nil {
		return err
	}

	hash, err := kc.PasswordHash()
	if err != nil {
		return err
	}

	fmt.Fprintln(cmd.OutOrStdout(), hash)
	return nil
}
