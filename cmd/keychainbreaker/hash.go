package main

import (
	"fmt"

	"github.com/spf13/cobra"
)

func newHashCmd(root *rootOptions) *cobra.Command {
	var file string
	cmd := &cobra.Command{
		Use:   "hash",
		Short: "Print the keychain password hash for offline cracking",
		Long: `Print the keychain password hash in the format hashcat (mode 23100) and
John the Ripper accept. No password is needed.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			kc, err := openKeychain(cmd, root, file)
			if err != nil {
				return err
			}
			hash, err := kc.PasswordHash()
			if err != nil {
				return err
			}
			_, err = fmt.Fprintln(cmd.OutOrStdout(), hash)
			return err
		},
	}
	cmd.Flags().StringVarP(&file, "file", "f", "", fileFlagUsage)
	return cmd
}
