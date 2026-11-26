package main

import (
	"github.com/spf13/cobra"
)

type rootOptions struct {
	verbose bool
}

// newRootCmd returns the keychainbreaker command with all of its subcommands.
func newRootCmd() *cobra.Command {
	opts := &rootOptions{}
	root := &cobra.Command{
		Use:   "keychainbreaker",
		Short: "Extract credentials from macOS Keychain files",
		Long: `keychainbreaker extracts passwords, private keys and certificates from
macOS Keychain files (login.keychain-db).`,
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.PersistentFlags().BoolVarP(&opts.verbose, "verbose", "v", false, "print diagnostics to stderr")
	root.AddCommand(
		newDumpCmd(opts),
		newHashCmd(opts),
		newVersionCmd(),
	)
	return root
}
