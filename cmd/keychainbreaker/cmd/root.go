package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/moond4rk/keychainbreaker"
)

const (
	flagFile     = "file"
	flagPassword = "password"
	flagKey      = "key"
	flagOutput   = "output"
)

// NewRootCmd creates the root command with global flags.
func NewRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "keychainbreaker",
		Short: "Extract credentials from macOS Keychain files",
		Long: `keychainbreaker extracts credentials, keys, and certificates from
macOS Keychain files (login.keychain-db).`,
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	root.PersistentFlags().StringP(flagFile, "f", "",
		"keychain file path (default: ~/Library/Keychains/login.keychain-db)")
	root.PersistentFlags().StringP(flagPassword, "p", "",
		"keychain password (omit to be prompted)")
	root.PersistentFlags().StringP(flagKey, "k", "",
		"hex-encoded 24-byte master key")
	root.PersistentFlags().StringP(flagOutput, "o", "",
		"output file path (default: ./keychain_dump.json)")

	root.AddCommand(
		NewDumpCmd(),
		NewHashCmd(),
		NewVersionCmd(),
	)
	return root
}

func openKeychain(cmd *cobra.Command) (*keychainbreaker.Keychain, error) {
	file, _ := cmd.Flags().GetString(flagFile)
	var opts []keychainbreaker.OpenOption
	if file != "" {
		opts = append(opts, keychainbreaker.WithFile(file))
	}

	if file == "" {
		file = "~/Library/Keychains/login.keychain-db"
	}
	fmt.Fprintf(os.Stderr, "Keychain: %s\n", file)

	return keychainbreaker.Open(opts...)
}

func openAndTryUnlock(cmd *cobra.Command) (*keychainbreaker.Keychain, error) {
	kc, err := openKeychain(cmd)
	if err != nil {
		return nil, err
	}

	var unlockOpts []keychainbreaker.UnlockOption
	switch {
	case cmd.Flags().Changed(flagKey):
		key, _ := cmd.Flags().GetString(flagKey)
		unlockOpts = append(unlockOpts, keychainbreaker.WithKey(key))
	case cmd.Flags().Changed(flagPassword):
		pwd, _ := cmd.Flags().GetString(flagPassword)
		unlockOpts = append(unlockOpts, keychainbreaker.WithPassword(pwd))
	default:
		pwd, err := readPassword()
		if err != nil {
			return nil, err
		}
		unlockOpts = append(unlockOpts, keychainbreaker.WithPassword(pwd))
	}

	if err := kc.TryUnlock(unlockOpts...); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: %v, exporting metadata only\n", err)
	}
	return kc, nil
}

func readPassword() (string, error) {
	fmt.Fprint(os.Stderr, "Enter keychain password: ")
	pwd, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", fmt.Errorf("failed to read password: %w", err)
	}
	return string(pwd), nil
}
