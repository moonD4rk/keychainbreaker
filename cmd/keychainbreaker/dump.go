package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"

	"github.com/spf13/cobra"

	"github.com/moond4rk/keychainbreaker"
)

const stdoutPath = "-"

type dumpOptions struct {
	file   string
	output string
	creds  credentials
}

func newDumpCmd(root *rootOptions) *cobra.Command {
	opts := &dumpOptions{}
	cmd := &cobra.Command{
		Use:   "dump",
		Short: "Export all keychain records to JSON",
		Long: `Export generic and internet passwords, private keys and certificates to JSON.

Without --password, --password-stdin or --key the password is prompted for.
A wrong or unusable credential still exports the metadata of every record.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runDump(cmd, root, opts)
		},
	}
	cmd.Flags().StringVarP(&opts.file, "file", "f", "", fileFlagUsage)
	cmd.Flags().StringVarP(&opts.output, "output", "o", "keychain_dump.json", `output file, or "-" for stdout`)
	opts.creds.addFlags(cmd)
	return cmd
}

func runDump(cmd *cobra.Command, root *rootOptions, opts *dumpOptions) error {
	kc, err := openKeychain(cmd, root, opts.file)
	if err != nil {
		return err
	}
	err = unlock(cmd, kc, &opts.creds)
	if err != nil {
		return err
	}

	records, err := collect(kc)
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(records, "", "  ")
	if err != nil {
		return fmt.Errorf("encode JSON: %w", err)
	}
	data = append(data, '\n')

	if opts.output == stdoutPath {
		_, err = cmd.OutOrStdout().Write(data)
	} else {
		err = writePrivateFile(opts.output, data, cmd.ErrOrStderr())
	}
	if err != nil {
		return fmt.Errorf("write output: %w", err)
	}
	printSummary(cmd.ErrOrStderr(), records, kc.Unlocked(), opts.output)
	return nil
}

// chownToSudoUser hands f to the user who invoked sudo, so a dump written as root is not left owned by root. It does
// nothing unless the process runs as root under sudo; os.Geteuid is -1 on Windows.
func chownToSudoUser(f *os.File) error {
	if os.Geteuid() != 0 {
		return nil
	}
	uid, err := strconv.Atoi(os.Getenv("SUDO_UID"))
	if err != nil {
		return nil
	}
	gid, err := strconv.Atoi(os.Getenv("SUDO_GID"))
	if err != nil {
		return nil
	}
	return f.Chown(uid, gid)
}

func collect(kc *keychainbreaker.Keychain) (*dump, error) {
	generic, err := kc.GenericPasswords()
	if err != nil {
		return nil, fmt.Errorf("read generic passwords: %w", err)
	}
	internet, err := kc.InternetPasswords()
	if err != nil {
		return nil, fmt.Errorf("read internet passwords: %w", err)
	}
	keys, err := kc.PrivateKeys()
	if err != nil {
		return nil, fmt.Errorf("read private keys: %w", err)
	}
	certs, err := kc.Certificates()
	if err != nil {
		return nil, fmt.Errorf("read certificates: %w", err)
	}
	return &dump{
		GenericPasswords:  convert(generic, newGenericPassword),
		InternetPasswords: convert(internet, newInternetPassword),
		PrivateKeys:       convert(keys, newPrivateKey),
		Certificates:      convert(certs, newCertificate),
	}, nil
}

// writePrivateFile renames a 0600 temp file into place: the secrets are never readable by others or half-written.
// Under sudo the temp file goes to the invoking user before the rename; if it cannot, a warning goes to warn.
func writePrivateFile(path string, data []byte, warn io.Writer) error {
	f, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	if err == nil {
		if chownErr := chownToSudoUser(f); chownErr != nil {
			fmt.Fprintf(warn, "Warning: could not restore ownership of %s: %v\n", path, chownErr)
		}
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err == nil {
		err = os.Rename(f.Name(), path)
	}
	if err != nil {
		_ = os.Remove(f.Name())
	}
	return err
}

func printSummary(w io.Writer, d *dump, unlocked bool, output string) {
	note := ""
	if !unlocked {
		note = " (metadata only)"
	}
	fmt.Fprintln(w, "Extracted:")
	fmt.Fprintf(w, "  Generic passwords:  %d%s\n", len(d.GenericPasswords), note)
	fmt.Fprintf(w, "  Internet passwords: %d%s\n", len(d.InternetPasswords), note)
	fmt.Fprintf(w, "  Private keys:       %d%s\n", len(d.PrivateKeys), note)
	fmt.Fprintf(w, "  Certificates:       %d\n", len(d.Certificates))
	if output != stdoutPath {
		fmt.Fprintf(w, "Output: %s\n", output)
	}
}
