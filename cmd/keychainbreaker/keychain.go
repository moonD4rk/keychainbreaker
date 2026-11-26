package main

import (
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/moond4rk/keychainbreaker"
)

const fileFlagUsage = "keychain file (default ~/Library/Keychains/login.keychain-db)"

func openKeychain(cmd *cobra.Command, root *rootOptions, path string) (*keychainbreaker.Keychain, error) {
	if path == "" {
		var err error
		if path, err = keychainbreaker.DefaultKeychainPath(); err != nil {
			return nil, err
		}
	}
	fmt.Fprintf(cmd.ErrOrStderr(), "Keychain: %s\n", path)

	var opts []keychainbreaker.Option
	if root.verbose {
		opts = append(opts, keychainbreaker.WithLogger(newLogger(cmd.ErrOrStderr())))
	}
	return keychainbreaker.Open(path, opts...)
}

func newLogger(w io.Writer) *slog.Logger {
	return slog.New(slog.NewTextHandler(w, &slog.HandlerOptions{
		Level: slog.LevelDebug,
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			if len(groups) == 0 && a.Key == slog.TimeKey {
				return slog.Attr{}
			}
			return a
		},
	}))
}

type credentials struct {
	password      string
	passwordStdin bool
	key           string
}

func (c *credentials) addFlags(cmd *cobra.Command) {
	flags := cmd.Flags()
	flags.StringVarP(&c.password, "password", "p", "",
		"keychain password; other local users can see it, prefer --password-stdin or the prompt")
	flags.BoolVar(&c.passwordStdin, "password-stdin", false, "read the keychain password from stdin")
	flags.StringVarP(&c.key, "key", "k", "", "hex-encoded 24-byte master key, used instead of the password")
	cmd.MarkFlagsMutuallyExclusive("password", "password-stdin", "key")
}

func (c *credentials) unlock(cmd *cobra.Command, kc *keychainbreaker.Keychain) error {
	switch {
	case cmd.Flags().Changed("key"):
		key, err := hex.DecodeString(strings.TrimPrefix(strings.TrimSpace(c.key), "0x"))
		if err != nil {
			return fmt.Errorf("decode --key: %w", err)
		}
		return kc.UnlockWithKey(key)
	case cmd.Flags().Changed("password"):
		return kc.UnlockWithPassword(c.password)
	case c.passwordStdin:
		password, err := readPassword(cmd.InOrStdin())
		if err != nil {
			return err
		}
		return kc.UnlockWithPassword(password)
	default:
		password, err := promptPassword(cmd)
		if err != nil {
			return err
		}
		return kc.UnlockWithPassword(password)
	}
}

// unlock leaves the keychain locked rather than failing on a wrong or unusable credential, so metadata still exports.
func unlock(cmd *cobra.Command, kc *keychainbreaker.Keychain, creds *credentials) error {
	err := creds.unlock(cmd, kc)
	switch {
	case err == nil:
		return nil
	case errors.Is(err, keychainbreaker.ErrUnsupportedBlobVersion):
		fmt.Fprintf(cmd.ErrOrStderr(),
			"Warning: %v; exporting metadata only (recover the master key on the originating Mac and pass --key)\n", err)
		return nil
	case errors.Is(err, keychainbreaker.ErrWrongKey):
		fmt.Fprintf(cmd.ErrOrStderr(), "Warning: %v; exporting metadata only\n", err)
		return nil
	default:
		return err
	}
}

func readPassword(r io.Reader) (string, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return "", fmt.Errorf("read password from stdin: %w", err)
	}
	password := strings.TrimSuffix(string(data), "\n")
	return strings.TrimSuffix(password, "\r"), nil
}

func promptPassword(cmd *cobra.Command) (string, error) {
	in, ok := cmd.InOrStdin().(*os.File)
	if !ok || !term.IsTerminal(int(in.Fd())) {
		return "", errors.New("no password: stdin is not a terminal, use --password-stdin or --key")
	}
	fmt.Fprint(cmd.ErrOrStderr(), "Enter keychain password: ")
	password, err := readTerminalPassword(int(in.Fd()))
	fmt.Fprintln(cmd.ErrOrStderr())
	if err != nil {
		return "", fmt.Errorf("read password: %w", err)
	}
	return string(password), nil
}

// readTerminalPassword restores echo on Ctrl-C, which term.ReadPassword leaves off when the process is interrupted.
func readTerminalPassword(fd int) ([]byte, error) {
	state, err := term.GetState(fd)
	if err != nil {
		return nil, err
	}
	interrupted := make(chan os.Signal, 1)
	signal.Notify(interrupted, os.Interrupt)
	defer signal.Stop(interrupted)

	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-interrupted:
			_ = term.Restore(fd, state)
			os.Exit(130)
		case <-done:
		}
	}()
	return term.ReadPassword(fd)
}
