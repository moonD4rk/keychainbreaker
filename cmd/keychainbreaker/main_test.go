package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	fixturePassword = "keychainbreaker-test"
	fixtureKey      = "4557eb716bbf20200945109cf3b884af9aca72e890e47c07"
	secret          = "password#123"
)

// fixture is absolute so that tests which change directory can still open it.
var fixture = func() string {
	path, err := filepath.Abs(filepath.Join("..", "..", "testdata", "test.keychain-db"))
	if err != nil {
		panic(err)
	}
	return path
}()

type result struct {
	stdout string
	stderr string
	err    error
}

func run(t *testing.T, stdin string, args ...string) result {
	t.Helper()
	var stdout, stderr bytes.Buffer
	cmd := newRootCmd()
	cmd.SetIn(strings.NewReader(stdin))
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	cmd.SetArgs(args)
	err := cmd.Execute()
	return result{stdout: stdout.String(), stderr: stderr.String(), err: err}
}

func decodeDump(t *testing.T, data []byte) dump {
	t.Helper()
	var d dump
	require.NoError(t, json.Unmarshal(data, &d))
	return d
}

func TestDumpWritesPrivateFile(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	require.NoError(t, os.WriteFile("keychain_dump.json", []byte("stale"), 0o644)) //nolint:gosec // the dump must replace it

	res := run(t, fixturePassword+"\n", "dump", "-f", fixture, "--password-stdin")
	require.NoError(t, res.err)
	assert.Empty(t, res.stdout)
	assert.Contains(t, res.stderr, "Keychain: "+fixture)
	assert.Contains(t, res.stderr, "Output: keychain_dump.json")
	assert.NotContains(t, res.stderr, "metadata only")

	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	require.Len(t, entries, 1, "the temp file must be renamed into place")
	info, err := entries[0].Info()
	require.NoError(t, err)
	if runtime.GOOS != "windows" {
		assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
	}

	data, err := os.ReadFile("keychain_dump.json")
	require.NoError(t, err)
	d := decodeDump(t, data)
	require.Len(t, d.GenericPasswords, 2)
	require.Len(t, d.InternetPasswords, 2)
	require.Len(t, d.PrivateKeys, 1)
	require.Len(t, d.Certificates, 1)
	for _, p := range d.GenericPasswords {
		assert.Equal(t, secret, p.Password, p.Service)
	}
	for _, p := range d.InternetPasswords {
		assert.Equal(t, secret, p.Password, p.Protocol)
		assert.Equal(t, "dflt", p.AuthType, p.Protocol)
	}
	assert.NotEmpty(t, d.PrivateKeys[0].DataHex)
	assert.Len(t, d.PrivateKeys[0].LabelHex, 40)
	assert.Equal(t, "keychainbreaker-test", d.Certificates[0].PrintName)
}

func TestDumpToStdoutWithKey(t *testing.T) {
	res := run(t, "", "dump", "-f", fixture, "--key", fixtureKey, "-o", "-")
	require.NoError(t, res.err)
	assert.NotContains(t, res.stderr, "Output:")

	d := decodeDump(t, []byte(res.stdout))
	require.Len(t, d.GenericPasswords, 2)
	for _, p := range d.GenericPasswords {
		assert.Equal(t, secret, p.Password, p.Service)
	}
}

func TestDumpWithWrongPasswordExportsMetadata(t *testing.T) {
	res := run(t, "", "dump", "-f", fixture, "-p", "wrong", "-o", "-")
	require.NoError(t, res.err)
	assert.Contains(t, res.stderr, "Warning:")
	assert.Contains(t, res.stderr, "Generic passwords:  2 (metadata only)")

	d := decodeDump(t, []byte(res.stdout))
	require.Len(t, d.GenericPasswords, 2)
	for _, p := range d.GenericPasswords {
		assert.NotEmpty(t, p.Service)
		assert.Empty(t, p.Password, p.Service)
		assert.Empty(t, p.HexPassword, p.Service)
	}
}

// The fixture is not entropy-protected, so an entropy file cannot unlock it: the run falls back to a metadata-only
// export, which proves --entropy is wired through to UnlockWithEntropy.
func TestDumpWithEntropyFileExportsMetadata(t *testing.T) {
	entropyFile := filepath.Join(t.TempDir(), "entropy.plist")
	plist := "<plist version=\"1.0\"><data>" +
		strings.Repeat("AAAA", 8) + "</data></plist>" // 32 zero bytes
	require.NoError(t, os.WriteFile(entropyFile, []byte(plist), 0o600))

	res := run(t, "", "dump", "-f", fixture, "-p", fixturePassword, "--entropy", entropyFile, "-o", "-")
	require.NoError(t, res.err)
	assert.Contains(t, res.stderr, "Generic passwords:  2 (metadata only)")

	d := decodeDump(t, []byte(res.stdout))
	for _, p := range d.GenericPasswords {
		assert.Empty(t, p.Password, p.Service)
	}
}

func TestDumpRejectsUnreadableEntropyFile(t *testing.T) {
	res := run(t, "", "dump", "-f", fixture, "-p", fixturePassword,
		"--entropy", filepath.Join(t.TempDir(), "missing"), "-o", "-")
	require.Error(t, res.err)
	assert.Empty(t, res.stdout)
}

func TestDumpRejectsEntropyWithKey(t *testing.T) {
	res := run(t, "", "dump", "-f", fixture, "-k", fixtureKey, "--entropy", "x", "-o", "-")
	require.Error(t, res.err)
	assert.Contains(t, res.err.Error(), "none of the others can be")
}

func TestDumpRejectsMalformedKeys(t *testing.T) {
	tests := map[string]string{
		"not hex":              "decode --key",
		"0x" + fixtureKey[:46]: "24",
	}
	for key, want := range tests {
		res := run(t, "", "dump", "-f", fixture, "--key", key, "-o", "-")
		require.Error(t, res.err, key)
		assert.Contains(t, res.err.Error(), want, key)
		assert.Empty(t, res.stdout, key)
	}
}

func TestDumpRejectsConflictingCredentials(t *testing.T) {
	res := run(t, "", "dump", "-f", fixture, "-p", fixturePassword, "-k", fixtureKey, "-o", "-")
	require.Error(t, res.err)
	assert.Contains(t, res.err.Error(), "none of the others can be")
	assert.Empty(t, res.stdout)
}

func TestDumpNeedsACredentialWithoutTerminal(t *testing.T) {
	res := run(t, "", "dump", "-f", fixture, "-o", "-")
	require.Error(t, res.err)
	assert.Contains(t, res.err.Error(), "--password-stdin")
	assert.Empty(t, res.stdout)
}

func TestHashPrintsHash(t *testing.T) {
	res := run(t, "", "hash", "-f", fixture)
	require.NoError(t, res.err)
	assert.True(t, strings.HasPrefix(res.stdout, "$keychain$*"), res.stdout)
	assert.Equal(t, 1, strings.Count(res.stdout, "\n"))
}

func TestHashTakesNoCredentials(t *testing.T) {
	res := run(t, "", "hash", "-f", fixture, "-p", fixturePassword)
	require.Error(t, res.err)
	assert.Contains(t, res.err.Error(), "unknown shorthand flag")
}

func TestVerboseLogsToStderr(t *testing.T) {
	res := run(t, "", "-v", "hash", "-f", fixture)
	require.NoError(t, res.err)
	assert.Contains(t, res.stderr, "level=")
	assert.NotContains(t, res.stderr, "time=")
	assert.NotContains(t, res.stdout, "level=")
}

func TestVersion(t *testing.T) {
	res := run(t, "", "version")
	require.NoError(t, res.err)
	assert.True(t, strings.HasPrefix(res.stdout, "keychainbreaker "), res.stdout)
	assert.Contains(t, res.stdout, "commit: ")
}

func TestReadPasswordTrimsOneLineEnding(t *testing.T) {
	tests := map[string]string{
		"pw":       "pw",
		"pw\n":     "pw",
		"pw\r\n":   "pw",
		"pw \n":    "pw ",
		"pw\n\n":   "pw\n",
		"":         "",
		"two\nl\n": "two\nl",
	}
	for in, want := range tests {
		got, err := readPassword(strings.NewReader(in))
		require.NoError(t, err)
		assert.Equal(t, want, got, "%q", in)
	}
}
