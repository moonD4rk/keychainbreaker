package keychainbreaker

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testKeychainPath = "./testdata/test.keychain-db"

func TestOpen(t *testing.T) {
	kc, err := Open(testKeychainPath)
	require.NoError(t, err)
	assert.Equal(t, "kych", string(kc.header.signature[:]))
	assert.NotNil(t, kc.schema)
	assert.NotEmpty(t, kc.tables)
}

func TestOpenInvalidFile(t *testing.T) {
	// Provide 20+ bytes so header parsing succeeds, but signature is wrong.
	_, err := OpenBytes(make([]byte, 64))
	assert.ErrorIs(t, err, ErrInvalidSignature)
}

func TestOpenTruncatedFile(t *testing.T) {
	_, err := OpenBytes([]byte("kych"))
	assert.Error(t, err)
}

func TestExtractBeforeUnlock(t *testing.T) {
	kc, err := Open(testKeychainPath)
	require.NoError(t, err)

	_, err = kc.GenericPasswords()
	assert.ErrorIs(t, err, ErrLocked)
}

func TestUnlockWrongKey(t *testing.T) {
	kc, err := Open(testKeychainPath)
	require.NoError(t, err)

	err = kc.Unlock(WithKey("000000000000000000000000000000000000000000000000"))
	assert.Error(t, err)
}

func TestUnlockWrongPassword(t *testing.T) {
	kc, err := Open(testKeychainPath)
	require.NoError(t, err)

	err = kc.Unlock(WithPassword("wrong-password"))
	assert.Error(t, err)
}

func TestPasswordHash(t *testing.T) {
	kc, err := Open(testKeychainPath)
	require.NoError(t, err)

	hash := kc.PasswordHash()
	assert.NotEmpty(t, hash)
	assert.Contains(t, hash, "$keychain$*")
}

const (
	// Master key derived from password "keychainbreaker-test" via PBKDF2.
	testMasterKeyHex = "ff358accf50cc180d034267e6575cb8602e9cafc4867831a"
	testPassword     = "keychainbreaker-test"
)

func TestGenericPasswordsWithKey(t *testing.T) {
	kc, err := Open(testKeychainPath)
	require.NoError(t, err)

	err = kc.Unlock(WithKey(testMasterKeyHex))
	require.NoError(t, err)

	assertGenericPasswords(t, kc)
}

func TestGenericPasswordsWithPassword(t *testing.T) {
	kc, err := Open(testKeychainPath)
	require.NoError(t, err)

	err = kc.Unlock(WithPassword(testPassword))
	require.NoError(t, err)

	assertGenericPasswords(t, kc)
}

func assertGenericPasswords(t *testing.T, kc *Keychain) {
	t.Helper()

	passwords, err := kc.GenericPasswords()
	require.NoError(t, err)
	require.Len(t, passwords, 2)

	byService := make(map[string]GenericPassword)
	for i := range passwords {
		byService[passwords[i].Service] = passwords[i]
	}

	p1, ok := byService["moond4rk.com"]
	require.True(t, ok, "missing moond4rk.com")
	assert.Equal(t, "user@moond4rk.com", p1.Account)
	assert.Equal(t, []byte("PlainTextPassword"), p1.Password)
	assert.False(t, p1.Created.IsZero())
	assert.False(t, p1.Modified.IsZero())

	p2, ok := byService["HackBrowserData"]
	require.True(t, ok, "missing HackBrowserData")
	assert.Equal(t, "admin@moond4rk.com", p2.Account)
	assert.Equal(t, []byte("Another!Pass#123"), p2.Password)
}

func TestDynamicSchema(t *testing.T) {
	kc, err := Open(testKeychainPath)
	require.NoError(t, err)

	gpSchema := kc.schema.forTable(tableGenericPassword)
	require.NotNil(t, gpSchema)

	required := []string{"svce", "acct", "desc", "icmt", "cdat", "mdat"}
	for _, name := range required {
		assert.GreaterOrEqual(t, gpSchema.attrIndex(name), 0, "missing attribute %q", name)
	}
	assert.Len(t, gpSchema.attrs, 16)
}
