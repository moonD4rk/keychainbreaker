package keychainbreaker

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testKeychainPath = "./testdata/test.keychain-db"

func openTestKeychain(t *testing.T) *Keychain {
	t.Helper()
	kc, err := Open(WithFile(testKeychainPath))
	require.NoError(t, err)
	return kc
}

func TestOpen(t *testing.T) {
	kc := openTestKeychain(t)
	assert.Equal(t, "kych", string(kc.header.signature[:]))
	assert.NotNil(t, kc.schema)
	assert.NotEmpty(t, kc.tables)
}

func TestOpenInvalidFile(t *testing.T) {
	_, err := Open(WithBytes(make([]byte, 64)))
	assert.ErrorIs(t, err, ErrInvalidSignature)
}

func TestOpenTruncatedFile(t *testing.T) {
	_, err := Open(WithBytes([]byte("kych")))
	assert.ErrorIs(t, err, ErrParseFailed)
}

func TestExtractBeforeUnlock(t *testing.T) {
	kc := openTestKeychain(t)
	_, err := kc.GenericPasswords()
	assert.ErrorIs(t, err, ErrLocked)
}

func TestUnlockWrongKey(t *testing.T) {
	kc := openTestKeychain(t)
	err := kc.Unlock(WithKey("000000000000000000000000000000000000000000000000"))
	assert.ErrorIs(t, err, ErrWrongKey)
}

func TestUnlockWrongPassword(t *testing.T) {
	kc := openTestKeychain(t)
	err := kc.Unlock(WithPassword("wrong-password"))
	assert.ErrorIs(t, err, ErrWrongKey)
}

func TestPasswordHash(t *testing.T) {
	kc := openTestKeychain(t)
	hash, err := kc.PasswordHash()
	require.NoError(t, err)
	assert.NotEmpty(t, hash)
	assert.Contains(t, hash, "$keychain$*")
}

const (
	testMasterKeyHex = "ff358accf50cc180d034267e6575cb8602e9cafc4867831a"
	testPassword     = "keychainbreaker-test"
)

func TestGenericPasswordsWithKey(t *testing.T) {
	kc := openTestKeychain(t)
	require.NoError(t, kc.Unlock(WithKey(testMasterKeyHex)))
	assertGenericPasswords(t, kc)
}

func TestGenericPasswordsWithPassword(t *testing.T) {
	kc := openTestKeychain(t)
	require.NoError(t, kc.Unlock(WithPassword(testPassword)))
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

func TestInternetPasswords(t *testing.T) {
	kc := openTestKeychain(t)
	require.NoError(t, kc.Unlock(WithPassword(testPassword)))

	passwords, err := kc.InternetPasswords()
	require.NoError(t, err)
	require.Len(t, passwords, 1)

	p := passwords[0]
	assert.Equal(t, "moond4rk.com", p.Server)
	assert.Equal(t, "webuser", p.Account)
	assert.Equal(t, []byte("WebPass456"), p.Password)
	assert.Equal(t, "htps", p.Protocol)
	assert.NotEmpty(t, p.AuthType)
	assert.Equal(t, uint32(443), p.Port)
	assert.Equal(t, "/", p.Path)
	assert.False(t, p.Created.IsZero())
	assert.False(t, p.Modified.IsZero())
}

func TestInternetPasswordsBeforeUnlock(t *testing.T) {
	kc := openTestKeychain(t)
	_, err := kc.InternetPasswords()
	assert.ErrorIs(t, err, ErrLocked)
}

func TestDynamicSchema(t *testing.T) {
	kc := openTestKeychain(t)
	gpSchema := kc.schema.forTable(tableGenericPassword)
	require.NotNil(t, gpSchema)

	required := []string{"svce", "acct", "desc", "icmt", "cdat", "mdat"}
	for _, name := range required {
		assert.GreaterOrEqual(t, gpSchema.attrIndex(name), 0, "missing attribute %q", name)
	}
	assert.Len(t, gpSchema.attrs, 16)
}
