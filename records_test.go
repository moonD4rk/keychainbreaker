package keychainbreaker

import (
	"crypto/rsa"
	"crypto/x509"
	"math/big"
	"sort"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var testPasswordBytes = []byte("password#123")

// The records stored in testdata/test.keychain-db, without their timestamps.
var (
	wantGenericPasswords = []GenericPassword{
		{
			Service:   "HackBrowserData",
			Account:   "admin",
			Password:  testPasswordBytes,
			PrintName: "HackBrowserData",
		},
		{
			Service:     "moond4rk.com",
			Account:     "admin",
			Password:    testPasswordBytes,
			Description: "application password",
			Comment:     "test generic password",
			Creator:     "mD4k",
			Type:        "note",
			PrintName:   "moond4rk.com",
		},
	}
	wantInternetPasswords = []InternetPassword{
		{
			Server:         "moond4rk.com",
			Account:        "admin",
			Password:       testPasswordBytes,
			SecurityDomain: "moond4rk.com",
			Protocol:       "htps",
			AuthType:       "dflt",
			Port:           443,
			Path:           "/login",
			Description:    "Internet password",
			Comment:        "test internet password",
			Creator:        "mD4k",
			Type:           "note",
			PrintName:      "moond4rk.com",
		},
		{
			Server:    "moond4rk.com",
			Account:   "admin",
			Password:  testPasswordBytes,
			Protocol:  "smb ",
			AuthType:  "dflt",
			Port:      445,
			PrintName: "moond4rk.com",
		},
	}
)

// genericWithoutTimes sorts the records and clears their timestamps, once read, so the rest compares exactly.
func genericWithoutTimes(t *testing.T, passwords []GenericPassword) []GenericPassword {
	t.Helper()
	sort.Slice(passwords, func(i, j int) bool { return passwords[i].Service < passwords[j].Service })
	for i := range passwords {
		assert.False(t, passwords[i].Created.IsZero(), passwords[i].Service)
		assert.False(t, passwords[i].Modified.IsZero(), passwords[i].Service)
		passwords[i].Created, passwords[i].Modified = time.Time{}, time.Time{}
	}
	return passwords
}

func internetWithoutTimes(t *testing.T, passwords []InternetPassword) []InternetPassword {
	t.Helper()
	sort.Slice(passwords, func(i, j int) bool { return passwords[i].Port < passwords[j].Port })
	for i := range passwords {
		assert.False(t, passwords[i].Created.IsZero(), passwords[i].Protocol)
		passwords[i].Created, passwords[i].Modified = time.Time{}, time.Time{}
	}
	return passwords
}

func TestGenericPasswords(t *testing.T) {
	passwords, err := unlockedTestKeychain(t).GenericPasswords()
	require.NoError(t, err)
	assert.Equal(t, wantGenericPasswords, genericWithoutTimes(t, passwords))
}

func TestInternetPasswords(t *testing.T) {
	passwords, err := unlockedTestKeychain(t).InternetPasswords()
	require.NoError(t, err)
	assert.Equal(t, wantInternetPasswords, internetWithoutTimes(t, passwords))
}

func TestPrivateKeys(t *testing.T) {
	keys, err := unlockedTestKeychain(t).PrivateKeys()
	require.NoError(t, err)
	require.Len(t, keys, 1)

	key := keys[0]
	assert.Equal(t, "93B7C5C0", key.PrintName)
	assert.Len(t, key.Label, 20)
	assert.Equal(t, uint32(16), key.KeyClass)
	assert.Equal(t, uint32(42), key.KeyType)
	assert.Equal(t, uint32(2048), key.KeySize)

	parsed, err := x509.ParsePKCS8PrivateKey(key.Data)
	require.NoError(t, err)
	rsaKey, ok := parsed.(*rsa.PrivateKey)
	require.True(t, ok, "want an RSA key, got %T", parsed)
	assert.Equal(t, 2048, rsaKey.N.BitLen())
	assert.NoError(t, rsaKey.Validate())
}

func TestCertificates(t *testing.T) {
	certs, err := openTestKeychain(t).Certificates()
	require.NoError(t, err)
	require.Len(t, certs, 1)

	c := certs[0]
	assert.Equal(t, "keychainbreaker-test", c.PrintName)
	parsed, err := x509.ParseCertificate(c.Data)
	require.NoError(t, err)
	assert.Equal(t, "keychainbreaker-test", parsed.Subject.CommonName)
	assert.Equal(t, parsed.RawSubject, c.Subject)
	assert.Equal(t, parsed.RawIssuer, c.Issuer)
	assert.Equal(t, 0, parsed.SerialNumber.Cmp(new(big.Int).SetBytes(c.Serial)))
}

func TestLockedKeychainReturnsMetadata(t *testing.T) {
	kc := openTestKeychain(t)

	generic, err := kc.GenericPasswords()
	require.NoError(t, err)
	want := make([]GenericPassword, len(wantGenericPasswords))
	copy(want, wantGenericPasswords)
	for i := range want {
		want[i].Password = nil
	}
	assert.Equal(t, want, genericWithoutTimes(t, generic))

	internet, err := kc.InternetPasswords()
	require.NoError(t, err)
	require.Len(t, internet, 2)
	for _, p := range internet {
		assert.Nil(t, p.Password)
		assert.Equal(t, "dflt", p.AuthType)
	}

	keys, err := kc.PrivateKeys()
	require.NoError(t, err)
	require.Len(t, keys, 1)
	assert.Nil(t, keys[0].Data)
	assert.Len(t, keys[0].Label, 20)
}

func TestEmptyPasswordIsNotNil(t *testing.T) {
	blob := append([]byte(secureStorageGroup), make([]byte, ssgpHeaderLen-len(secureStorageGroup))...)
	password, err := secrets{dbKey: make([]byte, tripleDESKeyLen)}.decryptPassword(&record{blob: blob})
	require.NoError(t, err)
	assert.NotNil(t, password)
	assert.Empty(t, password)
}
