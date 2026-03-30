package keychainbreaker

import (
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"testing"
	"time"

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
	assert.Equal(t,
		"$keychain$*fc143c45cce245f3e54fbb39141a894e2870dd85*26bca3823a0555be*07821bf723083271da09a3147cb6d73e415d7707099efc3273b36b01c975162bd388f4c5229979e556b74ec1ee3c7cdf",
		hash,
	)
}

const (
	// Derived from password "keychainbreaker-test" via PBKDF2-HMAC-SHA1.
	testMasterKeyHex = "4557eb716bbf20200945109cf3b884af9aca72e890e47c07"
	testPassword     = "keychainbreaker-test"
)

// Expected test data matching testdata/test.keychain-db.
var (
	wantGP1 = GenericPassword{
		Service:     "moond4rk.com",
		Account:     "admin",
		Password:    []byte("password#123"),
		Description: "application password",
		Comment:     "test generic password",
		Creator:     "mD4k",
		Type:        "note",
		PrintName:   "moond4rk.com",
	}
	wantGP2 = GenericPassword{
		Service:   "HackBrowserData",
		Account:   "admin",
		Password:  []byte("password#123"),
		PrintName: "HackBrowserData",
	}
	wantIP1 = InternetPassword{
		Server:         "moond4rk.com",
		Account:        "admin",
		Password:       []byte("password#123"),
		Description:    "Internet password",
		Comment:        "test internet password",
		Creator:        "mD4k",
		Type:           "note",
		PrintName:      "moond4rk.com",
		SecurityDomain: "moond4rk.com",
		Protocol:       "htps",
		Port:           443,
		Path:           "/login",
	}
	wantIP2 = InternetPassword{
		Server:    "moond4rk.com",
		Account:   "admin",
		Password:  []byte("password#123"),
		PrintName: "moond4rk.com",
		Protocol:  "smb ",
		Port:      445,
	}
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

	got1 := byService["moond4rk.com"]
	assert.False(t, got1.Created.IsZero())
	assert.False(t, got1.Modified.IsZero())
	got1.Created, got1.Modified = time.Time{}, time.Time{}
	assert.Equal(t, wantGP1, got1)

	got2 := byService["HackBrowserData"]
	got2.Created, got2.Modified = time.Time{}, time.Time{}
	assert.Equal(t, wantGP2, got2)
}

func TestInternetPasswords(t *testing.T) {
	kc := openTestKeychain(t)
	require.NoError(t, kc.Unlock(WithPassword(testPassword)))

	passwords, err := kc.InternetPasswords()
	require.NoError(t, err)
	require.Len(t, passwords, 2)

	byKey := make(map[string]InternetPassword)
	for i := range passwords {
		p := passwords[i]
		key := fmt.Sprintf("%s:%s:%d", p.Server, p.Protocol, p.Port)
		byKey[key] = p
	}

	got1 := byKey["moond4rk.com:htps:443"]
	assert.False(t, got1.Created.IsZero())
	assert.False(t, got1.Modified.IsZero())
	got1.Created, got1.Modified = time.Time{}, time.Time{}
	got1.AuthType = "" // raw uint32 value, not comparable as string
	assert.Equal(t, wantIP1, got1)

	got2 := byKey["moond4rk.com:smb :445"]
	got2.Created, got2.Modified = time.Time{}, time.Time{}
	got2.AuthType = ""
	assert.Equal(t, wantIP2, got2)
}

func TestPrivateKeys(t *testing.T) {
	kc := openTestKeychain(t)
	require.NoError(t, kc.Unlock(WithPassword(testPassword)))

	keys, err := kc.PrivateKeys()
	require.NoError(t, err)
	require.Len(t, keys, 1)

	pk := keys[0]
	assert.Equal(t, "93B7C5C0", pk.PrintName)
	assert.Equal(t, uint32(2048), pk.KeySize)

	// Verify Data is a valid PKCS#8 RSA private key.
	parsedKey, err := x509.ParsePKCS8PrivateKey(pk.Data)
	require.NoError(t, err)
	rsaKey, ok := parsedKey.(*rsa.PrivateKey)
	require.True(t, ok, "expected RSA private key")
	assert.Equal(t, 2048, rsaKey.N.BitLen())
	assert.NoError(t, rsaKey.Validate())
}

func TestCertificates(t *testing.T) {
	kc := openTestKeychain(t)
	require.NoError(t, kc.Unlock(WithPassword(testPassword)))

	certs, err := kc.Certificates()
	require.NoError(t, err)
	require.Len(t, certs, 1)

	c := certs[0]
	assert.Equal(t, "keychainbreaker-test", c.PrintName)
	assert.NotEmpty(t, c.Subject)
	assert.NotEmpty(t, c.Issuer)
	assert.NotEmpty(t, c.Serial)

	// Verify Data is a valid X.509 DER certificate.
	x509Cert, err := x509.ParseCertificate(c.Data)
	require.NoError(t, err)
	assert.Equal(t, "keychainbreaker-test", x509Cert.Subject.CommonName)
	assert.Equal(t, "keychainbreaker-test", x509Cert.Issuer.CommonName) // self-signed
	assert.Equal(t, x509.RSA, x509Cert.PublicKeyAlgorithm)
}

func TestInternetPasswordsBeforeUnlock(t *testing.T) {
	kc := openTestKeychain(t)
	_, err := kc.InternetPasswords()
	assert.ErrorIs(t, err, ErrLocked)
}

func TestTryUnlockWithWrongPassword(t *testing.T) {
	kc := openTestKeychain(t)
	err := kc.TryUnlock(WithPassword("wrong-password"))
	assert.ErrorIs(t, err, ErrWrongKey)
	assert.False(t, kc.Unlocked())

	// Metadata should be accessible despite wrong password.
	gps, err := kc.GenericPasswords()
	require.NoError(t, err)
	require.Len(t, gps, 2)
	for _, gp := range gps {
		assert.NotEmpty(t, gp.Service)
		assert.NotEmpty(t, gp.Account)
		assert.Nil(t, gp.Password)
	}

	ips, err := kc.InternetPasswords()
	require.NoError(t, err)
	require.Len(t, ips, 2)
	for _, ip := range ips {
		assert.NotEmpty(t, ip.Server)
		assert.Nil(t, ip.Password)
	}

	pks, err := kc.PrivateKeys()
	require.NoError(t, err)
	require.Len(t, pks, 1)
	assert.NotEmpty(t, pks[0].PrintName)
	assert.Equal(t, uint32(2048), pks[0].KeySize)
	assert.Nil(t, pks[0].Data)

	certs, err := kc.Certificates()
	require.NoError(t, err)
	require.Len(t, certs, 1)
	assert.NotEmpty(t, certs[0].Data)
	assert.Equal(t, "keychainbreaker-test", certs[0].PrintName)
}

func TestTryUnlockWithoutCredential(t *testing.T) {
	kc := openTestKeychain(t)
	err := kc.TryUnlock()
	assert.NoError(t, err)
	assert.False(t, kc.Unlocked())

	gps, err := kc.GenericPasswords()
	require.NoError(t, err)
	require.Len(t, gps, 2)
	for _, gp := range gps {
		assert.NotEmpty(t, gp.Service)
		assert.Nil(t, gp.Password)
	}
}

func TestTryUnlockWithCorrectPassword(t *testing.T) {
	kc := openTestKeychain(t)
	err := kc.TryUnlock(WithPassword(testPassword))
	require.NoError(t, err)
	assert.True(t, kc.Unlocked())

	// Full data should be available.
	gps, err := kc.GenericPasswords()
	require.NoError(t, err)
	require.Len(t, gps, 2)
	for _, gp := range gps {
		assert.NotNil(t, gp.Password)
	}
}

func TestDynamicSchema(t *testing.T) {
	kc := openTestKeychain(t)
	gpSchema := kc.schema.forTable(tableGenericPassword)
	require.NotNil(t, gpSchema)

	required := []string{"svce", "acct", "desc", "icmt", "cdat", "mdat", "PrintName"}
	for _, name := range required {
		assert.GreaterOrEqual(t, gpSchema.attrIndex(name), 0, "missing attribute %q", name)
	}
	assert.Len(t, gpSchema.attrs, 16)
}
