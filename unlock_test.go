package keychainbreaker

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPasswordUnlockRejectedForV2(t *testing.T) {
	kc := &Keychain{dbBlob: dbBlob{blobVersion: blobVersionV2, salt: make([]byte, 20)}}
	cfg := &unlockConfig{password: "whatever", passwordSet: true}

	_, err := deriveMasterKey(cfg, kc)
	assert.ErrorIs(t, err, ErrUnsupportedBlobVersion)
}

func TestPasswordUnlockAllowedForV1(t *testing.T) {
	kc := &Keychain{dbBlob: dbBlob{blobVersion: blobVersionV1, salt: make([]byte, 20)}}
	cfg := &unlockConfig{password: "whatever", passwordSet: true}

	_, err := deriveMasterKey(cfg, kc)
	require.NoError(t, err)
}

func TestKeyUnlockBypassesVersionGate(t *testing.T) {
	// WithKey must work regardless of blob version.
	kc := &Keychain{dbBlob: dbBlob{blobVersion: blobVersionV2}}
	cfg := &unlockConfig{hexKey: "000102030405060708090a0b0c0d0e0f1011121314151617"}

	key, err := deriveMasterKey(cfg, kc)
	require.NoError(t, err)
	assert.Len(t, key, keyLength)
}

func TestKeyUnlockDecryptsV2TaggedKeychain(t *testing.T) {
	// A v2 blob version gates password unlock but must not block the WithKey
	// path: tag the v1 fixture as v2 in memory, unlock with the known master
	// key, and confirm records still decrypt.
	kc := openTestKeychain(t)
	kc.dbBlob.blobVersion = blobVersionV2

	require.NoError(t, kc.Unlock(WithKey(testMasterKeyHex)))

	pws, err := kc.GenericPasswords()
	require.NoError(t, err)
	assert.NotEmpty(t, pws)
}

func TestTryUnlockV2PasswordExportsMetadata(t *testing.T) {
	// The CLI relies on this: a v2 password unlock fails with
	// ErrUnsupportedBlobVersion, yet metadata (service, account, ...) stays
	// extractable so `dump` can fall back to metadata-only output.
	kc := openTestKeychain(t)
	kc.dbBlob.blobVersion = blobVersionV2

	err := kc.TryUnlock(WithPassword(testPassword))
	require.ErrorIs(t, err, ErrUnsupportedBlobVersion)
	assert.False(t, kc.Unlocked())

	gps, err := kc.GenericPasswords()
	require.NoError(t, err)
	assert.NotEmpty(t, gps)
}
