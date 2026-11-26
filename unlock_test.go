package keychainbreaker

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUnlock(t *testing.T) {
	key := testMasterKey(t)
	tests := map[string]func(*Keychain) error{
		"password": func(kc *Keychain) error { return kc.UnlockWithPassword(testPassword) },
		"key":      func(kc *Keychain) error { return kc.UnlockWithKey(key) },
	}
	for name, unlock := range tests {
		t.Run(name, func(t *testing.T) {
			kc := openTestKeychain(t)
			require.NoError(t, unlock(kc))
			assert.True(t, kc.Unlocked())
			passwords, err := kc.GenericPasswords()
			require.NoError(t, err)
			for _, p := range passwords {
				assert.Equal(t, testPasswordBytes, p.Password, p.Service)
			}
		})
	}
}

func TestUnlockRejectsWrongCredentials(t *testing.T) {
	kc := openTestKeychain(t)
	require.ErrorIs(t, kc.UnlockWithPassword("wrong-password"), ErrWrongKey)
	require.ErrorIs(t, kc.UnlockWithKey(make([]byte, tripleDESKeyLen)), ErrWrongKey)
	assert.False(t, kc.Unlocked())
}

func TestUnlockCanBeRetried(t *testing.T) {
	kc := openTestKeychain(t)
	require.ErrorIs(t, kc.UnlockWithPassword("wrong-password"), ErrWrongKey)
	require.NoError(t, kc.UnlockWithPassword(testPassword))
	assert.True(t, kc.Unlocked())
}

func TestFailedUnlockKeepsEarlierUnlock(t *testing.T) {
	kc := unlockedTestKeychain(t)
	require.ErrorIs(t, kc.UnlockWithPassword("wrong-password"), ErrWrongKey)
	assert.True(t, kc.Unlocked())
	passwords, err := kc.GenericPasswords()
	require.NoError(t, err)
	assert.Equal(t, testPasswordBytes, passwords[0].Password)
}

func TestUnlockWithKeyChecksLength(t *testing.T) {
	err := openTestKeychain(t).UnlockWithKey(make([]byte, tripleDESKeyLen-1))
	require.Error(t, err)
	assert.NotErrorIs(t, err, ErrWrongKey)
}

func TestUnlockWithPasswordRejectsV2(t *testing.T) {
	kc := openTestKeychain(t)
	kc.dbBlob.version = blobVersionV2
	require.ErrorIs(t, kc.UnlockWithPassword(testPassword), ErrUnsupportedBlobVersion)
	assert.False(t, kc.Unlocked())
}

// The fixture is a v1 keychain; tagging it v2 in memory shows that the master key path ignores the version.
func TestUnlockWithKeyIgnoresBlobVersion(t *testing.T) {
	kc := openTestKeychain(t)
	kc.dbBlob.version = blobVersionV2
	require.NoError(t, kc.UnlockWithKey(testMasterKey(t)))
	passwords, err := kc.InternetPasswords()
	require.NoError(t, err)
	for _, p := range passwords {
		assert.Equal(t, testPasswordBytes, p.Password, p.Protocol)
	}
}
