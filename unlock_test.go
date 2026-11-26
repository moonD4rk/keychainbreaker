package keychainbreaker

import (
	"encoding/hex"
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

// On a keychain not protected by an entropy file, folding entropy in yields the wrong master key, so the password
// path and the entropy path are distinct. The fixture is such a keychain.
func TestUnlockWithEntropyRejectsPlainKeychain(t *testing.T) {
	kc := openTestKeychain(t)
	require.ErrorIs(t, kc.UnlockWithEntropy(testPassword, make([]byte, 32)), ErrWrongKey)
	assert.False(t, kc.Unlocked())
}

func TestUnlockWithEntropyRejectsEmptyEntropy(t *testing.T) {
	kc := openTestKeychain(t)
	err := kc.UnlockWithEntropy(testPassword, nil)
	require.Error(t, err)
	assert.NotErrorIs(t, err, ErrWrongKey)
}

// deriveMasterKey over mixEntropy is the macOS 26.4 derivation. This is a known-answer test: the expected key was
// computed independently (Python hashlib) from the entropy, password and salt below.
func TestEntropyDerivationKnownAnswer(t *testing.T) {
	entropy := make([]byte, 32)
	salt := make([]byte, 20)
	for i := range entropy {
		entropy[i] = byte(i)
	}
	for i := range salt {
		salt[i] = byte(i)
	}
	master := deriveMasterKey(mixEntropy(entropy, []byte(testPassword)), salt)
	assert.Equal(t, "1a2f1bb88ccae9b1e61567cefd567b0c14517c7a6e4cc987", hex.EncodeToString(master))
}
