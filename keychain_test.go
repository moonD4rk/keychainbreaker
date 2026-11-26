package keychainbreaker

import (
	"encoding/binary"
	"encoding/hex"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testKeychainPath = "testdata/test.keychain-db"
	testPassword     = "keychainbreaker-test"
	// testMasterKeyHex is what PBKDF2-HMAC-SHA1 derives from testPassword.
	testMasterKeyHex = "4557eb716bbf20200945109cf3b884af9aca72e890e47c07"
)

func readTestKeychain(tb testing.TB) []byte {
	tb.Helper()
	buf, err := os.ReadFile(testKeychainPath)
	require.NoError(tb, err)
	return buf
}

func testMasterKey(tb testing.TB) []byte {
	tb.Helper()
	key, err := hex.DecodeString(testMasterKeyHex)
	require.NoError(tb, err)
	return key
}

func openTestKeychain(tb testing.TB) *Keychain {
	tb.Helper()
	kc, err := Open(testKeychainPath)
	require.NoError(tb, err)
	return kc
}

func unlockedTestKeychain(tb testing.TB) *Keychain {
	tb.Helper()
	kc := openTestKeychain(tb)
	require.NoError(tb, kc.UnlockWithPassword(testPassword))
	return kc
}

func TestOpen(t *testing.T) {
	kc := openTestKeychain(t)
	assert.False(t, kc.Unlocked())
	for _, id := range []uint32{
		tableGenericPassword, tableInternetPassword, tablePrivateKey, tableSymmetricKey,
		tableX509Certificate, tableMetadata,
	} {
		assert.Contains(t, kc.tables, id, tableName(id))
	}
}

func TestOpenMissingFile(t *testing.T) {
	_, err := Open(filepath.Join(t.TempDir(), "missing.keychain-db"))
	assert.ErrorIs(t, err, fs.ErrNotExist)
}

func TestOpenBytesRejectsEmptyInput(t *testing.T) {
	for _, buf := range [][]byte{nil, {}} {
		_, err := OpenBytes(buf)
		assert.ErrorIs(t, err, ErrParseFailed)
	}
}

func TestOpenBytesCopiesInput(t *testing.T) {
	buf := readTestKeychain(t)
	kc, err := OpenBytes(buf)
	require.NoError(t, err)
	for i := range buf {
		buf[i] = 0
	}
	passwords, err := kc.GenericPasswords()
	require.NoError(t, err)
	assert.Len(t, passwords, 2)
}

func TestOpenInvalidSignature(t *testing.T) {
	_, err := OpenBytes(make([]byte, 64))
	assert.ErrorIs(t, err, ErrInvalidSignature)
}

func TestOpenTruncatedFile(t *testing.T) {
	_, err := OpenBytes([]byte(keychainSignature))
	assert.ErrorIs(t, err, ErrParseFailed)
}

// A table count far beyond the file used to allocate count*4 bytes before any bounds check.
func TestOpenRejectsOversizedTableDirectory(t *testing.T) {
	buf := readTestKeychain(t)
	binary.BigEndian.PutUint32(buf[fileHeaderLen+uint32Len:], 0x00FFFFFF)

	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	_, err := OpenBytes(buf)
	runtime.ReadMemStats(&after)

	require.ErrorIs(t, err, ErrParseFailed)
	assert.Less(t, after.TotalAlloc-before.TotalAlloc, uint64(1<<20))
}

func TestPasswordHash(t *testing.T) {
	hash, err := openTestKeychain(t).PasswordHash()
	require.NoError(t, err)
	assert.Equal(t,
		"$keychain$*fc143c45cce245f3e54fbb39141a894e2870dd85*26bca3823a0555be*07821bf723083271da09a3147cb6d73e415d7707099efc3273b36b01c975162bd388f4c5229979e556b74ec1ee3c7cdf",
		hash)
}

func TestPasswordHashRejectsV2(t *testing.T) {
	kc := openTestKeychain(t)
	kc.dbBlob.version = blobVersionV2
	_, err := kc.PasswordHash()
	assert.ErrorIs(t, err, ErrUnsupportedBlobVersion)
}

func TestDefaultKeychainPath(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	path, err := DefaultKeychainPath()
	require.NoError(t, err)
	assert.Equal(t, filepath.Join(home, "Library", "Keychains", "login.keychain-db"), path)
}

type recordingLogger struct {
	mu   sync.Mutex
	msgs []string
}

func (l *recordingLogger) Debug(msg string, _ ...any) { l.record(msg) }
func (l *recordingLogger) Warn(msg string, _ ...any)  { l.record(msg) }

func (l *recordingLogger) record(msg string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.msgs = append(l.msgs, msg)
}

func TestWithLogger(t *testing.T) {
	logger := &recordingLogger{}
	kc, err := Open(testKeychainPath, WithLogger(logger))
	require.NoError(t, err)
	require.NoError(t, kc.UnlockWithPassword(testPassword))
	assert.Contains(t, logger.msgs, "parsed keychain")
	assert.Contains(t, logger.msgs, "unlocked")
}

// Run with -race: schemas are shared between keychains, and secrets are swapped while records are read.
func TestConcurrentUse(t *testing.T) {
	key := testMasterKey(t)
	shared := openTestKeychain(t)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			kc, err := Open(testKeychainPath)
			if assert.NoError(t, err) {
				assert.NoError(t, kc.UnlockWithKey(key))
				_, err = kc.InternetPasswords()
				assert.NoError(t, err)
			}
		}()
		go func() {
			defer wg.Done()
			assert.NoError(t, shared.UnlockWithKey(key))
			_, err := shared.GenericPasswords()
			assert.NoError(t, err)
			_, err = shared.PrivateKeys()
			assert.NoError(t, err)
		}()
	}
	wg.Wait()
	assert.True(t, shared.Unlocked())
}
