package keychainbreaker

import "errors"

// Errors returned by Open.
var (
	// ErrInvalidSignature is returned when the file is not a valid keychain.
	ErrInvalidSignature = errors.New("keychainbreaker: invalid keychain signature")

	// ErrParseFailed is returned when the keychain file structure cannot be parsed.
	ErrParseFailed = errors.New("keychainbreaker: parse failed")
)

// Errors returned by Unlock.
var (
	// ErrWrongKey is returned when the provided key or password is incorrect.
	ErrWrongKey = errors.New("keychainbreaker: wrong key or password")

	// ErrUnsupportedBlobVersion is returned when unlocking with a password on a
	// keychain whose blob version is not the offline-decryptable v1 (0x100).
	// macOS 26.4+ re-keys the login keychain to v2 (0x200); the password can no
	// longer derive the master key from the keychain file alone. Recover the
	// 24-byte master key on the originating machine and pass it to WithKey.
	ErrUnsupportedBlobVersion = errors.New("keychainbreaker: unsupported keychain blob version for offline password unlock")
)

// Errors returned by record extraction methods.
var (
	// ErrLocked is returned when the keychain has not been unlocked yet.
	ErrLocked = errors.New("keychainbreaker: keychain is locked")
)
