package keychainbreaker

import "errors"

var (
	// ErrInvalidSignature is returned by Open and OpenBytes when the data is not a keychain.
	ErrInvalidSignature = errors.New("keychainbreaker: invalid keychain signature")

	// ErrParseFailed is returned when the keychain structure is malformed.
	ErrParseFailed = errors.New("keychainbreaker: parse failed")

	// ErrWrongKey is returned by UnlockWithPassword and UnlockWithKey when the credential does not decrypt the
	// keychain.
	ErrWrongKey = errors.New("keychainbreaker: wrong key or password")

	// ErrUnsupportedBlobVersion is returned by UnlockWithPassword and PasswordHash for a keychain whose database blob
	// is not version 0x100. macOS 26.4 and later re-key the login keychain to version 0x200, whose master key cannot be
	// derived from the password and the file alone: recover the 24-byte master key on the Mac that created the
	// keychain and pass it to UnlockWithKey.
	ErrUnsupportedBlobVersion = errors.New("keychainbreaker: unsupported keychain blob version for offline password unlock")
)
