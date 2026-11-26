package keychainbreaker

import "errors"

var (
	// ErrInvalidSignature is returned by Open and OpenBytes when the data is not a keychain.
	ErrInvalidSignature = errors.New("keychainbreaker: invalid keychain signature")

	// ErrParseFailed is returned when the keychain structure is malformed.
	ErrParseFailed = errors.New("keychainbreaker: parse failed")

	// ErrWrongKey is returned by UnlockWithPassword, UnlockWithKey and UnlockWithEntropy when the credential does not
	// decrypt the keychain.
	ErrWrongKey = errors.New("keychainbreaker: wrong key or password")
)
