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
)

// Errors returned by record extraction methods.
var (
	// ErrLocked is returned when the keychain has not been unlocked yet.
	ErrLocked = errors.New("keychainbreaker: keychain is locked")
)
