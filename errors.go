package keychainbreaker

import "errors"

// Sentinel errors returned by exported methods.
// Use errors.Is() to check error types.
var (
	// Open errors

	// ErrInvalidSignature indicates the data is not a valid keychain file.
	ErrInvalidSignature = errors.New("keychainbreaker: invalid keychain signature")

	// ErrParseFailed indicates the keychain file structure could not be parsed.
	ErrParseFailed = errors.New("keychainbreaker: parse failed")

	// Unlock errors

	// ErrWrongKey indicates the provided key or password is incorrect.
	ErrWrongKey = errors.New("keychainbreaker: wrong key or password")

	// State errors

	// ErrLocked indicates the keychain has not been unlocked yet.
	ErrLocked = errors.New("keychainbreaker: keychain is locked")
)
