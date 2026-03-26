package keychainbreaker

import "errors"

// Sentinel errors returned by exported methods.
// Use errors.Is() to check error types.
var (
	// Open errors

	// ErrInvalidSignature indicates the data is not a valid keychain file.
	ErrInvalidSignature = errors.New("invalid keychain signature")

	// ErrParseFailed indicates the keychain file structure could not be parsed.
	ErrParseFailed = errors.New("keychain parse failed")

	// Unlock errors

	// ErrWrongKey indicates the provided key or password is incorrect.
	ErrWrongKey = errors.New("wrong key or password")

	// State errors

	// ErrLocked indicates the keychain has not been unlocked yet.
	ErrLocked = errors.New("keychain is locked")
)
