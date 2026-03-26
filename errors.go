package keychainbreaker

import "errors"

var (
	// ErrInvalidSignature indicates the file is not a valid keychain.
	ErrInvalidSignature = errors.New("keychainbreaker: invalid keychain signature")

	// ErrLocked indicates the keychain has not been unlocked.
	ErrLocked = errors.New("keychainbreaker: keychain is locked")

	// ErrWrongKey indicates the provided key or password is incorrect.
	ErrWrongKey = errors.New("keychainbreaker: wrong key or password")

	// ErrNoKeys indicates no symmetric keys could be recovered.
	ErrNoKeys = errors.New("keychainbreaker: no symmetric keys recovered")
)
