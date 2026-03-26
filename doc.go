// Package keychainbreaker parses and decrypts macOS Keychain files
// (login.keychain-db).
//
// The library implements Apple's CSSM-based keychain binary format parser
// with dynamic schema discovery, and supports decrypting stored credentials
// using Triple-DES CBC encryption.
//
// # Quick Start
//
// Open a keychain file and unlock it with the keychain password:
//
//	kc, err := keychainbreaker.Open("/path/to/login.keychain-db")
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	if err := kc.Unlock(keychainbreaker.WithPassword("keychain-password")); err != nil {
//	    log.Fatal(err)
//	}
//
//	passwords, err := kc.GenericPasswords()
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	for _, p := range passwords {
//	    fmt.Printf("Service: %s, Account: %s, Password: %s\n", p.Service, p.Account, p.Password)
//	}
//
// # Unlock Methods
//
// Two unlock methods are supported:
//
//   - [WithPassword]: derives master key from password via PBKDF2-HMAC-SHA1
//   - [WithKey]: uses a hex-encoded 24-byte master key directly (from memory forensics)
package keychainbreaker
