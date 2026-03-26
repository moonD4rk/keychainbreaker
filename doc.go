// Package keychainbreaker parses and decrypts macOS Keychain files
// (login.keychain-db).
//
// The library implements Apple's CSSM-based keychain binary format parser
// with dynamic schema discovery, and supports decrypting stored credentials
// using Triple-DES CBC encryption.
//
// # Quick Start
//
// Open the default system keychain and unlock with password:
//
//	kc, err := keychainbreaker.Open()
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	if err := kc.Unlock(keychainbreaker.WithPassword("your-macos-login-password")); err != nil {
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
// # Open Options
//
// Three ways to open a keychain:
//
//   - Open() -- default system login keychain
//   - Open([WithFile]) -- specific file path
//   - Open([WithBytes]) -- in-memory buffer
//
// # Unlock Methods
//
// Two unlock methods are supported:
//
//   - [WithPassword]: derives master key from password via PBKDF2-HMAC-SHA1
//   - [WithKey]: uses a hex-encoded 24-byte master key directly (from memory forensics)
package keychainbreaker
