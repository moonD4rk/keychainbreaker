// Package keychainbreaker reads macOS Keychain files (login.keychain-db) and decrypts the credentials they hold.
//
// It parses the CSSM database format directly, discovering each table's schema from the file, so it needs no macOS
// API and runs on any platform.
//
// # Open, unlock, read
//
//	kc, err := keychainbreaker.Open("/path/to/login.keychain-db")
//	if err != nil {
//		return err
//	}
//	if err := kc.UnlockWithPassword(password); err != nil {
//		return err
//	}
//	passwords, err := kc.GenericPasswords()
//
// [DefaultKeychainPath] locates the current user's login keychain, and [OpenBytes] parses a keychain that is already
// in memory.
//
// # Locked keychains
//
// Opening needs no credential. Before an unlock, or after a failed one, every record still carries its metadata
// (service, account, timestamps and so on); passwords and private key data are nil, and certificates are complete.
// [Keychain.PasswordHash] exports the hash for offline cracking without any credential.
//
// # Unlocking
//
//   - [Keychain.UnlockWithPassword] derives the master key from the password with PBKDF2-HMAC-SHA1.
//   - [Keychain.UnlockWithEntropy] also folds in a per-machine entropy file: macOS 26.4 and later protect the login
//     keychain with HMAC-SHA256(entropy, password), so the password alone no longer unlocks it. [Keychain.EntropyPath]
//     locates the file and [DecodeEntropy] reads its contents.
//   - [Keychain.UnlockWithKey] takes the 24-byte master key itself, such as one recovered from securityd's memory.
//
// A failed unlock returns [ErrWrongKey] and leaves the keychain as it was, so another credential can be tried.
package keychainbreaker
