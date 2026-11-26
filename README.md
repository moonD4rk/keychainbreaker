# keychainbreaker

[![Go CI](https://github.com/moonD4rk/keychainbreaker/actions/workflows/ci.yml/badge.svg)](https://github.com/moonD4rk/keychainbreaker/actions/workflows/ci.yml) [![codecov](https://codecov.io/gh/moonD4rk/keychainbreaker/branch/main/graph/badge.svg)](https://codecov.io/gh/moonD4rk/keychainbreaker) [![Go Reference](https://pkg.go.dev/badge/github.com/moond4rk/keychainbreaker.svg)](https://pkg.go.dev/github.com/moond4rk/keychainbreaker) [![License](https://img.shields.io/github/license/moonD4rk/keychainbreaker)](https://github.com/moonD4rk/keychainbreaker/blob/main/LICENSE)

A Go library and CLI that read and decrypt macOS Keychain files (`login.keychain-db`). It parses the file itself, so it runs on Linux, macOS and Windows with no CGO and no macOS APIs, and extracts:

- **Generic passwords**: app credentials such as Chrome Safe Storage or Wi-Fi passwords
- **Internet passwords**: website, server and file share credentials
- **Private keys** (PKCS#8) and **X.509 certificates**

## CLI

```bash
brew install moond4rk/tap/keychainbreaker
go install github.com/moond4rk/keychainbreaker/cmd/keychainbreaker@latest # Go 1.27+
```

Binaries are on [GitHub Releases](https://github.com/moonD4rk/keychainbreaker/releases). Every command reads `~/Library/Keychains/login.keychain-db` unless `-f` names another file, and `-v` prints diagnostics to stderr.

### dump

Exports every record to JSON. Each password appears as `password`, `hex_password` and `base64_password`, since a secret need not be valid text.

```
    --entropy string    entropy file for a macOS 26.4+ login keychain (default: auto from /var/db/SystemKeys)
-f, --file string       keychain file (default ~/Library/Keychains/login.keychain-db)
-k, --key string        hex-encoded 24-byte master key, used instead of the password
-o, --output string     output file, or "-" for stdout (default "keychain_dump.json")
-p, --password string   keychain password; other local users can see it, prefer --password-stdin or the prompt
    --password-stdin    read the keychain password from stdin
```

```bash
keychainbreaker dump                                                    # prompts for the password
keychainbreaker dump -f login.keychain-db --password-stdin < password.txt
keychainbreaker dump --key <48-char-hex> -o - | jq '.generic_passwords[].service'
sudo keychainbreaker dump                                               # macOS 26.4+, see below
```

A wrong password still exports the metadata of every record. The output file is created with mode `0600` and replaced in one step; under `sudo` it is handed back to the invoking user.

### hash

```bash
keychainbreaker hash # $keychain$*<salt>*<iv>*<ciphertext>, for hashcat (mode 23100) and John the Ripper
```

No password is needed, but the hash of an entropy-protected macOS 26.4+ login keychain cannot be cracked.

## Library

```bash
go get github.com/moond4rk/keychainbreaker # Go 1.20+, standard library only
```

```go
path, err := keychainbreaker.DefaultKeychainPath() // ~/Library/Keychains/login.keychain-db
if err != nil {
    return err
}
kc, err := keychainbreaker.Open(path) // or OpenBytes(buf); add WithLogger(l) for diagnostics
if err != nil {
    return err
}
if err := kc.UnlockWithPassword("macos-login-password"); err != nil {
    return err
}
passwords, err := kc.GenericPasswords()
if err != nil {
    return err
}
for _, p := range passwords {
    fmt.Printf("%s %s %s\n", p.Service, p.Account, p.Password)
}
```

### Unlock

```go
err := kc.UnlockWithPassword(password)         // PBKDF2-HMAC-SHA1 of the password
err := kc.UnlockWithEntropy(password, entropy) // macOS 26.4+: the password plus the keychain's entropy file
err := kc.UnlockWithKey(masterKey)             // the 24-byte master key itself
```

Each returns `ErrWrongKey` for a wrong credential and leaves the keychain as it was, so another one can be tried.

### Read

```go
generic, err := kc.GenericPasswords()   // application passwords
internet, err := kc.InternetPasswords() // website, server and file share passwords
keys, err := kc.PrivateKeys()           // PKCS#8 private keys
certs, err := kc.Certificates()         // DER-encoded X.509 certificates
hash, err := kc.PasswordHash()          // needs no unlock
```

Records carry their metadata even while the keychain is locked; passwords and private key data stay nil until an unlock succeeds. A `Keychain` is safe for concurrent use. The record types are documented on [pkg.go.dev](https://pkg.go.dev/github.com/moond4rk/keychainbreaker).

## macOS 26.4 and Later

Since macOS 26.4 a login keychain can also be protected by an entropy file, so the password alone no longer unlocks it. Each keychain has its own file, `/var/db/SystemKeys/<SALT>`, named by its salt in uppercase hex (`security show-keychain-info -s` prints it). The file holds 32 random bytes, and the master key becomes `PBKDF2(HMAC-SHA256(entropy, password), salt)`.

The directory is readable only by root, and only while [SIP is disabled](https://developer.apple.com/documentation/security/disabling-and-enabling-system-integrity-protection). Copy the file along with the keychain: Apple's [TN3137](https://developer.apple.com/documentation/technotes/tn3137-on-mac-keychains) warns that a backup without it may be useless, and that its name, location and format are not an API.

```bash
sudo keychainbreaker dump                          # tries the password alone, then reads the entropy file
sudo cat /var/db/SystemKeys/<SALT> > entropy.plist # or copy the file out once...
keychainbreaker dump --entropy entropy.plist       # ...and run unprivileged
```

```go
data, err := os.ReadFile(kc.EntropyPath()) // /var/db/SystemKeys/<SALT>; needs root and SIP off
if err != nil {
    return err
}
entropy, err := keychainbreaker.DecodeEntropy(data)
if err != nil {
    return err
}
err = kc.UnlockWithEntropy(password, entropy)
```

A master key captured from `securityd` ([lldb steps](https://github.com/moonD4rk/keychainbreaker/issues/18#issuecomment-4940156777)) also works, through `--key` or `UnlockWithKey`, without the password or the entropy file. The keychain's blob version, `0x200`, is unrelated: it marks partition support and dates to OS X 10.11.4.

## How It Works

```
Password --> PBKDF2 --> Master Key --> DB Key --> Per-Record Keys --> Plaintext
```

1. **Master key**: PBKDF2-HMAC-SHA1 of the password, or on macOS 26.4+ of `HMAC-SHA256(entropy, password)`
2. **Database key**: decrypted from the keychain's metadata blob with the master key
3. **Record keys**: unwrapped with the database key (RFC 3217 Triple-DES key wrap), as are private keys
4. **Passwords**: decrypted with their record keys, 3DES-CBC

Table schemas are read from the file itself rather than hard-coded. [RFC 001](rfcs/001-keychain-encryption.md) describes the format in full.

## Compatibility

- Supported: `.keychain` and `.keychain-db` files from OS X 10.6 through macOS 27
- Not supported: `keychain-2.db` (iCloud Keychain) and Secure Enclave protected keys

## License

[Apache-2.0](LICENSE)
