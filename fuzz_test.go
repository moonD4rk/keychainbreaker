package keychainbreaker

import (
	"testing"
)

// FuzzOpenBytes feeds mutated keychains through parsing, unlocking and extraction, which must never panic.
func FuzzOpenBytes(f *testing.F) {
	fixture := readTestKeychain(f)
	f.Add(fixture)
	f.Add(fixture[:len(fixture)/2])
	key := testMasterKey(f)

	f.Fuzz(func(_ *testing.T, data []byte) {
		kc, err := OpenBytes(data)
		if err != nil {
			return
		}
		_, _ = kc.PasswordHash()
		readAll(kc)
		if kc.UnlockWithKey(key) == nil {
			readAll(kc)
		}
	})
}

func readAll(kc *Keychain) {
	_, _ = kc.GenericPasswords()
	_, _ = kc.InternetPasswords()
	_, _ = kc.PrivateKeys()
	_, _ = kc.Certificates()
}
