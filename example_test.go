package keychainbreaker_test

import (
	"encoding/hex"
	"fmt"
	"log"

	"github.com/moond4rk/keychainbreaker"
)

func Example() {
	kc, err := keychainbreaker.Open("testdata/test.keychain-db")
	if err != nil {
		log.Fatal(err)
	}
	err = kc.UnlockWithPassword("keychainbreaker-test")
	if err != nil {
		log.Fatal(err)
	}
	passwords, err := kc.GenericPasswords()
	if err != nil {
		log.Fatal(err)
	}
	for i := range passwords {
		p := &passwords[i]
		fmt.Printf("%s %s %s\n", p.Service, p.Account, p.Password)
	}
	// Unordered output:
	// moond4rk.com admin password#123
	// HackBrowserData admin password#123
}

func ExampleKeychain_UnlockWithKey() {
	kc, err := keychainbreaker.Open("testdata/test.keychain-db")
	if err != nil {
		log.Fatal(err)
	}
	key, err := hex.DecodeString("4557eb716bbf20200945109cf3b884af9aca72e890e47c07")
	if err != nil {
		log.Fatal(err)
	}
	err = kc.UnlockWithKey(key)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(kc.Unlocked())
	// Output: true
}

// Without an unlock, records still carry their metadata; only the secrets are nil.
func ExampleKeychain_GenericPasswords_locked() {
	kc, err := keychainbreaker.Open("testdata/test.keychain-db")
	if err != nil {
		log.Fatal(err)
	}
	passwords, err := kc.GenericPasswords()
	if err != nil {
		log.Fatal(err)
	}
	for i := range passwords {
		fmt.Println(passwords[i].Service, passwords[i].Password == nil)
	}
	// Unordered output:
	// moond4rk.com true
	// HackBrowserData true
}

func ExampleKeychain_PasswordHash() {
	kc, err := keychainbreaker.Open("testdata/test.keychain-db")
	if err != nil {
		log.Fatal(err)
	}
	hash, err := kc.PasswordHash()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(hash)
	// Output: $keychain$*fc143c45cce245f3e54fbb39141a894e2870dd85*26bca3823a0555be*07821bf723083271da09a3147cb6d73e415d7707099efc3273b36b01c975162bd388f4c5229979e556b74ec1ee3c7cdf
}
