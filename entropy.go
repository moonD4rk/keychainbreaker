package keychainbreaker

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"strings"
)

// systemKeysDir is where macOS 26.4 and later keep login keychain entropy files.
const systemKeysDir = "/var/db/SystemKeys"

// EntropyPath returns the conventional location of this keychain's entropy file, /var/db/SystemKeys/<SALT>, where
// macOS 26.4 and later store the per-machine secret that UnlockWithEntropy needs. The salt is the file's name, in
// uppercase hex, the same value "security show-keychain-info -s" prints.
//
// The directory is readable only by root and only while System Integrity Protection is disabled, so reading the file
// usually needs both. Apple documents (Technical Note TN3137) that the name, location and format are not an API and
// may change.
func (kc *Keychain) EntropyPath() string {
	return systemKeysDir + "/" + strings.ToUpper(hex.EncodeToString(kc.dbBlob.salt))
}

// DecodeEntropy extracts the raw secret from the contents of an entropy file. The file is an XML property list whose
// single <data> element holds the base64-encoded secret, 32 bytes on current macOS. The format is not a stable API.
func DecodeEntropy(plist []byte) ([]byte, error) {
	var doc struct {
		Data string `xml:"data"`
	}
	if err := xml.Unmarshal(plist, &doc); err != nil {
		return nil, fmt.Errorf("keychainbreaker: parse entropy plist: %w", err)
	}
	encoded := strings.Join(strings.Fields(doc.Data), "")
	if encoded == "" {
		return nil, errors.New("keychainbreaker: entropy plist has no data element")
	}
	secret, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("keychainbreaker: decode entropy: %w", err)
	}
	return secret, nil
}

// mixEntropy folds the entropy into the password the way macOS 26.4 and later do before PBKDF2: the entropy is the
// HMAC-SHA256 key and the password is the message, as in an HKDF extract step.
func mixEntropy(entropy, password []byte) []byte {
	mac := hmac.New(sha256.New, entropy)
	mac.Write(password)
	return mac.Sum(nil)
}
