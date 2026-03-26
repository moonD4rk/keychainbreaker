package keychainbreaker

import (
	"crypto/cipher"
	"crypto/des"
	"errors"
	"fmt"
)

const (
	blockSize = 8
	keyLength = 24
)

// magicCMSIV is the fixed IV used by Apple's CMS key wrapping (RFC 3217).
var magicCMSIV = []byte{0x4a, 0xdd, 0xa2, 0x2c, 0x79, 0xe8, 0x21, 0x05}

// kcDecrypt decrypts ciphertext using 3DES-CBC and validates PKCS#7 padding.
func kcDecrypt(key, iv, data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, errors.New("ciphertext is empty")
	}
	if len(data)%blockSize != 0 {
		return nil, errors.New("ciphertext not aligned to block size")
	}
	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		return nil, err
	}
	if len(iv) != blockSize {
		return nil, errors.New("invalid IV length")
	}
	plain := make([]byte, len(data))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(plain, data)

	pad := int(plain[len(plain)-1])
	if pad == 0 || pad > blockSize {
		return nil, fmt.Errorf("invalid padding value %d: %w", pad, ErrWrongKey)
	}
	for _, b := range plain[len(plain)-pad:] {
		if int(b) != pad {
			return nil, fmt.Errorf("padding verification failed: %w", ErrWrongKey)
		}
	}
	return plain[:len(plain)-pad], nil
}

// keyblobDecrypt performs RFC 3217 two-stage key unwrapping for symmetric keys.
// Stage 1: decrypt with dbKey + magicCMSIV
// Stage 2: reverse first 32 bytes
// Stage 3: decrypt with dbKey + record IV
func keyblobDecrypt(encryptedBlob, iv, dbKey []byte) ([]byte, error) {
	plain, err := kcDecrypt(dbKey, magicCMSIV, encryptedBlob)
	if err != nil {
		return nil, fmt.Errorf("key unwrap stage 1: %w", err)
	}
	if len(plain) < 32 {
		return nil, errors.New("decrypted blob too short for key unwrap")
	}
	rev := make([]byte, 32)
	for i := 0; i < 32; i++ {
		rev[i] = plain[31-i]
	}
	finalPlain, err := kcDecrypt(dbKey, iv, rev)
	if err != nil {
		return nil, fmt.Errorf("key unwrap stage 2: %w", err)
	}
	if len(finalPlain) < 4 {
		return nil, errors.New("unwrapped key too short")
	}
	key := finalPlain[4:]
	if len(key) != keyLength {
		return nil, fmt.Errorf("invalid unwrapped key length: got %d, want %d", len(key), keyLength)
	}
	return append([]byte{}, key...), nil
}
