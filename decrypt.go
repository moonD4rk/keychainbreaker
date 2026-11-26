package keychainbreaker

import (
	"crypto/cipher"
	"crypto/des"
	"crypto/hmac"
	"crypto/sha1"
	"errors"
	"fmt"
	"hash"
)

const (
	blockSize        = des.BlockSize
	tripleDESKeyLen  = 24
	pbkdf2Iterations = 1000
)

// cmsWrapIV is the fixed IV of Apple's CMS key wrapping (RFC 3217).
var cmsWrapIV = []byte{0x4a, 0xdd, 0xa2, 0x2c, 0x79, 0xe8, 0x21, 0x05}

// decryptCBC decrypts 3DES-CBC ciphertext and strips its PKCS#7 padding.
func decryptCBC(key, iv, data []byte) ([]byte, error) {
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
		return nil, fmt.Errorf("invalid padding value %d", pad)
	}
	for _, b := range plain[len(plain)-pad:] {
		if int(b) != pad {
			return nil, errors.New("padding verification failed")
		}
	}
	return plain[:len(plain)-pad], nil
}

// unwrapKey unwraps a 24-byte symmetric key (RFC 3217): decrypt with the CMS IV, reverse the first 32 bytes,
// decrypt again with the record's IV.
func unwrapKey(encryptedBlob, iv, dbKey []byte) ([]byte, error) {
	plain, err := decryptCBC(dbKey, cmsWrapIV, encryptedBlob)
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
	finalPlain, err := decryptCBC(dbKey, iv, rev)
	if err != nil {
		return nil, fmt.Errorf("key unwrap stage 2: %w", err)
	}
	if len(finalPlain) < 4 {
		return nil, errors.New("unwrapped key too short")
	}
	key := finalPlain[4:]
	if len(key) != tripleDESKeyLen {
		return nil, fmt.Errorf("invalid unwrapped key length: got %d, want %d", len(key), tripleDESKeyLen)
	}
	return append([]byte{}, key...), nil
}

// unwrapPrivateKey unwraps a private key like unwrapKey, except that it reverses every byte, not just the first 32.
func unwrapPrivateKey(encryptedBlob, iv, dbKey []byte) ([]byte, error) {
	plain, err := decryptCBC(dbKey, cmsWrapIV, encryptedBlob)
	if err != nil {
		return nil, fmt.Errorf("private key unwrap stage 1: %w", err)
	}
	rev := make([]byte, len(plain))
	for i := range plain {
		rev[i] = plain[len(plain)-1-i]
	}
	finalPlain, err := decryptCBC(dbKey, iv, rev)
	if err != nil {
		return nil, fmt.Errorf("private key unwrap stage 2: %w", err)
	}
	return finalPlain, nil
}

// deriveMasterKey derives the 24-byte master key from a passphrase with PBKDF2-HMAC-SHA1 and the database blob's
// salt. The passphrase is the login password, or HMAC-SHA256(entropy, password) on macOS 26.4 and later; see
// mixEntropy.
func deriveMasterKey(passphrase, salt []byte) []byte {
	return pbkdf2Key(passphrase, salt, pbkdf2Iterations, tripleDESKeyLen, sha1.New)
}

// pbkdf2Key is golang.org/x/crypto/pbkdf2.Key: crypto/pbkdf2 needs Go 1.24, and the library has no dependencies.
func pbkdf2Key(password, salt []byte, iter, keyLen int, h func() hash.Hash) []byte {
	prf := hmac.New(h, password)
	hashLen := prf.Size()
	numBlocks := (keyLen + hashLen - 1) / hashLen

	var buf [4]byte
	dk := make([]byte, 0, numBlocks*hashLen)
	u := make([]byte, hashLen)
	for block := 1; block <= numBlocks; block++ {
		prf.Reset()
		prf.Write(salt)
		buf[0] = byte(block >> 24)
		buf[1] = byte(block >> 16)
		buf[2] = byte(block >> 8)
		buf[3] = byte(block)
		prf.Write(buf[:4])
		dk = prf.Sum(dk)
		t := dk[len(dk)-hashLen:]
		copy(u, t)

		for n := 2; n <= iter; n++ {
			prf.Reset()
			prf.Write(u)
			u = u[:0]
			u = prf.Sum(u)
			for x := range u {
				t[x] ^= u[x]
			}
		}
	}
	return dk[:keyLen]
}
