package academic

// DES experiment: CBC mode. INSECURE — academic comparison only.
// DES has a 56-bit effective key and was withdrawn by NIST in 2005.
// Never use this to protect real data.

import (
	"crypto/cipher"
	"crypto/des"
	"crypto/rand"
	"fmt"
)

// EncryptDESCBC encrypts plaintext with DES in CBC mode and PKCS#7 padding.
func EncryptDESCBC(key, plaintext []byte) (iv, ct []byte, err error) {
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, nil, fmt.Errorf("academic: DES-CBC: %w", err)
	}

	iv = make([]byte, des.BlockSize)
	if _, err = rand.Read(iv); err != nil {
		return nil, nil, fmt.Errorf("academic: DES-CBC: generate IV: %w", err)
	}

	padded := pkcs7Pad(plaintext, des.BlockSize)
	ct = make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ct, padded)
	return iv, ct, nil
}

// DecryptDESCBC decrypts DES-CBC ciphertext and removes PKCS#7 padding.
func DecryptDESCBC(key, iv, ct []byte) ([]byte, error) {
	if len(iv) != des.BlockSize {
		return nil, fmt.Errorf("academic: DES-CBC: IV must be %d bytes", des.BlockSize)
	}
	if len(ct) == 0 {
		return nil, fmt.Errorf("academic: DES-CBC: ciphertext must not be empty")
	}
	if len(ct)%des.BlockSize != 0 {
		return nil, fmt.Errorf("academic: DES-CBC: ciphertext length must be a multiple of %d bytes", des.BlockSize)
	}

	block, err := des.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("academic: DES-CBC: %w", err)
	}
	plaintext := make([]byte, len(ct))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(plaintext, ct)
	return pkcs7Unpad(plaintext, des.BlockSize)
}
