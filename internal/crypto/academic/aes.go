package academic

// AES experiment: CBC and CTR modes. Not for production use.

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
)

func pkcs7Pad(data []byte, blockSize int) []byte {
	if blockSize <= 0 {
		return nil
	}

	padding := blockSize - len(data)%blockSize
	padded := make([]byte, len(data)+padding)
	copy(padded, data)
	for i := len(data); i < len(padded); i++ {
		padded[i] = byte(padding)
	}
	return padded
}

func pkcs7Unpad(data []byte, blockSize int) ([]byte, error) {
	if blockSize <= 0 {
		return nil, errors.New("academic: invalid PKCS#7 block size")
	}
	if len(data) == 0 {
		return nil, errors.New("academic: invalid PKCS#7 padding: empty input")
	}
	if len(data)%blockSize != 0 {
		return nil, errors.New("academic: invalid PKCS#7 padding: input is not block-aligned")
	}

	padding := int(data[len(data)-1])
	if padding == 0 {
		return nil, errors.New("academic: invalid PKCS#7 padding: zero padding length")
	}
	if padding > blockSize || padding > len(data) {
		return nil, errors.New("academic: invalid PKCS#7 padding: padding length exceeds block size")
	}
	for _, value := range data[len(data)-padding:] {
		if int(value) != padding {
			return nil, errors.New("academic: invalid PKCS#7 padding: inconsistent padding bytes")
		}
	}
	return data[:len(data)-padding], nil
}

func newAESBlock(key []byte, name string, keySize int) (cipher.Block, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("academic: %s: %w", name, err)
	}
	if len(key) != keySize {
		return nil, fmt.Errorf("academic: %s: key must be %d bytes", name, keySize)
	}
	return block, nil
}

func encryptAESCBC(key, plaintext []byte, name string, keySize int) (iv, ct []byte, err error) {
	block, err := newAESBlock(key, name, keySize)
	if err != nil {
		return nil, nil, err
	}

	iv = make([]byte, aes.BlockSize)
	if _, err = rand.Read(iv); err != nil {
		return nil, nil, fmt.Errorf("academic: %s: generate IV: %w", name, err)
	}

	padded := pkcs7Pad(plaintext, aes.BlockSize)
	ct = make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ct, padded)
	return iv, ct, nil
}

func decryptAESCBC(key, iv, ct []byte, name string, keySize int) ([]byte, error) {
	if len(iv) != aes.BlockSize {
		return nil, fmt.Errorf("academic: %s: IV must be %d bytes", name, aes.BlockSize)
	}
	if len(ct) == 0 {
		return nil, fmt.Errorf("academic: %s: ciphertext must not be empty", name)
	}
	if len(ct)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("academic: %s: ciphertext length must be a multiple of %d bytes", name, aes.BlockSize)
	}

	block, err := newAESBlock(key, name, keySize)
	if err != nil {
		return nil, err
	}
	plaintext := make([]byte, len(ct))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(plaintext, ct)
	return pkcs7Unpad(plaintext, aes.BlockSize)
}

func encryptAESCTR(key, plaintext []byte, name string, keySize int) (iv, ct []byte, err error) {
	block, err := newAESBlock(key, name, keySize)
	if err != nil {
		return nil, nil, err
	}

	iv = make([]byte, aes.BlockSize)
	if _, err = rand.Read(iv); err != nil {
		return nil, nil, fmt.Errorf("academic: %s: generate IV: %w", name, err)
	}

	ct = make([]byte, len(plaintext))
	cipher.NewCTR(block, iv).XORKeyStream(ct, plaintext)
	return iv, ct, nil
}

func decryptAESCTR(key, iv, ct []byte, name string, keySize int) ([]byte, error) {
	if len(iv) != aes.BlockSize {
		return nil, fmt.Errorf("academic: %s: IV must be %d bytes", name, aes.BlockSize)
	}
	block, err := newAESBlock(key, name, keySize)
	if err != nil {
		return nil, err
	}

	plaintext := make([]byte, len(ct))
	cipher.NewCTR(block, iv).XORKeyStream(plaintext, ct)
	return plaintext, nil
}

// EncryptAES128CBC encrypts plaintext with AES-128 in CBC mode and PKCS#7 padding.
func EncryptAES128CBC(key, plaintext []byte) (iv, ct []byte, err error) {
	return encryptAESCBC(key, plaintext, "AES-128-CBC", 16)
}

// DecryptAES128CBC decrypts AES-128-CBC ciphertext and removes PKCS#7 padding.
func DecryptAES128CBC(key, iv, ct []byte) ([]byte, error) {
	return decryptAESCBC(key, iv, ct, "AES-128-CBC", 16)
}

// EncryptAES256CBC encrypts plaintext with AES-256 in CBC mode and PKCS#7 padding.
func EncryptAES256CBC(key, plaintext []byte) (iv, ct []byte, err error) {
	return encryptAESCBC(key, plaintext, "AES-256-CBC", 32)
}

// DecryptAES256CBC decrypts AES-256-CBC ciphertext and removes PKCS#7 padding.
func DecryptAES256CBC(key, iv, ct []byte) ([]byte, error) {
	return decryptAESCBC(key, iv, ct, "AES-256-CBC", 32)
}

// EncryptAES128CTR encrypts plaintext with AES-128 in CTR mode without padding.
func EncryptAES128CTR(key, plaintext []byte) (iv, ct []byte, err error) {
	return encryptAESCTR(key, plaintext, "AES-128-CTR", 16)
}

// DecryptAES128CTR decrypts AES-128-CTR ciphertext without padding.
func DecryptAES128CTR(key, iv, ct []byte) ([]byte, error) {
	return decryptAESCTR(key, iv, ct, "AES-128-CTR", 16)
}

// EncryptAES256CTR encrypts plaintext with AES-256 in CTR mode without padding.
func EncryptAES256CTR(key, plaintext []byte) (iv, ct []byte, err error) {
	return encryptAESCTR(key, plaintext, "AES-256-CTR", 32)
}

// DecryptAES256CTR decrypts AES-256-CTR ciphertext without padding.
func DecryptAES256CTR(key, iv, ct []byte) ([]byte, error) {
	return decryptAESCTR(key, iv, ct, "AES-256-CTR", 32)
}
