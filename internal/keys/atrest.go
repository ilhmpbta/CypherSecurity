package keys

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/argon2"
)

func DeriveWrapKey(password string, salt []byte) []byte {
	return argon2.IDKey([]byte(password), salt, 2, 19456, 1, 32)
}

func EncryptPrivateKey(wrapKey []byte, privDER []byte) (encrypted []byte, nonce []byte, err error) {
	if len(wrapKey) != 32 {
		return nil, nil, errors.New("keys: wrapKey must be 32 bytes")
	}
	block, err := aes.NewCipher(wrapKey)
	if err != nil {
		return nil, nil, fmt.Errorf("keys: aes cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, fmt.Errorf("keys: gcm: %w", err)
	}
	nonce = make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, fmt.Errorf("keys: nonce: %w", err)
	}
	encrypted = gcm.Seal(nil, nonce, privDER, nil)
	return encrypted, nonce, nil
}

func DecryptPrivateKey(wrapKey []byte, encrypted, nonce []byte) (*rsa.PrivateKey, error) {
	if len(wrapKey) != 32 {
		return nil, errors.New("keys: wrapKey must be 32 bytes")
	}
	block, err := aes.NewCipher(wrapKey)
	if err != nil {
		return nil, fmt.Errorf("keys: aes cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("keys: gcm: %w", err)
	}
	privDER, err := gcm.Open(nil, nonce, encrypted, nil)
	if err != nil {
		return nil, fmt.Errorf("keys: decrypt private key: %w", err)
	}
	privKeyAny, err := x509.ParsePKCS8PrivateKey(privDER)
	if err != nil {
		return nil, fmt.Errorf("keys: parse pkcs8: %w", err)
	}
	privKey, ok := privKeyAny.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("keys: not an RSA private key")
	}
	return privKey, nil
}
