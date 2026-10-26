package academic

// RC4 experiment. INSECURE — academic comparison only.
// RC4 is marked "cryptographically broken" by the Go documentation and is
// prohibited by RFC 7465 and every modern security standard.
// Never use this to protect real data.

import (
	"crypto/rc4"
	"errors"
	"fmt"
)

// EncryptRC4 encrypts plaintext with RC4.
// RC4 is a stream cipher; the returned IV is nil. The `iv` parameter on
// DecryptRC4 is ignored and must be nil.
func EncryptRC4(key, plaintext []byte) (iv, ct []byte, err error) {
	if len(key) == 0 {
		return nil, nil, errors.New("academic: RC4: empty key")
	}
	stream, err := rc4.NewCipher(key)
	if err != nil {
		return nil, nil, fmt.Errorf("academic: RC4: %w", err)
	}

	ct = make([]byte, len(plaintext))
	stream.XORKeyStream(ct, plaintext)
	return nil, ct, nil
}

// DecryptRC4 decrypts ciphertext with RC4.
// RC4 is a stream cipher; the `iv` parameter must be nil.
func DecryptRC4(key, iv, ct []byte) ([]byte, error) {
	if iv != nil {
		return nil, errors.New("academic: RC4: IV must be nil")
	}
	if len(key) == 0 {
		return nil, errors.New("academic: RC4: empty key")
	}
	stream, err := rc4.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("academic: RC4: %w", err)
	}

	plaintext := make([]byte, len(ct))
	stream.XORKeyStream(plaintext, ct)
	return plaintext, nil
}
