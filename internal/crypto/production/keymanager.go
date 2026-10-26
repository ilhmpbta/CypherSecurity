package production

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
)

// KeyManager wraps DEKs under one or more KEKs (key encryption keys).
// The map key is the KEK version; the value is a 32-byte AES-256 key.
//
// Wrap always uses the newest (highest-numbered) KEK so that rotation works
// without caller changes: add a new KEK, restart, and new uploads use it
// while old DEKs wrapped under older versions still Unwrap fine.
type KeyManager struct {
	keks map[int][]byte
}

var ErrUnknownKEKVersion = errors.New("production: unknown KEK version")

// New validates every KEK is 32 bytes and copies the map so the caller
// cannot mutate it after construction.
func New(keks map[int][]byte) (*KeyManager, error) {
	if len(keks) == 0 {
		return nil, errors.New("production: KeyManager: no KEKs provided")
	}

	copied := make(map[int][]byte, len(keks))
	for version, kek := range keks {
		if len(kek) != 32 {
			return nil, fmt.Errorf("production: KeyManager: KEK version %d is %d bytes, want 32", version, len(kek))
		}
		copiedKEK := make([]byte, 32)
		copy(copiedKEK, kek)
		copied[version] = copiedKEK
	}
	return &KeyManager{keks: copied}, nil
}

// GenerateDEK returns 32 random bytes from crypto/rand.
func (km *KeyManager) GenerateDEK() ([]byte, error) {
	dek := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, dek); err != nil {
		return nil, fmt.Errorf("production: GenerateDEK: %w", err)
	}
	return dek, nil
}

// Wrap seals dek under the newest KEK with AES-256-GCM. The returned wrapped
// blob is nonce (12 bytes) followed by the GCM ciphertext and tag.
//
// The raw dek is not retained by the KeyManager and is not stored in the
// returned blob in plaintext.
func (km *KeyManager) Wrap(dek []byte) (wrapped []byte, kekVersion int, err error) {
	if km == nil || len(km.keks) == 0 {
		return nil, 0, errors.New("production: Wrap: no KEKs available")
	}
	maxVersion, found := 0, false
	for version := range km.keks {
		if !found || version > maxVersion {
			maxVersion = version
			found = true
		}
	}
	if !found {
		return nil, 0, errors.New("production: Wrap: no KEKs available")
	}

	block, err := aes.NewCipher(km.keks[maxVersion])
	if err != nil {
		return nil, 0, fmt.Errorf("production: Wrap: create AES cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, 0, fmt.Errorf("production: Wrap: create GCM: %w", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, 0, fmt.Errorf("production: Wrap: generate nonce: %w", err)
	}
	wrapped = make([]byte, len(nonce), len(nonce)+len(dek)+gcm.Overhead())
	copy(wrapped, nonce)
	wrapped = gcm.Seal(wrapped, nonce, dek, nil)
	return wrapped, maxVersion, nil
}

// Unwrap reverses Wrap. It returns ErrUnknownKEKVersion when the selected KEK
// version is unavailable and a wrapped error when the blob is invalid or does
// not authenticate.
func (km *KeyManager) Unwrap(wrapped []byte, kekVersion int) ([]byte, error) {
	if km == nil {
		return nil, ErrUnknownKEKVersion
	}
	kek, ok := km.keks[kekVersion]
	if !ok {
		return nil, ErrUnknownKEKVersion
	}
	if len(wrapped) < baseNonceSize+tagSize {
		return nil, fmt.Errorf("production: Unwrap: wrapped DEK too short: %d bytes", len(wrapped))
	}

	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, fmt.Errorf("production: Unwrap: create AES cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("production: Unwrap: create GCM: %w", err)
	}
	dek, err := gcm.Open(nil, wrapped[:baseNonceSize], wrapped[baseNonceSize:], nil)
	if err != nil {
		return nil, fmt.Errorf("production: Unwrap: %w", err)
	}
	return dek, nil
}
