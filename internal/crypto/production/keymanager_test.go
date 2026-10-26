package production

import (
	"bytes"
	"crypto/rand"
	"errors"
	"testing"
)

func TestKeyManagerWrapUnwrap(t *testing.T) {
	keks := map[int][]byte{
		1: bytes.Repeat([]byte{0x01}, 32),
		2: bytes.Repeat([]byte{0x02}, 32),
		3: bytes.Repeat([]byte{0x03}, 32),
	}
	km, err := New(keks)
	if !errors.Is(err, nil) {
		t.Fatalf("New returned error: %v", err)
	}

	dek := make([]byte, 32)
	if _, err := rand.Read(dek); err != nil {
		t.Fatal(err)
	}
	wrapped, version, err := km.Wrap(dek)
	if !errors.Is(err, nil) {
		t.Fatalf("Wrap returned error: %v", err)
	}
	if version != 3 {
		t.Fatalf("Wrap KEK version = %d, want 3", version)
	}
	got, err := km.Unwrap(wrapped, version)
	if !errors.Is(err, nil) {
		t.Fatalf("Unwrap returned error: %v", err)
	}
	if !bytes.Equal(got, dek) {
		t.Fatal("Unwrap(Wrap(dek)) did not recover the DEK")
	}
}

func TestKeyManagerTamperDetection(t *testing.T) {
	km, err := New(map[int][]byte{1: bytes.Repeat([]byte{0x17}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	dek := bytes.Repeat([]byte{0x42}, 32)
	wrapped, version, err := km.Wrap(dek)
	if err != nil {
		t.Fatal(err)
	}

	positions := []struct {
		name string
		pos  int
	}{
		{"nonce first byte", 0},
		{"nonce last byte", 11},
		{"ciphertext first byte", 12},
		{"tag last byte", len(wrapped) - 1},
	}
	for _, position := range positions {
		t.Run(position.name, func(t *testing.T) {
			tampered := append([]byte(nil), wrapped...)
			tampered[position.pos] ^= 0xff
			if _, err := km.Unwrap(tampered, version); err == nil {
				t.Fatal("expected tampered wrapped DEK to fail authentication")
			} else if errors.Is(err, ErrUnknownKEKVersion) {
				t.Fatalf("tampering returned unknown-version error: %v", err)
			}
		})
	}
}

func TestKeyManagerUnknownVersion(t *testing.T) {
	km, err := New(map[int][]byte{1: bytes.Repeat([]byte{0x19}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := km.Unwrap(nil, 999); !errors.Is(err, ErrUnknownKEKVersion) {
		t.Fatalf("Unwrap error = %v, want ErrUnknownKEKVersion", err)
	}
}

func TestKeyManagerWrapUsesFreshNonce(t *testing.T) {
	km, err := New(map[int][]byte{1: bytes.Repeat([]byte{0x21}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	dek := bytes.Repeat([]byte{0x31}, 32)
	wrapped1, _, err := km.Wrap(dek)
	if err != nil {
		t.Fatal(err)
	}
	wrapped2, _, err := km.Wrap(dek)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(wrapped1, wrapped2) {
		t.Fatal("wrapped DEKs must differ because each wrap uses a fresh nonce")
	}
}

func TestKeyManagerNewValidation(t *testing.T) {
	t.Run("empty KEK map", func(t *testing.T) {
		if _, err := New(map[int][]byte{}); err == nil {
			t.Fatal("expected empty KEK map to be rejected")
		}
	})
	t.Run("incorrect KEK size", func(t *testing.T) {
		if _, err := New(map[int][]byte{1: make([]byte, 16)}); err == nil {
			t.Fatal("expected 16-byte KEK to be rejected")
		}
	})
	t.Run("multiple valid KEKs", func(t *testing.T) {
		if _, err := New(map[int][]byte{
			1: make([]byte, 32),
			2: bytes.Repeat([]byte{0x01}, 32),
		}); err != nil {
			t.Fatalf("New returned error for valid KEKs: %v", err)
		}
	})
}

func TestKeyManagerCopiesKEKValues(t *testing.T) {
	callerKEK := bytes.Repeat([]byte{0x51}, 32)
	expectedKEK := append([]byte(nil), callerKEK...)
	km, err := New(map[int][]byte{7: callerKEK})
	if err != nil {
		t.Fatal(err)
	}
	for i := range callerKEK {
		callerKEK[i] ^= 0xff
	}

	dek := bytes.Repeat([]byte{0x61}, 32)
	wrapped, version, err := km.Wrap(dek)
	if err != nil {
		t.Fatal(err)
	}
	if version != 7 {
		t.Fatalf("Wrap KEK version = %d, want 7", version)
	}
	independent, err := New(map[int][]byte{7: expectedKEK})
	if err != nil {
		t.Fatal(err)
	}
	got, err := independent.Unwrap(wrapped, version)
	if err != nil {
		t.Fatalf("copied KEK was affected by caller mutation: %v", err)
	}
	if !bytes.Equal(got, dek) {
		t.Fatal("Unwrap did not recover the original DEK")
	}
}

func TestGenerateDEK(t *testing.T) {
	km, err := New(map[int][]byte{1: bytes.Repeat([]byte{0x71}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	dek1, err := km.GenerateDEK()
	if err != nil {
		t.Fatal(err)
	}
	dek2, err := km.GenerateDEK()
	if err != nil {
		t.Fatal(err)
	}
	if len(dek1) != 32 || len(dek2) != 32 {
		t.Fatalf("GenerateDEK lengths = %d, %d; want 32", len(dek1), len(dek2))
	}
	if bytes.Equal(dek1, dek2) {
		t.Fatal("GenerateDEK calls must return different bytes")
	}
}

func TestKeyManagerUnwrapErrors(t *testing.T) {
	km, err := New(map[int][]byte{1: bytes.Repeat([]byte{0x81}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := km.Unwrap(make([]byte, baseNonceSize+tagSize-1), 1); err == nil {
		t.Fatal("expected short wrapped DEK to be rejected")
	}
}
