package academic

import (
	"bytes"
	"testing"
)

func TestRC4RoundTrips(t *testing.T) {
	lengths := []int{0, 1, 15, 16, 17}
	key := []byte("academic-key")
	for _, length := range lengths {
		t.Run(testLengthName(length), func(t *testing.T) {
			plaintext := bytes.Repeat([]byte{0x45}, length)
			iv, ct, err := EncryptRC4(key, plaintext)
			if err != nil {
				t.Fatal(err)
			}
			if iv != nil {
				t.Fatalf("IV = %v, want nil", iv)
			}
			if len(ct) != len(plaintext) {
				t.Fatalf("ciphertext length = %d, want %d", len(ct), len(plaintext))
			}
			got, err := DecryptRC4(key, iv, ct)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, plaintext) {
				t.Fatalf("decrypted plaintext = %x, want %x", got, plaintext)
			}
		})
	}

	plaintext := []byte("The quick brown fox jumps over the lazy dog")
	iv, ct, err := EncryptRC4(key, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecryptRC4(key, iv, ct)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("realistic payload round trip failed: got %q", got)
	}
}

func TestRC4IVIsNil(t *testing.T) {
	iv, ct, err := EncryptRC4([]byte("key"), []byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	if iv != nil {
		t.Fatalf("IV = %v, want nil", iv)
	}
	if len(ct) != 5 {
		t.Fatalf("ciphertext length = %d, want 5", len(ct))
	}
	pt, err := DecryptRC4([]byte("key"), iv, ct)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pt, []byte("hello")) {
		t.Fatalf("plaintext = %q, want hello", pt)
	}
	if _, err = DecryptRC4([]byte("key"), []byte{0x00}, ct); err == nil {
		t.Fatal("expected a non-nil IV to be rejected")
	}
}

func TestRC4Errors(t *testing.T) {
	t.Run("empty encryption key", func(t *testing.T) {
		if _, _, err := EncryptRC4(nil, []byte("data")); err == nil {
			t.Fatal("expected an error for an empty key")
		}
	})
	t.Run("empty decryption key", func(t *testing.T) {
		if _, err := DecryptRC4(nil, nil, []byte("data")); err == nil {
			t.Fatal("expected an error for an empty key")
		}
	})
	t.Run("non-nil IV", func(t *testing.T) {
		if _, err := DecryptRC4([]byte("key"), []byte{}, nil); err == nil {
			t.Fatal("expected a non-nil IV to be rejected")
		}
	})
}
