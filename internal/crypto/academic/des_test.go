package academic

import (
	"bytes"
	"testing"
)

func TestDESCBCroundTrips(t *testing.T) {
	lengths := []int{0, 1, 7, 8, 9, 15, 16, 17}
	key := []byte("12345678")
	for _, length := range lengths {
		t.Run(testLengthName(length), func(t *testing.T) {
			plaintext := bytes.Repeat([]byte{0x44}, length)
			iv, ct, err := EncryptDESCBC(key, plaintext)
			if err != nil {
				t.Fatal(err)
			}
			if len(iv) != 8 {
				t.Fatalf("IV length = %d, want 8", len(iv))
			}
			if len(ct) != len(pkcs7Pad(plaintext, 8)) {
				t.Fatalf("ciphertext length = %d, want %d", len(ct), len(pkcs7Pad(plaintext, 8)))
			}
			got, err := DecryptDESCBC(key, iv, ct)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, plaintext) {
				t.Fatalf("decrypted plaintext = %x, want %x", got, plaintext)
			}
		})
	}

	plaintext := []byte("The quick brown fox jumps over the lazy dog")
	iv, ct, err := EncryptDESCBC(key, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecryptDESCBC(key, iv, ct)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("realistic payload round trip failed: got %q", got)
	}
}

func TestDESCBCFreshIV(t *testing.T) {
	key := []byte("12345678")
	iv1, _, err := EncryptDESCBC(key, []byte("x"))
	if err != nil {
		t.Fatal(err)
	}
	iv2, _, err := EncryptDESCBC(key, []byte("x"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(iv1, iv2) {
		t.Fatal("IVs must differ across calls")
	}
}

func TestDESCBCDecryptErrors(t *testing.T) {
	key := []byte("12345678")
	iv := make([]byte, 8)
	ct := make([]byte, 8)

	t.Run("wrong key length", func(t *testing.T) {
		if _, err := DecryptDESCBC([]byte{1}, iv, ct); err == nil {
			t.Fatal("expected an error for invalid key length")
		}
	})
	t.Run("ciphertext not block-aligned", func(t *testing.T) {
		if _, err := DecryptDESCBC(key, iv, []byte{1}); err == nil {
			t.Fatal("expected an error for unaligned ciphertext")
		}
	})
	t.Run("wrong IV length", func(t *testing.T) {
		if _, err := DecryptDESCBC(key, []byte{1}, ct); err == nil {
			t.Fatal("expected an error for invalid IV length")
		}
	})
	t.Run("tampered CBC padding", func(t *testing.T) {
		validIV, validCT, err := EncryptDESCBC(key, []byte("x"))
		if err != nil {
			t.Fatal(err)
		}
		validCT[len(validCT)-1] ^= 1
		if _, err := DecryptDESCBC(key, validIV, validCT); err == nil {
			t.Fatal("expected an error for tampered padding")
		}
	})
}
