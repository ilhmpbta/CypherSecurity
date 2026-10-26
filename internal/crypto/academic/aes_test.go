package academic

import (
	"bytes"
	"strconv"
	"testing"
)

func TestAESCBCroundTrips(t *testing.T) {
	tests := []struct {
		name    string
		keySize int
		encrypt func([]byte, []byte) ([]byte, []byte, error)
		decrypt func([]byte, []byte, []byte) ([]byte, error)
	}{
		{"AES-128-CBC", 16, EncryptAES128CBC, DecryptAES128CBC},
		{"AES-256-CBC", 32, EncryptAES256CBC, DecryptAES256CBC},
	}
	lengths := []int{0, 1, 15, 16, 17}
	for _, algorithm := range tests {
		t.Run(algorithm.name, func(t *testing.T) {
			key := bytes.Repeat([]byte{0x01}, algorithm.keySize)
			for _, length := range lengths {
				t.Run(testLengthName(length), func(t *testing.T) {
					plaintext := bytes.Repeat([]byte{0x42}, length)
					iv, ct, err := algorithm.encrypt(key, plaintext)
					if err != nil {
						t.Fatal(err)
					}
					if len(iv) != 16 {
						t.Fatalf("IV length = %d, want 16", len(iv))
					}
					if len(ct) != len(pkcs7Pad(plaintext, 16)) {
						t.Fatalf("ciphertext length = %d, want %d", len(ct), len(pkcs7Pad(plaintext, 16)))
					}
					got, err := algorithm.decrypt(key, iv, ct)
					if err != nil {
						t.Fatal(err)
					}
					if !bytes.Equal(got, plaintext) {
						t.Fatalf("decrypted plaintext = %x, want %x", got, plaintext)
					}
				})
			}

			plaintext := []byte("The quick brown fox jumps over the lazy dog")
			iv, ct, err := algorithm.encrypt(key, plaintext)
			if err != nil {
				t.Fatal(err)
			}
			got, err := algorithm.decrypt(key, iv, ct)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, plaintext) {
				t.Fatalf("realistic payload round trip failed: got %q", got)
			}
		})
	}
}

func TestAESCTRRoundsTrips(t *testing.T) {
	tests := []struct {
		name    string
		keySize int
		encrypt func([]byte, []byte) ([]byte, []byte, error)
		decrypt func([]byte, []byte, []byte) ([]byte, error)
	}{
		{"AES-128-CTR", 16, EncryptAES128CTR, DecryptAES128CTR},
		{"AES-256-CTR", 32, EncryptAES256CTR, DecryptAES256CTR},
	}
	lengths := []int{0, 1, 15, 16, 17}
	for _, algorithm := range tests {
		t.Run(algorithm.name, func(t *testing.T) {
			key := bytes.Repeat([]byte{0x02}, algorithm.keySize)
			for _, length := range lengths {
				t.Run(testLengthName(length), func(t *testing.T) {
					plaintext := bytes.Repeat([]byte{0x43}, length)
					iv, ct, err := algorithm.encrypt(key, plaintext)
					if err != nil {
						t.Fatal(err)
					}
					if len(iv) != 16 {
						t.Fatalf("IV length = %d, want 16", len(iv))
					}
					if len(ct) != len(plaintext) {
						t.Fatalf("ciphertext length = %d, want %d", len(ct), len(plaintext))
					}
					got, err := algorithm.decrypt(key, iv, ct)
					if err != nil {
						t.Fatal(err)
					}
					if !bytes.Equal(got, plaintext) {
						t.Fatalf("decrypted plaintext = %x, want %x", got, plaintext)
					}
				})
			}

			plaintext := []byte("The quick brown fox jumps over the lazy dog")
			iv, ct, err := algorithm.encrypt(key, plaintext)
			if err != nil {
				t.Fatal(err)
			}
			got, err := algorithm.decrypt(key, iv, ct)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, plaintext) {
				t.Fatalf("realistic payload round trip failed: got %q", got)
			}
		})
	}
}

func TestAESCBCFreshIVs(t *testing.T) {
	tests := []struct {
		name    string
		keySize int
		encrypt func([]byte, []byte) ([]byte, []byte, error)
	}{
		{"AES-128-CBC", 16, EncryptAES128CBC},
		{"AES-256-CBC", 32, EncryptAES256CBC},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assertFreshAESIV(t, test.encrypt, test.keySize)
		})
	}
}

func TestAESCTRFreshIVs(t *testing.T) {
	tests := []struct {
		name    string
		keySize int
		encrypt func([]byte, []byte) ([]byte, []byte, error)
	}{
		{"AES-128-CTR", 16, EncryptAES128CTR},
		{"AES-256-CTR", 32, EncryptAES256CTR},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assertFreshAESIV(t, test.encrypt, test.keySize)
		})
	}
}

func TestAESDecryptErrors(t *testing.T) {
	key128 := make([]byte, 16)
	validCBCIV := make([]byte, 16)
	validCBCCT := make([]byte, 16)

	t.Run("wrong AES-128-CBC key length", func(t *testing.T) {
		if _, err := DecryptAES128CBC(nil, validCBCIV, validCBCCT); err == nil {
			t.Fatal("expected an error for invalid key length")
		}
	})
	t.Run("wrong AES-256-CBC key length", func(t *testing.T) {
		if _, err := DecryptAES256CBC(key128, validCBCIV, validCBCCT); err == nil {
			t.Fatal("expected an error for invalid key length")
		}
	})
	t.Run("wrong AES-128-CTR key length", func(t *testing.T) {
		if _, err := DecryptAES128CTR(nil, validCBCIV, nil); err == nil {
			t.Fatal("expected an error for invalid key length")
		}
	})
	t.Run("wrong AES-256-CTR key length", func(t *testing.T) {
		if _, err := DecryptAES256CTR(key128, validCBCIV, nil); err == nil {
			t.Fatal("expected an error for invalid key length")
		}
	})
	t.Run("CBC ciphertext not block-aligned", func(t *testing.T) {
		if _, err := DecryptAES128CBC(key128, validCBCIV, []byte{1}); err == nil {
			t.Fatal("expected an error for unaligned ciphertext")
		}
	})
	t.Run("CBC IV wrong length", func(t *testing.T) {
		if _, err := DecryptAES128CBC(key128, []byte{1}, validCBCCT); err == nil {
			t.Fatal("expected an error for invalid IV length")
		}
	})
	t.Run("CTR IV wrong length", func(t *testing.T) {
		if _, err := DecryptAES128CTR(key128, []byte{1}, nil); err == nil {
			t.Fatal("expected an error for invalid IV length")
		}
	})
	t.Run("tampered CBC padding", func(t *testing.T) {
		iv, ct, err := EncryptAES128CBC(key128, []byte("x"))
		if err != nil {
			t.Fatal(err)
		}
		ct[len(ct)-1] ^= 1
		if _, err := DecryptAES128CBC(key128, iv, ct); err == nil {
			t.Fatal("expected an error for tampered padding")
		}
	})
}

func TestPKCS7UnpadRejectsInvalidPadding(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{"empty input", nil},
		{"padding length exceeds block size", bytes.Repeat([]byte{0}, 15+1)},
		{"zero padding length", make([]byte, 16)},
		{"inconsistent padding bytes", append(bytes.Repeat([]byte{1}, 15), 2)},
	}
	tests[1].data[15] = 17

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := pkcs7Unpad(test.data, 16); err == nil {
				t.Fatal("expected invalid padding to be rejected")
			}
		})
	}
}

func assertFreshAESIV(t *testing.T, encrypt func([]byte, []byte) ([]byte, []byte, error), keySize int) {
	t.Helper()
	key := make([]byte, keySize)
	iv1, _, err := encrypt(key, []byte("x"))
	if err != nil {
		t.Fatal(err)
	}
	iv2, _, err := encrypt(key, []byte("x"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(iv1, iv2) {
		t.Fatal("IVs must differ across calls")
	}
}

func testLengthName(length int) string {
	return "len=" + strconv.Itoa(length)
}
