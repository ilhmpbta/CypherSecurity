package benchmark

import (
	"bytes"
	"crypto/aes"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/ilhmpbta/CypherSecurity/internal/crypto/academic"
	"github.com/ilhmpbta/CypherSecurity/internal/crypto/production"
)

func TestFixturesExist(t *testing.T) {
	ensureFixtures(t)
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("could not locate harness test source")
	}
	dir := filepath.Join(filepath.Dir(thisFile), "files")
	for _, fixture := range fixtureSizes {
		info, err := os.Stat(filepath.Join(dir, fixture.Name+".bin"))
		if err != nil {
			t.Fatalf("stat fixture %s: %v", fixture.Name, err)
		}
		if info.Size() != int64(fixture.Size) {
			t.Errorf("fixture %s size = %d, want %d", fixture.Name, info.Size(), fixture.Size)
		}
	}
}

func TestFixtureDeterministic(t *testing.T) {
	before := loadFixture(t, "doc")
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("could not locate harness test source")
	}
	path := filepath.Join(filepath.Dir(thisFile), "files", "doc.bin")
	if err := os.Remove(path); err != nil {
		t.Fatalf("remove fixture: %v", err)
	}
	ensureFixtures(t)
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read regenerated fixture: %v", err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("regenerated fixture differs from original")
	}
}

func TestTamperDetectedGCM(t *testing.T) {
	key := make([]byte, 32)
	var sealed bytes.Buffer
	writer, err := production.NewWriter(&sealed, key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write([]byte("small test payload")); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	ciphertext := append([]byte(nil), sealed.Bytes()...)
	ciphertext[20] ^= 0xff
	reader, err := production.NewReader(bytes.NewReader(ciphertext), key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadAll(reader); err == nil {
		t.Fatal("tampered GCM stream was accepted")
	}
}

func TestTamperSilentCBC(t *testing.T) {
	key := make([]byte, 32)
	plaintext := bytes.Repeat([]byte("x"), 64)
	iv, ciphertext, err := academic.EncryptAES256CBC(key, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	combined := append(append([]byte(nil), iv...), ciphertext...)
	combined[20] ^= 0xff
	if _, err := academic.DecryptAES256CBC(key, combined[:aes.BlockSize], combined[aes.BlockSize:]); err != nil {
		t.Fatalf("CBC ciphertext tampering unexpectedly detected: %v", err)
	}
}

func TestGCMCiphertextSize(t *testing.T) {
	payload := loadFixture(t, "xls")
	key := make([]byte, 32)
	scheme := aesGCMScheme(key, payload)
	size, err := scheme.encrypt()
	if err != nil {
		t.Fatal(err)
	}
	chunks := (len(payload) + (1 << 20) - 1) / (1 << 20)
	want := 12 + len(payload) + 16*chunks
	if size != want {
		t.Fatalf("GCM ciphertext size = %d, want %d", size, want)
	}
}

func TestMbPerSec(t *testing.T) {
	tests := []struct {
		name string
		n    int
		want float64
	}{
		{"one iteration", 1, 1},
		{"one thousand iterations", 1000, 1000},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := mbps(1_000_000, time.Second, test.n)
			if got-test.want > 0.001 || test.want-got > 0.001 {
				t.Fatalf("mbps = %f, want %f", got, test.want)
			}
		})
	}
	if got := mbps(1, time.Second, 0); got != 0 {
		t.Fatalf("mbps with zero iterations = %f, want 0", got)
	}
}
