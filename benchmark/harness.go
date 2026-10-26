package benchmark

import (
	"bytes"
	"crypto/rand"
	"hash/crc32"
	"io"
	mathrand "math/rand"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/ilhmpbta/CypherSecurity/internal/crypto/academic"
	"github.com/ilhmpbta/CypherSecurity/internal/crypto/production"
)

// fixtureSizes is the fixture set from design doc §8.1.
var fixtureSizes = []struct {
	Name string
	Size int
}{
	{"id_image", 200 << 10},
	{"pdf", 2 << 20},
	{"doc", 1 << 20},
	{"xls", 10 << 20},
	{"video", 100 << 20},
}

// ensureFixtures creates benchmark/files/<name>.bin for every fixture that
// doesn't exist yet. Content is deterministic pseudo-random (seeded from the
// name via crc32), so deleting and regenerating produces byte-identical files.
// Must be called with the benchmark timer stopped.
func ensureFixtures(tb testing.TB) {
	tb.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		tb.Fatalf("benchmark: locating harness source failed")
	}
	dir := filepath.Join(filepath.Dir(thisFile), "files")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		tb.Fatalf("benchmark: creating fixture directory: %v", err)
	}

	for _, fixture := range fixtureSizes {
		path := filepath.Join(dir, fixture.Name+".bin")
		if _, err := os.Stat(path); err == nil {
			continue
		} else if !os.IsNotExist(err) {
			tb.Fatalf("benchmark: checking fixture %s: %v", fixture.Name, err)
		}

		file, err := os.Create(path)
		if err != nil {
			tb.Fatalf("benchmark: creating fixture %s: %v", fixture.Name, err)
		}
		source := mathrand.New(mathrand.NewSource(int64(crc32.ChecksumIEEE([]byte(fixture.Name)))))
		if _, err := io.CopyN(file, source, int64(fixture.Size)); err != nil {
			_ = file.Close()
			tb.Fatalf("benchmark: generating fixture %s: %v", fixture.Name, err)
		}
		if err := file.Close(); err != nil {
			tb.Fatalf("benchmark: closing fixture %s: %v", fixture.Name, err)
		}
	}
}

// loadFixture returns the bytes of benchmark/files/<name>.bin, creating it
// first if needed. The slice is freshly allocated each call; callers should
// hoist it outside their b.N loop.
func loadFixture(tb testing.TB, name string) []byte {
	tb.Helper()
	ensureFixtures(tb)
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		tb.Fatalf("benchmark: locating harness source failed")
	}
	path := filepath.Join(filepath.Dir(thisFile), "files", name+".bin")
	data, err := os.ReadFile(path)
	if err != nil {
		tb.Fatalf("benchmark: reading fixture %s: %v", name, err)
	}
	return data
}

// Row is one raw (per-run) benchmark result. report.go will aggregate these
// by (Algorithm, Mode, File, Op). Columns mirror the eventual CSV.
type Row struct {
	Algorithm      string
	Mode           string
	File           string
	Op             string
	NsPerOp        float64
	MBPerSec       float64
	CiphertextSize int
	TamperDetected bool
	PlaintextSize  int
	Run            int
}

var (
	collectorMu sync.Mutex
	collector   []Row
)

func record(r Row) {
	collectorMu.Lock()
	collector = append(collector, r)
	collectorMu.Unlock()
}

// Results returns a snapshot of the collected benchmark results.
func Results() []Row {
	collectorMu.Lock()
	defer collectorMu.Unlock()
	return append([]Row(nil), collector...)
}

// ResetResults clears all previously collected benchmark results.
func ResetResults() {
	collectorMu.Lock()
	collector = nil
	collectorMu.Unlock()
}

// mbps returns plaintext throughput in MB/s for a single op, given the
// elapsed time and iteration count of the current benchmark run.
func mbps(plaintextBytes int, elapsed time.Duration, n int) float64 {
	if n == 0 || elapsed == 0 {
		return 0
	}
	secsPerOp := elapsed.Seconds() / float64(n)
	if secsPerOp == 0 {
		return 0
	}
	return float64(plaintextBytes) / secsPerOp / 1e6
}

// makeKey returns n random bytes; tb.Fatal on error.
func makeKey(tb testing.TB, n int) []byte {
	tb.Helper()
	key := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		tb.Fatalf("benchmark: generating key: %v", err)
	}
	return key
}

var benchmarkBytesSink []byte

type benchmarkScheme struct {
	algorithm string
	mode      string
	tamper    bool
	encrypt   func() (int, error)
	prepare   func() (int, func() error, error)
}

func runFixtureBenchmarks(b *testing.B, file string, payload []byte, scheme benchmarkScheme, includeFile bool) {
	b.Helper()
	encryptName, decryptName := "encrypt", "decrypt"
	if includeFile {
		encryptName += "/" + file
		decryptName += "/" + file
	}
	b.Run(encryptName, func(b *testing.B) {
		b.SetBytes(int64(len(payload)))
		b.ReportAllocs()
		b.ResetTimer()
		ciphertextSize := 0
		for i := 0; i < b.N; i++ {
			size, err := scheme.encrypt()
			if err != nil {
				b.Fatal(err)
			}
			ciphertextSize = size
		}
		b.StopTimer()
		runtime.KeepAlive(benchmarkBytesSink)
		elapsed := b.Elapsed()
		record(Row{
			Algorithm: scheme.algorithm, Mode: scheme.mode, File: file, Op: "encrypt",
			NsPerOp:  float64(elapsed.Nanoseconds()) / float64(b.N),
			MBPerSec: mbps(len(payload), elapsed, b.N), CiphertextSize: ciphertextSize,
			TamperDetected: scheme.tamper, PlaintextSize: len(payload),
		})
	})
	b.Run(decryptName, func(b *testing.B) {
		ciphertextSize, decrypt, err := scheme.prepare()
		if err != nil {
			b.Fatal(err)
		}
		b.SetBytes(int64(len(payload)))
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if err := decrypt(); err != nil {
				b.Fatal(err)
			}
		}
		b.StopTimer()
		runtime.KeepAlive(benchmarkBytesSink)
		elapsed := b.Elapsed()
		record(Row{
			Algorithm: scheme.algorithm, Mode: scheme.mode, File: file, Op: "decrypt",
			NsPerOp:  float64(elapsed.Nanoseconds()) / float64(b.N),
			MBPerSec: mbps(len(payload), elapsed, b.N), CiphertextSize: ciphertextSize,
			TamperDetected: scheme.tamper, PlaintextSize: len(payload),
		})
	})
}

func aesCBCScheme(key, payload []byte) benchmarkScheme {
	var iv, ciphertext []byte
	return benchmarkScheme{
		algorithm: "AES-256",
		mode:      "CBC",
		encrypt: func() (int, error) {
			var err error
			iv, ciphertext, err = academic.EncryptAES256CBC(key, payload)
			if err == nil {
				benchmarkBytesSink = ciphertext
			}
			return len(iv) + len(ciphertext), err
		},
		prepare: func() (int, func() error, error) {
			size, err := encryptOnce(func() ([]byte, []byte, error) {
				return academic.EncryptAES256CBC(key, payload)
			}, &iv, &ciphertext)
			return size, func() error {
				plaintext, err := academic.DecryptAES256CBC(key, iv, ciphertext)
				benchmarkBytesSink = plaintext
				return err
			}, err
		},
	}
}

func aesCTRScheme(key, payload []byte) benchmarkScheme {
	var iv, ciphertext []byte
	return benchmarkScheme{
		algorithm: "AES-256",
		mode:      "CTR",
		encrypt: func() (int, error) {
			var err error
			iv, ciphertext, err = academic.EncryptAES256CTR(key, payload)
			if err == nil {
				benchmarkBytesSink = ciphertext
			}
			return len(iv) + len(ciphertext), err
		},
		prepare: func() (int, func() error, error) {
			size, err := encryptOnce(func() ([]byte, []byte, error) {
				return academic.EncryptAES256CTR(key, payload)
			}, &iv, &ciphertext)
			return size, func() error {
				plaintext, err := academic.DecryptAES256CTR(key, iv, ciphertext)
				benchmarkBytesSink = plaintext
				return err
			}, err
		},
	}
}

func rc4Scheme(key, payload []byte) benchmarkScheme {
	var iv, ciphertext []byte
	return benchmarkScheme{
		algorithm: "RC4",
		mode:      "stream",
		encrypt: func() (int, error) {
			var err error
			iv, ciphertext, err = academic.EncryptRC4(key, payload)
			if err == nil {
				benchmarkBytesSink = ciphertext
			}
			return len(iv) + len(ciphertext), err
		},
		prepare: func() (int, func() error, error) {
			size, err := encryptOnce(func() ([]byte, []byte, error) {
				return academic.EncryptRC4(key, payload)
			}, &iv, &ciphertext)
			return size, func() error {
				plaintext, err := academic.DecryptRC4(key, iv, ciphertext)
				benchmarkBytesSink = plaintext
				return err
			}, err
		},
	}
}

func desCBCScheme(key, payload []byte) benchmarkScheme {
	var iv, ciphertext []byte
	return benchmarkScheme{
		algorithm: "DES",
		mode:      "CBC",
		encrypt: func() (int, error) {
			var err error
			iv, ciphertext, err = academic.EncryptDESCBC(key, payload)
			if err == nil {
				benchmarkBytesSink = ciphertext
			}
			return len(iv) + len(ciphertext), err
		},
		prepare: func() (int, func() error, error) {
			size, err := encryptOnce(func() ([]byte, []byte, error) {
				return academic.EncryptDESCBC(key, payload)
			}, &iv, &ciphertext)
			return size, func() error {
				plaintext, err := academic.DecryptDESCBC(key, iv, ciphertext)
				benchmarkBytesSink = plaintext
				return err
			}, err
		},
	}
}

func aesGCMScheme(key, payload []byte) benchmarkScheme {
	var sealed []byte
	encrypt := func() (int, error) {
		var buf bytes.Buffer
		writer, err := production.NewWriter(&buf, key)
		if err != nil {
			return 0, err
		}
		if _, err := writer.Write(payload); err != nil {
			return 0, err
		}
		if err := writer.Close(); err != nil {
			return 0, err
		}
		sealed = buf.Bytes()
		benchmarkBytesSink = sealed
		return len(sealed), nil
	}
	prepare := func() (int, func() error, error) {
		if _, err := encrypt(); err != nil {
			return 0, nil, err
		}
		return len(sealed), func() error {
			reader, err := production.NewReader(bytes.NewReader(sealed), key)
			if err != nil {
				return err
			}
			_, err = io.Copy(io.Discard, reader)
			return err
		}, nil
	}
	return benchmarkScheme{
		algorithm: "AES-256",
		mode:      "GCM",
		tamper:    true,
		encrypt:   encrypt,
		prepare:   prepare,
	}
}

func encryptOnce(encrypt func() ([]byte, []byte, error), iv, ciphertext *[]byte) (int, error) {
	var err error
	*iv, *ciphertext, err = encrypt()
	if err != nil {
		return 0, err
	}
	benchmarkBytesSink = *ciphertext
	return len(*iv) + len(*ciphertext), nil
}

func benchmarkSmallFiles(b *testing.B, schemeForKey func([]byte, []byte) benchmarkScheme, keySize int) {
	b.Helper()
	key := makeKey(b, keySize)
	for _, fixture := range fixtureSizes {
		if fixture.Name == "video" {
			continue
		}
		payload := loadFixture(b, fixture.Name)
		scheme := schemeForKey(key, payload)
		runFixtureBenchmarks(b, fixture.Name, payload, scheme, true)
	}
}
