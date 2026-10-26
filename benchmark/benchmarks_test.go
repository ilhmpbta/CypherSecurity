package benchmark

import "testing"

// BenchmarkAESCBC compares AES-256-CBC encryption and decryption.
func BenchmarkAESCBC(b *testing.B) {
	benchmarkSmallFiles(b, aesCBCScheme, 32)
}

// BenchmarkAESCTR compares AES-256-CTR encryption and decryption.
func BenchmarkAESCTR(b *testing.B) {
	benchmarkSmallFiles(b, aesCTRScheme, 32)
}

// BenchmarkAESGCM compares streaming AES-256-GCM encryption and decryption.
func BenchmarkAESGCM(b *testing.B) {
	benchmarkSmallFiles(b, aesGCMScheme, 32)
}

// BenchmarkRC4 compares RC4 encryption and decryption.
func BenchmarkRC4(b *testing.B) {
	benchmarkSmallFiles(b, rc4Scheme, 32)
}

// BenchmarkDESCBC compares DES-CBC encryption and decryption.
func BenchmarkDESCBC(b *testing.B) {
	benchmarkSmallFiles(b, desCBCScheme, 8)
}

// BenchmarkLarge benchmarks each scheme against the 100 MiB video fixture.
func BenchmarkLarge(b *testing.B) {
	if testing.Short() {
		b.Skip("100 MB benchmarks skipped under -short")
	}
	payload := loadFixture(b, "video")
	tests := []struct {
		name    string
		keySize int
		scheme  func([]byte, []byte) benchmarkScheme
	}{
		{"AESCBC", 32, aesCBCScheme},
		{"AESCTR", 32, aesCTRScheme},
		{"AESGCM", 32, aesGCMScheme},
		{"RC4", 32, rc4Scheme},
		{"DESCBC", 8, desCBCScheme},
	}
	for _, test := range tests {
		key := makeKey(b, test.keySize)
		b.Run(test.name, func(b *testing.B) {
			scheme := test.scheme(key, payload)
			runFixtureBenchmarks(b, "video", payload, scheme, false)
		})
	}
}
