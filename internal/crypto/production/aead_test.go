package production

import (
	"bytes"
	"crypto/sha256"
	"io"
	"os"
	"runtime"
	"strconv"
	"testing"
)

func TestAEADRoundTrips(t *testing.T) {
	lengths := []int{
		0, 1, 15, 16, 17,
		chunkSize - 1, chunkSize, chunkSize + 1,
		2*chunkSize + 3,
	}
	dek := bytes.Repeat([]byte{0x12}, 32)
	for _, length := range lengths {
		t.Run("len="+strconv.Itoa(length), func(t *testing.T) {
			plaintext := make([]byte, length)
			for i := range plaintext {
				plaintext[i] = byte(i * 31)
			}
			sealed := seal(t, dek, plaintext)
			got, err := open(t, dek, sealed)
			if err != nil {
				t.Fatalf("open returned error: %v", err)
			}
			if !bytes.Equal(got, plaintext) {
				t.Fatalf("round trip mismatch for %d-byte plaintext", length)
			}
		})
	}
}

func TestAEADLargeStreamMemory(t *testing.T) {
	if testing.Short() {
		t.Skip("100MB test")
	}

	const total = 100 << 20
	dek := bytes.Repeat([]byte{0x27}, 32)
	pattern := make([]byte, chunkSize)
	for i := range pattern {
		pattern[i] = byte(i*31 + 7)
	}

	file, err := os.CreateTemp(t.TempDir(), "aead-*")
	if err != nil {
		t.Fatal(err)
	}
	writer, err := NewWriter(file, dek)
	if err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	written, err := io.Copy(writer, io.LimitReader(&repeatingReader{pattern: pattern}, total))
	if err != nil {
		_ = writer.Close()
		_ = file.Close()
		t.Fatal(err)
	}
	if written != total {
		_ = writer.Close()
		_ = file.Close()
		t.Fatalf("encrypted %d bytes, want %d", written, total)
	}
	if err := writer.Close(); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}

	reader, err := NewReader(file, dek)
	if err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)
	outputHash := sha256.New()
	read, copyErr := io.Copy(outputHash, reader)
	if copyErr != nil {
		_ = file.Close()
		t.Fatalf("decrypting stream: %v", copyErr)
	}
	if read != total {
		_ = file.Close()
		t.Fatalf("decrypted %d bytes, want %d", read, total)
	}
	runtime.GC()
	var after runtime.MemStats
	runtime.ReadMemStats(&after)
	if after.HeapAlloc > before.HeapAlloc && after.HeapAlloc-before.HeapAlloc >= 50<<20 {
		_ = file.Close()
		t.Fatalf("retained heap increased by %d bytes, want less than 50 MiB", after.HeapAlloc-before.HeapAlloc)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}

	expectedHash := sha256.New()
	for i := 0; i < total/chunkSize; i++ {
		if _, err := expectedHash.Write(pattern); err != nil {
			t.Fatal(err)
		}
	}
	if !bytes.Equal(outputHash.Sum(nil), expectedHash.Sum(nil)) {
		t.Fatal("100MB stream hash mismatch")
	}
}

func TestAEADTamperDetection(t *testing.T) {
	dek := bytes.Repeat([]byte{0x38}, 32)
	plaintext := bytes.Repeat([]byte{0x5a}, 3*chunkSize+100)
	valid := seal(t, dek, plaintext)
	positions := []int{0, baseNonceSize, baseNonceSize + chunkSize + 5, len(valid) - 1}

	for _, pos := range positions {
		t.Run("pos="+strconv.Itoa(pos), func(t *testing.T) {
			tampered := append([]byte(nil), valid...)
			tampered[pos] ^= 0xff
			reader, err := NewReader(bytes.NewReader(tampered), dek)
			if err != nil {
				t.Fatal(err)
			}
			out, err := io.ReadAll(reader)
			if err == nil {
				t.Fatal("expected tampered stream to fail authentication")
			}

			chunkIndex := 0
			if pos >= baseNonceSize {
				chunkIndex = (pos - baseNonceSize) / (chunkSize + tagSize)
			}
			wantPrefix := chunkIndex * chunkSize
			if len(out) != wantPrefix {
				t.Fatalf("received %d plaintext bytes, want authenticated prefix of %d", len(out), wantPrefix)
			}
		})
	}
}

func TestAEADWrongKey(t *testing.T) {
	dek1 := bytes.Repeat([]byte{0x41}, 32)
	dek2 := bytes.Repeat([]byte{0x42}, 32)
	sealed := seal(t, dek1, []byte("sensitive file content"))
	out, err := open(t, dek2, sealed)
	if err == nil {
		t.Fatal("expected wrong key to fail authentication")
	}
	if len(out) != 0 {
		t.Fatalf("wrong key returned %d plaintext bytes", len(out))
	}
}

func TestAEADTruncatedStreams(t *testing.T) {
	dek := bytes.Repeat([]byte{0x53}, 32)
	sealed := seal(t, dek, bytes.Repeat([]byte{0x62}, 2*chunkSize+10))
	tests := []struct {
		name       string
		end        int
		wantErr    bool
		wantOutput int
	}{
		{"nonce only is valid empty stream", baseNonceSize, false, 0},
		{"incomplete tag", baseNonceSize + tagSize - 1, true, 0},
		{"missing final tag bytes", len(sealed) - 5, true, 2 * chunkSize},
		{"second chunk missing tag bytes", baseNonceSize + chunkSize + tagSize + tagSize - 5, true, chunkSize},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			out, err := open(t, dek, sealed[:test.end])
			if test.wantErr && err == nil {
				t.Fatal("expected truncated stream to fail")
			}
			if !test.wantErr && err != nil {
				t.Fatalf("open returned unexpected error: %v", err)
			}
			if len(out) != test.wantOutput {
				t.Fatalf("received %d bytes, want %d", len(out), test.wantOutput)
			}
		})
	}
}

func TestAEADNonceDistinctness(t *testing.T) {
	dek := bytes.Repeat([]byte{0x64}, 32)
	sealed := seal(t, dek, bytes.Repeat([]byte{0x75}, 5*chunkSize))
	base := sealed[:baseNonceSize]

	nonces := make([][]byte, 5)
	for i := range nonces {
		nonces[i] = chunkNonce(base, uint64(i))
		if len(nonces[i]) != baseNonceSize {
			t.Fatalf("nonce %d length = %d, want %d", i, len(nonces[i]), baseNonceSize)
		}
		for j := 0; j < i; j++ {
			if bytes.Equal(nonces[i], nonces[j]) {
				t.Fatalf("nonce %d equals nonce %d", i, j)
			}
		}
	}
}

func TestAEADReaderStickyError(t *testing.T) {
	dek := bytes.Repeat([]byte{0x86}, 32)
	sealed := seal(t, dek, bytes.Repeat([]byte{0x97}, 2*chunkSize+1))
	chunkOneStart := baseNonceSize + chunkSize + tagSize
	sealed[chunkOneStart+4] ^= 0xff

	reader, err := NewReader(bytes.NewReader(sealed), dek)
	if err != nil {
		t.Fatal(err)
	}
	out, readErr := io.ReadAll(reader)
	if readErr == nil {
		t.Fatal("expected corrupted second chunk to fail")
	}
	if len(out) != chunkSize {
		t.Fatalf("received %d bytes, want one authenticated chunk (%d)", len(out), chunkSize)
	}
	n, laterErr := reader.Read(make([]byte, 16))
	if n != 0 || laterErr == nil {
		t.Fatalf("subsequent Read = (%d, %v), want (0, same error)", n, laterErr)
	}
	if laterErr != readErr {
		t.Fatalf("subsequent error = %v, want original sticky error %v", laterErr, readErr)
	}
}

func TestAEADEmptyStream(t *testing.T) {
	dek := bytes.Repeat([]byte{0xa8}, 32)
	sealed := seal(t, dek, []byte{})
	if len(sealed) != baseNonceSize {
		t.Fatalf("empty sealed stream length = %d, want %d", len(sealed), baseNonceSize)
	}
	out, err := open(t, dek, sealed)
	if err != nil {
		t.Fatalf("opening empty stream: %v", err)
	}
	if len(out) != 0 {
		t.Fatalf("empty stream returned %d plaintext bytes", len(out))
	}
}

func TestAEADWriterCloseBehavior(t *testing.T) {
	dek := bytes.Repeat([]byte{0xb9}, 32)
	var sealed bytes.Buffer
	writer, err := NewWriter(&sealed, dek)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write([]byte("final chunk")); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("second Close returned error: %v", err)
	}
	if n, err := writer.Write([]byte("after close")); n != 0 || err == nil {
		t.Fatalf("Write after Close = (%d, %v), want an error", n, err)
	}
	opened, err := open(t, dek, sealed.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(opened, []byte("final chunk")) {
		t.Fatalf("opened content = %q, want final chunk", opened)
	}
}

func TestAEADInvalidKeysAndBaseNonce(t *testing.T) {
	if _, err := NewWriter(io.Discard, make([]byte, 31)); err == nil {
		t.Fatal("NewWriter accepted a non-32-byte DEK")
	}
	if _, err := NewReader(bytes.NewReader(make([]byte, baseNonceSize)), make([]byte, 31)); err == nil {
		t.Fatal("NewReader accepted a non-32-byte DEK")
	}
	if _, err := NewReader(bytes.NewReader(make([]byte, baseNonceSize-1)), make([]byte, 32)); err == nil {
		t.Fatal("NewReader accepted a truncated base nonce")
	}
}

func seal(t *testing.T, dek, plaintext []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	writer, err := NewWriter(&buf, dek)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write(plaintext); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func open(t *testing.T, dek, sealed []byte) ([]byte, error) {
	t.Helper()
	reader, err := NewReader(bytes.NewReader(sealed), dek)
	if err != nil {
		t.Fatal(err)
	}
	return io.ReadAll(reader)
}

type repeatingReader struct {
	pattern []byte
	offset  int
}

func (r *repeatingReader) Read(p []byte) (int, error) {
	if len(r.pattern) == 0 {
		return 0, io.EOF
	}
	n := 0
	for n < len(p) {
		copied := copy(p[n:], r.pattern[r.offset:])
		n += copied
		r.offset = (r.offset + copied) % len(r.pattern)
	}
	return n, nil
}
