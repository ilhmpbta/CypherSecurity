package production

import (
	"bytes"
	"io"
	"testing"
)

func FuzzAEADReader(f *testing.F) {
	f.Add([]byte{}, make([]byte, 32))
	f.Add(make([]byte, baseNonceSize), make([]byte, 32))
	f.Add(make([]byte, baseNonceSize+tagSize), make([]byte, 32))
	f.Add(bytes.Repeat([]byte{0xab}, baseNonceSize+chunkSize+tagSize), make([]byte, 32))
	f.Fuzz(func(t *testing.T, data, dek []byte) {
		if len(dek) != 32 {
			return
		}
		reader, err := NewReader(bytes.NewReader(data), dek)
		if err != nil {
			return
		}
		out, readErr := io.ReadAll(reader)
		if readErr == nil {
			_ = out
			return
		}

		n, laterErr := reader.Read(make([]byte, 1))
		if n != 0 || laterErr == nil {
			t.Fatalf("reader not error-sticky after error: n=%d err=%v", n, laterErr)
		}
	})
}
