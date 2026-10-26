// Package production implements the encryption that protects real user files.
// This is NOT the academic comparison package: it uses AES-256-GCM exclusively
// (streaming AEAD) and never CBC/CTR/RC4/DES.
//
// # Wire format
//
// A sealed stream is:
//
//	[ 12-byte base nonce ][ chunk_0 ][ chunk_1 ] ... [ chunk_N ]
//
// Each chunk is the AES-256-GCM sealing of 0..chunkSize plaintext bytes under
// the same DEK, with the 16-byte GCM tag appended. The wire format permits a
// final chunk with 0 plaintext bytes when the plaintext length is an exact
// multiple of chunkSize; this writer omits that zero-length chunk. The reader
// detects end-of-stream when the underlying io.Reader is exhausted; there is
// no explicit end marker.
//
// chunkSize = 1 MiB (1 << 20). This bounds peak memory to roughly one chunk
// plus a few copies regardless of total file size.
//
// The base nonce is the first 12 bytes of the stream. It MUST NOT be
// duplicated in database metadata: it is part of the ciphertext blob, and a
// second copy can silently diverge if the blob is ever truncated.
//
// # Nonce derivation
//
// For chunk index i (0-based, big-endian uint64), the per-chunk nonce is
// derived from the base nonce as:
//
//	nonce[0:4]  = base[0:4]
//	nonce[4:12] = base[4:12] XOR big_endian_uint64(i)
//
// i.e. the 8-byte big-endian chunk counter is XORed into the last 8 bytes of
// the base nonce. This is injective in i for a fixed base, so nonces never
// repeat under a given DEK (up to 2^64 chunks), and it is random across
// streams because the base is random.
//
// The chunk index i is ALSO passed as AAD (associated authenticated data) to
// Seal/Open. Without the AAD, an attacker could reorder or drop chunks and
// each chunk would still authenticate; with the AAD, any reordering or
// removal causes Open to fail on the affected chunk. This is what makes the
// "any tampered chunk causes a Read error" guarantee hold against structural
// attacks, not just bit-flips.
//
// # Error semantics
//
// The reader is error-sticky: once Read returns a non-nil error, every
// subsequent Read returns (0, sameErr). Bytes returned before the error are
// always from fully authenticated chunks — no partial plaintext is ever
// emitted for a chunk that failed to authenticate or for a truncated stream.
//
// # Key handling
//
// The raw DEK is passed to NewWriter/NewReader, immediately expanded by
// aes.NewCipher, and NOT retained in any struct field. Callers may zero the
// DEK slice as soon as NewWriter/NewReader returns. The DEK is never logged,
// never persisted in plaintext, and never returned from this package except
// by GenerateDEK and Unwrap in keymanager.go.
//
// # Truncation limitation
//
// A stream containing only the 12-byte base nonce is indistinguishable from a
// valid empty file. Likewise, truncation at a complete chunk boundary produces
// a valid shorter stream because the format has no authenticated length or end
// marker. Callers must store the expected plaintext length in trusted database
// metadata and compare it with the number of bytes read to detect truncation
// to empty or at a chunk boundary.
package production

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

var _ io.WriteCloser = (*streamWriter)(nil)
var _ io.Reader = (*streamReader)(nil)

const (
	chunkSize     = 1 << 20
	baseNonceSize = 12
	tagSize       = 16
)

// chunkNonce returns an independently allocated nonce for chunk i.
func chunkNonce(base []byte, i uint64) []byte {
	nonce := make([]byte, baseNonceSize)
	copy(nonce, base)
	var counter [8]byte
	binary.BigEndian.PutUint64(counter[:], i)
	for j := range counter {
		nonce[4+j] ^= counter[j]
	}
	return nonce
}

// chunkAAD returns an independently allocated big-endian encoding of i.
func chunkAAD(i uint64) []byte {
	aad := make([]byte, 8)
	binary.BigEndian.PutUint64(aad, i)
	return aad
}

func newGCM(dek []byte, operation string) (cipher.AEAD, error) {
	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, fmt.Errorf("production: %s: AES-256: %w", operation, err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("production: %s: create GCM: %w", operation, err)
	}
	if gcm.NonceSize() != baseNonceSize || gcm.Overhead() != tagSize {
		return nil, fmt.Errorf("production: %s: unexpected GCM parameters: nonce size %d, tag size %d", operation, gcm.NonceSize(), gcm.Overhead())
	}
	return gcm, nil
}

// NewWriter creates a streaming AES-256-GCM writer.
// The caller owns w; Close does NOT close the underlying writer. Close MUST be
// called and its error checked: the final chunk is sealed and written during
// Close, so a Close error means the stream is truncated and unreadable. After
// NewWriter returns, the caller may zero the dek slice; the writer does not
// retain it.
func NewWriter(w io.Writer, dek []byte) (io.WriteCloser, error) {
	if len(dek) != 32 {
		return nil, fmt.Errorf("production: NewWriter: DEK must be 32 bytes, got %d", len(dek))
	}
	if w == nil {
		return nil, errors.New("production: NewWriter: writer must not be nil")
	}
	gcm, err := newGCM(dek, "NewWriter")
	if err != nil {
		return nil, err
	}

	base := make([]byte, baseNonceSize)
	if _, err := io.ReadFull(rand.Reader, base); err != nil {
		return nil, fmt.Errorf("production: NewWriter: generate base nonce: %w", err)
	}
	if err := writeFull(w, base); err != nil {
		return nil, fmt.Errorf("production: NewWriter: write base nonce: %w", err)
	}

	return &streamWriter{
		w:    w,
		gcm:  gcm,
		base: base,
		buf:  make([]byte, 0, chunkSize),
	}, nil
}

type streamWriter struct {
	w       io.Writer
	gcm     cipher.AEAD
	base    []byte
	counter uint64
	buf     []byte
	closed  bool
	err     error
}

// Write buffers and seals full chunks. If a flush fails, Write returns the
// number of bytes from p accepted through that chunk; the writer is dead and
// the stream is unusable.
func (w *streamWriter) Write(p []byte) (int, error) {
	if w.closed {
		return 0, errors.New("production: write after Close")
	}
	if w.err != nil {
		return 0, w.err
	}

	consumed := 0
	for len(p) > 0 {
		toCopy := chunkSize - len(w.buf)
		if toCopy > len(p) {
			toCopy = len(p)
		}
		w.buf = append(w.buf, p[:toCopy]...)
		p = p[toCopy:]
		consumed += toCopy
		if len(w.buf) == chunkSize {
			ct := w.gcm.Seal(nil, chunkNonce(w.base, w.counter), w.buf, chunkAAD(w.counter))
			if err := writeFull(w.w, ct); err != nil {
				w.err = fmt.Errorf("production: write: %w", err)
				return consumed, w.err
			}
			w.buf = w.buf[:0]
			w.counter++
		}
	}
	return consumed, nil
}

// Close seals and writes the final short chunk if one is buffered.
func (w *streamWriter) Close() error {
	if w.closed {
		return nil
	}
	w.closed = true
	if w.err != nil {
		return w.err
	}
	if len(w.buf) == 0 {
		return nil
	}

	ct := w.gcm.Seal(nil, chunkNonce(w.base, w.counter), w.buf, chunkAAD(w.counter))
	if err := writeFull(w.w, ct); err != nil {
		w.err = fmt.Errorf("production: close: %w", err)
		return w.err
	}
	w.buf = nil
	return nil
}

func writeFull(w io.Writer, p []byte) error {
	for len(p) > 0 {
		n, err := w.Write(p)
		if n < 0 || n > len(p) {
			return errors.New("invalid write count")
		}
		p = p[n:]
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}

// NewReader creates a streaming AES-256-GCM reader.
// The caller owns r; the reader does not close it. Once Read returns a
// non-nil error, all subsequent Read calls return (0, sameErr); the reader is
// error-sticky. Bytes returned before an error are always from fully
// authenticated chunks. After NewReader returns, the caller may zero the dek
// slice; the reader does not retain it.
func NewReader(r io.Reader, dek []byte) (io.Reader, error) {
	if len(dek) != 32 {
		return nil, fmt.Errorf("production: NewReader: DEK must be 32 bytes, got %d", len(dek))
	}
	if r == nil {
		return nil, errors.New("production: NewReader: reader must not be nil")
	}
	gcm, err := newGCM(dek, "NewReader")
	if err != nil {
		return nil, err
	}

	base := make([]byte, baseNonceSize)
	if _, err := io.ReadFull(r, base); err != nil {
		return nil, fmt.Errorf("production: NewReader: reading base nonce: %w", err)
	}
	return &streamReader{
		r:    r,
		gcm:  gcm,
		base: base,
		buf:  make([]byte, chunkSize+tagSize),
	}, nil
}

type streamReader struct {
	r       io.Reader
	gcm     cipher.AEAD
	base    []byte
	counter uint64
	buf     []byte
	current []byte
	dead    bool
	err     error
}

func (r *streamReader) Read(p []byte) (int, error) {
	if r.dead {
		return 0, r.err
	}
	if len(p) == 0 {
		return 0, nil
	}

	for len(r.current) == 0 {
		n, err := io.ReadFull(r.r, r.buf)
		switch {
		case err == io.EOF && n == 0:
			r.dead = true
			r.err = io.EOF
			return 0, r.err
		case err == io.ErrUnexpectedEOF:
			if n < tagSize {
				r.dead = true
				r.err = fmt.Errorf("production: read: truncated chunk: %w", err)
				return 0, r.err
			}
		case err != nil:
			r.dead = true
			r.err = fmt.Errorf("production: read: %w", err)
			return 0, r.err
		}

		nonce := chunkNonce(r.base, r.counter)
		aad := chunkAAD(r.counter)
		plaintext, openErr := r.gcm.Open(nil, nonce, r.buf[:n], aad)
		if openErr != nil {
			r.dead = true
			r.err = fmt.Errorf("production: read: chunk %d authentication failed: %w", r.counter, openErr)
			return 0, r.err
		}
		r.counter++
		r.current = plaintext
	}

	n := copy(p, r.current)
	r.current = r.current[n:]
	if len(r.current) == 0 {
		r.current = nil
	}
	return n, nil
}
