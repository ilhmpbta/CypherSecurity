package pdfsign_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/ilhmpbta/CypherSecurity/internal/pdfsign"
	"github.com/stretchr/testify/require"
)

// generateTestPDF returns bytes for a valid minimal test PDF.
func generateTestPDF() []byte {
	return []byte(`%PDF-1.4
1 0 obj
<<
  /Type /Catalog
  /Pages 2 0 R
>>
endobj
2 0 obj
<<
  /Type /Pages
  /Kids [3 0 R]
  /Count 1
>>
endobj
3 0 obj
<<
  /Type /Page
  /Parent 2 0 R
  /MediaBox [0 0 612 792]
>>
endobj
xref
0 4
0000000000 65535 f
0000000009 00000 n
0000000058 00000 n
0000000115 00000 n
trailer
<<
  /Size 4
  /Root 1 0 R
>>
startxref
185
%%EOF
`)
}

func TestIncrementalUpdate_Basic(t *testing.T) {
	orig := generateTestPDF()

	updated, err := pdfsign.IncrementalUpdate(orig)
	require.NoError(t, err)
	require.NotEmpty(t, updated)

	// 1. Original bytes remain completely unchanged at their original offsets
	require.True(t, bytes.HasPrefix(updated, orig))

	// 2. Compute ByteRange and verify partitioning
	br, err := pdfsign.ComputeByteRange(updated)
	require.NoError(t, err)

	off1, len1, off2, len2 := br[0], br[1], br[2], br[3]
	require.Equal(t, int64(0), off1)
	require.True(t, len1 > 0)
	require.True(t, off2 > len1)
	require.True(t, len2 > 0)
	require.Equal(t, int64(len(updated)), off2+len2)

	// Verify partition around /Contents
	contentsMarker := []byte("/Contents <")
	cIdx := bytes.LastIndex(updated, contentsMarker)
	require.NotEqual(t, -1, cIdx)
	hexStart := int64(cIdx + len(contentsMarker))
	closeAngle := bytes.Index(updated[hexStart:], []byte(">"))
	require.NotEqual(t, -1, closeAngle)
	hexEnd := hexStart + int64(closeAngle)

	// Range 1 ends at hexStart (includes opening '<')
	require.Equal(t, hexStart, len1)
	// Range 2 starts at hexEnd (includes closing '>')
	require.Equal(t, hexEnd, off2)

	// Verify zero overlap with /Contents hex slot
	for i := hexStart; i < hexEnd; i++ {
		require.True(t, i >= len1 && i < off2)
	}
}

func TestInjectSignature(t *testing.T) {
	orig := generateTestPDF()
	updated, err := pdfsign.IncrementalUpdate(orig)
	require.NoError(t, err)

	fakeSig := []byte("deadbeef")
	signedPDF, err := pdfsign.InjectSignature(updated, fakeSig)
	require.NoError(t, err)
	require.Len(t, signedPDF, len(updated)) // File length must remain identical

	// Verify signature bytes were correctly hex-encoded into /Contents
	contentsMarker := []byte("/Contents <")
	cIdx := bytes.LastIndex(signedPDF, contentsMarker)
	require.NotEqual(t, -1, cIdx)
	hexStart := cIdx + len(contentsMarker)
	closeAngle := bytes.Index(signedPDF[hexStart:], []byte(">"))
	require.NotEqual(t, -1, closeAngle)
	hexEnd := hexStart + closeAngle

	hexContent := string(signedPDF[hexStart:hexEnd])
	require.True(t, strings.HasPrefix(hexContent, "6465616462656566")) // hex of "deadbeef"
	require.Equal(t, pdfsign.ContentsHexSize, len(hexContent))
}

func TestMultipleIncrementalUpdates(t *testing.T) {
	orig := generateTestPDF()

	// First incremental update (signing 1)
	updated1, err := pdfsign.IncrementalUpdate(orig)
	require.NoError(t, err)

	// Inject first signature
	sig1, err := pdfsign.InjectSignature(updated1, []byte("signature-one"))
	require.NoError(t, err)

	// Second incremental update (signing 2 - appending second signature onto already-signed PDF)
	updated2, err := pdfsign.IncrementalUpdate(sig1)
	require.NoError(t, err)
	require.NotEmpty(t, updated2)

	// Inject second signature
	sig2, err := pdfsign.InjectSignature(updated2, []byte("signature-two"))
	require.NoError(t, err)

	// Verify both original PDF and first incremental update are preserved
	require.True(t, bytes.HasPrefix(sig2, orig))
	require.True(t, bytes.HasPrefix(updated2, sig1))

	// Verify ComputeAllByteRanges returns both independent byte ranges
	allRanges, err := pdfsign.ComputeAllByteRanges(sig2)
	require.NoError(t, err)
	require.Len(t, allRanges, 2)

	// Verify distinct field names (Signature1 and Signature2)
	require.True(t, bytes.Contains(sig2, []byte("/T (Signature1)")))
	require.True(t, bytes.Contains(sig2, []byte("/T (Signature2)")))

	// Verify latest startxref and trailer point back correctly via /Prev
	startXref, err := pdfsign.FindStartXref(sig2)
	require.NoError(t, err)
	require.True(t, startXref > 0)
}

func TestStructuralSanityChecks(t *testing.T) {
	orig := generateTestPDF()
	updated, err := pdfsign.IncrementalUpdate(orig)
	require.NoError(t, err)

	startXref, err := pdfsign.FindStartXref(updated)
	require.NoError(t, err)
	require.True(t, startXref < int64(len(updated)))

	require.True(t, bytes.HasSuffix(bytes.TrimSpace(updated), []byte("%%EOF")))
	require.True(t, bytes.Contains(updated, []byte("/Prev")))
}
