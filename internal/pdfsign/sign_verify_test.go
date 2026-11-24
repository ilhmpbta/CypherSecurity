package pdfsign_test

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/ilhmpbta/CypherSecurity/internal/keys"
	"github.com/ilhmpbta/CypherSecurity/internal/pdfsign"
	"github.com/stretchr/testify/require"
)

func generateValidTestPDF() []byte {
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

func TestSignAndVerify_SingleSignature(t *testing.T) {
	ctx := context.Background()
	keysSvc := keys.NewFake()
	userID := uuid.New()
	wrapKey := []byte("32-byte-secret-wrap-key-for-test!!")
	sess := keys.Session{UserID: userID, WrapKey: wrapKey}

	orig := generateValidTestPDF()

	// Sign PDF
	signedPDF, err := pdfsign.SignPDF(ctx, orig, keysSvc, sess)
	require.NoError(t, err)
	require.NotEmpty(t, signedPDF)

	// Verify PDF
	results, err := pdfsign.VerifyPDF(ctx, signedPDF, keysSvc, userID)
	require.NoError(t, err)
	require.Len(t, results, 1)
	require.True(t, results[0].Valid)
	require.Empty(t, results[0].Reason)
	require.NotNil(t, results[0].Certificate)
}

func TestSignAndVerify_MultipleSignatures(t *testing.T) {
	ctx := context.Background()
	keysSvc := keys.NewFake()
	userID := uuid.New()
	wrapKey := []byte("32-byte-secret-wrap-key-for-test!!")
	sess := keys.Session{UserID: userID, WrapKey: wrapKey}

	orig := generateValidTestPDF()

	// First sign
	signed1, err := pdfsign.SignPDF(ctx, orig, keysSvc, sess)
	require.NoError(t, err)

	// Second sign (signing an already signed PDF)
	signed2, err := pdfsign.SignPDF(ctx, signed1, keysSvc, sess)
	require.NoError(t, err)
	require.NotEmpty(t, signed2)

	// Verify both signatures
	results, err := pdfsign.VerifyPDF(ctx, signed2, keysSvc, userID)
	require.NoError(t, err)
	require.Len(t, results, 2)

	require.True(t, results[0].Valid)
	require.True(t, results[1].Valid)
}

func TestVerify_UnsignedPDF(t *testing.T) {
	ctx := context.Background()
	keysSvc := keys.NewFake()
	orig := generateValidTestPDF()

	results, err := pdfsign.VerifyPDF(ctx, orig, keysSvc, uuid.New())
	require.NoError(t, err)
	require.Len(t, results, 1)
	require.False(t, results[0].Valid)
	require.Equal(t, "no_signature", results[0].Reason)
}

func TestVerify_TamperedContent(t *testing.T) {
	ctx := context.Background()
	keysSvc := keys.NewFake()
	userID := uuid.New()
	wrapKey := []byte("32-byte-secret-wrap-key-for-test!!")
	sess := keys.Session{UserID: userID, WrapKey: wrapKey}

	orig := generateValidTestPDF()
	signedPDF, err := pdfsign.SignPDF(ctx, orig, keysSvc, sess)
	require.NoError(t, err)

	// Tamper with a byte inside the original PDF bytes (e.g., change '%PDF-1.4' to '%PDF-1.5')
	tampered := make([]byte, len(signedPDF))
	copy(tampered, signedPDF)
	tampered[7] = '5'

	results, err := pdfsign.VerifyPDF(ctx, tampered, keysSvc, userID)
	require.NoError(t, err)
	require.Len(t, results, 1)
	require.False(t, results[0].Valid)
	require.Equal(t, "content_modified", results[0].Reason)
}

func TestVerify_UnknownSigner(t *testing.T) {
	ctx := context.Background()
	keysSvc := keys.NewFake()
	userID := uuid.New()
	wrapKey := []byte("32-byte-secret-wrap-key-for-test!!")
	sess := keys.Session{UserID: userID, WrapKey: wrapKey}

	orig := generateValidTestPDF()
	signedPDF, err := pdfsign.SignPDF(ctx, orig, keysSvc, sess)
	require.NoError(t, err)

	// Verify with a different unknown user ID and empty keys service
	otherUserID := uuid.New()
	emptySvc := keys.NewFake()

	results, err := pdfsign.VerifyPDF(ctx, signedPDF, emptySvc, otherUserID)
	require.NoError(t, err)
	require.Len(t, results, 1)
	require.False(t, results[0].Valid)
	require.Equal(t, "unknown_signer", results[0].Reason)
}
