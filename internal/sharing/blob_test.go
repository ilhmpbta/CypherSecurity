package sharing

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/google/uuid"
	"github.com/ilhmpbta/CypherSecurity/internal/keys"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBlobEncodeDecodeVerify(t *testing.T) {
	ctx := context.Background()
	fakeKeys := keys.NewFake()

	ownerID := uuid.New()
	requesterID := uuid.New()
	fileID := uuid.New()
	shareID := uuid.New()

	ownerSess := keys.Session{UserID: ownerID, WrapKey: []byte("01234567890123456789012345678901")}
	reqSess := keys.Session{UserID: requesterID, WrapKey: []byte("01234567890123456789012345678901")}

	ownerKP, err := fakeKeys.EnsureForUser(ctx, ownerSess)
	require.NoError(t, err)
	reqKP, err := fakeKeys.EnsureForUser(ctx, reqSess)
	require.NoError(t, err)

	req := ShareRequest{
		ID:       shareID,
		FileID:   fileID,
		FileName: "secret.pdf",
		Owner: ShareIdentity{
			ID:          ownerID,
			Username:    "alice",
			Fingerprint: ownerKP.Fingerprint,
		},
		Requester: ShareIdentity{
			ID:          requesterID,
			Username:    "bob",
			Fingerprint: reqKP.Fingerprint,
		},
		Status: StatusApproved,
	}

	fakeDEK := []byte("this-is-a-32-byte-test-dek-12345")
	wrappedDEK, err := fakeKeys.WrapForRequester(ctx, requesterID, fakeDEK)
	require.NoError(t, err)

	// Encode blob
	blob, err := EncodeBlob(req, wrappedDEK, func(digest []byte) ([]byte, error) {
		return fakeKeys.Sign(ctx, ownerSess, digest)
	})
	require.NoError(t, err)
	assert.NotEmpty(t, blob)
	assert.Equal(t, "CSKEY\x01", string(blob[:6]))

	// Decode blob
	decoded, err := DecodeBlob(blob)
	require.NoError(t, err)
	assert.Equal(t, uint8(CSKeyVersion), decoded.Header.Version)
	assert.Equal(t, uint8(KeyAlgID), decoded.Header.KeyAlg)
	assert.Equal(t, shareID, decoded.Header.ShareRequestID)
	assert.Equal(t, fileID, decoded.Header.FileID)
	assert.Equal(t, ownerKP.Fingerprint, decoded.Header.OwnerFingerprint)
	assert.Equal(t, reqKP.Fingerprint, decoded.Header.RequesterFingerprint)
	assert.Equal(t, wrappedDEK, decoded.WrappedDEK)

	// Verify blob
	err = VerifyBlob(decoded, req, func(oid uuid.UUID, digest, sig []byte) (bool, error) {
		return fakeKeys.Verify(ctx, oid, digest, sig)
	})
	require.NoError(t, err)
}

func TestBlobTamperedEnvelopeFails(t *testing.T) {
	ctx := context.Background()
	fakeKeys := keys.NewFake()

	ownerID := uuid.New()
	requesterID := uuid.New()
	fileID := uuid.New()
	shareID := uuid.New()

	ownerSess := keys.Session{UserID: ownerID, WrapKey: []byte("01234567890123456789012345678901")}
	reqSess := keys.Session{UserID: requesterID, WrapKey: []byte("01234567890123456789012345678901")}

	ownerKP, err := fakeKeys.EnsureForUser(ctx, ownerSess)
	require.NoError(t, err)
	reqKP, err := fakeKeys.EnsureForUser(ctx, reqSess)
	require.NoError(t, err)

	req := ShareRequest{
		ID:       shareID,
		FileID:   fileID,
		FileName: "doc.txt",
		Owner: ShareIdentity{
			ID:          ownerID,
			Username:    "alice",
			Fingerprint: ownerKP.Fingerprint,
		},
		Requester: ShareIdentity{
			ID:          requesterID,
			Username:    "bob",
			Fingerprint: reqKP.Fingerprint,
		},
		Status: StatusApproved,
	}

	wrappedDEK := []byte("wrapped-key-payload")
	blob, err := EncodeBlob(req, wrappedDEK, func(digest []byte) ([]byte, error) {
		return fakeKeys.Sign(ctx, ownerSess, digest)
	})
	require.NoError(t, err)

	t.Run("tampered magic bytes", func(t *testing.T) {
		tampered := make([]byte, len(blob))
		copy(tampered, blob)
		tampered[0] ^= 1
		_, err := DecodeBlob(tampered)
		assert.ErrorIs(t, err, ErrValidationFailed)
	})

	t.Run("tampered payload fails signature verification", func(t *testing.T) {
		tampered := make([]byte, len(blob))
		copy(tampered, blob)
		// Alter byte inside wrapped key payload
		tampered[110] ^= 0xFF
		decoded, err := DecodeBlob(tampered)
		require.NoError(t, err)

		err = VerifyBlob(decoded, req, func(oid uuid.UUID, digest, sig []byte) (bool, error) {
			return fakeKeys.Verify(ctx, oid, digest, sig)
		})
		assert.ErrorIs(t, err, ErrValidationFailed)
	})

	t.Run("tampered signature fails", func(t *testing.T) {
		tampered := make([]byte, len(blob))
		copy(tampered, blob)
		tampered[len(tampered)-1] ^= 0x55
		decoded, err := DecodeBlob(tampered)
		require.NoError(t, err)

		err = VerifyBlob(decoded, req, func(oid uuid.UUID, digest, sig []byte) (bool, error) {
			return fakeKeys.Verify(ctx, oid, digest, sig)
		})
		assert.ErrorIs(t, err, ErrValidationFailed)
	})

	t.Run("mismatched share request ID fails", func(t *testing.T) {
		decoded, err := DecodeBlob(blob)
		require.NoError(t, err)

		wrongReq := req
		wrongReq.ID = uuid.New()
		err = VerifyBlob(decoded, wrongReq, func(oid uuid.UUID, digest, sig []byte) (bool, error) {
			return fakeKeys.Verify(ctx, oid, digest, sig)
		})
		assert.ErrorIs(t, err, ErrValidationFailed)
	})

	t.Run("mismatched file ID fails", func(t *testing.T) {
		decoded, err := DecodeBlob(blob)
		require.NoError(t, err)

		wrongReq := req
		wrongReq.FileID = uuid.New()
		err = VerifyBlob(decoded, wrongReq, func(oid uuid.UUID, digest, sig []byte) (bool, error) {
			return fakeKeys.Verify(ctx, oid, digest, sig)
		})
		assert.ErrorIs(t, err, ErrValidationFailed)
	})

	t.Run("mismatched fingerprints fails", func(t *testing.T) {
		decoded, err := DecodeBlob(blob)
		require.NoError(t, err)

		wrongReq := req
		dummyFP := hex.EncodeToString(sha256.New().Sum([]byte("other")))
		wrongReq.Owner.Fingerprint = dummyFP
		err = VerifyBlob(decoded, wrongReq, func(oid uuid.UUID, digest, sig []byte) (bool, error) {
			return fakeKeys.Verify(ctx, oid, digest, sig)
		})
		assert.ErrorIs(t, err, ErrValidationFailed)
	})
}
