package keys_test

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"testing"

	"github.com/google/uuid"
	"github.com/ilhmpbta/CypherSecurity/internal/keys"
	"github.com/stretchr/testify/require"
)

func TestFakeService_RoundTripAndIdempotency(t *testing.T) {
	ctx := context.Background()
	svc := keys.NewFake()
	userID := uuid.New()
	wrapKey := make([]byte, 32)
	_, err := rand.Read(wrapKey)
	require.NoError(t, err)

	sessLocked := keys.Session{UserID: userID, WrapKey: nil}
	_, err = svc.EnsureForUser(ctx, sessLocked)
	require.ErrorIs(t, err, keys.ErrSessionLocked)

	sess := keys.Session{UserID: userID, WrapKey: wrapKey}
	kp1, err := svc.EnsureForUser(ctx, sess)
	require.NoError(t, err)
	require.NotEmpty(t, kp1.Fingerprint)
	require.NotNil(t, kp1.PublicKey)

	// Idempotency: repeated call returns same fingerprint
	kp2, err := svc.EnsureForUser(ctx, sess)
	require.NoError(t, err)
	require.Equal(t, kp1.Fingerprint, kp2.Fingerprint)

	// Wrap / Unwrap
	dek := []byte("secret-data-encryption-key-32b!!")
	wrapped, err := svc.WrapForRequester(ctx, userID, dek)
	require.NoError(t, err)

	// Unwrap with locked session fails
	_, err = svc.UnwrapForRequester(ctx, sessLocked, wrapped)
	require.ErrorIs(t, err, keys.ErrSessionLocked)

	unwrapped, err := svc.UnwrapForRequester(ctx, sess, wrapped)
	require.NoError(t, err)
	require.Equal(t, dek, unwrapped)

	// Sign / Verify
	digest := sha256.Sum256([]byte("hello world"))
	sig, err := svc.Sign(ctx, sess, digest[:])
	require.NoError(t, err)

	// Sign with locked session fails
	_, err = svc.Sign(ctx, sessLocked, digest[:])
	require.ErrorIs(t, err, keys.ErrSessionLocked)

	valid, err := svc.Verify(ctx, userID, digest[:], sig)
	require.NoError(t, err)
	require.True(t, valid)

	// Wrong digest verification fails
	wrongDigest := sha256.Sum256([]byte("wrong"))
	valid, err = svc.Verify(ctx, userID, wrongDigest[:], sig)
	require.NoError(t, err)
	require.False(t, valid)
}

func TestAtRest_EncryptionAndWrongKey(t *testing.T) {
	password := "secure-password-123"
	salt := make([]byte, 16)
	_, err := rand.Read(salt)
	require.NoError(t, err)

	wrapKey := keys.DeriveWrapKey(password, salt)
	require.Len(t, wrapKey, 32)

	priv, privDER, certDER, fingerprint, _, err := keys.GenerateKeypairAndCert("test-user")
	require.NoError(t, err)
	require.NotEmpty(t, fingerprint)
	require.NotEmpty(t, certDER)

	encrypted, nonce, err := keys.EncryptPrivateKey(wrapKey, privDER)
	require.NoError(t, err)
	require.NotEqual(t, privDER, encrypted)

	// Correct key decrypts
	decryptedPriv, err := keys.DecryptPrivateKey(wrapKey, encrypted, nonce)
	require.NoError(t, err)
	require.Equal(t, priv.D.Cmp(decryptedPriv.D), 0)

	// Wrong wrapKey fails decryption
	wrongWrapKey := make([]byte, 32)
	_, err = rand.Read(wrongWrapKey)
	require.NoError(t, err)

	_, err = keys.DecryptPrivateKey(wrongWrapKey, encrypted, nonce)
	require.Error(t, err)
}

func TestX509Certificate(t *testing.T) {
	_, _, certDER, _, _, err := keys.GenerateKeypairAndCert("test-common-name")
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)
	require.Equal(t, "test-common-name", cert.Subject.CommonName)
}
