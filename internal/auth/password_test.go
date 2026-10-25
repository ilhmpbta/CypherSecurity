package auth

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPasswordHashAndVerify(t *testing.T) {
	plain := "SecretPassword123!"
	hash, err := HashPassword(plain)
	require.NoError(t, err)
	require.NotEmpty(t, hash)

	valid, err := VerifyPassword(hash, plain)
	assert.NoError(t, err)
	assert.True(t, valid)

	valid, err = VerifyPassword(hash, "WrongPassword")
	assert.NoError(t, err)
	assert.False(t, valid)
}

func TestVerifyPasswordMalformedAndBounds(t *testing.T) {
	// Malformed PHC
	valid, err := VerifyPassword("not-a-valid-hash", "plain")
	assert.Error(t, err)
	assert.False(t, valid)

	tests := []struct {
		name          string
		hash          string
		expectedError string
	}{
		{
			name:          "out of bounds memory (m=4294967295)",
			hash:          "$argon2id$v=19$m=4294967295,t=2,p=1$c2FsdHNhbHRzYWx0cw$aGFzaGhhc2hoYXNoaGFzaGhhc2hoYXNoaGFzaGhhc2g",
			expectedError: "hash parameters out of range",
		},
		{
			name:          "unknown parameter (x=99)",
			hash:          "$argon2id$v=19$m=19456,t=2,p=1,x=99$c2FsdHNhbHRzYWx0cw$aGFzaGhhc2hoYXNoaGFzaGhhc2hoYXNoaGFzaGhhc2g",
			expectedError: "invalid hash parameters",
		},
		{
			name:          "iterations out of range (t=11)",
			hash:          "$argon2id$v=19$m=19456,t=11,p=1$c2FsdHNhbHRzYWx0cw$aGFzaGhhc2hoYXNoaGFzaGhhc2hoYXNoaGFzaGhhc2g",
			expectedError: "hash parameters out of range",
		},
		{
			name:          "parallelism out of range (p=17)",
			hash:          "$argon2id$v=19$m=19456,t=2,p=17$c2FsdHNhbHRzYWx0cw$aGFzaGhhc2hoYXNoaGFzaGhhc2hoYXNoaGFzaGhhc2g",
			expectedError: "hash parameters out of range",
		},
		{
			name:          "salt too short (3 bytes decoded)",
			hash:          "$argon2id$v=19$m=19456,t=2,p=1$Zm9v$aGFzaGhhc2hoYXNoaGFzaGhhc2hoYXNoaGFzaGhhc2g",
			expectedError: "hash parameters out of range",
		},
		{
			name:          "salt too long (65 bytes decoded)",
			hash:          "$argon2id$v=19$m=19456,t=2,p=1$" + base64.RawStdEncoding.EncodeToString(make([]byte, 65)) + "$aGFzaGhhc2hoYXNoaGFzaGhhc2hoYXNoaGFzaGhhc2g",
			expectedError: "hash parameters out of range",
		},
		{
			name:          "hash too short (3 bytes decoded)",
			hash:          "$argon2id$v=19$m=19456,t=2,p=1$c2FsdHNhbHRzYWx0cw$Zm9v",
			expectedError: "hash parameters out of range",
		},
		{
			name:          "hash too long (200 bytes decoded)",
			hash:          "$argon2id$v=19$m=19456,t=2,p=1$c2FsdHNhbHRzYWx0cw$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
			expectedError: "hash parameters out of range",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			v, err := VerifyPassword(tc.hash, "plain")
			assert.Error(t, err)
			assert.Contains(t, err.Error(), tc.expectedError)
			assert.False(t, v)
		})
	}
}

// Enumeration defense in Login discards the error from this call; if dummyHash becomes
// unparseable (e.g. defaultParams or bounds change), the constant-time path silently degrades.
// This test is the guard.
func TestDummyHashIsValid(t *testing.T) {
	valid, err := VerifyPassword(dummyHash, "anything")
	assert.NoError(t, err)
	assert.False(t, valid)
}
