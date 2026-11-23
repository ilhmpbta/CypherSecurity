package keys

import (
	"crypto/rsa"
	"crypto/x509"
	"time"

	"github.com/google/uuid"
)

type Session struct {
	UserID  uuid.UUID
	WrapKey []byte
}

type Keypair struct {
	UserID         uuid.UUID
	Algorithm      string
	PublicKey      *rsa.PublicKey
	PublicKeyDER   []byte
	Fingerprint    string
	Certificate    *x509.Certificate
	CertificateDER []byte
	CertExpiresAt  time.Time
	CreatedAt      time.Time
}
