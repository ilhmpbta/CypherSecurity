package keys

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"sync"
	"time"

	"github.com/google/uuid"
)

type Fake struct {
	mu       sync.Mutex
	keypairs map[uuid.UUID]Keypair
	privKeys map[uuid.UUID]*rsa.PrivateKey
	pubKeys  map[uuid.UUID]*rsa.PublicKey
}

func NewFake() *Fake {
	return &Fake{
		keypairs: make(map[uuid.UUID]Keypair),
		privKeys: make(map[uuid.UUID]*rsa.PrivateKey),
		pubKeys:  make(map[uuid.UUID]*rsa.PublicKey),
	}
}

func (f *Fake) EnsureForUser(ctx context.Context, sess Session) (Keypair, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if kp, ok := f.keypairs[sess.UserID]; ok {
		return kp, nil
	}

	if len(sess.WrapKey) == 0 {
		return Keypair{}, ErrSessionLocked
	}

	priv, privDER, certDER, fingerprint, notAfter, err := GenerateKeypairAndCert(sess.UserID.String())
	if err != nil {
		return Keypair{}, err
	}

	cert, _ := x509.ParseCertificate(certDER)

	pubDER, _ := x509.MarshalPKIXPublicKey(&priv.PublicKey)

	kp := Keypair{
		UserID:         sess.UserID,
		Algorithm:      "RSA-3072",
		PublicKey:      &priv.PublicKey,
		PublicKeyDER:   pubDER,
		Fingerprint:    fingerprint,
		Certificate:    cert,
		CertificateDER: certDER,
		CertExpiresAt:  notAfter,
		CreatedAt:      time.Now(),
	}

	f.keypairs[sess.UserID] = kp
	f.privKeys[sess.UserID] = priv
	f.pubKeys[sess.UserID] = &priv.PublicKey

	_ = privDER // suppress unused warning if any
	return kp, nil
}

func (f *Fake) Get(ctx context.Context, userID uuid.UUID) (Keypair, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	kp, ok := f.keypairs[userID]
	if !ok {
		return Keypair{}, ErrNoKeypair
	}
	return kp, nil
}

func (f *Fake) PublicKey(ctx context.Context, userID uuid.UUID) (*rsa.PublicKey, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	pub, ok := f.pubKeys[userID]
	if !ok {
		return nil, ErrNoKeypair
	}
	return pub, nil
}

func (f *Fake) WrapForRequester(ctx context.Context, requesterID uuid.UUID, dek []byte) ([]byte, error) {
	pub, err := f.PublicKey(ctx, requesterID)
	if err != nil {
		return nil, err
	}
	return rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, dek, nil)
}

func (f *Fake) UnwrapForRequester(ctx context.Context, sess Session, wrapped []byte) ([]byte, error) {
	if len(sess.WrapKey) == 0 {
		return nil, ErrSessionLocked
	}
	f.mu.Lock()
	priv, ok := f.privKeys[sess.UserID]
	f.mu.Unlock()
	if !ok {
		return nil, ErrNoKeypair
	}
	return rsa.DecryptOAEP(sha256.New(), rand.Reader, priv, wrapped, nil)
}

func (f *Fake) Sign(ctx context.Context, sess Session, digest []byte) ([]byte, error) {
	if len(sess.WrapKey) == 0 {
		return nil, ErrSessionLocked
	}
	f.mu.Lock()
	priv, ok := f.privKeys[sess.UserID]
	f.mu.Unlock()
	if !ok {
		return nil, ErrNoKeypair
	}
	return rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, digest)
}

func (f *Fake) Verify(ctx context.Context, userID uuid.UUID, digest, sig []byte) (bool, error) {
	pub, err := f.PublicKey(ctx, userID)
	if err != nil {
		return false, err
	}
	err = rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest, sig)
	if err != nil {
		return false, nil
	}
	return true, nil
}
