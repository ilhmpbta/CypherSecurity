package keys

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"io"

	"github.com/google/uuid"
	"github.com/ilhmpbta/CypherSecurity/internal/repository"
)

type Service interface {
	EnsureForUser(ctx context.Context, sess Session) (Keypair, error)
	Get(ctx context.Context, userID uuid.UUID) (Keypair, error)
	PublicKey(ctx context.Context, userID uuid.UUID) (*rsa.PublicKey, error)
	WrapForRequester(ctx context.Context, requesterID uuid.UUID, dek []byte) ([]byte, error)
	UnwrapForRequester(ctx context.Context, sess Session, wrapped []byte) ([]byte, error)
	Sign(ctx context.Context, sess Session, digest []byte) ([]byte, error)
	Verify(ctx context.Context, userID uuid.UUID, digest, sig []byte) (bool, error)
}

type DBService struct {
	keypairRepo repository.UserKeypairRepo
	userRepo    repository.UserRepo
}

func NewDBService(keypairRepo repository.UserKeypairRepo, userRepo repository.UserRepo) *DBService {
	return &DBService{
		keypairRepo: keypairRepo,
		userRepo:    userRepo,
	}
}

func toKeypairDomain(kp repository.UserKeypair) (Keypair, error) {
	pubKey, err := ParsePublicKey(kp.PublicKey)
	if err != nil {
		return Keypair{}, err
	}
	var cert *x509.Certificate
	if len(kp.Certificate) > 0 {
		var parseErr error
		cert, parseErr = x509.ParseCertificate(kp.Certificate)
		if parseErr != nil {
			return Keypair{}, fmt.Errorf("parse certificate: %w", parseErr)
		}
	}
	return Keypair{
		UserID:         kp.UserID,
		Algorithm:      kp.Algorithm,
		PublicKey:      pubKey,
		PublicKeyDER:   kp.PublicKey,
		Fingerprint:    kp.Fingerprint,
		Certificate:    cert,
		CertificateDER: kp.Certificate,
		CertExpiresAt:  kp.CertExpiresAt,
		CreatedAt:      kp.CreatedAt,
	}, nil
}

func (s *DBService) EnsureForUser(ctx context.Context, sess Session) (Keypair, error) {
	existing, err := s.keypairRepo.GetByUserID(ctx, sess.UserID)
	if err == nil {
		return toKeypairDomain(existing)
	}
	if !errors.Is(err, repository.ErrNotFound) {
		return Keypair{}, fmt.Errorf("get user keypair: %w", err)
	}

	if len(sess.WrapKey) == 0 {
		return Keypair{}, ErrSessionLocked
	}

	username := sess.UserID.String()
	if s.userRepo != nil {
		if u, uErr := s.userRepo.GetByID(ctx, sess.UserID); uErr == nil {
			username = u.Username
		}
	}

	priv, privDER, certDER, fingerprint, notAfter, err := GenerateKeypairAndCert(username)
	if err != nil {
		return Keypair{}, err
	}

	encryptedPriv, nonce, err := EncryptPrivateKey(sess.WrapKey, privDER)
	if err != nil {
		return Keypair{}, err
	}

	pubDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		return Keypair{}, fmt.Errorf("marshal public key: %w", err)
	}

	kdfSalt := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, kdfSalt); err != nil {
		return Keypair{}, fmt.Errorf("generate kdf salt: %w", err)
	}

	newKP := repository.UserKeypair{
		UserID:              sess.UserID,
		Algorithm:           "RSA-3072",
		PublicKey:           pubDER,
		PrivateKeyEncrypted: encryptedPriv,
		PrivateKeyNonce:     nonce,
		Fingerprint:         fingerprint,
		Certificate:         certDER,
		CertExpiresAt:       notAfter,
		KDFSalt:             kdfSalt,
	}

	created, err := s.keypairRepo.Create(ctx, newKP)
	if errors.Is(err, repository.ErrConflict) {
		existing, err = s.keypairRepo.GetByUserID(ctx, sess.UserID)
		if err != nil {
			return Keypair{}, fmt.Errorf("get concurrent keypair: %w", err)
		}
		return toKeypairDomain(existing)
	}
	if err != nil {
		return Keypair{}, fmt.Errorf("create keypair repo: %w", err)
	}

	return toKeypairDomain(created)
}

func (s *DBService) Get(ctx context.Context, userID uuid.UUID) (Keypair, error) {
	kp, err := s.keypairRepo.GetByUserID(ctx, userID)
	if errors.Is(err, repository.ErrNotFound) {
		return Keypair{}, ErrNoKeypair
	}
	if err != nil {
		return Keypair{}, fmt.Errorf("get keypair: %w", err)
	}
	return toKeypairDomain(kp)
}

func (s *DBService) PublicKey(ctx context.Context, userID uuid.UUID) (*rsa.PublicKey, error) {
	kp, err := s.Get(ctx, userID)
	if err != nil {
		return nil, err
	}
	return kp.PublicKey, nil
}

func (s *DBService) WrapForRequester(ctx context.Context, requesterID uuid.UUID, dek []byte) ([]byte, error) {
	pubKey, err := s.PublicKey(ctx, requesterID)
	if err != nil {
		return nil, err
	}
	wrapped, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pubKey, dek, nil)
	if err != nil {
		return nil, fmt.Errorf("rsa encrypt oaep: %w", err)
	}
	return wrapped, nil
}

func (s *DBService) UnwrapForRequester(ctx context.Context, sess Session, wrapped []byte) ([]byte, error) {
	if len(sess.WrapKey) == 0 {
		return nil, ErrSessionLocked
	}
	rawKP, err := s.keypairRepo.GetByUserID(ctx, sess.UserID)
	if errors.Is(err, repository.ErrNotFound) {
		return nil, ErrNoKeypair
	}
	if err != nil {
		return nil, fmt.Errorf("get keypair: %w", err)
	}

	privKey, err := DecryptPrivateKey(sess.WrapKey, rawKP.PrivateKeyEncrypted, rawKP.PrivateKeyNonce)
	if err != nil {
		return nil, err
	}

	dek, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, privKey, wrapped, nil)
	if err != nil {
		return nil, fmt.Errorf("rsa decrypt oaep: %w", err)
	}
	return dek, nil
}

func (s *DBService) Sign(ctx context.Context, sess Session, digest []byte) ([]byte, error) {
	if len(sess.WrapKey) == 0 {
		return nil, ErrSessionLocked
	}
	rawKP, err := s.keypairRepo.GetByUserID(ctx, sess.UserID)
	if errors.Is(err, repository.ErrNotFound) {
		return nil, ErrNoKeypair
	}
	if err != nil {
		return nil, fmt.Errorf("get keypair: %w", err)
	}

	privKey, err := DecryptPrivateKey(sess.WrapKey, rawKP.PrivateKeyEncrypted, rawKP.PrivateKeyNonce)
	if err != nil {
		return nil, err
	}

	sig, err := rsa.SignPKCS1v15(rand.Reader, privKey, crypto.SHA256, digest)
	if err != nil {
		return nil, fmt.Errorf("rsa sign pkcs1v15: %w", err)
	}
	return sig, nil
}

func (s *DBService) Verify(ctx context.Context, userID uuid.UUID, digest, sig []byte) (bool, error) {
	pubKey, err := s.PublicKey(ctx, userID)
	if err != nil {
		return false, err
	}
	err = rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, digest, sig)
	if err != nil {
		return false, nil
	}
	return true, nil
}
