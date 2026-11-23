package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/ilhmpbta/CypherSecurity/internal/repository"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

type UserKeypairRepo struct {
	pool *pgxpool.Pool
}

func NewUserKeypairRepo(pool *pgxpool.Pool) *UserKeypairRepo {
	return &UserKeypairRepo{pool: pool}
}

func (r *UserKeypairRepo) Create(ctx context.Context, kp repository.UserKeypair) (repository.UserKeypair, error) {
	var (
		res           repository.UserKeypair
		uid           pgtype.UUID
		cert          []byte
		certExpiresAt pgtype.Timestamptz
	)

	err := r.pool.QueryRow(ctx,
		`INSERT INTO user_keypairs (user_id, algorithm, public_key, private_key_encrypted, private_key_nonce, fingerprint, certificate, cert_expires_at, kdf_salt)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		 RETURNING user_id, algorithm, public_key, private_key_encrypted, private_key_nonce, fingerprint, certificate, cert_expires_at, kdf_salt, created_at`,
		toPgUUID(kp.UserID), kp.Algorithm, kp.PublicKey, kp.PrivateKeyEncrypted, kp.PrivateKeyNonce, kp.Fingerprint, kp.Certificate, kp.CertExpiresAt, kp.KDFSalt,
	).Scan(
		&uid, &res.Algorithm, &res.PublicKey, &res.PrivateKeyEncrypted, &res.PrivateKeyNonce, &res.Fingerprint, &cert, &certExpiresAt, &res.KDFSalt, &res.CreatedAt,
	)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return repository.UserKeypair{}, repository.ErrConflict
		}
		return repository.UserKeypair{}, fmt.Errorf("create user keypair: %w", err)
	}
	res.UserID = fromPgUUID(uid)
	res.Certificate = cert
	if certExpiresAt.Valid {
		res.CertExpiresAt = certExpiresAt.Time
	}
	return res, nil
}

func (r *UserKeypairRepo) GetByUserID(ctx context.Context, userID uuid.UUID) (repository.UserKeypair, error) {
	var (
		res           repository.UserKeypair
		uid           pgtype.UUID
		cert          []byte
		certExpiresAt pgtype.Timestamptz
	)
	err := r.pool.QueryRow(ctx,
		`SELECT user_id, algorithm, public_key, private_key_encrypted, private_key_nonce, fingerprint, certificate, cert_expires_at, kdf_salt, created_at
		 FROM user_keypairs WHERE user_id = $1`,
		toPgUUID(userID),
	).Scan(
		&uid, &res.Algorithm, &res.PublicKey, &res.PrivateKeyEncrypted, &res.PrivateKeyNonce, &res.Fingerprint, &cert, &certExpiresAt, &res.KDFSalt, &res.CreatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return repository.UserKeypair{}, repository.ErrNotFound
	}
	if err != nil {
		return repository.UserKeypair{}, fmt.Errorf("get user keypair by user id: %w", err)
	}
	res.UserID = fromPgUUID(uid)
	res.Certificate = cert
	if certExpiresAt.Valid {
		res.CertExpiresAt = certExpiresAt.Time
	}
	return res, nil
}

func (r *UserKeypairRepo) GetByFingerprint(ctx context.Context, fingerprint string) (repository.UserKeypair, error) {
	var (
		res           repository.UserKeypair
		uid           pgtype.UUID
		cert          []byte
		certExpiresAt pgtype.Timestamptz
	)
	err := r.pool.QueryRow(ctx,
		`SELECT user_id, algorithm, public_key, private_key_encrypted, private_key_nonce, fingerprint, certificate, cert_expires_at, kdf_salt, created_at
		 FROM user_keypairs WHERE fingerprint = $1`,
		fingerprint,
	).Scan(
		&uid, &res.Algorithm, &res.PublicKey, &res.PrivateKeyEncrypted, &res.PrivateKeyNonce, &res.Fingerprint, &cert, &certExpiresAt, &res.KDFSalt, &res.CreatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return repository.UserKeypair{}, repository.ErrNotFound
	}
	if err != nil {
		return repository.UserKeypair{}, fmt.Errorf("get user keypair by fingerprint: %w", err)
	}
	res.UserID = fromPgUUID(uid)
	res.Certificate = cert
	if certExpiresAt.Valid {
		res.CertExpiresAt = certExpiresAt.Time
	}
	return res, nil
}
