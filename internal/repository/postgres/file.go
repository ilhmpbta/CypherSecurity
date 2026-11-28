package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/ilhmpbta/CypherSecurity/internal/repository"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

type FileRepo struct {
	pool *pgxpool.Pool
}

func NewFileRepo(pool *pgxpool.Pool) *FileRepo { return &FileRepo{pool: pool} }

func (r *FileRepo) Create(ctx context.Context, f repository.File) (repository.File, error) {
	var (
		id        pgtype.UUID
		createdAt = f.CreatedAt
	)
	err := r.pool.QueryRow(ctx,
		`INSERT INTO stored_files
		    (owner_id, storage_key, original_name, content_type,
		     plaintext_size, ciphertext_size, alg_id, wrapped_dek, nonce_prefix)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
		 RETURNING id, created_at`,
		toPgUUID(f.OwnerID), f.StorageKey, f.OriginalName, f.ContentType,
		f.PlaintextSize, f.CiphertextSize, f.AlgID, f.WrappedDEK, f.NoncePrefix,
	).Scan(&id, &createdAt)
	if err != nil {
		return repository.File{}, fmt.Errorf("create file: %w", err)
	}
	f.ID = fromPgUUID(id)
	f.CreatedAt = createdAt
	return f, nil
}

func (r *FileRepo) GetByIDForOwner(ctx context.Context, id, ownerID uuid.UUID) (repository.File, error) {
	var (
		f      repository.File
		pid    pgtype.UUID
		powner pgtype.UUID
	)
	err := r.pool.QueryRow(ctx,
		`SELECT id, owner_id, storage_key, original_name, content_type,
		        plaintext_size, ciphertext_size, alg_id, wrapped_dek, nonce_prefix, created_at
		 FROM stored_files
		 WHERE id = $1 AND owner_id = $2`,
		toPgUUID(id), toPgUUID(ownerID),
	).Scan(&pid, &powner, &f.StorageKey, &f.OriginalName, &f.ContentType,
		&f.PlaintextSize, &f.CiphertextSize, &f.AlgID, &f.WrappedDEK, &f.NoncePrefix, &f.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return repository.File{}, repository.ErrNotFound
	}
	if err != nil {
		return repository.File{}, fmt.Errorf("get file: %w", err)
	}
	f.ID = fromPgUUID(pid)
	f.OwnerID = fromPgUUID(powner)
	return f, nil
}

func (r *FileRepo) GetByID(ctx context.Context, id uuid.UUID) (repository.File, error) {
	var (
		f      repository.File
		pid    pgtype.UUID
		powner pgtype.UUID
	)
	err := r.pool.QueryRow(ctx,
		`SELECT id, owner_id, storage_key, original_name, content_type,
		        plaintext_size, ciphertext_size, alg_id, wrapped_dek, nonce_prefix, created_at
		 FROM stored_files
		 WHERE id = $1`,
		toPgUUID(id),
	).Scan(&pid, &powner, &f.StorageKey, &f.OriginalName, &f.ContentType,
		&f.PlaintextSize, &f.CiphertextSize, &f.AlgID, &f.WrappedDEK, &f.NoncePrefix, &f.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return repository.File{}, repository.ErrNotFound
	}
	if err != nil {
		return repository.File{}, fmt.Errorf("get file by id: %w", err)
	}
	f.ID = fromPgUUID(pid)
	f.OwnerID = fromPgUUID(powner)
	return f, nil
}

func (r *FileRepo) ListByOwner(ctx context.Context, ownerID uuid.UUID) ([]repository.File, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT id, owner_id, storage_key, original_name, content_type,
		        plaintext_size, ciphertext_size, alg_id, wrapped_dek, nonce_prefix, created_at
		 FROM stored_files
		 WHERE owner_id = $1
		 ORDER BY created_at DESC`,
		toPgUUID(ownerID),
	)
	if err != nil {
		return nil, fmt.Errorf("list files: %w", err)
	}
	defer rows.Close()

	var out []repository.File
	for rows.Next() {
		var (
			f      repository.File
			pid    pgtype.UUID
			powner pgtype.UUID
		)
		if err := rows.Scan(&pid, &powner, &f.StorageKey, &f.OriginalName, &f.ContentType,
			&f.PlaintextSize, &f.CiphertextSize, &f.AlgID, &f.WrappedDEK, &f.NoncePrefix, &f.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan file: %w", err)
		}
		f.ID = fromPgUUID(pid)
		f.OwnerID = fromPgUUID(powner)
		out = append(out, f)
	}
	return out, rows.Err()
}

func (r *FileRepo) ListAll(ctx context.Context) ([]repository.File, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT id, owner_id, storage_key, original_name, content_type,
		        plaintext_size, ciphertext_size, alg_id, wrapped_dek, nonce_prefix, created_at
		 FROM stored_files
		 ORDER BY created_at DESC`,
	)
	if err != nil {
		return nil, fmt.Errorf("list all files: %w", err)
	}
	defer rows.Close()

	var out []repository.File
	for rows.Next() {
		var (
			f      repository.File
			pid    pgtype.UUID
			powner pgtype.UUID
		)
		if err := rows.Scan(&pid, &powner, &f.StorageKey, &f.OriginalName, &f.ContentType,
			&f.PlaintextSize, &f.CiphertextSize, &f.AlgID, &f.WrappedDEK, &f.NoncePrefix, &f.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan file: %w", err)
		}
		f.ID = fromPgUUID(pid)
		f.OwnerID = fromPgUUID(powner)
		out = append(out, f)
	}
	return out, rows.Err()
}

func (r *FileRepo) DeleteByOwner(ctx context.Context, id, ownerID uuid.UUID) error {
	tag, err := r.pool.Exec(ctx,
		`DELETE FROM stored_files WHERE id = $1 AND owner_id = $2`,
		toPgUUID(id), toPgUUID(ownerID),
	)
	if err != nil {
		return fmt.Errorf("delete file: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return repository.ErrNotFound
	}
	return nil
}

func (r *FileRepo) UpdateForOwner(ctx context.Context, f repository.File) (repository.File, error) {
	tag, err := r.pool.Exec(ctx,
		`UPDATE stored_files
		 SET storage_key = $1, plaintext_size = $2, ciphertext_size = $3
		 WHERE id = $4 AND owner_id = $5`,
		f.StorageKey, f.PlaintextSize, f.CiphertextSize,
		toPgUUID(f.ID), toPgUUID(f.OwnerID),
	)
	if err != nil {
		return repository.File{}, fmt.Errorf("update file: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return repository.File{}, repository.ErrNotFound
	}
	return f, nil
}
