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

type PersonalRecordRepo struct {
	pool *pgxpool.Pool
}

func NewPersonalRecordRepo(pool *pgxpool.Pool) *PersonalRecordRepo {
	return &PersonalRecordRepo{pool: pool}
}

func (r *PersonalRecordRepo) Create(ctx context.Context, rec repository.PersonalRecord) (repository.PersonalRecord, error) {
	var (
		id        pgtype.UUID
		createdAt = rec.CreatedAt
		updatedAt = rec.UpdatedAt
	)
	err := r.pool.QueryRow(ctx,
		`INSERT INTO personal_records (owner_id, data_type, payload)
		 VALUES ($1, $2, $3)
		 RETURNING id, created_at, updated_at`,
		toPgUUID(rec.OwnerID), rec.DataType, rec.Payload,
	).Scan(&id, &createdAt, &updatedAt)
	if err != nil {
		return repository.PersonalRecord{}, fmt.Errorf("create personal record: %w", err)
	}
	rec.ID = fromPgUUID(id)
	rec.CreatedAt = createdAt
	rec.UpdatedAt = updatedAt
	return rec, nil
}

func (r *PersonalRecordRepo) GetByIDForOwner(ctx context.Context, id, ownerID uuid.UUID) (repository.PersonalRecord, error) {
	var (
		rec    repository.PersonalRecord
		pid    pgtype.UUID
		powner pgtype.UUID
	)
	err := r.pool.QueryRow(ctx,
		`SELECT id, owner_id, data_type, payload, created_at, updated_at
		 FROM personal_records
		 WHERE id = $1 AND owner_id = $2`,
		toPgUUID(id), toPgUUID(ownerID),
	).Scan(&pid, &powner, &rec.DataType, &rec.Payload, &rec.CreatedAt, &rec.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return repository.PersonalRecord{}, repository.ErrNotFound
	}
	if err != nil {
		return repository.PersonalRecord{}, fmt.Errorf("get personal record: %w", err)
	}
	rec.ID = fromPgUUID(pid)
	rec.OwnerID = fromPgUUID(powner)
	return rec, nil
}

func (r *PersonalRecordRepo) ListByOwner(ctx context.Context, ownerID uuid.UUID) ([]repository.PersonalRecord, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT id, owner_id, data_type, payload, created_at, updated_at
		 FROM personal_records
		 WHERE owner_id = $1
		 ORDER BY created_at DESC`,
		toPgUUID(ownerID),
	)
	if err != nil {
		return nil, fmt.Errorf("list personal records: %w", err)
	}
	defer rows.Close()

	var out []repository.PersonalRecord
	for rows.Next() {
		var (
			rec    repository.PersonalRecord
			pid    pgtype.UUID
			powner pgtype.UUID
		)
		if err := rows.Scan(&pid, &powner, &rec.DataType, &rec.Payload, &rec.CreatedAt, &rec.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan personal record: %w", err)
		}
		rec.ID = fromPgUUID(pid)
		rec.OwnerID = fromPgUUID(powner)
		out = append(out, rec)
	}
	return out, rows.Err()
}

func (r *PersonalRecordRepo) UpdateForOwner(ctx context.Context, rec repository.PersonalRecord, ownerID uuid.UUID) (repository.PersonalRecord, error) {
	var (
		pid    pgtype.UUID
		powner pgtype.UUID
	)
	err := r.pool.QueryRow(ctx,
		`UPDATE personal_records
		 SET data_type = $1, payload = $2, updated_at = now()
		 WHERE id = $3 AND owner_id = $4
		 RETURNING id, owner_id, data_type, payload, created_at, updated_at`,
		rec.DataType, rec.Payload, toPgUUID(rec.ID), toPgUUID(ownerID),
	).Scan(&pid, &powner, &rec.DataType, &rec.Payload, &rec.CreatedAt, &rec.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return repository.PersonalRecord{}, repository.ErrNotFound
	}
	if err != nil {
		return repository.PersonalRecord{}, fmt.Errorf("update personal record: %w", err)
	}
	rec.ID = fromPgUUID(pid)
	rec.OwnerID = fromPgUUID(powner)
	return rec, nil
}

func (r *PersonalRecordRepo) DeleteByOwner(ctx context.Context, id, ownerID uuid.UUID) error {
	tag, err := r.pool.Exec(ctx,
		`DELETE FROM personal_records WHERE id = $1 AND owner_id = $2`,
		toPgUUID(id), toPgUUID(ownerID),
	)
	if err != nil {
		return fmt.Errorf("delete personal record: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return repository.ErrNotFound
	}
	return nil
}
