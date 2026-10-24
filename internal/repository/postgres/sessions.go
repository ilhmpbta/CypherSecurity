package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/ilhmpbta/CypherSecurity/internal/repository"
)

type SessionRepo struct {
	pool *pgxpool.Pool
}

func NewSessionRepo(pool *pgxpool.Pool) *SessionRepo { return &SessionRepo{pool: pool} }

func (r *SessionRepo) Create(ctx context.Context, s repository.Session) error {
	_, err := r.pool.Exec(ctx,
		`INSERT INTO sessions (id, user_id, expires_at)
		 VALUES ($1, $2, $3)`,
		toPgUUID(s.ID), toPgUUID(s.UserID), s.ExpiresAt,
	)
	if err != nil {
		return fmt.Errorf("create session: %w", err)
	}
	return nil
}

func (r *SessionRepo) GetByID(ctx context.Context, id uuid.UUID) (repository.Session, error) {
	var (
		s      repository.Session
		pid    pgtype.UUID
		userID pgtype.UUID
	)
	err := r.pool.QueryRow(ctx,
		`SELECT id, user_id, expires_at, created_at
		 FROM sessions WHERE id = $1`,
		toPgUUID(id),
	).Scan(&pid, &userID, &s.ExpiresAt, &s.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return repository.Session{}, repository.ErrNotFound
	}
	if err != nil {
		return repository.Session{}, fmt.Errorf("get session: %w", err)
	}
	s.ID = fromPgUUID(pid)
	s.UserID = fromPgUUID(userID)
	return s, nil
}

func (r *SessionRepo) Delete(ctx context.Context, id uuid.UUID) error {
	tag, err := r.pool.Exec(ctx,
		`DELETE FROM sessions WHERE id = $1`, toPgUUID(id))
	if err != nil {
		return fmt.Errorf("delete session: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return repository.ErrNotFound
	}
	return nil
}

func (r *SessionRepo) DeleteExpired(ctx context.Context, before time.Time) (int64, error) {
	tag, err := r.pool.Exec(ctx,
		`DELETE FROM sessions WHERE expires_at < $1`, before)
	if err != nil {
		return 0, fmt.Errorf("delete expired sessions: %w", err)
	}
	return tag.RowsAffected(), nil
}
