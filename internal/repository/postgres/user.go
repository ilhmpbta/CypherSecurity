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

type UserRepo struct {
	pool *pgxpool.Pool
}

func NewUserRepo(pool *pgxpool.Pool) *UserRepo { return &UserRepo{pool: pool} }

// Note: Postgres unique violation mapping (23505 -> ErrConflict) is tested indirectly via service integration tests using mocks; a direct testcontainers test is deferred (b).
func (r *UserRepo) Create(ctx context.Context, username, passwordHash string) (repository.User, error) {
	var (
		u  repository.User
		id pgtype.UUID
	)
	err := r.pool.QueryRow(ctx,
		`INSERT INTO users (username, password_hash)
		 VALUES ($1, $2)
		 RETURNING id, username, password_hash, created_at`,
		username, passwordHash,
	).Scan(&id, &u.Username, &u.PasswordHash, &u.CreatedAt)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return repository.User{}, repository.ErrConflict
		}
		return repository.User{}, fmt.Errorf("create user: %w", err)
	}
	u.ID = fromPgUUID(id)
	return u, nil
}

func (r *UserRepo) GetByUsername(ctx context.Context, username string) (repository.User, error) {
	return r.getOne(ctx,
		`SELECT id, username, password_hash, created_at
		 FROM users WHERE username = $1`, username)
}

func (r *UserRepo) GetByID(ctx context.Context, id uuid.UUID) (repository.User, error) {
	return r.getOne(ctx,
		`SELECT id, username, password_hash, created_at
		 FROM users WHERE id = $1`, toPgUUID(id))
}

func (r *UserRepo) getOne(ctx context.Context, sql string, args ...any) (repository.User, error) {
	var (
		u  repository.User
		id pgtype.UUID
	)
	err := r.pool.QueryRow(ctx, sql, args...).Scan(&id, &u.Username, &u.PasswordHash, &u.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return repository.User{}, repository.ErrNotFound
	}
	if err != nil {
		return repository.User{}, fmt.Errorf("get user: %w", err)
	}
	u.ID = fromPgUUID(id)
	return u, nil
}
